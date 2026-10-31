//! A store specialized for claims, keeping each as rows rather than bytes:
//! a tag is a row, not a blob. So far `Group` claims, which are tags, and
//! `Tomb`s, which retract them.
//!
//! A claim is admitted only if it's exactly a claim in canonical form (see
//! `claim::Claim::parse`); anything else that's dag-cbor belongs to the
//! IPLD store. Links are rows by interned multihash, as everywhere, with
//! their CID prefixes kept to manifest them, so the rows double as a
//! `RefIndex` and as an index of tags.
//!
//! A dissolved claim (see `claim`) is rows with no multihash of its own:
//! its CID is its bytes, so it's found by what it says. A precipitated one
//! is rows under its multihash, like any block.
//!
//! A tomb retracts a dissolved claim at once, deleting its rows, and keeps
//! it from being put again. A precipitated claim it targets stays until
//! it's collected, but no longer counts as a tag.

use rusqlite::{OptionalExtension, params};

use crate::block::{Block, IDENTITY};
use crate::cid::{BaseCid, Cid, CidRef, Cidv1, DAG_CBOR_CODEC};
use crate::claim::{self, Claim, Group, Tomb};
use crate::model::Link;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Id, Key, Put, RefIndex, Result, Store, query_keys, split_cid};

const NAME: &str = "claims";

/// Whether a group counts: dissolved claims are deleted when they're
/// tombstoned, precipitated ones have to be checked.
const LIVE: &str = "(c.claim IS NULL OR NOT EXISTS (
    SELECT 1 FROM claim_targets x JOIN claims k ON k.id = x.claim WHERE x.target = c.claim AND k.kind = 'tomb'
))";

/// Admits canonical claims, keeping them as rows.
pub struct ClaimStore {
    db: Db,
}

/// A link back out of its prefix and multihash.
fn link(prefix: &[u8], multihash: &[u8]) -> Result<Link> {
    Link::decode(&[prefix, multihash].concat())
        .map_err(|e| Error::Invalid { store: NAME, reason: format!("CID: {e:?}") })
}

/// A link's prefix and multihash, for rows.
fn split(link: &Link) -> Result<(Vec<u8>, Multihash)> {
    let bytes = link.to_bytes();
    let (prefix, multihash) = split_cid(&bytes).ok_or_else(|| Error::Invalid { store: NAME, reason: format!("CID {link}") })?;
    Ok((prefix.to_vec(), super::decode_key(NAME, &multihash.to_bytes())?))
}

/// Rows of (prefix, multihash) as links.
fn links(rows: impl Iterator<Item = rusqlite::Result<(Vec<u8>, Vec<u8>)>>) -> Result<Vec<Link>> {
    rows.map(|row| {
        let (prefix, multihash) = row?;
        link(&prefix, &multihash)
    })
    .collect()
}

fn pair(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
    Ok((row.get(0)?, row.get(1)?))
}

impl ClaimStore {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(&format!(
            "-- Every claim, of any type. `claim` is a precipitated claim's
             -- multihash, NULL for a dissolved one, which has none; `kind` is
             -- its type, as the claim's own `claim` key says it.
             CREATE TABLE IF NOT EXISTS claims (
                 id INTEGER PRIMARY KEY,
                 claim INTEGER UNIQUE REFERENCES multihashes (id),
                 kind TEXT NOT NULL CHECK (kind IN ('group', 'tomb'))
             );
             -- Every claim's targets, which every type has.
             CREATE TABLE IF NOT EXISTS claim_targets (
                 claim INTEGER NOT NULL REFERENCES claims (id) ON DELETE CASCADE,
                 target INTEGER NOT NULL REFERENCES multihashes (id),
                 prefix BLOB NOT NULL,
                 PRIMARY KEY (claim, target, prefix)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS claim_targets_target ON claim_targets (target);
             -- What's particular to each type; a tomb has nothing but targets.
             CREATE TABLE IF NOT EXISTS group_claims (
                 id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
                 into_ INTEGER NOT NULL REFERENCES multihashes (id),
                 into_prefix BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS group_claims_into ON group_claims (into_);
             -- Every block's tags that still count. A simple tag's name is its
             -- identity digest, after the multihash's code and length varint
             -- (one byte, or two from 128).
             CREATE VIEW IF NOT EXISTS tags (target, tag, name) AS
                 SELECT DISTINCT t.target, g.into_,
                     CASE WHEN g.into_prefix = x'0155' AND substr(i.multihash, 1, 1) = x'00' THEN
                         CAST(substr(i.multihash, CASE WHEN length(i.multihash) <= 129 THEN 3 ELSE 4 END) AS TEXT)
                     END
                 FROM claim_targets t
                 JOIN claims c ON c.id = t.claim
                 JOIN group_claims g ON g.id = c.id
                 JOIN multihashes i ON i.id = g.into_
                 WHERE {LIVE};"
        ))?;
        Ok(Self { db })
    }

    fn group(&self, id: Id) -> Result<Group> {
        let (prefix, into) = self.db.conn()
            .prepare_cached("SELECT g.into_prefix, i.multihash FROM group_claims g JOIN multihashes i ON i.id = g.into_ WHERE g.id = ?1")?
            .query_row([id], pair)?;
        Group::new(self.targets(id)?, link(&prefix, &into)?)
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "a group with no targets".into() })
    }

    fn targets(&self, id: Id) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT t.prefix, m.multihash FROM claim_targets t JOIN multihashes m ON m.id = t.target WHERE t.claim = ?1",
        )?;
        links(stmt.query_map([id], pair)?)
    }

    /// The claim in a row, by its type.
    fn claim(&self, id: Id, kind: &str) -> Result<Claim> {
        match kind {
            "group" => self.group(id).map(Claim::Group),
            "tomb" => self.tomb(id).map(Claim::Tomb),
            _ => Err(Error::Invalid { store: NAME, reason: format!("a claim of kind {kind}") }),
        }
    }

    fn tomb(&self, id: Id) -> Result<Tomb> {
        Tomb::new(self.targets(id)?).ok_or_else(|| Error::Invalid { store: NAME, reason: "a tomb with no targets".into() })
    }

    /// A precipitated claim, by its multihash.
    fn load(&self, key: Key<'_>) -> Result<Option<Claim>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(None);
        };
        let row = self.db.conn()
            .prepare_cached("SELECT id, kind FROM claims WHERE claim = ?1")?
            .query_row([id], |r| Ok((r.get::<_, Id>(0)?, r.get::<_, String>(1)?)))
            .optional()?;
        row.map(|(id, kind)| self.claim(id, &kind)).transpose()
    }

    /// The row of a dissolved claim, which has a single target, found by
    /// what it says.
    fn find_dissolved(&self, claim: &Claim) -> Result<Option<Id>> {
        let [target] = claim.target() else {
            return Ok(None);
        };
        let (prefix, multihash) = split(target)?;
        let Some(target) = self.db.lookup(multihash.as_ref())? else {
            return Ok(None);
        };
        Ok(match claim {
            Claim::Group(group) => {
                let (into_prefix, into) = split(group.group())?;
                let Some(into) = self.db.lookup(into.as_ref())? else {
                    return Ok(None);
                };
                self.db.conn()
                    .prepare_cached(
                        "SELECT c.id FROM claims c JOIN group_claims g ON g.id = c.id JOIN claim_targets t ON t.claim = c.id
                         WHERE c.claim IS NULL AND g.into_ = ?1 AND g.into_prefix = ?2 AND t.target = ?3 AND t.prefix = ?4",
                    )?
                    .query_row(params![into, into_prefix, target, prefix], |r| r.get(0))
                    .optional()?
            },
            Claim::Tomb(_) => self.db.conn()
                .prepare_cached(
                    "SELECT c.id FROM claims c JOIN claim_targets t ON t.claim = c.id
                     WHERE c.claim IS NULL AND c.kind = 'tomb' AND t.target = ?1 AND t.prefix = ?2",
                )?
                .query_row(params![target, prefix], |r| r.get(0))
                .optional()?,
        })
    }

    /// Whether a tomb targets a claim's multihash.
    fn tombstoned(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN claim_targets t ON t.target = m.id JOIN claims c ON c.id = t.claim
                 WHERE m.multihash = ?1 AND c.kind = 'tomb' LIMIT 1",
            )?
            .exists([key.to_bytes()])?)
    }

    /// Every dissolved claim here.
    pub fn dissolved(&self) -> Result<Vec<Claim>> {
        let rows: Vec<(Id, String)> = self.db.conn()
            .prepare_cached("SELECT id, kind FROM claims WHERE claim IS NULL ORDER BY id")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(id, kind)| self.claim(id, &kind)).collect()
    }

    /// The dissolved claim in a row, if it's one.
    pub fn dissolved_row(&self, id: Id) -> Result<Option<Claim>> {
        let kind: Option<String> = self.db.conn()
            .prepare_cached("SELECT kind FROM claims WHERE id = ?1 AND claim IS NULL")?
            .query_row([id], |r| r.get(0))
            .optional()?;
        kind.map(|kind| self.claim(id, &kind)).transpose()
    }

    /// Whether a dissolved claim is here.
    pub fn has_dissolved(&self, claim: &Claim) -> Result<bool> {
        Ok(self.find_dissolved(claim)?.is_some())
    }

    /// Put a claim, under its multihash if it's precipitated.
    fn insert(&self, claim: &Claim, multihash: Option<Key<'_>>) -> Result<()> {
        let id = multihash.map(|key| self.db.intern(key)).transpose()?;
        let conn = self.db.conn();
        let kind = match claim {
            Claim::Group(_) => "group",
            Claim::Tomb(_) => "tomb",
        };
        conn.prepare_cached("INSERT INTO claims (claim, kind) VALUES (?1, ?2)")?.execute(params![id, kind])?;
        let row = conn.last_insert_rowid();
        if let Claim::Group(group) = claim {
            let (into_prefix, into) = split(group.group())?;
            conn.prepare_cached("INSERT INTO group_claims (id, into_, into_prefix) VALUES (?1, ?2, ?3)")?
                .execute(params![row, self.db.intern(into.as_ref())?, into_prefix])?;
        }
        let mut stmt = conn.prepare_cached("INSERT OR IGNORE INTO claim_targets (claim, target, prefix) VALUES (?1, ?2, ?3)")?;
        for target in claim.target() {
            let (prefix, multihash) = split(target)?;
            stmt.execute(params![row, self.db.intern(multihash.as_ref())?, prefix])?;
        }
        Ok(())
    }

    /// Retract the dissolved claims a tomb targets.
    fn bury(&self, tomb: &Tomb) -> Result<()> {
        for target in tomb.target() {
            if let Some(Claim::Group(group)) = claim::dissolved(target)
                && let Some(id) = self.find_dissolved(&Claim::Group(group))?
            {
                self.db.conn().prepare_cached("DELETE FROM claims WHERE id = ?1")?.execute([id])?;
            }
        }
        Ok(())
    }

    /// Every tag on a block that counts, under any CID.
    pub fn tags(&self, target: Key<'_>) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT g.into_prefix, i.multihash FROM multihashes m
             JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim
             JOIN group_claims g ON g.id = c.id
             JOIN multihashes i ON i.id = g.into_
             WHERE m.multihash = ?1 AND {LIVE}
             ORDER BY i.multihash"
        ))?;
        links(stmt.query_map([target.to_bytes()], pair)?)
    }

    /// Every block with a tag that counts, under the CIDs it was tagged by.
    pub fn tagged(&self, tag: Key<'_>) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT t.prefix, m.multihash FROM multihashes i
             JOIN group_claims g ON g.into_ = i.id
             JOIN claims c ON c.id = g.id
             JOIN claim_targets t ON t.claim = c.id
             JOIN multihashes m ON m.id = t.target
             WHERE i.multihash = ?1 AND {LIVE}
             ORDER BY m.multihash, t.prefix"
        ))?;
        links(stmt.query_map([tag.to_bytes()], pair)?)
    }

    /// The claims that count which tag a block with a tag, as CIDs and
    /// what they say.
    pub fn tagging(&self, target: Key<'_>, tag: Key<'_>) -> Result<Vec<(Link, Group)>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT c.id, k.multihash FROM multihashes m
             JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim
             JOIN group_claims g ON g.id = c.id
             JOIN multihashes i ON i.id = g.into_
             LEFT JOIN multihashes k ON k.id = c.claim
             WHERE m.multihash = ?1 AND i.multihash = ?2 AND {LIVE}"
        ))?;
        let rows = stmt.query_map([target.to_bytes(), tag.to_bytes()], |row| Ok((row.get::<_, Id>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)))?;
        rows.map(|row| {
            let (id, multihash) = row?;
            let group = self.group(id)?;
            let cid = match multihash {
                Some(multihash) => crate::cid::AnyCid::V1(Cidv1::new(DAG_CBOR_CODEC, super::decode_key(NAME, &multihash)?)),
                None => Claim::Group(group.clone()).cid(),
            };
            Ok((cid, group))
        })
        .collect()
    }
}

/// The multihash a claim row is known by: its own if precipitated, its
/// identity if dissolved.
fn key_of(claim: Option<Vec<u8>>, dissolved: impl FnOnce() -> Result<Claim>) -> Result<Multihash> {
    if let Some(bytes) = claim {
        return super::decode_key(NAME, &bytes);
    }
    Ok(Multihash::from(dissolved()?.block().cid().clone()))
}

impl Store for ClaimStore {
    fn name(&self) -> &'static str { NAME }
    fn refs(&self) -> Option<&dyn RefIndex> { Some(self) }
}

impl BlockIndex for ClaimStore {
    /// Precipitated claims; dissolved ones aren't blocks, but their CIDs.
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.load(key)?.is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(
            &self.db,
            NAME,
            "SELECT m.multihash FROM multihashes m WHERE m.id IN (SELECT claim FROM claims)",
        )
    }
}

impl BlockSource for ClaimStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        Ok(self.load(key)?.map(|claim| claim.block().into_data().into_vec()))
    }
}

impl BlockStore for ClaimStore {
    fn put(&self, block: &Block) -> Result<Put> {
        if block.cid().codec() != DAG_CBOR_CODEC {
            return Ok(Put::Declined);
        }
        let Some(claim) = Claim::parse(block.data()) else {
            return Ok(Put::Declined);
        };
        let key = block.cid().multihash();
        let dissolved = block.cid().hashcode() == IDENTITY;
        // An identity CID for a claim that should be hashed isn't one
        if dissolved && !claim.dissolves() {
            return Ok(Put::Declined);
        }
        let present = if dissolved { self.has_dissolved(&claim)? } else { self.has(key)? };
        // A retracted dissolved claim isn't brought back
        if present || (dissolved && self.tombstoned(key)?) {
            return Ok(Put::Stored);
        }
        self.db.atomically(|| {
            self.insert(&claim, (!dissolved).then_some(key))?;
            if let Claim::Tomb(tomb) = &claim {
                self.bury(tomb)?;
            }
            Ok(Put::Stored)
        })
    }
}

impl RefIndex for ClaimStore {
    /// Claims with a link to the multihash, as a target or what they're
    /// into.
    fn backrefs(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT c.id, c.kind, k.multihash FROM multihashes m JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim LEFT JOIN multihashes k ON k.id = c.claim WHERE m.multihash = ?1
             UNION
             SELECT c.id, c.kind, k.multihash FROM multihashes m JOIN group_claims g ON g.into_ = m.id
             JOIN claims c ON c.id = g.id LEFT JOIN multihashes k ON k.id = c.claim WHERE m.multihash = ?1",
        )?;
        let rows: Vec<(Id, String, Option<Vec<u8>>)> = stmt
            .query_map([key.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(id, kind, claim)| key_of(claim, || self.claim(id, &kind))).collect()
    }
}
