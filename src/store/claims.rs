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
const LIVE: &str = "(g.claim IS NULL OR NOT EXISTS (SELECT 1 FROM tomb_targets x WHERE x.target = g.claim))";

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
            "-- `claim` is a precipitated claim's multihash, NULL for a
             -- dissolved one, which has none.
             CREATE TABLE IF NOT EXISTS group_claims (
                 id INTEGER PRIMARY KEY,
                 claim INTEGER UNIQUE REFERENCES multihashes (id),
                 into_ INTEGER NOT NULL REFERENCES multihashes (id),
                 into_prefix BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS group_claims_into ON group_claims (into_);
             CREATE TABLE IF NOT EXISTS group_targets (
                 group_ INTEGER NOT NULL REFERENCES group_claims (id) ON DELETE CASCADE,
                 target INTEGER NOT NULL REFERENCES multihashes (id),
                 prefix BLOB NOT NULL,
                 PRIMARY KEY (group_, target, prefix)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS group_targets_target ON group_targets (target);
             CREATE TABLE IF NOT EXISTS tombs (
                 id INTEGER PRIMARY KEY,
                 claim INTEGER UNIQUE REFERENCES multihashes (id)
             );
             CREATE TABLE IF NOT EXISTS tomb_targets (
                 tomb INTEGER NOT NULL REFERENCES tombs (id) ON DELETE CASCADE,
                 target INTEGER NOT NULL REFERENCES multihashes (id),
                 prefix BLOB NOT NULL,
                 PRIMARY KEY (tomb, target, prefix)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS tomb_targets_target ON tomb_targets (target);
             -- Every block's tags that still count. A simple tag's name is its
             -- identity digest, after the multihash's code and length varint
             -- (one byte, or two from 128).
             CREATE VIEW IF NOT EXISTS tags (target, tag, name) AS
                 SELECT DISTINCT t.target, g.into_,
                     CASE WHEN g.into_prefix = x'0155' AND substr(i.multihash, 1, 1) = x'00' THEN
                         CAST(substr(i.multihash, CASE WHEN length(i.multihash) <= 129 THEN 3 ELSE 4 END) AS TEXT)
                     END
                 FROM group_targets t
                 JOIN group_claims g ON g.id = t.group_
                 JOIN multihashes i ON i.id = g.into_
                 WHERE {LIVE};"
        ))?;
        Ok(Self { db })
    }

    fn group(&self, id: Id) -> Result<Group> {
        let (prefix, into) = self.db.conn()
            .prepare_cached("SELECT g.into_prefix, i.multihash FROM group_claims g JOIN multihashes i ON i.id = g.into_ WHERE g.id = ?1")?
            .query_row([id], pair)?;
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT t.prefix, m.multihash FROM group_targets t JOIN multihashes m ON m.id = t.target WHERE t.group_ = ?1",
        )?;
        let target = links(stmt.query_map([id], pair)?)?;
        Group::new(target, link(&prefix, &into)?)
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "a group with no targets".into() })
    }

    fn tomb(&self, id: Id) -> Result<Tomb> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT t.prefix, m.multihash FROM tomb_targets t JOIN multihashes m ON m.id = t.target WHERE t.tomb = ?1",
        )?;
        let target = links(stmt.query_map([id], pair)?)?;
        Tomb::new(target).ok_or_else(|| Error::Invalid { store: NAME, reason: "a tomb with no targets".into() })
    }

    /// A precipitated claim, by its multihash.
    fn load(&self, key: Key<'_>) -> Result<Option<Claim>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(None);
        };
        let conn = self.db.conn();
        if let Some(group) = conn.prepare_cached("SELECT id FROM group_claims WHERE claim = ?1")?.query_row([id], |r| r.get(0)).optional()? {
            return self.group(group).map(|g| Some(Claim::Group(g)));
        }
        if let Some(tomb) = conn.prepare_cached("SELECT id FROM tombs WHERE claim = ?1")?.query_row([id], |r| r.get(0)).optional()? {
            return self.tomb(tomb).map(|t| Some(Claim::Tomb(t)));
        }
        Ok(None)
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
                        "SELECT g.id FROM group_claims g JOIN group_targets t ON t.group_ = g.id
                         WHERE g.claim IS NULL AND g.into_ = ?1 AND g.into_prefix = ?2 AND t.target = ?3 AND t.prefix = ?4",
                    )?
                    .query_row(params![into, into_prefix, target, prefix], |r| r.get(0))
                    .optional()?
            },
            Claim::Tomb(_) => self.db.conn()
                .prepare_cached(
                    "SELECT b.id FROM tombs b JOIN tomb_targets t ON t.tomb = b.id
                     WHERE b.claim IS NULL AND t.target = ?1 AND t.prefix = ?2",
                )?
                .query_row(params![target, prefix], |r| r.get(0))
                .optional()?,
        })
    }

    /// Whether a tomb targets a claim's multihash.
    fn tombstoned(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM multihashes m JOIN tomb_targets t ON t.target = m.id WHERE m.multihash = ?1 LIMIT 1")?
            .exists([key.to_bytes()])?)
    }

    /// Whether a dissolved claim is here.
    pub fn has_dissolved(&self, claim: &Claim) -> Result<bool> {
        Ok(self.find_dissolved(claim)?.is_some())
    }

    /// Put a claim, under its multihash if it's precipitated.
    fn insert(&self, claim: &Claim, multihash: Option<Key<'_>>) -> Result<()> {
        let id = multihash.map(|key| self.db.intern(key)).transpose()?;
        let conn = self.db.conn();
        let (row, targets_sql) = match claim {
            Claim::Group(group) => {
                let (into_prefix, into) = split(group.group())?;
                let into = self.db.intern(into.as_ref())?;
                conn.prepare_cached("INSERT INTO group_claims (claim, into_, into_prefix) VALUES (?1, ?2, ?3)")?
                    .execute(params![id, into, into_prefix])?;
                (conn.last_insert_rowid(), "INSERT OR IGNORE INTO group_targets (group_, target, prefix) VALUES (?1, ?2, ?3)")
            },
            Claim::Tomb(_) => {
                conn.prepare_cached("INSERT INTO tombs (claim) VALUES (?1)")?.execute([id])?;
                (conn.last_insert_rowid(), "INSERT OR IGNORE INTO tomb_targets (tomb, target, prefix) VALUES (?1, ?2, ?3)")
            },
        };
        let mut stmt = conn.prepare_cached(targets_sql)?;
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
                self.db.conn().prepare_cached("DELETE FROM group_claims WHERE id = ?1")?.execute([id])?;
            }
        }
        Ok(())
    }

    /// Every tag on a block that counts, under any CID.
    pub fn tags(&self, target: Key<'_>) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT g.into_prefix, i.multihash FROM multihashes m
             JOIN group_targets t ON t.target = m.id
             JOIN group_claims g ON g.id = t.group_
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
             JOIN group_targets t ON t.group_ = g.id
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
            "SELECT DISTINCT g.id, c.multihash FROM multihashes m
             JOIN group_targets t ON t.target = m.id
             JOIN group_claims g ON g.id = t.group_
             JOIN multihashes i ON i.id = g.into_
             LEFT JOIN multihashes c ON c.id = g.claim
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
            "SELECT m.multihash FROM multihashes m WHERE m.id IN (
                 SELECT claim FROM group_claims UNION SELECT claim FROM tombs
             )",
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
        let mut out = Vec::new();
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT g.id, c.multihash FROM multihashes m JOIN group_targets t ON t.target = m.id
             JOIN group_claims g ON g.id = t.group_ LEFT JOIN multihashes c ON c.id = g.claim WHERE m.multihash = ?1
             UNION
             SELECT g.id, c.multihash FROM multihashes m JOIN group_claims g ON g.into_ = m.id
             LEFT JOIN multihashes c ON c.id = g.claim WHERE m.multihash = ?1",
        )?;
        let groups: Vec<(Id, Option<Vec<u8>>)> = stmt
            .query_map([key.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, claim) in groups {
            out.push(key_of(claim, || self.group(id).map(Claim::Group))?);
        }
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT b.id, c.multihash FROM multihashes m JOIN tomb_targets t ON t.target = m.id
             JOIN tombs b ON b.id = t.tomb LEFT JOIN multihashes c ON c.id = b.claim WHERE m.multihash = ?1",
        )?;
        let tombs: Vec<(Id, Option<Vec<u8>>)> = stmt
            .query_map([key.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, claim) in tombs {
            out.push(key_of(claim, || self.tomb(id).map(Claim::Tomb))?);
        }
        Ok(out)
    }
}
