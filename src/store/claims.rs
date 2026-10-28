//! A store specialized for claims, keeping each as rows rather than bytes:
//! a tag is a row, not a blob. So far only `Group` claims, which are tags.
//!
//! A claim is admitted only if it's exactly a claim in canonical form (see
//! `claim::Group::parse`); anything else that's dag-cbor belongs to the
//! IPLD store. Links are rows by interned multihash, as everywhere, with
//! their CID prefixes kept to manifest them, so the rows double as a
//! `RefIndex` and as an index of tags.

use rusqlite::{OptionalExtension, params};

use crate::block::Block;
use crate::cid::{BaseCid, Cid, CidRef, DAG_CBOR_CODEC};
use crate::claim::Group;
use crate::model::Link;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Key, Put, RefIndex, Result, Store, query_keys, split_cid};

const NAME: &str = "claims";

/// Admits canonical claims, keeping them as rows.
pub struct ClaimStore {
    db: Db,
}

/// A link back out of its prefix and multihash.
fn link(prefix: &[u8], multihash: &[u8]) -> Result<Link> {
    Link::decode(&[prefix, multihash].concat())
        .map_err(|e| Error::Invalid { store: NAME, reason: format!("CID: {e:?}") })
}

impl ClaimStore {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS group_claims (
                 claim INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 into_ INTEGER NOT NULL REFERENCES multihashes (id),
                 into_prefix BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS group_claims_into ON group_claims (into_);
             CREATE TABLE IF NOT EXISTS group_targets (
                 claim INTEGER NOT NULL REFERENCES group_claims (claim) ON DELETE CASCADE,
                 target INTEGER NOT NULL REFERENCES multihashes (id),
                 prefix BLOB NOT NULL,
                 PRIMARY KEY (claim, target, prefix)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS group_targets_target ON group_targets (target);
             -- Every block's tags, by the claims tagging it. A simple tag's
             -- name is its identity digest, after the multihash's code and
             -- length bytes.
             CREATE VIEW IF NOT EXISTS tags (target, tag, name, claim) AS
                 SELECT t.target, c.into_,
                     CASE WHEN c.into_prefix = x'0155' AND substr(i.multihash, 1, 1) = x'00'
                         THEN CAST(substr(i.multihash, 3) AS TEXT) END,
                     c.claim
                 FROM group_targets t
                 JOIN group_claims c ON c.claim = t.claim
                 JOIN multihashes i ON i.id = c.into_;",
        )?;
        Ok(Self { db })
    }

    fn load(&self, key: Key<'_>) -> Result<Option<Group>> {
        let row = self.db.conn()
            .prepare_cached(
                "SELECT c.claim, c.into_prefix, i.multihash FROM multihashes m
                 JOIN group_claims c ON c.claim = m.id
                 JOIN multihashes i ON i.id = c.into_
                 WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?)))
            .optional()?;
        let Some((id, into_prefix, into)) = row else {
            return Ok(None);
        };
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT t.prefix, m.multihash FROM group_targets t JOIN multihashes m ON m.id = t.target WHERE t.claim = ?1",
        )?;
        let target = stmt
            .query_map([id], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?
            .map(|row| {
                let (prefix, multihash) = row?;
                link(&prefix, &multihash)
            })
            .collect::<Result<Vec<_>>>()?;
        Group::new(target, link(&into_prefix, &into)?)
            .map(Some)
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "a group with no targets".into() })
    }

    /// Links from a query of (prefix, multihash) rows, each once.
    fn links(&self, sql: &str, key: Key<'_>) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(sql)?;
        let rows = stmt.query_map([key.to_bytes()], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
        rows.map(|row| {
            let (prefix, multihash) = row?;
            link(&prefix, &multihash)
        })
        .collect()
    }

    /// Every tag on a block, under any CID.
    pub fn tags(&self, target: Key<'_>) -> Result<Vec<Link>> {
        self.links(
            "SELECT DISTINCT c.into_prefix, i.multihash FROM multihashes m
             JOIN group_targets t ON t.target = m.id
             JOIN group_claims c ON c.claim = t.claim
             JOIN multihashes i ON i.id = c.into_
             WHERE m.multihash = ?1
             ORDER BY i.multihash",
            target,
        )
    }

    /// Every block with a tag, under the CIDs it was tagged by.
    pub fn tagged(&self, tag: Key<'_>) -> Result<Vec<Link>> {
        self.links(
            "SELECT DISTINCT t.prefix, m.multihash FROM multihashes i
             JOIN group_claims c ON c.into_ = i.id
             JOIN group_targets t ON t.claim = c.claim
             JOIN multihashes m ON m.id = t.target
             WHERE i.multihash = ?1
             ORDER BY m.multihash, t.prefix",
            tag,
        )
    }
}

impl Store for ClaimStore {
    fn name(&self) -> &'static str { NAME }
    fn refs(&self) -> Option<&dyn RefIndex> { Some(self) }
}

impl BlockIndex for ClaimStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM multihashes m JOIN group_claims c ON c.claim = m.id WHERE m.multihash = ?1")?
            .query_row([key.to_bytes()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, NAME, "SELECT m.multihash FROM group_claims c JOIN multihashes m ON m.id = c.claim")
    }
}

impl BlockSource for ClaimStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        Ok(self.load(key)?.map(|group| group.block().into_data().into_vec()))
    }
}

impl BlockStore for ClaimStore {
    fn put(&self, block: &Block) -> Result<Put> {
        if block.cid().codec() != DAG_CBOR_CODEC {
            return Ok(Put::Declined);
        }
        let Some(group) = Group::parse(block.data()) else {
            return Ok(Put::Declined);
        };
        if self.has(block.cid().multihash())? {
            return Ok(Put::Stored);
        }
        self.db.atomically(|| {
            let id = self.db.intern(block.cid().multihash())?;
            let into = group.group().to_bytes();
            let Some((into_prefix, into)) = split_cid(&into) else {
                return Ok(Put::Declined);
            };
            self.db.conn()
                .prepare_cached("INSERT INTO group_claims (claim, into_, into_prefix) VALUES (?1, ?2, ?3)")?
                .execute(params![id, self.db.intern(into)?, into_prefix])?;
            let mut stmt = self.db.conn()
                .prepare_cached("INSERT INTO group_targets (claim, target, prefix) VALUES (?1, ?2, ?3)")?;
            for target in group.target() {
                let bytes = target.to_bytes();
                let Some((prefix, multihash)) = split_cid(&bytes) else {
                    return Err(Error::Invalid { store: NAME, reason: format!("target {target}") });
                };
                stmt.execute(params![id, self.db.intern(multihash)?, prefix])?;
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
            "SELECT c.multihash FROM multihashes m JOIN group_targets t ON t.target = m.id
             JOIN multihashes c ON c.id = t.claim WHERE m.multihash = ?1
             UNION
             SELECT c.multihash FROM multihashes m JOIN group_claims g ON g.into_ = m.id
             JOIN multihashes c ON c.id = g.claim WHERE m.multihash = ?1",
        )?;
        let rows = stmt.query_map([key.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|bytes| super::decode_key(NAME, &bytes?)).collect()
    }
}
