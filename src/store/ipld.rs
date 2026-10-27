//! A store specialized for dag-cbor and dag-json: blocks as `SQLite` JSONB,
//! so their contents can be queried in place (`data ->> '$.name'`).
//!
//! The JSON is the block's data in dag-json form, links as
//! `{"/": "<CID>"}` and bytes as `{"/": {"bytes": "<base64>"}}`, whichever
//! codec the block is in. A block is admitted only if it manifests from its
//! JSONB byte-for-byte. That rules out non-canonical encodings and data
//! dag-json can't express (a map whose only key is "/" with a string
//! value reads back as a link), which fall through to a generic store.
//!
//! Links are also kept as rows, by interned multihash, for backreferences.

use rusqlite::{OptionalExtension, params};

use crate::block::Block;
use crate::cid::{BaseCid, CidRef, DAG_CBOR_CODEC, DAG_JSON_CODEC};
use crate::model::Ipld;
use crate::multihash::Multihash;
use crate::{dagcbor, dagjson};

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Key, Put, RefIndex, Result, Store, query_keys};

const NAME: &str = "ipld";

/// Admits canonical dag-cbor and dag-json, keeping them as JSONB.
pub struct IpldStore {
    db: Db,
}

fn decode(codec: u64, data: &[u8]) -> Option<Ipld> {
    match codec {
        DAG_CBOR_CODEC => dagcbor::from_slice(data).ok(),
        DAG_JSON_CODEC => dagjson::from_slice(data).ok(),
        _ => None,
    }
}

fn encode(codec: u64, value: &Ipld) -> Option<Vec<u8>> {
    match codec {
        DAG_CBOR_CODEC => dagcbor::to_vec(value).ok(),
        DAG_JSON_CODEC => dagjson::to_vec(value).ok(),
        _ => None,
    }
}

/// Every link in a value.
fn links<'a>(value: &'a Ipld, out: &mut Vec<&'a crate::model::Link>) {
    match value {
        Ipld::Link(link) => out.push(link),
        Ipld::List(items) => items.iter().for_each(|item| links(item, out)),
        Ipld::Map(map) => map.values().for_each(|item| links(item, out)),
        _ => {},
    }
}

impl IpldStore {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS ipld_blocks (
                 block INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 codec INTEGER NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS ipld_links (
                 block INTEGER NOT NULL REFERENCES ipld_blocks (block) ON DELETE CASCADE,
                 target INTEGER NOT NULL REFERENCES multihashes (id),
                 PRIMARY KEY (block, target)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS ipld_links_target ON ipld_links (target);",
        )?;
        Ok(Self { db })
    }

    /// The JSON text `SQLite` gives back for some JSON, or None if it won't
    /// take it as JSONB (too deeply nested, say).
    fn through_jsonb(&self, json: &[u8]) -> Result<Option<Vec<u8>>> {
        let Ok(json) = std::str::from_utf8(json) else {
            return Ok(None);
        };
        let back = self.db.conn()
            .prepare_cached("SELECT json(jsonb(?1))")?
            .query_row([json], |row| row.get::<_, String>(0));
        match back {
            Ok(text) => Ok(Some(text.into_bytes())),
            Err(rusqlite::Error::SqliteFailure(..)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Rebuild a block from its JSON.
    fn manifest(codec: u64, json: &[u8]) -> Result<Vec<u8>> {
        dagjson::from_slice::<Ipld>(json)
            .ok()
            .and_then(|value| encode(codec, &value))
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "JSON doesn't manifest a block".into() })
    }
}

impl Store for IpldStore {
    fn name(&self) -> &'static str { NAME }
}

impl BlockIndex for IpldStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN ipld_blocks b ON b.block = m.id WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, NAME, "SELECT m.multihash FROM ipld_blocks b JOIN multihashes m ON m.id = b.block")
    }
}

impl BlockSource for IpldStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        let row = self.db.conn()
            .prepare_cached(
                "SELECT b.codec, json(b.data) FROM multihashes m
                 JOIN ipld_blocks b ON b.block = m.id WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))
            .optional()?;
        let Some((codec, json)) = row else {
            return Ok(None);
        };
        let codec = u64::try_from(codec)
            .map_err(|_| Error::Invalid { store: NAME, reason: format!("codec {codec}") })?;
        Self::manifest(codec, json.as_bytes()).map(Some)
    }
}

impl BlockStore for IpldStore {
    fn put(&self, block: &Block) -> Result<Put> {
        let codec = block.cid().codec();
        let Some(value) = decode(codec, block.data()) else {
            return Ok(Put::Declined);
        };
        let Ok(json) = dagjson::to_vec(&value) else {
            return Ok(Put::Declined);
        };
        // Admitted only if what SQLite gives back manifests exactly
        let Some(back) = self.through_jsonb(&json)? else {
            return Ok(Put::Declined);
        };
        if Self::manifest(codec, &back).ok().as_deref() != Some(block.data()) {
            return Ok(Put::Declined);
        }
        if self.has(block.cid().multihash())? {
            return Ok(Put::Stored);
        }
        let mut targets = Vec::new();
        links(&value, &mut targets);
        self.db.atomically(|| {
            let id = self.db.intern(block.cid().multihash())?;
            self.db.conn()
                .prepare_cached("INSERT INTO ipld_blocks (block, codec, data) VALUES (?1, ?2, jsonb(?3))")?
                .execute(params![id, codec.cast_signed(), std::str::from_utf8(&json).unwrap_or_default()])?;
            let mut stmt = self.db.conn()
                .prepare_cached("INSERT OR IGNORE INTO ipld_links (block, target) VALUES (?1, ?2)")?;
            for target in targets {
                stmt.execute(params![id, self.db.intern(target.multihash())?])?;
            }
            Ok::<_, Error>(())
        })?;
        Ok(Put::Stored)
    }
}

impl RefIndex for IpldStore {
    fn backrefs(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT n.multihash FROM multihashes t
             JOIN ipld_links l ON l.target = t.id
             JOIN multihashes n ON n.id = l.block
             WHERE t.multihash = ?1",
        )?;
        let rows = stmt.query_map([key.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|bytes| super::decode_key(NAME, &bytes?)).collect()
    }
}
