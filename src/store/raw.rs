//! The generic store: any block, as raw bytes.

use rusqlite::{OptionalExtension, params};

use crate::block::Block;
use crate::cid::CidRef;

use super::{BlockIndex, BlockSource, BlockStore, Db, Key, Put, Result, Store, query_keys};
use crate::multihash::Multihash;

const NAME: &str = "raw";

/// Admits every block, keeping its bytes as they are.
pub struct RawStore {
    db: Db,
}

impl RawStore {
    pub fn open(db: Db) -> Result<Self> {
        // A rowid table: SQLite advises against WITHOUT ROWID for large rows
        db.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS raw_blocks (
                 block INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 data BLOB NOT NULL
             );",
        )?;
        Ok(Self { db })
    }
}

impl Store for RawStore {
    fn name(&self) -> &'static str { NAME }

    fn remove(&self, key: Key<'_>) -> Result<Option<u64>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(Some(0));
        };
        let len: Option<i64> = self.db.conn()
            .prepare_cached("DELETE FROM raw_blocks WHERE block = ?1 RETURNING length(data)")?
            .query_row([id], |row| row.get(0))
            .optional()?;
        Ok(Some(len.map_or(0, |len| u64::try_from(len).unwrap_or_default())))
    }
}

impl BlockIndex for RawStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN raw_blocks r ON r.block = m.id WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, NAME, "SELECT m.multihash FROM raw_blocks r JOIN multihashes m ON m.id = r.block")
    }
}

impl BlockSource for RawStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT r.data FROM multihashes m JOIN raw_blocks r ON r.block = m.id WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |row| row.get(0))
            .optional()?)
    }
}

impl BlockStore for RawStore {
    fn put(&self, block: &Block) -> Result<Put> {
        let id = self.db.intern(block.cid().multihash())?;
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO raw_blocks (block, data) VALUES (?1, ?2)")?
            .execute(params![id, block.data()])?;
        Ok(Put::Stored)
    }
}
