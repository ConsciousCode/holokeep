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
                 id INTEGER PRIMARY KEY,
                 multihash BLOB UNIQUE NOT NULL,
                 data BLOB NOT NULL
             );",
        )?;
        Ok(Self { db })
    }
}

impl Store for RawStore {
    fn name(&self) -> &'static str { NAME }
}

impl BlockIndex for RawStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .query_row("SELECT 1 FROM raw_blocks WHERE multihash = ?1", [key.to_bytes()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, NAME, "SELECT multihash FROM raw_blocks")
    }
}

impl BlockSource for RawStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        Ok(self.db.conn()
            .query_row("SELECT data FROM raw_blocks WHERE multihash = ?1", [key.to_bytes()], |row| row.get(0))
            .optional()?)
    }
}

impl BlockStore for RawStore {
    fn put(&self, block: &Block) -> Result<Put> {
        self.db.conn().execute(
            "INSERT OR IGNORE INTO raw_blocks (multihash, data) VALUES (?1, ?2)",
            params![block.cid().multihash().to_bytes(), block.data()],
        )?;
        Ok(Put::Stored)
    }
}
