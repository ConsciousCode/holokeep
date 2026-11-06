//! The delta store: blocks kept as deltas on other blocks it keeps, or
//! whole, compressed either way when that's smaller.
//!
//! A block is kept as a delta only when it comes with one
//! (`Provenance::Delta`), on a base this store keeps, shorter than the
//! block, and checked to make it. Git objects come whole too, as a pack's
//! bases do, and versions of files written over (`Provenance::Superseded`),
//! for the versions before them to be deltas on; both are kept whole till
//! a delta comes for them. A chain of deltas is at most `MAX_DEPTH` long,
//! so a read applies at most that many: a block made a delta deepens what's
//! on it, and is left whole if that would go too deep. A base let go of
//! first makes each block on it whole, so nothing's left on what isn't
//! here.

use std::io::{Read as _, Write as _};

use rusqlite::{OptionalExtension, params};

use crate::block::Block;
use crate::cid::{BaseCid as _, CidRef, GIT_RAW_CODEC};
use crate::dag::Provenance;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Id, Key, Put, Result, Store, query_keys};

const NAME: &str = "delta";

/// The longest chain of deltas, as git's default.
pub const MAX_DEPTH: i64 = 50;

pub struct DeltaStore {
    db: Db,
}

/// A row's bytes as kept: compressed, or as they are where compressing
/// doesn't make them smaller.
fn pack(bytes: &[u8]) -> (bool, Vec<u8>) {
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let compressed = zlib.write_all(bytes).ok().and_then(|()| zlib.finish().ok());
    match compressed {
        Some(compressed) if compressed.len() < bytes.len() => (true, compressed),
        _ => (false, bytes.to_vec()),
    }
}

fn unpack(zlib: bool, data: Vec<u8>) -> Result<Vec<u8>> {
    if !zlib {
        return Ok(data);
    }
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(&*data).read_to_end(&mut out).map_err(|e| Error::Volume(format!("a delta row that won't inflate: {e}")))?;
    Ok(out)
}

/// A row: its base, if it's a delta, its depth, and its bytes as kept.
struct Row {
    base: Option<Id>,
    depth: i64,
    zlib: bool,
    data: Vec<u8>,
}

impl DeltaStore {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS delta_blocks (
                 block INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 -- What it's a delta on, or NULL if it's whole
                 base INTEGER REFERENCES delta_blocks (block),
                 -- How many deltas reading it applies, at most
                 depth INTEGER NOT NULL,
                 zlib INTEGER NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS delta_blocks_base ON delta_blocks (base) WHERE base IS NOT NULL;",
        )?;
        Ok(Self { db })
    }

    fn row(&self, id: Id) -> Result<Option<Row>> {
        Ok(self.db.conn()
            .prepare_cached("SELECT base, depth, zlib, data FROM delta_blocks WHERE block = ?1")?
            .query_row([id], |row| Ok(Row { base: row.get(0)?, depth: row.get(1)?, zlib: row.get(2)?, data: row.get(3)? }))
            .optional()?)
    }

    /// A block's bytes, by its id.
    fn bytes(&self, id: Id) -> Result<Option<Vec<u8>>> {
        let mut deltas: Vec<Vec<u8>> = Vec::new();
        let mut at = id;
        loop {
            let Some(row) = self.row(at)? else {
                return if deltas.is_empty() { Ok(None) } else { Err(Error::Volume("a delta on a block that isn't here".to_owned())) };
            };
            let data = unpack(row.zlib, row.data)?;
            match row.base {
                None => {
                    let mut bytes = data;
                    for delta in deltas.iter().rev() {
                        bytes = crate::delta::apply(&bytes, delta).map_err(|e| Error::Volume(e.to_string()))?;
                    }
                    return Ok(Some(bytes));
                },
                Some(base) => {
                    deltas.push(data);
                    if i64::try_from(deltas.len()).unwrap_or(i64::MAX) > MAX_DEPTH {
                        return Err(Error::Volume("a chain of deltas too long".to_owned()));
                    }
                    at = base;
                },
            }
        }
    }

    /// Whether `id` is `base` or any block it's a delta on.
    fn under(&self, base: Id, id: Id) -> Result<bool> {
        let mut at = Some(base);
        let mut steps = 0_i64;
        while let Some(now) = at {
            if now == id {
                return Ok(true);
            }
            steps = steps.saturating_add(1);
            if steps > MAX_DEPTH.saturating_add(1) {
                return Ok(true);
            }
            at = self.row(now)?.and_then(|row| row.base);
        }
        Ok(false)
    }

    /// Every block on `id`, however deep, and how deep the deepest is.
    fn on(&self, id: Id) -> Result<(Vec<Id>, i64)> {
        let mut stmt = self.db.conn().prepare_cached(
            "WITH RECURSIVE on_it (block) AS (
                 SELECT block FROM delta_blocks WHERE base = ?1
                 UNION SELECT d.block FROM delta_blocks d JOIN on_it ON d.base = on_it.block
             )
             SELECT d.block, d.depth FROM on_it JOIN delta_blocks d ON d.block = on_it.block",
        )?;
        let rows: Vec<(Id, i64)> = stmt.query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        let deepest = rows.iter().map(|&(_, depth)| depth).max().unwrap_or_default();
        Ok((rows.into_iter().map(|(block, _)| block).collect(), deepest))
    }

    /// Move blocks deeper, or shallower.
    fn deepen(&self, blocks: &[Id], by: i64) -> Result<()> {
        let mut stmt = self.db.conn().prepare_cached("UPDATE delta_blocks SET depth = depth + ?2 WHERE block = ?1")?;
        for &block in blocks {
            stmt.execute(params![block, by])?;
        }
        Ok(())
    }

    fn write(&self, id: Id, base: Option<(Id, i64)>, bytes: &[u8]) -> Result<()> {
        let (zlib, data) = pack(bytes);
        self.db.conn()
            .prepare_cached(
                "INSERT INTO delta_blocks (block, base, depth, zlib, data) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (block) DO UPDATE SET base = excluded.base, depth = excluded.depth, zlib = excluded.zlib, data = excluded.data",
            )?
            .execute(params![id, base.map(|(base, _)| base), base.map_or(0, |(_, depth)| depth.saturating_add(1)), zlib, data])?;
        Ok(())
    }

    /// Keep a block as a delta on `base`, if that's here, shallow enough,
    /// shorter than the block, makes it, and doesn't loop. Returns whether
    /// it's here.
    fn put_delta(&self, block: &Block, base: Key<'_>, delta: &[u8]) -> Result<bool> {
        let Some(base_id) = self.db.lookup(base)? else {
            return Ok(false);
        };
        let Some(base_row) = self.row(base_id)? else {
            return Ok(false);
        };
        if base_row.depth >= MAX_DEPTH || delta.len() >= block.data().len() {
            return Ok(false);
        }
        let id = self.db.intern(block.cid().multihash())?;
        let existing = self.row(id)?;
        if existing.as_ref().is_some_and(|row| row.base.is_some()) || self.under(base_id, id)? {
            return Ok(existing.is_some());
        }
        let Some(base_bytes) = self.bytes(base_id)? else {
            return Ok(false);
        };
        if crate::delta::apply(&base_bytes, delta).ok().as_deref() != Some(block.data()) {
            return Ok(false);
        }
        // A delta, whether or not the block was here whole, unless being
        // whole is smaller, or what's on it would go too deep
        let depth = base_row.depth.saturating_add(1);
        let mut deeper = Vec::new();
        if let Some(row) = existing {
            let (_, packed) = pack(delta);
            if row.data.len() <= packed.len() {
                return Ok(true);
            }
            let deepest;
            (deeper, deepest) = self.on(id)?;
            if deepest.saturating_add(depth) > MAX_DEPTH {
                return Ok(true);
            }
        }
        self.write(id, Some((base_id, base_row.depth)), delta)?;
        self.deepen(&deeper, depth)?;
        Ok(true)
    }

    /// How many blocks are deltas, and how many whole.
    pub fn counts(&self) -> Result<(u64, u64)> {
        Ok(self.db.conn().query_row(
            "SELECT count(base), count(*) - count(base) FROM delta_blocks",
            [],
            |row| Ok((row.get::<_, i64>(0)?.try_into().unwrap_or_default(), row.get::<_, i64>(1)?.try_into().unwrap_or_default())),
        )?)
    }
}

impl DeltaStore {
    /// A block kept whole if it's here or `admit`ted.
    fn put_whole(&self, block: &Block, admit: bool) -> Result<Put> {
        let id = match self.db.lookup(block.cid().multihash())? {
            Some(id) if self.row(id)?.is_some() => return Ok(Put::Stored),
            _ if !admit => return Ok(Put::Declined),
            Some(id) => id,
            None => self.db.intern(block.cid().multihash())?,
        };
        self.write(id, None, block.data())?;
        Ok(Put::Stored)
    }
}

impl Store for DeltaStore {
    fn name(&self) -> &'static str { NAME }

    fn is_delta(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM multihashes m JOIN delta_blocks d ON d.block = m.id WHERE m.multihash = ?1 AND d.base IS NOT NULL")?
            .exists([key.to_bytes()])?)
    }

    fn remove(&self, key: Key<'_>) -> Result<Option<u64>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(Some(0));
        };
        let Some(row) = self.row(id)? else {
            return Ok(Some(0));
        };
        // What's on it, made whole first
        let on: Vec<Id> = self.db.conn()
            .prepare_cached("SELECT block FROM delta_blocks WHERE base = ?1")?
            .query_map([id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut added = 0_u64;
        for child in on {
            let (before, depth) = self.row(child)?.map_or((0, 0), |row| (row.data.len(), row.depth));
            let bytes = self.bytes(child)?.ok_or_else(|| Error::Volume("a delta that won't read".to_owned()))?;
            self.write(child, None, &bytes)?;
            self.deepen(&self.on(child)?.0, depth.saturating_neg())?;
            let after = self.row(child)?.map_or(0, |row| row.data.len());
            added = added.saturating_add(u64::try_from(after.saturating_sub(before)).unwrap_or_default());
        }
        self.db.conn().prepare_cached("DELETE FROM delta_blocks WHERE block = ?1")?.execute([id])?;
        Ok(Some(u64::try_from(row.data.len()).unwrap_or_default().saturating_sub(added)))
    }
}

impl BlockIndex for DeltaStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM multihashes m JOIN delta_blocks d ON d.block = m.id WHERE m.multihash = ?1")?
            .exists([key.to_bytes()])?)
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, NAME, "SELECT m.multihash FROM delta_blocks d JOIN multihashes m ON m.id = d.block")
    }
}

impl BlockSource for DeltaStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(None);
        };
        self.bytes(id)
    }
}

impl BlockStore for DeltaStore {
    /// Git objects, whole; nothing else without a delta.
    fn put(&self, block: &Block) -> Result<Put> {
        self.put_whole(block, block.cid().codec() == GIT_RAW_CODEC)
    }

    fn put_from(&self, block: &Block, provenance: Provenance<'_>) -> Result<Put> {
        match provenance {
            Provenance::Delta { base, delta } if self.put_delta(block, base, delta)? => Ok(Put::Stored),
            Provenance::Superseded => self.put_whole(block, true),
            _ => self.put(block),
        }
    }
}
