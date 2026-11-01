//! A store specialized for blocks which are byte ranges of larger files,
//! so a file's contents are stored once: as itself.
//!
//! A range is of a blob, a whole file named by its multihash (sha2-256 of
//! its bytes), which may be found in the repo's shards (see `ShardStore`)
//! or at external paths imported in place. The blob's multihash is the
//! range's identity, so a block is served from any copy of its blob.
//!
//! Offsets are never searched for. A block's bytes can't say where else
//! they're found, so this store only admits blocks put with a
//! `Provenance::FileRange`, which the importer gives each leaf as it reads
//! it. That provenance is trusted: within one executable, the importer has
//! just read those bytes from that range. A file's multihash isn't known
//! until all of it has been read, so its ranges are pending until the
//! sink importing it `settle`s them.
//!
//! External files belong to the user and may change. Each is recorded with
//! a fingerprint (size, mtime, inode) taken as it's imported, and a range
//! is only served while its file's fingerprint still matches; the router
//! re-hashes what it serves regardless. Kept files are the repo's own and
//! never change. A block is served from a kept file first, then whichever
//! external file is still unchanged.

use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::block::Block;
use crate::cid::{BaseCid, CidRef, RAW_CODEC};
use crate::dag::Provenance;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Key, Put, Result, ShardStore, Store, query_keys};

const NAME: &str = "offset";

const SHA2_256: u64 = 0x12;

/// Keeps blocks as (blob, offset, length).
pub struct OffsetStore {
    db: Db,
    shards: Option<Rc<ShardStore>>,
}

/// What identifies a version of a file, short of hashing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    size: i64,
    /// Nanoseconds since the epoch.
    mtime: i64,
    inode: i64,
}

impl Fingerprint {
    fn of(meta: &fs::Metadata) -> Option<Self> {
        let mtime = meta.mtime().checked_mul(1_000_000_000)?.checked_add(meta.mtime_nsec())?;
        Some(Self {
            size: i64::try_from(meta.size()).ok()?,
            mtime,
            // Only ever compared, so the sign doesn't matter
            inode: meta.ino().cast_signed(),
        })
    }

    pub fn read(path: &Path) -> Option<Self> {
        fs::metadata(path).ok().as_ref().and_then(Self::of)
    }
}

/// A file's multihash, from its leaves as they arrive in order.
pub struct Whole {
    hasher: Sha256,
    len: u64,
}

impl Default for Whole {
    fn default() -> Self {
        Self { hasher: Sha256::new(), len: 0 }
    }
}

impl Whole {
    /// Add the leaf at `offset`, which must follow the last.
    pub fn push(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        if offset != self.len {
            return Err(io::Error::other(format!("leaf at {offset} doesn't follow the {} bytes before it", self.len)));
        }
        self.hasher.update(data);
        self.len = self.len.saturating_add(crate::dag::len64(data));
        Ok(())
    }

    pub const fn len(&self) -> u64 { self.len }

    pub fn finish(self) -> Multihash<[u8; 32]> {
        Multihash::new(SHA2_256, self.hasher.finalize().into())
    }
}

/// Where a blob whose ranges are being settled is.
pub enum Location<'a> {
    /// At a path outside the repo, as of a fingerprint.
    External { path: &'a Path, fingerprint: Fingerprint },
    /// In the repo's shards.
    Kept,
}

/// Where a range's bytes may be read.
enum Place {
    External { path: PathBuf, fingerprint: Fingerprint },
    Kept(PathBuf),
}

impl Place {
    /// The bytes, or the error to give if there are none to be had: an
    /// external file has changed, or a kept one is gone.
    fn read(&self, offset: u64, len: usize) -> Result<std::result::Result<Vec<u8>, Error>> {
        let path = match self {
            Self::External { path, fingerprint } => {
                if Fingerprint::read(path) != Some(*fingerprint) {
                    return Ok(Err(Error::Stale(path.clone())));
                }
                path
            },
            Self::Kept(path) => path,
        };
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Err(Error::Missing(path.clone()))),
            Err(e) => return Err(e.into()),
        };
        let mut data = vec![0; len];
        file.read_exact_at(&mut data, offset)?;
        Ok(Ok(data))
    }
}

fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

/// Create the tables for offsets and the shards they index into.
pub(super) fn schema(db: &Db) -> Result<()> {
    db.conn().execute_batch(
        "-- Ranges of blobs, by the blob's multihash.
         CREATE TABLE IF NOT EXISTS offset_ranges (
             block INTEGER NOT NULL REFERENCES multihashes (id),
             blob INTEGER NOT NULL REFERENCES multihashes (id),
             offset INTEGER NOT NULL,
             len INTEGER NOT NULL,
             PRIMARY KEY (block, blob)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS offset_ranges_blob ON offset_ranges (blob);
         -- Paths outside the repo a blob was imported from, as of when.
         CREATE TABLE IF NOT EXISTS external_files (
             blob INTEGER NOT NULL REFERENCES multihashes (id),
             path BLOB NOT NULL,
             size INTEGER NOT NULL,
             mtime INTEGER NOT NULL,
             inode INTEGER NOT NULL,
             PRIMARY KEY (blob, path)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS external_files_path ON external_files (path);
         -- Sharded directories, by their labels as volumes.
         CREATE TABLE IF NOT EXISTS shard_dirs (
             id INTEGER PRIMARY KEY,
             label BLOB UNIQUE NOT NULL
         );
         -- What's in each sharded directory, so finding a blob needn't
         -- touch the filesystem. Rebuilt from the directory by a rescan.
         CREATE TABLE IF NOT EXISTS shard_files (
             dir INTEGER NOT NULL REFERENCES shard_dirs (id),
             blob INTEGER NOT NULL REFERENCES multihashes (id),
             shard TEXT NOT NULL,
             size INTEGER NOT NULL,
             PRIMARY KEY (dir, blob)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS shard_files_shard ON shard_files (dir, shard);
         -- Each shard's mtime when it was last listed, to catch up by.
         CREATE TABLE IF NOT EXISTS shard_mtimes (
             dir INTEGER NOT NULL REFERENCES shard_dirs (id),
             shard TEXT NOT NULL,
             mtime INTEGER NOT NULL,
             PRIMARY KEY (dir, shard)
         ) WITHOUT ROWID;
         -- Which UnixFS roots each kept file was imported as.
         CREATE TABLE IF NOT EXISTS shard_roots (
             blob INTEGER NOT NULL REFERENCES multihashes (id),
             root INTEGER NOT NULL REFERENCES multihashes (id),
             PRIMARY KEY (blob, root)
         ) WITHOUT ROWID;
         -- Ranges of a file whose multihash isn't known yet, by the path
         -- it's being imported from. Private to the connection.
         CREATE TEMP TABLE IF NOT EXISTS pending_ranges (
             path BLOB NOT NULL,
             offset INTEGER NOT NULL,
             block INTEGER NOT NULL,
             len INTEGER NOT NULL,
             PRIMARY KEY (path, offset)
         ) WITHOUT ROWID;",
    )?;
    Ok(())
}

impl OffsetStore {
    /// An offset store for external files, and kept ones if there are
    /// shards to keep them in.
    pub fn open(db: Db, shards: Option<Rc<ShardStore>>) -> Result<Self> {
        schema(&db)?;
        Ok(Self { db, shards })
    }

    /// The file imported from `path` has multihash `blob` and is `len`
    /// bytes long: its pending ranges are of that blob, which is at
    /// `location`. Returns how many ranges the blob has in all.
    pub fn settle(&self, path: &Path, blob: Key<'_>, len: u64, location: &Location<'_>) -> Result<u64> {
        let len = i64::try_from(len).map_err(|_| Error::Invalid { store: NAME, reason: "file too large".into() })?;
        let conn = self.db.conn();
        let beyond = conn
            .prepare_cached("SELECT 1 FROM temp.pending_ranges WHERE path = ?1 AND offset + len > ?2")?
            .exists(params![path_bytes(path), len])?;
        if beyond {
            // Discarded, so they can't be settled as part of anything else
            conn.prepare_cached("DELETE FROM temp.pending_ranges WHERE path = ?1")?.execute([path_bytes(path)])?;
            return Err(Error::Invalid { store: NAME, reason: format!("ranges beyond the end of {}", path.display()) });
        }
        self.db.atomically(|| {
            let blob_id = self.db.intern(blob)?;
            conn.prepare_cached(
                "INSERT OR IGNORE INTO offset_ranges (block, blob, offset, len)
                 SELECT block, ?2, offset, len FROM temp.pending_ranges WHERE path = ?1",
            )?
            .execute(params![path_bytes(path), blob_id])?;
            conn.prepare_cached("DELETE FROM temp.pending_ranges WHERE path = ?1")?.execute([path_bytes(path)])?;
            if let Location::External { path, fingerprint: fp } = *location {
                let path = fs::canonicalize(path)?;
                conn.prepare_cached(
                    "INSERT INTO external_files (blob, path, size, mtime, inode) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (blob, path) DO UPDATE SET size = ?3, mtime = ?4, inode = ?5",
                )?
                .execute(params![blob_id, path_bytes(&path), fp.size, fp.mtime, fp.inode])?;
            }
            let ranges: i64 = conn
                .prepare_cached("SELECT count(*) FROM offset_ranges WHERE blob = ?1")?
                .query_row([blob_id], |row| row.get(0))?;
            Ok(u64::try_from(ranges).unwrap_or_default())
        })
    }

    /// Everywhere a blob may be read, kept first.
    fn places(&self, blob: Key<'_>, kept: bool) -> Result<Vec<Place>> {
        let mut places = Vec::new();
        if kept && let Some(shards) = &self.shards {
            places.push(Place::Kept(shards.path(blob)));
        }
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT e.path, e.size, e.mtime, e.inode FROM multihashes m
             JOIN external_files e ON e.blob = m.id WHERE m.multihash = ?1",
        )?;
        let rows = stmt.query_map([blob.to_bytes()], |row| Ok(Place::External {
            path: PathBuf::from(std::ffi::OsStr::from_bytes(&row.get::<_, Vec<u8>>(0)?)),
            fingerprint: Fingerprint { size: row.get(1)?, mtime: row.get(2)?, inode: row.get(3)? },
        }))?;
        for place in rows {
            places.push(place?);
        }
        Ok(places)
    }

    /// Every range a block is kept as: the blob, whether it's kept, the
    /// offset and the length. Kept blobs come first.
    fn ranges(&self, key: Key<'_>) -> Result<Vec<(Multihash, bool, u64, usize)>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT b.multihash, s.blob IS NOT NULL, r.offset, r.len
             FROM multihashes m
             JOIN offset_ranges r ON r.block = m.id
             JOIN multihashes b ON b.id = r.blob
             LEFT JOIN shard_files s ON s.blob = r.blob AND s.dir = ?2
             WHERE m.multihash = ?1
             ORDER BY s.blob IS NULL",
        )?;
        let shards = self.shards.as_ref().map(|shards| shards.id());
        let rows = stmt.query_map(params![key.to_bytes(), shards], |row| Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, bool>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        )))?;
        let invalid = |what| Error::Invalid { store: NAME, reason: format!("negative {what}") };
        rows.map(|row| {
            let (blob, kept, offset, len) = row?;
            Ok((
                super::decode_key(NAME, &blob)?,
                kept,
                u64::try_from(offset).map_err(|_| invalid("offset"))?,
                usize::try_from(len).map_err(|_| invalid("length"))?,
            ))
        })
        .collect()
    }
}

/// A file imported in place, as recorded when it was.
#[derive(Debug, Clone)]
pub struct ExternalFile {
    pub blob: Multihash,
    pub path: PathBuf,
    fingerprint: Fingerprint,
}

impl ExternalFile {
    /// Whether the file's gone or changed since, by its fingerprint.
    pub fn changed(&self) -> bool {
        Fingerprint::read(&self.path) != Some(self.fingerprint)
    }
}

/// Noticing files imported in place which have gone or changed: the user's
/// to change, so what was imported from them may stop being here.
impl OffsetStore {
    /// Files imported in place, a random sample of them or all.
    pub fn external_files(&self, sample: Option<usize>) -> Result<Vec<ExternalFile>> {
        let limit = sample.map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));
        let order = if sample.is_some() { "ORDER BY random()" } else { "" };
        self.query_external(&format!("{order} LIMIT {limit}"), params![])
    }

    /// The files imported in place from a path, one for each version
    /// recorded.
    pub fn external_at(&self, path: &Path) -> Result<Vec<ExternalFile>> {
        self.query_external("AND e.path = ?1", params![path_bytes(path)])
    }

    fn query_external(&self, tail: &str, args: impl rusqlite::Params) -> Result<Vec<ExternalFile>> {
        let sql = format!(
            "SELECT m.multihash, e.path, e.size, e.mtime, e.inode FROM external_files e
             JOIN multihashes m ON m.id = e.blob WHERE 1 {tail}"
        );
        let mut stmt = self.db.conn().prepare(&sql)?;
        let rows = stmt.query_map(args, |row| Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            Fingerprint { size: row.get(2)?, mtime: row.get(3)?, inode: row.get(4)? },
        )))?;
        rows.map(|row| {
            let (blob, path, fingerprint) = row?;
            Ok(ExternalFile { blob: super::decode_key(NAME, &blob)?, path: PathBuf::from(std::ffi::OsStr::from_bytes(&path)), fingerprint })
        })
        .collect()
    }

    /// Forget a file imported in place, as it's gone or changed. Its
    /// ranges go too unless its blob's somewhere else still; returns the
    /// blocks no longer ranges of anything.
    pub fn forget_external(&self, file: &ExternalFile) -> Result<Vec<Multihash>> {
        let Some(blob) = self.db.lookup(file.blob.as_ref())? else {
            return Ok(Vec::new());
        };
        let conn = self.db.conn();
        conn.prepare_cached("DELETE FROM external_files WHERE blob = ?1 AND path = ?2")?.execute(params![blob, path_bytes(&file.path)])?;
        let elsewhere = conn.prepare_cached("SELECT 1 FROM external_files WHERE blob = ?1")?.exists([blob])?
            || self.shards.as_ref().is_some_and(|shards| {
                conn.prepare_cached("SELECT 1 FROM shard_files WHERE blob = ?1 AND dir = ?2")
                    .and_then(|mut stmt| stmt.exists(params![blob, shards.id()]))
                    .unwrap_or(true)
            });
        if elsewhere {
            return Ok(Vec::new());
        }
        let blocks: Vec<Vec<u8>> = conn
            .prepare_cached("DELETE FROM offset_ranges WHERE blob = ?1 RETURNING (SELECT multihash FROM multihashes WHERE id = block)")?
            .query_map([blob], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut lost = Vec::new();
        for block in blocks {
            let block = super::decode_key(NAME, &block)?;
            if !self.ranged(block.as_ref())? {
                lost.push(block);
            }
        }
        Ok(lost)
    }
}

/// Letting go of kept files, which exist for the files they were imported
/// as: once any of one's leaves goes, so has its file, and what's left of
/// it is blocks other DAGs share, which the catalog moves out to be
/// blocks of their own before the kept file goes.
impl OffsetStore {
    /// Whether a block is only ranges of files the repo keeps, which it
    /// can let go of, rather than of files the user's imported in place.
    pub fn only_kept(&self, key: Key<'_>) -> Result<bool> {
        let Some(shards) = &self.shards else {
            return Ok(false);
        };
        let Some(id) = self.db.lookup(key)? else {
            return Ok(false);
        };
        let conn = self.db.conn();
        let ranged = conn.prepare_cached("SELECT 1 FROM offset_ranges WHERE block = ?1")?.exists([id])?;
        let elsewhere = conn
            .prepare_cached(
                "SELECT 1 FROM offset_ranges r WHERE r.block = ?1 AND (
                     r.blob IN (SELECT blob FROM external_files)
                     OR r.blob NOT IN (SELECT blob FROM shard_files WHERE dir = ?2))",
            )?
            .exists(params![id, shards.id()])?;
        Ok(ranged && !elsewhere)
    }

    /// The kept files a block is a range of.
    pub fn kept_blobs(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        let Some(shards) = &self.shards else {
            return Ok(Vec::new());
        };
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT b.multihash FROM multihashes m
             JOIN offset_ranges r ON r.block = m.id
             JOIN multihashes b ON b.id = r.blob
             JOIN shard_files s ON s.blob = r.blob AND s.dir = ?2
             WHERE m.multihash = ?1",
        )?;
        let rows = stmt.query_map(params![key.to_bytes(), shards.id()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|bytes| super::decode_key(NAME, &bytes?)).collect()
    }

    /// The blocks a blob's ranges are, and whether each is a range of
    /// any other blob too.
    pub fn ranges_of(&self, blob: Key<'_>) -> Result<Vec<(Multihash, bool)>> {
        let Some(id) = self.db.lookup(blob)? else {
            return Ok(Vec::new());
        };
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT m.multihash, EXISTS (SELECT 1 FROM offset_ranges o WHERE o.block = r.block AND o.blob != r.blob)
             FROM offset_ranges r JOIN multihashes m ON m.id = r.block
             WHERE r.blob = ?1 ORDER BY r.offset",
        )?;
        let rows = stmt.query_map([id], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, bool>(1)?)))?;
        rows.map(|row| {
            let (block, elsewhere) = row?;
            Ok((super::decode_key(NAME, &block)?, elsewhere))
        })
        .collect()
    }

    /// Whether a block is still a range of anything.
    pub fn ranged(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM multihashes m JOIN offset_ranges r ON r.block = m.id WHERE m.multihash = ?1")?
            .exists([key.to_bytes()])?)
    }

    /// Forget a kept file: its ranges, the roots it was imported as, and
    /// the file. Returns its size.
    pub fn unkeep(&self, blob: Key<'_>) -> Result<u64> {
        let (Some(shards), Some(id)) = (&self.shards, self.db.lookup(blob)?) else {
            return Ok(0);
        };
        let conn = self.db.conn();
        let size: Option<i64> = conn
            .prepare_cached("SELECT size FROM shard_files WHERE dir = ?1 AND blob = ?2")?
            .query_row(params![shards.id(), id], |row| row.get(0))
            .optional()?;
        conn.prepare_cached("DELETE FROM offset_ranges WHERE blob = ?1")?.execute([id])?;
        conn.prepare_cached("DELETE FROM shard_roots WHERE blob = ?1")?.execute([id])?;
        shards.forget(blob)?;
        Ok(size.map_or(0, |size| u64::try_from(size).unwrap_or_default()))
    }
}

impl Store for OffsetStore {
    fn name(&self) -> &'static str { NAME }
}

impl BlockIndex for OffsetStore {
    /// Whether the block is recorded here, though its files may since have
    /// changed.
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN offset_ranges r ON r.block = m.id WHERE m.multihash = ?1 LIMIT 1",
            )?
            .query_row([key.to_bytes()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(
            &self.db,
            NAME,
            "SELECT m.multihash FROM multihashes m WHERE m.id IN (SELECT block FROM offset_ranges)",
        )
    }
}

impl BlockSource for OffsetStore {
    /// The block from whichever of its blobs' copies is readable, or why
    /// the first can't be read if none are.
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        let mut first = None;
        for (blob, kept, offset, len) in self.ranges(key)? {
            for place in self.places(blob.as_ref(), kept)? {
                match place.read(offset, len)? {
                    Ok(data) => return Ok(Some(data)),
                    Err(e) => { first.get_or_insert(e); },
                }
            }
        }
        first.map_or(Ok(None), Err)
    }
}

impl BlockStore for OffsetStore {
    /// Without provenance there's nowhere to keep a block.
    fn put(&self, _block: &Block) -> Result<Put> {
        Ok(Put::Declined)
    }

    /// Admitted as pending, until the sink importing its file settles it.
    fn put_from(&self, block: &Block, provenance: Provenance<'_>) -> Result<Put> {
        let Provenance::FileRange { path, offset } = provenance else {
            return Ok(Put::Declined);
        };
        // Only raw blocks are their file's bytes unwrapped
        if block.cid().codec() != RAW_CODEC {
            return Ok(Put::Declined);
        }
        let len = crate::dag::len64(block.data());
        let (Ok(offset), Ok(len)) = (i64::try_from(offset), i64::try_from(len)) else {
            return Ok(Put::Declined);
        };
        let id = self.db.intern(block.cid().multihash())?;
        self.db.conn()
            .prepare_cached("INSERT OR REPLACE INTO temp.pending_ranges (path, offset, block, len) VALUES (?1, ?2, ?3, ?4)")?
            .execute(params![path_bytes(path), offset, id, len])?;
        Ok(Put::Stored)
    }
}
