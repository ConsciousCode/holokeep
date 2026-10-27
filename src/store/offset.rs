//! A store specialized for blocks which are byte ranges of files on disk,
//! so a file imported in place is stored once: as itself.
//!
//! Offsets are never searched for. A block's bytes can't say where else
//! they're found, so this store only admits blocks put with a
//! `Provenance::FileRange`, which the importer gives each leaf as it reads
//! it. That provenance is trusted: within one executable, the importer has
//! just read those bytes from that range.
//!
//! The files belong to the user and may change. Each file is recorded with
//! a fingerprint (size, mtime, inode) taken when it's first seen, and a
//! range is only served while its file's fingerprint still matches; the
//! router re-hashes what it serves regardless. A block may be kept in
//! several files, and is served from whichever is still unchanged.

use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use rusqlite::{OptionalExtension, params};

use crate::block::Block;
use crate::cid::{BaseCid, CidRef, RAW_CODEC};
use crate::dag::Provenance;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Id, Key, Put, Result, Store, query_keys};

const NAME: &str = "offset";

/// Keeps blocks as (file, offset, length).
pub struct OffsetStore {
    db: Db,
}

/// What identifies a version of a file, short of hashing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
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

    fn read(path: &Path) -> Option<Self> {
        fs::metadata(path).ok().as_ref().and_then(Self::of)
    }
}

/// Where a block is kept.
struct Range {
    path: PathBuf,
    fingerprint: Fingerprint,
    offset: u64,
    len: usize,
}

impl Range {
    /// The range's bytes, if its file is unchanged.
    fn read(&self) -> Result<Option<Vec<u8>>> {
        if Fingerprint::read(&self.path) != Some(self.fingerprint) {
            return Ok(None);
        }
        let mut data = vec![0; self.len];
        File::open(&self.path)?.read_exact_at(&mut data, self.offset)?;
        Ok(Some(data))
    }
}

fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

impl OffsetStore {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "-- Each version of a file seen, so ranges of a version which has
             -- since changed are never served from the new one.
             CREATE TABLE IF NOT EXISTS offset_files (
                 id INTEGER PRIMARY KEY,
                 path BLOB NOT NULL,
                 size INTEGER NOT NULL,
                 mtime INTEGER NOT NULL,
                 inode INTEGER NOT NULL,
                 UNIQUE (path, size, mtime, inode)
             );
             CREATE TABLE IF NOT EXISTS offset_ranges (
                 block INTEGER NOT NULL REFERENCES multihashes (id),
                 file INTEGER NOT NULL REFERENCES offset_files (id),
                 offset INTEGER NOT NULL,
                 len INTEGER NOT NULL,
                 PRIMARY KEY (block, file)
             ) WITHOUT ROWID;",
        )?;
        Ok(Self { db })
    }

    /// The id of the file's current version, recording it if it's new.
    fn file(&self, path: &Path) -> Result<Option<(Id, Fingerprint)>> {
        let path = fs::canonicalize(path)?;
        let Some(fp) = Fingerprint::read(&path) else {
            return Ok(None);
        };
        let conn = self.db.conn();
        let existing = conn
            .prepare_cached("SELECT id FROM offset_files WHERE path = ?1 AND size = ?2 AND mtime = ?3 AND inode = ?4")?
            .query_row(params![path_bytes(&path), fp.size, fp.mtime, fp.inode], |row| row.get(0))
            .optional()?;
        if let Some(id) = existing {
            return Ok(Some((id, fp)));
        }
        conn.prepare_cached("INSERT INTO offset_files (path, size, mtime, inode) VALUES (?1, ?2, ?3, ?4)")?
            .execute(params![path_bytes(&path), fp.size, fp.mtime, fp.inode])?;
        Ok(Some((conn.last_insert_rowid(), fp)))
    }

    /// Every range a block is kept in, newest file first.
    fn ranges(&self, key: Key<'_>) -> Result<Vec<Range>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT f.path, f.size, f.mtime, f.inode, r.offset, r.len
             FROM multihashes m
             JOIN offset_ranges r ON r.block = m.id
             JOIN offset_files f ON f.id = r.file
             WHERE m.multihash = ?1
             ORDER BY f.id DESC",
        )?;
        let rows = stmt.query_map([key.to_bytes()], |row| Ok((
            row.get::<_, Vec<u8>>(0)?,
            Fingerprint { size: row.get(1)?, mtime: row.get(2)?, inode: row.get(3)? },
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        )))?;
        rows.map(|row| {
            let (path, fingerprint, offset, len) = row?;
            let invalid = |what| Error::Invalid { store: NAME, reason: format!("negative {what}") };
            Ok(Range {
                path: PathBuf::from(std::ffi::OsStr::from_bytes(&path)),
                fingerprint,
                offset: u64::try_from(offset).map_err(|_| invalid("offset"))?,
                len: usize::try_from(len).map_err(|_| invalid("length"))?,
            })
        })
        .collect()
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
    /// The block from whichever of its files is unchanged, or `Stale` if
    /// they've all changed.
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        let ranges = self.ranges(key)?;
        for range in &ranges {
            if let Some(data) = range.read()? {
                return Ok(Some(data));
            }
        }
        match ranges.into_iter().next() {
            Some(newest) => Err(Error::Stale(newest.path)),
            None => Ok(None),
        }
    }
}

impl BlockStore for OffsetStore {
    /// Without provenance there's nowhere to keep a block.
    fn put(&self, _block: &Block) -> Result<Put> {
        Ok(Put::Declined)
    }

    fn put_from(&self, block: &Block, provenance: Provenance<'_>) -> Result<Put> {
        let Provenance::FileRange { path, offset } = provenance else {
            return Ok(Put::Declined);
        };
        // Only raw blocks are their file's bytes unwrapped
        if block.cid().codec() != RAW_CODEC {
            return Ok(Put::Declined);
        }
        let len = crate::dag::len64(block.data());
        let (Ok(offset_sql), Ok(len_sql)) = (i64::try_from(offset), i64::try_from(len)) else {
            return Ok(Put::Declined);
        };
        self.db.atomically(|| {
            let Some((file, fp)) = self.file(path)? else {
                return Ok(Put::Declined);
            };
            if offset_sql.checked_add(len_sql).is_none_or(|end| end > fp.size) {
                return Ok(Put::Declined);
            }
            let id = self.db.intern(block.cid().multihash())?;
            self.db.conn()
                .prepare_cached("INSERT OR IGNORE INTO offset_ranges (block, file, offset, len) VALUES (?1, ?2, ?3, ?4)")?
                .execute(params![id, file, offset_sql, len_sql])?;
            Ok(Put::Stored)
        })
    }
}
