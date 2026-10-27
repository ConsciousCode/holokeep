//! A store specialized for blocks which are byte ranges of files on disk,
//! so a file's contents are stored once: as itself.
//!
//! A range is of a source, which is either an external file, imported in
//! place, or a file kept whole in the repo's shards (see `Shards`).
//!
//! Offsets are never searched for. A block's bytes can't say where else
//! they're found, so this store only admits blocks put with a
//! `Provenance::FileRange`, which the importer gives each leaf as it reads
//! it. That provenance is trusted: within one executable, the importer has
//! just read those bytes from that range.
//!
//! External files belong to the user and may change. Each is recorded with
//! a fingerprint (size, mtime, inode) taken when it's first seen, and a
//! range is only served while its file's fingerprint still matches; the
//! router re-hashes what it serves regardless. Kept files are the repo's
//! own and never change. A block may be kept in several sources, and is
//! served from a kept file first, then whichever external file is still
//! unchanged.

use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::{OptionalExtension, params};

use crate::block::Block;
use crate::cid::{BaseCid, CidRef, RAW_CODEC};
use crate::dag::Provenance;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Id, Key, Put, Result, Shards, Store, query_keys};

const NAME: &str = "offset";

/// Keeps blocks as (source, offset, length).
pub struct OffsetStore {
    db: Db,
    shards: Option<Rc<Shards>>,
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

/// Where a range's bytes are.
enum Place {
    External { path: PathBuf, fingerprint: Fingerprint },
    Kept(PathBuf),
}

/// Where a block is kept.
struct Range {
    place: Place,
    offset: u64,
    len: usize,
}

impl Range {
    /// The range's bytes, or the error to give if there are none to be had:
    /// its external file has changed, or its kept file is gone.
    fn read(&self) -> Result<std::result::Result<Vec<u8>, Error>> {
        let path = match &self.place {
            Place::External { path, fingerprint } => {
                if Fingerprint::read(path) != Some(*fingerprint) {
                    return Ok(Err(Error::Stale(path.clone())));
                }
                path
            },
            Place::Kept(path) => {
                if !path.exists() {
                    return Ok(Err(Error::Missing(path.clone())));
                }
                path
            },
        };
        let mut data = vec![0; self.len];
        File::open(path)?.read_exact_at(&mut data, self.offset)?;
        Ok(Ok(data))
    }
}

fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

/// Create the offset tables, which `Shards` shares.
pub(super) fn schema(db: &Db) -> Result<()> {
    db.atomically(|| {
        let conn = db.conn();
        // Before sources, ranges were of external files only
        let v1 = conn
            .prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'offset_files'")?
            .exists([])?;
        if v1 {
            conn.execute_batch("ALTER TABLE offset_ranges RENAME TO offset_ranges_v1")?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS offset_sources (id INTEGER PRIMARY KEY);
             -- Each version of an external file seen, so ranges of a version
             -- which has since changed are never served from the new one.
             CREATE TABLE IF NOT EXISTS external_files (
                 source INTEGER PRIMARY KEY REFERENCES offset_sources (id) ON DELETE CASCADE,
                 path BLOB NOT NULL,
                 size INTEGER NOT NULL,
                 mtime INTEGER NOT NULL,
                 inode INTEGER NOT NULL,
                 UNIQUE (path, size, mtime, inode)
             );
             -- Files kept whole in the shards, by their whole-file multihash.
             CREATE TABLE IF NOT EXISTS shard_files (
                 source INTEGER PRIMARY KEY REFERENCES offset_sources (id) ON DELETE CASCADE,
                 blob INTEGER UNIQUE NOT NULL REFERENCES multihashes (id),
                 size INTEGER NOT NULL
             );
             -- Which UnixFS roots each kept file was imported as.
             CREATE TABLE IF NOT EXISTS shard_roots (
                 blob INTEGER NOT NULL REFERENCES multihashes (id),
                 root INTEGER NOT NULL REFERENCES multihashes (id),
                 PRIMARY KEY (blob, root)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS offset_ranges (
                 block INTEGER NOT NULL REFERENCES multihashes (id),
                 source INTEGER NOT NULL REFERENCES offset_sources (id) ON DELETE CASCADE,
                 offset INTEGER NOT NULL,
                 len INTEGER NOT NULL,
                 PRIMARY KEY (block, source)
             ) WITHOUT ROWID;",
        )?;
        if v1 {
            conn.execute_batch(
                "INSERT INTO offset_sources (id) SELECT id FROM offset_files;
                 INSERT INTO external_files (source, path, size, mtime, inode)
                     SELECT id, path, size, mtime, inode FROM offset_files;
                 INSERT INTO offset_ranges (block, source, offset, len)
                     SELECT block, file, offset, len FROM offset_ranges_v1;
                 DROP TABLE offset_ranges_v1;
                 DROP TABLE offset_files;",
            )?;
        }
        Ok(())
    })
}

impl OffsetStore {
    /// An offset store for external files, and kept ones if there are
    /// shards to keep them in.
    pub fn open(db: Db, shards: Option<Rc<Shards>>) -> Result<Self> {
        schema(&db)?;
        Ok(Self { db, shards })
    }

    /// The source for an external file's current version, recording it if
    /// it's new, and the file's size.
    fn external(&self, path: &Path) -> Result<Option<(Id, i64)>> {
        let path = fs::canonicalize(path)?;
        let Some(fp) = Fingerprint::read(&path) else {
            return Ok(None);
        };
        let conn = self.db.conn();
        let existing = conn
            .prepare_cached(
                "SELECT source FROM external_files WHERE path = ?1 AND size = ?2 AND mtime = ?3 AND inode = ?4",
            )?
            .query_row(params![path_bytes(&path), fp.size, fp.mtime, fp.inode], |row| row.get(0))
            .optional()?;
        if let Some(source) = existing {
            return Ok(Some((source, fp.size)));
        }
        conn.prepare_cached("INSERT INTO offset_sources DEFAULT VALUES")?.execute([])?;
        let source = conn.last_insert_rowid();
        conn.prepare_cached("INSERT INTO external_files (source, path, size, mtime, inode) VALUES (?1, ?2, ?3, ?4, ?5)")?
            .execute(params![source, path_bytes(&path), fp.size, fp.mtime, fp.inode])?;
        Ok(Some((source, fp.size)))
    }

    /// The source for a path, kept or external, and its size.
    fn source(&self, path: &Path) -> Result<Option<(Id, i64)>> {
        match self.shards.as_ref().and_then(|shards| Some((shards, shards.blob(path)?))) {
            Some((shards, blob)) => shards.source(blob.as_ref()).map(Some),
            None => self.external(path),
        }
    }

    /// Every range a block is kept in, kept files first, then newest
    /// external file first.
    fn ranges(&self, key: Key<'_>) -> Result<Vec<Range>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT r.offset, r.len, e.path, e.size, e.mtime, e.inode, b.multihash
             FROM multihashes m
             JOIN offset_ranges r ON r.block = m.id
             LEFT JOIN external_files e ON e.source = r.source
             LEFT JOIN shard_files s ON s.source = r.source
             LEFT JOIN multihashes b ON b.id = s.blob
             WHERE m.multihash = ?1
             ORDER BY s.source IS NULL, r.source DESC",
        )?;
        let rows = stmt.query_map([key.to_bytes()], |row| Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            (row.get::<_, Option<i64>>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?),
            row.get::<_, Option<Vec<u8>>>(6)?,
        )))?;
        let invalid = |reason: &str| Error::Invalid { store: NAME, reason: reason.into() };
        rows.map(|row| {
            let (offset, len, path, (size, mtime, inode), blob) = row?;
            let place = match (path, size, mtime, inode, blob) {
                (Some(path), Some(size), Some(mtime), Some(inode), None) => Place::External {
                    path: PathBuf::from(std::ffi::OsStr::from_bytes(&path)),
                    fingerprint: Fingerprint { size, mtime, inode },
                },
                (None, .., Some(blob)) => {
                    let shards = self.shards.as_ref().ok_or_else(|| invalid("a kept file, but no shards"))?;
                    Place::Kept(shards.path(super::decode_key(NAME, &blob)?.as_ref()))
                },
                _ => return Err(invalid("a range of no one source")),
            };
            Ok(Range {
                place,
                offset: u64::try_from(offset).map_err(|_| invalid("negative offset"))?,
                len: usize::try_from(len).map_err(|_| invalid("negative length"))?,
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
    /// The block from whichever of its sources is readable, or why the
    /// first can't be read if none are.
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        let mut first = None;
        for range in self.ranges(key)? {
            match range.read()? {
                Ok(data) => return Ok(Some(data)),
                Err(e) => { first.get_or_insert(e); },
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
            let Some((source, size)) = self.source(path)? else {
                return Ok(Put::Declined);
            };
            if offset_sql.checked_add(len_sql).is_none_or(|end| end > size) {
                return Ok(Put::Declined);
            }
            let id = self.db.intern(block.cid().multihash())?;
            self.db.conn()
                .prepare_cached("INSERT OR IGNORE INTO offset_ranges (block, source, offset, len) VALUES (?1, ?2, ?3, ?4)")?
                .execute(params![id, source, offset_sql, len_sql])?;
            Ok(Put::Stored)
        })
    }
}
