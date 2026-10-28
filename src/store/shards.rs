//! A sharded directory for blobs too large to be worth keeping in `SQLite`:
//! blocks over `THRESHOLD`, and whole files kept so their leaves are
//! contiguous, which the offset store indexes into.
//!
//! The layout is Kubo's flatfs: each blob is named by its multihash in
//! base32upper with no multibase prefix, sharded `next-to-last/2`, so a
//! blob's name checks its bytes without the database. `shard_files` caches
//! what's there, so reads needn't touch the filesystem to find a blob, and
//! a rescan rebuilds it.
//!
//! A kept file's multihash is a second name for the content its UnixFS
//! root names. `shard_roots` records which roots each kept file was
//! imported as, which is what lets its ranges be rebuilt from the roots'
//! `blocksizes`. That's a `Same` claim in all but name, and will become
//! one; until then a kept file isn't a block anyone can get.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use multibase::Base;
use rusqlite::{OptionalExtension, params};
use tempfile::NamedTempFile;

use crate::block::Block;
use crate::cid::CidRef;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Key, Put, Result, Store, query_keys};

const NAME: &str = "shards";

/// Blobs larger than this are kept here rather than in `SQLite`, which is
/// faster for smaller ones at its default 4 KiB pages
/// (<https://sqlite.org/intern-v-extern-blob.html>).
pub const THRESHOLD: usize = 64 * 1024;

/// What flatfs writes to say how a directory is sharded.
const SHARDING: &str = "/repo/flatfs/shard/v1/next-to-last/2\n";

/// Admits blocks larger than its threshold, keeping each as a file.
pub struct ShardStore {
    dir: PathBuf,
    db: Db,
    /// Blobs larger than this are kept here; see `THRESHOLD`.
    pub threshold: usize,
}

/// A blob's name in the directory.
fn key(blob: Key<'_>) -> String {
    Base::Base32Upper.encode(blob.to_bytes())
}

impl ShardStore {
    pub fn open(db: Db, dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join(".temp"))?;
        let sharding = dir.join("SHARDING");
        if !sharding.exists() {
            fs::write(sharding, SHARDING)?;
        }
        super::offset::schema(&db)?;
        Ok(Self { dir: fs::canonicalize(dir)?, db, threshold: THRESHOLD })
    }

    /// Where the blob with this multihash is kept.
    pub fn path(&self, blob: Key<'_>) -> PathBuf {
        let key = key(blob);
        let shard = key.len().checked_sub(3).and_then(|start| key.get(start..start.saturating_add(2)));
        self.dir.join(shard.unwrap_or("_")).join(format!("{key}.data"))
    }

    /// A temporary file in the directory, to become a blob.
    pub fn temp(&self) -> Result<NamedTempFile> {
        Ok(tempfile::Builder::new().prefix("put-").tempfile_in(self.dir.join(".temp"))?)
    }

    /// Make a temporary file the blob with this multihash, unless it's
    /// already here.
    pub fn persist(&self, file: NamedTempFile, blob: Key<'_>) -> Result<()> {
        let size = file.as_file().metadata()?.len();
        file.as_file().set_permissions(fs::Permissions::from_mode(0o444))?;
        file.as_file().sync_all()?;
        let dest = self.path(blob);
        let shard = dest.parent().unwrap_or(&self.dir);
        fs::create_dir_all(shard)?;
        match file.persist_noclobber(&dest) {
            Ok(_) => File::open(shard)?.sync_all()?,
            // The temporary file is removed as it's dropped
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.error.into()),
        }
        self.cache(blob, size)
    }

    fn cache(&self, blob: Key<'_>, size: u64) -> Result<()> {
        let size = i64::try_from(size).map_err(|_| Error::Invalid { store: NAME, reason: "blob too large".into() })?;
        self.db.conn()
            .prepare_cached("INSERT OR REPLACE INTO shard_files (blob, size) VALUES (?1, ?2)")?
            .execute(params![self.db.intern(blob)?, size])?;
        Ok(())
    }

    /// A kept file was imported as `root`.
    pub fn record_root(&self, blob: Key<'_>, root: Key<'_>) -> Result<()> {
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO shard_roots (blob, root) VALUES (?1, ?2)")?
            .execute(params![self.db.intern(blob)?, self.db.intern(root)?])?;
        Ok(())
    }

    /// Let a blob go.
    pub fn forget(&self, blob: Key<'_>) -> Result<()> {
        if let Some(id) = self.db.lookup(blob)? {
            self.db.conn().prepare_cached("DELETE FROM shard_files WHERE blob = ?1")?.execute([id])?;
        }
        match fs::remove_file(self.path(blob)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    /// Rebuild the cache of what's here from the directory.
    pub fn rescan(&self) -> Result<()> {
        self.db.atomically(|| {
            self.db.conn().execute("DELETE FROM shard_files", [])?;
            for shard in fs::read_dir(&self.dir)? {
                let shard = shard?;
                if !shard.file_type()?.is_dir() || shard.file_name() == ".temp" {
                    continue;
                }
                for entry in fs::read_dir(shard.path())? {
                    let path = entry?.path();
                    let blob = path.file_name()
                        .and_then(|name| name.to_str()?.strip_suffix(".data"))
                        .and_then(|key| Base::Base32Upper.decode(key).ok())
                        .and_then(|bytes| Multihash::<Box<[u8]>>::decode(&bytes).ok());
                    // Anything else isn't ours
                    if let Some(blob) = blob && self.path(blob.as_ref()) == path {
                        self.cache(blob.as_ref(), fs::metadata(&path)?.len())?;
                    }
                }
            }
            Ok(())
        })
    }
}

impl Store for ShardStore {
    fn name(&self) -> &'static str { NAME }
}

impl BlockIndex for ShardStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN shard_files s ON s.blob = m.id WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Every blob but kept files, which aren't blocks.
    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(
            &self.db,
            NAME,
            "SELECT m.multihash FROM shard_files s JOIN multihashes m ON m.id = s.blob
             WHERE s.blob NOT IN (SELECT blob FROM shard_roots)",
        )
    }
}

impl BlockSource for ShardStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        if !self.has(key)? {
            return Ok(None);
        }
        let path = self.path(key);
        match fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Missing(path)),
            Err(e) => Err(e.into()),
        }
    }
}

impl BlockStore for ShardStore {
    fn put(&self, block: &Block) -> Result<Put> {
        if block.data().len() <= self.threshold {
            return Ok(Put::Declined);
        }
        let blob = block.cid().multihash();
        if !self.has(blob)? {
            let mut file = self.temp()?;
            io::Write::write_all(&mut file, block.data())?;
            self.persist(file, blob)?;
        }
        Ok(Put::Stored)
    }
}
