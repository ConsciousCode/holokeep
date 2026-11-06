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
//! The directory is a volume of its own, labelled by its `VOLUME` file,
//! and may be shared: a drive other nodes write to as well. So the cache
//! catches up with the directory by each shard's mtime, which changes
//! whenever a blob is added to it or removed: only shards whose mtime
//! isn't the one recorded when they were last listed are listed again.
//! Comparing the writer's own timestamps, rather than this machine's
//! clock, keeps that right across machines whose clocks disagree.
//!
//! A kept file's multihash is a second name for the content its UnixFS
//! root names. `shard_roots` records which roots each kept file was
//! imported as, which is what lets its ranges be rebuilt from the roots'
//! `blocksizes`. That's a `Same` claim in all but name, and will become
//! one; until then a kept file isn't a block anyone can get.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use multibase::Base;
use rusqlite::{OptionalExtension, params};
use tempfile::NamedTempFile;

use crate::block::Block;
use crate::cid::CidRef;
use crate::multihash::Multihash;

use super::volume::{Label, dir_label, read_dir_label};
use super::{BlockIndex, BlockSource, BlockStore, Changes, Db, Error, Id, Key, Put, Result, Store};

const NAME: &str = "flatfs";

/// Blobs larger than this are kept here rather than in `SQLite`, which is
/// faster for smaller ones at its default 4 KiB pages
/// (<https://sqlite.org/intern-v-extern-blob.html>).
pub const THRESHOLD: usize = 64 * 1024;

/// What flatfs writes to say how a directory is sharded.
const SHARDING: &str = "/repo/flatfs/shard/v1/next-to-last/2\n";

/// A shard changed this recently may change again within its mtime's
/// granularity (two seconds, on FAT) without its mtime changing, so it's
/// listed again next time.
const SETTLED: Duration = Duration::from_secs(2);

/// Admits blocks larger than its threshold, keeping each as a file.
pub struct ShardStore {
    dir: PathBuf,
    label: Label,
    /// The directory's id in `shard_dirs`.
    id: Id,
    db: Db,
    /// Blobs larger than this are kept here, or any if there's none; see
    /// `THRESHOLD`.
    pub threshold: Option<usize>,
}

/// A blob's name in the directory.
fn key(blob: Key<'_>) -> String {
    Base::Base32Upper.encode(blob.to_bytes())
}

/// The shard a blob's name belongs in.
fn shard_of(key: &str) -> &str {
    key.len().checked_sub(3).and_then(|start| key.get(start..start.saturating_add(2))).unwrap_or("_")
}

/// A blob's name back as its multihash, if it's one.
fn blob_of(name: &str) -> Option<Multihash> {
    let key = name.strip_suffix(".data")?;
    let bytes = Base::Base32Upper.decode(key).ok()?;
    let blob = Multihash::decode(&bytes).ok()?;
    // Only the canonical name counts
    (self::key(blob.as_ref()) == key).then_some(blob)
}

/// A file's mtime in nanoseconds, or zero if it's too recent to trust.
fn mtime(path: &Path) -> Result<i64> {
    let modified = fs::metadata(path)?.modified()?;
    if SystemTime::now().duration_since(modified).unwrap_or_default() < SETTLED {
        return Ok(0);
    }
    let nanos = modified.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_nanos();
    Ok(i64::try_from(nanos).unwrap_or(i64::MAX))
}

impl ShardStore {
    /// Open a directory, making it a volume if it isn't one.
    pub fn open(db: Db, dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join(".temp"))?;
        let sharding = dir.join("SHARDING");
        if !sharding.exists() {
            fs::write(sharding, SHARDING)?;
        }
        let label = dir_label(dir)?;
        Self::with_label(db, dir, label)
    }

    /// Open a directory if it's the volume with this label, and not
    /// otherwise: a drive that isn't mounted, or something else mounted
    /// in its place.
    pub fn attach(db: Db, dir: &Path, label: Label) -> Result<Option<Self>> {
        if read_dir_label(dir)? != Some(label) {
            return Ok(None);
        }
        fs::create_dir_all(dir.join(".temp"))?;
        Self::with_label(db, dir, label).map(Some)
    }

    fn with_label(db: Db, dir: &Path, label: Label) -> Result<Self> {
        super::offset::schema(&db)?;
        // Only if it's new: opening a repo as it was doesn't wait for a writer
        let known: Option<Id> = db.conn()
            .prepare_cached("SELECT id FROM shard_dirs WHERE label = ?1")?
            .query_row([label.as_slice()], |row| row.get(0))
            .optional()?;
        let id: Id = match known {
            Some(id) => id,
            None => db.conn()
                .prepare_cached("INSERT INTO shard_dirs (label) VALUES (?1) ON CONFLICT (label) DO UPDATE SET label = label RETURNING id")?
                .query_row([label.as_slice()], |row| row.get(0))?,
        };
        Ok(Self { dir: fs::canonicalize(dir)?, label, id, db, threshold: Some(THRESHOLD) })
    }

    /// The directory's identity as a volume.
    pub const fn label(&self) -> Label { self.label }

    pub fn dir(&self) -> &Path { &self.dir }

    /// The directory's id in `shard_dirs`, which `shard_files` are under.
    pub const fn id(&self) -> Id { self.id }

    /// Where the blob with this multihash is kept.
    pub fn path(&self, blob: Key<'_>) -> PathBuf {
        let key = key(blob);
        self.dir.join(shard_of(&key)).join(format!("{key}.data"))
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
            .prepare_cached("INSERT OR REPLACE INTO shard_files (dir, blob, shard, size) VALUES (?1, ?2, ?3, ?4)")?
            .execute(params![self.id, self.db.intern(blob)?, shard_of(&key(blob)), size])?;
        Ok(())
    }

    fn uncache(&self, blob: Id) -> Result<()> {
        self.db.conn()
            .prepare_cached("DELETE FROM shard_files WHERE dir = ?1 AND blob = ?2")?
            .execute([self.id, blob])?;
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
            self.uncache(id)?;
        }
        match fs::remove_file(self.path(blob)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    /// Whether a blob is a kept file rather than a block.
    fn is_kept_file(&self, blob: Id) -> Result<bool> {
        Ok(self.db.conn().prepare_cached("SELECT 1 FROM shard_roots WHERE blob = ?1")?.exists([blob])?)
    }

    /// The shard directories, by name.
    fn shards(&self) -> Result<Vec<(String, PathBuf)>> {
        let mut shards = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(name) = name.to_str()
                && name != ".temp"
                && entry.file_type()?.is_dir()
            {
                shards.push((name.to_owned(), entry.path()));
            }
        }
        Ok(shards)
    }

    /// List a shard again, bringing the cache up to date with it and
    /// recording its mtime as of before it was listed. A shard that's
    /// gone lists as empty. Adds the blocks it gained and lost to
    /// `changes`.
    fn relist(&self, shard: &str, path: &Path, changes: &mut Changes) -> Result<()> {
        let mut found = BTreeMap::new();
        let seen = match fs::read_dir(path) {
            Ok(entries) => {
                let seen = mtime(path)?;
                for entry in entries {
                    let path = entry?.path();
                    // Anything else isn't ours
                    if let Some(blob) = path.file_name().and_then(|name| blob_of(name.to_str()?))
                        && shard_of(&key(blob.as_ref())) == shard
                    {
                        found.insert(blob.to_bytes(), (blob, fs::metadata(&path)?.len()));
                    }
                }
                Some(seen)
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let cached: Vec<(Id, Vec<u8>)> = self.db.conn()
            .prepare_cached("SELECT s.blob, m.multihash FROM shard_files s JOIN multihashes m ON m.id = s.blob WHERE s.dir = ?1 AND s.shard = ?2")?
            .query_map(params![self.id, shard], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, bytes) in cached {
            if found.remove(&bytes).is_none() {
                self.uncache(id)?;
                if !self.is_kept_file(id)? {
                    changes.removed.push(super::decode_key(NAME, &bytes)?);
                }
            }
        }
        for (blob, size) in found.into_values() {
            self.cache(blob.as_ref(), size)?;
            if !self.is_kept_file(self.db.intern(blob.as_ref())?)? {
                changes.added.push(blob);
            }
        }
        match seen {
            Some(seen) => self.db.conn()
                .prepare_cached("INSERT OR REPLACE INTO shard_mtimes (dir, shard, mtime) VALUES (?1, ?2, ?3)")?
                .execute(params![self.id, shard, seen])?,
            None => self.db.conn()
                .prepare_cached("DELETE FROM shard_mtimes WHERE dir = ?1 AND shard = ?2")?
                .execute(params![self.id, shard])?,
        };
        Ok(())
    }
}

impl Store for ShardStore {
    fn name(&self) -> &'static str { NAME }

    /// A blob other blocks are ranges of stays: it's theirs too.
    fn remove(&self, key: Key<'_>) -> Result<Option<u64>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(Some(0));
        };
        let conn = self.db.conn();
        if conn.prepare_cached("SELECT 1 FROM offset_ranges WHERE blob = ?1 AND block != ?1")?.exists([id])? {
            return Ok(None);
        }
        let size: Option<i64> = conn
            .prepare_cached("SELECT size FROM shard_files WHERE dir = ?1 AND blob = ?2")?
            .query_row([self.id, id], |row| row.get(0))
            .optional()?;
        self.forget(key)?;
        Ok(Some(size.map_or(0, |size| u64::try_from(size).unwrap_or_default())))
    }

    /// List again only the shards whose mtime has changed since they were
    /// last listed, and forget those which are gone.
    fn catch_up(&self) -> Result<Changes> {
        self.db.atomically(|| {
            let mut changes = Changes::default();
            let mut listed = Vec::new();
            for (shard, path) in self.shards()? {
                let seen: Option<i64> = self.db.conn()
                    .prepare_cached("SELECT mtime FROM shard_mtimes WHERE dir = ?1 AND shard = ?2")?
                    .query_row(params![self.id, shard], |row| row.get(0))
                    .optional()?;
                // Zero is a shard that was too recent to trust
                if seen.is_none_or(|seen| seen == 0 || seen != mtime(&path).unwrap_or(0)) {
                    self.relist(&shard, &path, &mut changes)?;
                }
                listed.push(shard);
            }
            let known: Vec<String> = self.db.conn()
                .prepare_cached("SELECT DISTINCT shard FROM shard_files WHERE dir = ?1")?
                .query_map([self.id], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for shard in known.iter().filter(|shard| !listed.contains(shard)) {
                self.relist(shard, &self.dir.join(shard), &mut changes)?;
            }
            Ok(changes)
        })
    }

    /// List every shard again.
    fn rescan(&self) -> Result<()> {
        self.db.atomically(|| {
            self.db.conn().execute("DELETE FROM shard_files WHERE dir = ?1", [self.id])?;
            self.db.conn().execute("DELETE FROM shard_mtimes WHERE dir = ?1", [self.id])?;
            let mut changes = Changes::default();
            for (shard, path) in self.shards()? {
                self.relist(&shard, &path, &mut changes)?;
            }
            Ok(())
        })
    }
}

impl BlockIndex for ShardStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN shard_files s ON s.blob = m.id WHERE m.multihash = ?1 AND s.dir = ?2",
            )?
            .exists(params![key.to_bytes(), self.id])?)
    }

    /// Every blob but kept files, which aren't blocks.
    fn keys(&self) -> Result<Vec<Multihash>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT m.multihash FROM shard_files s JOIN multihashes m ON m.id = s.blob
             WHERE s.dir = ?1 AND s.blob NOT IN (SELECT blob FROM shard_roots)",
        )?;
        let rows = stmt.query_map([self.id], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|bytes| super::decode_key(NAME, &bytes?)).collect()
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
        if self.threshold.is_some_and(|threshold| block.data().len() <= threshold) {
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
