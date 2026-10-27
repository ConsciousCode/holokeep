//! A sharded directory of whole files, copied in so their contents are kept
//! contiguously, and immutably, outside the database. The offset store
//! keeps their leaves as ranges of them.
//!
//! Each file is named by its multihash (sha2-256 of its bytes) and sharded
//! on the digest's first byte: `ab/1220ab…`, so the directory checks itself
//! without the database. A file's whole-file multihash is a second name for
//! the content its UnixFS root names; `shard_roots` records which roots
//! each file was imported as, which is what lets its ranges be rebuilt from
//! the roots' `blocksizes`. That's a `Same` claim in all but name, and will
//! become one; until then the whole-file multihash isn't a block anyone can
//! get.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::multihash::Multihash;

use super::{Db, Error, Id, Key, Result};

/// Files larger than this are kept whole when copied in. Smaller ones are
/// cheaper as rows: they're at most one leaf at the default chunk size.
pub const THRESHOLD: u64 = 1024 * 1024;

const SHA2_256: u64 = 0x12;

/// Names temporary files uniquely within a process.
static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct Shards {
    dir: PathBuf,
    db: Db,
    /// Files larger than this are kept whole; see `THRESHOLD`.
    pub threshold: u64,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len().saturating_mul(2)), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

impl Shards {
    pub fn open(db: Db, dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join("tmp"))?;
        super::offset::schema(&db)?;
        Ok(Self { dir: fs::canonicalize(dir)?, db, threshold: THRESHOLD })
    }

    /// Where the file with this multihash is kept.
    pub(super) fn path(&self, blob: Key<'_>) -> PathBuf {
        let first = blob.digest_ref().first().copied().unwrap_or_default();
        self.dir.join(hex(&[first])).join(hex(&blob.to_bytes()))
    }

    /// The multihash of a file, if the path is one of ours.
    pub fn blob(&self, path: &Path) -> Option<Multihash> {
        let name = path.file_name()?.to_str()?;
        let bytes = (0..name.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(name.get(i..i.checked_add(2)?)?, 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        let blob = Multihash::decode(&bytes).ok()?;
        (self.path(blob.as_ref()) == path).then_some(blob)
    }

    /// Copy a file in, returning where it's kept. A file which is already
    /// here is kept once.
    pub fn keep(&self, path: &Path) -> Result<PathBuf> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let tmp = self.dir.join("tmp").join(format!("{}-{n}", std::process::id()));
        let result = self.copy(path, &tmp);
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn copy(&self, path: &Path, tmp: &Path) -> Result<PathBuf> {
        let mut from = File::open(path)?;
        let mut to = File::create_new(tmp)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = match from.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            let chunk = buf.get(..n).unwrap_or_default();
            hasher.update(chunk);
            to.write_all(chunk)?;
        }
        to.set_permissions(fs::Permissions::from_mode(0o444))?;
        to.sync_all()?;
        drop(to);

        let digest = hasher.finalize();
        let dest = self.path(Multihash::wrap(SHA2_256, &digest));
        if dest.exists() {
            fs::remove_file(tmp)?;
            return Ok(dest);
        }
        let shard = dest.parent().unwrap_or(&self.dir);
        fs::create_dir_all(shard)?;
        fs::rename(tmp, &dest)?;
        File::open(shard)?.sync_all()?;
        Ok(dest)
    }

    /// The offset source for a kept file, recording it if it's new, and the
    /// file's size.
    pub(super) fn source(&self, blob: Key<'_>) -> Result<(Id, i64)> {
        let blob_id = self.db.intern(blob)?;
        let conn = self.db.conn();
        let existing = conn
            .prepare_cached("SELECT source, size FROM shard_files WHERE blob = ?1")?
            .query_row([blob_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        if let Some(found) = existing {
            return Ok(found);
        }
        let size = i64::try_from(fs::metadata(self.path(blob))?.len())
            .map_err(|_| Error::Invalid { store: "shards", reason: "file too large".into() })?;
        conn.prepare_cached("INSERT INTO offset_sources DEFAULT VALUES")?.execute([])?;
        let source = conn.last_insert_rowid();
        conn.prepare_cached("INSERT INTO shard_files (source, blob, size) VALUES (?1, ?2, ?3)")?
            .execute(params![source, blob_id, size])?;
        Ok((source, size))
    }

    /// A kept file was imported as `root`. If none of its ranges were kept
    /// (its leaves were already stored elsewhere) it's let go.
    pub fn kept(&self, copy: &Path, root: Key<'_>) -> Result<()> {
        let Some(blob) = self.blob(copy) else {
            return Ok(());
        };
        let blob_id = self.db.intern(blob.as_ref())?;
        let used = self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM shard_files f JOIN offset_ranges r ON r.source = f.source WHERE f.blob = ?1 LIMIT 1",
            )?
            .query_row([blob_id], |_| Ok(()))
            .optional()?
            .is_some();
        if !used {
            self.db.conn()
                .prepare_cached(
                    "DELETE FROM offset_sources WHERE id IN (SELECT source FROM shard_files WHERE blob = ?1)",
                )?
                .execute([blob_id])?;
            fs::remove_file(copy)?;
            return Ok(());
        }
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO shard_roots (blob, root) VALUES (?1, ?2)")?
            .execute(params![blob_id, self.db.intern(root)?])?;
        Ok(())
    }
}
