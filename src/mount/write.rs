//! Writing to anchors: their overlays, and committing them.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fuser::{Errno, FileAttr};

use crate::cid::CidRef as _;
use crate::export::{self, Kind};
use crate::model::Link;
use crate::store::{Catalog, Mount};

use super::{At, Inode, Soup, Source, errno, store_errno};

/// How long an anchor's left quiet, nothing of it open to write, before
/// what's been written is committed: long enough for an editor's save,
/// which writes, renames and removes in a burst, to be one.
const QUIET: Duration = Duration::from_secs(1);

/// How often the committer looks.
const TICK: Duration = Duration::from_millis(250);

/// How much of a file's copied into a work directory at once.
const COPY: usize = 1 << 20;

/// A file open: in an anchor's work directory, and whether it's open to
/// write.
pub struct Handle {
    file: File,
    anchor: Link,
    writable: bool,
}

/// What's been written to and not committed yet.
#[derive(Default)]
struct Pending {
    /// Anchors written to, as of when last.
    dirty: HashMap<Vec<u8>, (Link, Instant)>,
    /// How many files of each anchor are open to write.
    writers: HashMap<Vec<u8>, usize>,
}

/// Commits anchors once what's written to them settles.
pub struct Committer {
    open: Arc<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync>,
    pending: Mutex<Pending>,
    stop: AtomicBool,
}

impl Committer {
    pub fn new(open: Arc<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync>) -> Self {
        Self { open, pending: Mutex::new(Pending::default()), stop: AtomicBool::new(false) }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Note an anchor's been written to.
    fn touched(&self, anchor: &Link) {
        self.pending().dirty.insert(anchor.to_bytes(), (anchor.clone(), Instant::now()));
    }

    /// Note a file of an anchor opened or closed to write.
    fn writing(&self, anchor: &Link, open: bool) {
        let mut pending = self.pending();
        let writers = pending.writers.entry(anchor.to_bytes()).or_default();
        *writers = if open { writers.saturating_add(1) } else { writers.saturating_sub(1) };
        drop(pending);
    }

    /// The anchors due to be committed, no longer pending: quiet long
    /// enough, nothing of theirs open to write, or every one if `all`.
    fn due(&self, all: bool) -> Vec<Link> {
        let mut pending = self.pending();
        let Pending { dirty, writers } = &mut *pending;
        let mut due = Vec::new();
        dirty.retain(|key, (anchor, at)| {
            let ready = all || (writers.get(key).copied().unwrap_or_default() == 0 && at.elapsed() >= QUIET);
            if ready {
                due.push(anchor.clone());
            }
            !ready
        });
        drop(pending);
        due
    }

    /// Commit what's due, with a catalog opened on this thread: import
    /// each anchor's overlay and set it. What fails is tried again later.
    pub fn commit(&self, catalog: &mut Catalog, all: bool) {
        for anchor in self.due(all) {
            let mount = catalog.mounts().ok().and_then(|mounts| mounts.into_iter().find(|mount| mount.anchor == anchor && mount.overlay));
            let Some(mount) = mount else {
                continue;
            };
            match catalog.remount(&mount) {
                Ok(value) => eprintln!("{anchor} is {value} now"),
                Err(e) => {
                    eprintln!("{anchor} couldn't be committed, so it stays as it was for now: {e}");
                    self.touched(&anchor);
                },
            }
        }
    }

    /// Commit every overlay mount, as after a mount that ended before it
    /// could.
    pub fn recover(&self) {
        match (self.open)() {
            Ok(mut catalog) => {
                for mount in catalog.mounts().unwrap_or_default().into_iter().filter(|mount| mount.overlay) {
                    if let Err(e) = catalog.remount(&mount) {
                        eprintln!("{} couldn't be committed: {e}", mount.anchor);
                    }
                }
            },
            Err(e) => eprintln!("not committing what was written before: {e}"),
        }
    }

    /// Commit what's due every so often, until stopped, on a thread of
    /// its own with a catalog of its own.
    pub fn run(self: Arc<Self>) {
        std::thread::spawn(move || {
            let mut catalog = None;
            while !self.stop.load(Ordering::Relaxed) {
                std::thread::sleep(super::write::TICK);
                if self.pending().dirty.is_empty() {
                    continue;
                }
                if catalog.is_none() {
                    catalog = (self.open)().map_err(|e| eprintln!("not committing yet: {e}")).ok();
                }
                if let Some(catalog) = &mut catalog {
                    self.commit(catalog, false);
                }
            }
        });
    }

    /// Stop committing every so often, committing everything now.
    pub fn finish(&self) {
        self.stop.store(true, Ordering::Relaxed);
        match (self.open)() {
            Ok(mut catalog) => self.commit(&mut catalog, true),
            Err(e) => eprintln!("what was written isn't committed yet, and will be when next mounted: {e}"),
        }
    }
}

fn io_errno(e: &io::Error) -> Errno {
    match e.kind() {
        io::ErrorKind::AlreadyExists => Errno::EEXIST,
        io::ErrorKind::DirectoryNotEmpty => Errno::ENOTEMPTY,
        io::ErrorKind::PermissionDenied => Errno::EACCES,
        _ => errno(e),
    }
}

impl Soup {
    fn handles(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Handle>> {
        self.handles.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The anchor and path of an inode which can be written to.
    fn overlay_of(&self, ino: u64) -> Result<(Link, PathBuf), Errno> {
        match self.inode(ino)? {
            Inode::Path(anchor, rel) if self.work.is_some() => Ok((anchor, rel)),
            _ => Err(Errno::EROFS),
        }
    }

    /// An anchor's work directory, making it an overlay mount if it isn't
    /// one yet. An anchor mounted on files imported in place is theirs to
    /// change, not this.
    fn prepare(&self, catalog: &Catalog, anchor: &Link) -> Result<PathBuf, Errno> {
        let dir = self.work_path(anchor, Path::new("")).ok_or(Errno::EROFS)?;
        match catalog.mounts().map_err(store_errno)?.into_iter().find(|mount| &mount.anchor == anchor) {
            Some(mount) if mount.overlay => {},
            Some(_) => return Err(Errno::EROFS),
            None => catalog
                .mount(&Mount { anchor: anchor.clone(), path: dir.clone(), chunk_size: crate::import::CHUNK_SIZE, width: crate::dag::FILE_WIDTH, hidden: true, overlay: true })
                .map_err(store_errno)?,
        }
        Ok(dir)
    }

    /// Make sure the directories over a path of a work directory are
    /// there.
    fn parents(path: &Path) -> Result<(), Errno> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_errno(&e))?;
        }
        Ok(())
    }

    /// A file of an anchor, in its work directory: copied there if it's
    /// only what the anchor had, unless it's to be emptied anyway.
    fn materialize(&self, catalog: &Catalog, anchor: &Link, rel: &Path, truncate: bool) -> Result<PathBuf, Errno> {
        self.prepare(catalog, anchor)?;
        let path = self.work_path(anchor, rel).ok_or(Errno::EROFS)?;
        if fs::symlink_metadata(&path).is_ok() {
            if truncate {
                File::options().write(true).truncate(true).open(&path).map_err(|e| io_errno(&e))?;
            }
            return Ok(path);
        }
        let (cid, _) = self.base_at(catalog, anchor, rel)?.ok_or(Errno::ENOENT)?;
        Self::parents(&path)?;
        let mut file = File::create_new(&path).map_err(|e| io_errno(&e))?;
        if !truncate {
            let source = Source { catalog, fetcher: self.fetcher.as_ref() };
            if export::stat(&source, &cid).map_err(|e| errno(&e))? == Kind::Directory {
                drop(file);
                let _ = fs::remove_file(&path);
                return Err(Errno::EISDIR);
            }
            let mut offset = 0u64;
            loop {
                let part = export::read_at(&source, &cid, offset, COPY).map_err(|e| errno(&e))?;
                if part.is_empty() {
                    break;
                }
                file.write_all(&part).map_err(|e| io_errno(&e))?;
                offset = offset.saturating_add(u64::try_from(part.len()).unwrap_or(u64::MAX));
            }
        }
        Ok(path)
    }

    fn handle(&self, file: File, anchor: Link, writable: bool) -> u64 {
        let fh = self.next_handle.fetch_add(1, Ordering::Relaxed);
        if writable {
            self.committer.writing(&anchor, true);
        }
        self.handles().insert(fh, Handle { file, anchor, writable });
        fh
    }

    /// Open a file, to write if `write`: what's written goes to a copy of
    /// it in its anchor's work directory. Returns a handle, or 0 for what's
    /// read straight from the soup.
    pub fn open(&self, ino: u64, write: bool, truncate: bool) -> Result<u64, Errno> {
        if !write {
            if let Inode::Path(anchor, rel) = self.inode(ino)?
                && let Some(path) = self.work_path(&anchor, &rel)
                && let Ok(file) = File::open(path)
            {
                return Ok(self.handle(file, anchor, false));
            }
            return Ok(0);
        }
        let (anchor, rel) = self.overlay_of(ino)?;
        let catalog = self.catalog()?;
        let path = self.materialize(&catalog, &anchor, &rel, truncate)?;
        let file = File::options().read(true).write(true).open(path).map_err(|e| io_errno(&e))?;
        if truncate {
            self.committer.touched(&anchor);
        }
        Ok(self.handle(file, anchor, true))
    }

    /// Read from an open file, if it's one with a handle.
    pub fn read_handle(&self, fh: u64, offset: u64, size: usize) -> Option<Result<Vec<u8>, Errno>> {
        let handles = self.handles();
        let read = handles.get(&fh).map(|handle| super::read_file(&handle.file, offset, size));
        drop(handles);
        read
    }

    /// Write to an open file.
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<usize, Errno> {
        let handles = self.handles();
        let handle = handles.get(&fh).filter(|handle| handle.writable).ok_or(Errno::EBADF)?;
        let written = handle.file.write_all_at(data, offset);
        let anchor = handle.anchor.clone();
        drop(handles);
        written.map_err(|e| io_errno(&e))?;
        self.committer.touched(&anchor);
        Ok(data.len())
    }

    /// Close a file.
    pub fn release(&self, fh: u64) {
        if let Some(handle) = self.handles().remove(&fh)
            && handle.writable
        {
            self.committer.writing(&handle.anchor, false);
            self.committer.touched(&handle.anchor);
        }
    }

    /// Make a file, open to write.
    pub fn create(&self, parent: u64, name: &OsStr) -> Result<(FileAttr, u64), Errno> {
        let (anchor, rel) = self.overlay_of(parent)?;
        let rel = rel.join(name);
        let catalog = self.catalog()?;
        self.prepare(&catalog, &anchor)?;
        let path = self.work_path(&anchor, &rel).ok_or(Errno::EROFS)?;
        Self::parents(&path)?;
        let file = File::options().read(true).write(true).create(true).truncate(true).open(&path).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        let fh = self.handle(file, anchor, true);
        Ok((self.resolve(parent, name)?, fh))
    }

    /// Make a directory.
    pub fn mkdir(&self, parent: u64, name: &OsStr) -> Result<FileAttr, Errno> {
        let (anchor, rel) = self.overlay_of(parent)?;
        let catalog = self.catalog()?;
        self.prepare(&catalog, &anchor)?;
        fs::create_dir_all(self.work_path(&anchor, &rel.join(name)).ok_or(Errno::EROFS)?).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        self.resolve(parent, name)
    }

    /// Make a symlink.
    pub fn symlink(&self, parent: u64, name: &OsStr, target: &Path) -> Result<FileAttr, Errno> {
        let (anchor, rel) = self.overlay_of(parent)?;
        let catalog = self.catalog()?;
        self.prepare(&catalog, &anchor)?;
        let path = self.work_path(&anchor, &rel.join(name)).ok_or(Errno::EROFS)?;
        Self::parents(&path)?;
        std::os::unix::fs::symlink(target, path).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        self.resolve(parent, name)
    }

    /// Mark a path gone if the anchor had anything there, else forget its
    /// marks.
    fn gone(&self, catalog: &Catalog, anchor: &Link, rel: &Path) -> Result<(), Errno> {
        catalog.clear_overlay_marks(anchor, rel).map_err(store_errno)?;
        if self.base_at(catalog, anchor, rel)?.is_some() {
            catalog.set_overlay_mark(anchor, rel, &None).map_err(store_errno)?;
        }
        Ok(())
    }

    /// Remove a file or symlink.
    pub fn unlink(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        let (anchor, rel) = self.overlay_of(parent)?;
        let rel = rel.join(name);
        let catalog = self.catalog()?;
        match self.at(&catalog, &anchor, &rel)?.ok_or(Errno::ENOENT)? {
            At::Work(meta) if meta.is_dir() => return Err(Errno::EISDIR),
            At::Work(_) => fs::remove_file(self.work_path(&anchor, &rel).ok_or(Errno::EROFS)?).map_err(|e| io_errno(&e))?,
            At::Base(..) => {},
        }
        self.prepare(&catalog, &anchor)?;
        self.gone(&catalog, &anchor, &rel)?;
        drop(catalog);
        self.committer.touched(&anchor);
        Ok(())
    }

    /// Remove an empty directory.
    pub fn rmdir(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        let (anchor, rel) = self.overlay_of(parent)?;
        let rel = rel.join(name);
        let catalog = self.catalog()?;
        if self.kind(&catalog, &Inode::Path(anchor.clone(), rel.clone()))? != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if !self.overlay_entries(&catalog, &anchor, &rel)?.is_empty() {
            return Err(Errno::ENOTEMPTY);
        }
        if let Some(path) = self.work_path(&anchor, &rel)
            && path.is_dir()
        {
            fs::remove_dir(path).map_err(|e| io_errno(&e))?;
        }
        self.prepare(&catalog, &anchor)?;
        self.gone(&catalog, &anchor, &rel)?;
        drop(catalog);
        self.committer.touched(&anchor);
        Ok(())
    }

    /// Rename within an anchor: what's in the work directory moves there,
    /// and what the anchor had moves by marks, copying nothing.
    pub fn rename(&self, parent: u64, name: &OsStr, new_parent: u64, new_name: &OsStr, no_replace: bool) -> Result<(), Errno> {
        let (anchor, from) = self.overlay_of(parent)?;
        let (other, to) = self.overlay_of(new_parent)?;
        if anchor != other {
            return Err(Errno::EXDEV);
        }
        let (from, to) = (from.join(name), to.join(new_name));
        if from == to {
            return Ok(());
        }
        if to.starts_with(&from) {
            return Err(Errno::EINVAL);
        }
        let catalog = self.catalog()?;
        let source = self.kind(&catalog, &Inode::Path(anchor.clone(), from.clone()))?;
        if self.at(&catalog, &anchor, &to)?.is_some() {
            if no_replace {
                return Err(Errno::EEXIST);
            }
            let replaced = self.kind(&catalog, &Inode::Path(anchor.clone(), to.clone()))?;
            match (source == Kind::Directory, replaced == Kind::Directory) {
                (false, true) => return Err(Errno::EISDIR),
                (true, false) => return Err(Errno::ENOTDIR),
                (true, true) if !self.overlay_entries(&catalog, &anchor, &to)?.is_empty() => return Err(Errno::ENOTEMPTY),
                _ => {},
            }
        }
        self.prepare(&catalog, &anchor)?;
        let base = self.base_at(&catalog, &anchor, &from)?;
        let (work_from, work_to) = (self.work_path(&anchor, &from).ok_or(Errno::EROFS)?, self.work_path(&anchor, &to).ok_or(Errno::EROFS)?);
        // What's replaced goes first
        match fs::symlink_metadata(&work_to) {
            Ok(meta) if meta.is_dir() => fs::remove_dir(&work_to).map_err(|e| io_errno(&e))?,
            Ok(_) => fs::remove_file(&work_to).map_err(|e| io_errno(&e))?,
            Err(_) => {},
        }
        catalog.clear_overlay_marks(&anchor, &to).map_err(store_errno)?;
        if fs::symlink_metadata(&work_from).is_ok() {
            Self::parents(&work_to)?;
            fs::rename(&work_from, &work_to).map_err(|e| io_errno(&e))?;
        }
        catalog.move_overlay_marks(&anchor, &from, &to).map_err(store_errno)?;
        // It's exactly what was there: what the anchor had, or nothing
        let mark = base.map(|(cid, size)| (cid, size.unwrap_or_default()));
        catalog.set_overlay_mark(&anchor, &to, &mark).map_err(store_errno)?;
        if self.base_at(&catalog, &anchor, &from)?.is_some() {
            catalog.set_overlay_mark(&anchor, &from, &None).map_err(store_errno)?;
        }
        drop(catalog);
        self.inodes().renamed(&anchor, &from, &to);
        self.committer.touched(&anchor);
        Ok(())
    }

    /// Change a file's size: copying it to the work directory, if it isn't
    /// there yet.
    pub fn truncate(&self, ino: u64, fh: Option<u64>, size: u64) -> Result<(), Errno> {
        if let Some(fh) = fh {
            let handles = self.handles();
            if let Some(handle) = handles.get(&fh).filter(|handle| handle.writable) {
                handle.file.set_len(size).map_err(|e| io_errno(&e))?;
                self.committer.touched(&handle.anchor);
                return Ok(());
            }
        }
        let (anchor, rel) = self.overlay_of(ino)?;
        let catalog = self.catalog()?;
        let path = self.materialize(&catalog, &anchor, &rel, size == 0)?;
        File::options().write(true).open(path).and_then(|file| file.set_len(size)).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        Ok(())
    }

    /// Commit everything written now, rather than once it settles.
    pub fn commit(&self) {
        match (self.open)() {
            Ok(mut catalog) => self.committer.commit(&mut catalog, true),
            Err(e) => eprintln!("not committing: {e}"),
        }
    }

    /// Start committing as what's written settles, having committed what
    /// was written before.
    pub fn start(&self) {
        if self.work.is_some() {
            self.committer.recover();
            Arc::clone(&self.committer).run();
        }
    }

    /// Stop, committing everything written.
    pub fn finish(&self) {
        if self.work.is_some() {
            self.committer.finish();
        }
    }
}
