//! Writing to anchors: their overlays, and committing them.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fuser::{Errno, FileAttr};

use crate::cid::CidRef as _;
use crate::export::{self, Kind};
use crate::model::Link;
use crate::store::overlay::{CHUNK, Partial};
use crate::store::{Catalog, Mount};

use super::{At, Inode, Soup, Source, errno, store_errno};

/// An empty UnixFS directory, as dag-pb.
const EMPTY_DIR: &[u8] = &[0x0a, 0x02, 0x08, 0x01];

/// How long an anchor's left quiet, nothing of it open to write, before
/// what's been written is committed: long enough for an editor's save,
/// which writes, renames and removes in a burst, to be one.
const QUIET: Duration = Duration::from_secs(1);

/// How often the committer looks.
const TICK: Duration = Duration::from_millis(250);

/// How many chunks of partial files are filled each tick, in the
/// background: what's read and written is filled as it is.
const FILLS: usize = 8;

/// A file open: in an anchor's work directory, and whether it's open to
/// write.
pub struct Handle {
    file: File,
    /// The anchor it's of, or none for a loose file.
    anchor: Option<Link>,
    /// Its path within the anchor.
    rel: PathBuf,
    writable: bool,
}

/// Copies files of overlays from what their anchors had as they're read
/// and written, and the rest in the background, so a big file opened to
/// write needn't be copied before it can be.
pub struct Filler {
    work: Option<PathBuf>,
    fetcher: Option<Arc<super::Fetcher>>,
    partials: Mutex<HashMap<(Vec<u8>, PathBuf), Partial>>,
}

impl Filler {
    pub fn new(work: Option<PathBuf>, fetcher: Option<Arc<super::Fetcher>>) -> Self {
        Self { work, fetcher, partials: Mutex::new(HashMap::new()) }
    }

    fn partials(&self) -> std::sync::MutexGuard<'_, HashMap<(Vec<u8>, PathBuf), Partial>> {
        self.partials.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take up where a mount before left off.
    fn load(&self, catalog: &Catalog) {
        let mut partials = self.partials();
        for partial in catalog.partials().unwrap_or_default() {
            partials.insert((partial.anchor.to_bytes(), partial.path.clone()), partial);
        }
    }

    /// A file to fill as it's read and written.
    fn add(&self, catalog: &Catalog, partial: Partial) -> io::Result<()> {
        catalog.set_partial(&partial).map_err(io::Error::other)?;
        self.partials().insert((partial.anchor.to_bytes(), partial.path.clone()), partial);
        Ok(())
    }

    /// Fill the chunks a range of a file is in, if it's partial, so it can
    /// be read or written. Chunks that `writing` will wholly overwrite are
    /// only marked filled.
    pub fn fill(&self, catalog: &Catalog, anchor: &Link, rel: &Path, offset: u64, size: usize, writing: Option<(u64, u64)>) -> io::Result<()> {
        let key = (anchor.to_bytes(), rel.to_path_buf());
        let mut partials = self.partials();
        let Some(partial) = partials.get_mut(&key) else {
            return Ok(());
        };
        let chunks: Vec<u64> = partial.unfilled(offset, u64::try_from(size).unwrap_or(u64::MAX)).collect();
        for chunk in chunks {
            self.fill_chunk(catalog, partial, chunk, writing)?;
        }
        if partial.next_unfilled().is_none() {
            catalog.remove_partial(anchor, rel).map_err(io::Error::other)?;
            partials.remove(&key);
        }
        drop(partials);
        Ok(())
    }

    /// Fill one chunk of a partial file from what it's copied from, then
    /// mark it, before anything's written to it.
    fn fill_chunk(&self, catalog: &Catalog, partial: &mut Partial, chunk: u64, writing: Option<(u64, u64)>) -> io::Result<()> {
        let start = chunk.saturating_mul(CHUNK);
        let end = start.saturating_add(CHUNK).min(partial.len);
        let overwritten = writing.is_some_and(|(at, len)| at <= start && at.saturating_add(len) >= end);
        if !overwritten {
            let work = self.work.as_ref().ok_or_else(|| io::Error::other("not writable"))?;
            let source = Source { catalog, fetcher: self.fetcher.as_deref() };
            let data = export::read_at(&source, &partial.base, start, usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX))?;
            File::options().write(true).open(super::work_path(work, &partial.anchor, &partial.path))?.write_all_at(&data, start)?;
        }
        partial.fill(chunk);
        catalog.set_partial(partial).map_err(io::Error::other)
    }

    /// Fill some of whatever's partial, a chunk at a time. Returns whether
    /// there was any.
    fn step(&self, catalog: &Catalog, chunks: usize) -> bool {
        for _ in 0..chunks {
            let next = self.partials().iter().find_map(|(_, partial)| partial.next_unfilled().map(|chunk| (partial.anchor.clone(), partial.path.clone(), chunk)));
            let Some((anchor, rel, chunk)) = next else {
                return false;
            };
            let offset = chunk.saturating_mul(CHUNK);
            if let Err(e) = self.fill(catalog, &anchor, &rel, offset, 1, None) {
                eprintln!("couldn't copy {} of {anchor} yet: {e}", rel.display());
                return true;
            }
        }
        true
    }

    /// Fill everything partial of an anchor, as it's to be committed.
    fn complete(&self, catalog: &Catalog, anchor: &Link) -> io::Result<()> {
        let files: Vec<(PathBuf, u64)> = self.partials().values().filter(|partial| &partial.anchor == anchor).map(|partial| (partial.path.clone(), partial.len)).collect();
        for (rel, len) in files {
            self.fill(catalog, anchor, &rel, 0, usize::try_from(len).unwrap_or(usize::MAX), None)?;
        }
        Ok(())
    }

    /// A partial file cut short: what's past `len` isn't wanted, but the
    /// chunk `len` is in is filled first, keeping what's before it.
    fn cut(&self, catalog: &Catalog, anchor: &Link, rel: &Path, len: u64) -> io::Result<()> {
        self.fill(catalog, anchor, rel, len, 1, None)?;
        let key = (anchor.to_bytes(), rel.to_path_buf());
        let mut partials = self.partials();
        if let Some(partial) = partials.get_mut(&key) {
            partial.cut(len);
            if partial.next_unfilled().is_none() {
                catalog.remove_partial(anchor, rel).map_err(io::Error::other)?;
                partials.remove(&key);
            } else {
                catalog.set_partial(partial).map_err(io::Error::other)?;
            }
        }
        drop(partials);
        Ok(())
    }

    /// Partial files at a path and under it renamed, or gone.
    fn moved(&self, catalog: &Catalog, anchor: &Link, from: &Path, to: Option<&Path>) -> io::Result<()> {
        let mut partials = self.partials();
        let keys: Vec<_> = partials.keys().filter(|(at, rel)| *at == anchor.to_bytes() && rel.starts_with(from)).cloned().collect();
        for key in keys {
            let Some(mut partial) = partials.remove(&key) else {
                continue;
            };
            catalog.remove_partial(anchor, &partial.path).map_err(io::Error::other)?;
            if let Some(to) = to {
                let rest = partial.path.strip_prefix(from).map(Path::to_path_buf).unwrap_or_default();
                partial.path = if rest.as_os_str().is_empty() { to.to_path_buf() } else { to.join(rest) };
                catalog.set_partial(&partial).map_err(io::Error::other)?;
                partials.insert((anchor.to_bytes(), partial.path.clone()), partial);
            }
        }
        drop(partials);
        Ok(())
    }
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
    filler: Arc<Filler>,
    pending: Mutex<Pending>,
    stop: AtomicBool,
}

impl Committer {
    pub fn new(open: Arc<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync>, filler: Arc<Filler>) -> Self {
        Self { open, filler, pending: Mutex::new(Pending::default()), stop: AtomicBool::new(false) }
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
            // What's partial is filled first, so nothing's imported with holes
            if let Err(e) = self.filler.complete(catalog, &anchor) {
                eprintln!("{anchor} couldn't be committed, not all of it having been copied: {e}");
                self.touched(&anchor);
                continue;
            }
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
                self.filler.load(&catalog);
                for mount in catalog.mounts().unwrap_or_default().into_iter().filter(|mount| mount.overlay) {
                    if let Err(e) = self.filler.complete(&catalog, &mount.anchor) {
                        eprintln!("{} couldn't be committed, not all of it having been copied: {e}", mount.anchor);
                        continue;
                    }
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
                if self.pending().dirty.is_empty() && self.filler.partials().is_empty() {
                    continue;
                }
                if catalog.is_none() {
                    catalog = (self.open)().map_err(|e| eprintln!("not committing yet: {e}")).ok();
                }
                if let Some(catalog) = &mut catalog {
                    self.filler.step(catalog, FILLS);
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
            Inode::Root if self.work.is_some() => Ok((Self::root(&*self.catalog()?)?.ok_or(Errno::EROFS)?, PathBuf::new())),
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
                self.filler.cut(catalog, anchor, rel, 0).map_err(|e| io_errno(&e))?;
                File::options().write(true).truncate(true).open(&path).map_err(|e| io_errno(&e))?;
            }
            return Ok(path);
        }
        let (cid, _) = self.base_at(catalog, anchor, rel)?.ok_or(Errno::ENOENT)?;
        let size = if truncate {
            0
        } else {
            match export::stat(&Source { catalog, fetcher: self.fetcher.as_deref() }, &cid).map_err(|e| errno(&e))? {
                Kind::File(size) => size,
                Kind::Directory => return Err(Errno::EISDIR),
                Kind::Symlink(_) => return Err(Errno::EINVAL),
            }
        };
        Self::parents(&path)?;
        // As big as it is, its chunks copied as they're read and written,
        // and the rest in the background
        File::create_new(&path).and_then(|file| file.set_len(size)).map_err(|e| io_errno(&e))?;
        if size > 0 {
            self.filler.add(catalog, Partial::new(anchor.clone(), rel.to_path_buf(), cid, size)).map_err(|e| io_errno(&e))?;
        }
        Ok(path)
    }

    fn handle(&self, file: File, anchor: Option<Link>, rel: PathBuf, writable: bool) -> u64 {
        let fh = self.next_handle.fetch_add(1, Ordering::Relaxed);
        if writable && let Some(anchor) = &anchor {
            self.committer.writing(anchor, true);
        }
        self.handles().insert(fh, Handle { file, anchor, rel, writable });
        fh
    }

    /// Open a file, to write if `write`: what's written goes to a copy of
    /// it in its anchor's work directory. Returns a handle, or 0 for what's
    /// read straight from the soup.
    pub fn open(&self, ino: u64, write: bool, truncate: bool) -> Result<u64, Errno> {
        if let Inode::Loose(name) = self.inode(ino)? {
            let path = self.loose_path(&name).ok_or(Errno::ENOENT)?;
            let file = File::options().read(true).write(write).truncate(truncate).open(path).map_err(|e| io_errno(&e))?;
            return Ok(self.handle(file, None, PathBuf::new(), write));
        }
        if !write {
            if let Inode::Path(anchor, rel) = self.inode(ino)?
                && let Some(path) = self.work_path(&anchor, &rel)
                && let Ok(file) = File::open(path)
            {
                return Ok(self.handle(file, Some(anchor), rel, false));
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
        Ok(self.handle(file, Some(anchor), rel, true))
    }

    /// Read from an open file, if it's one with a handle.
    pub fn read_handle(&self, fh: u64, offset: u64, size: usize) -> Option<Result<Vec<u8>, Errno>> {
        let handles = self.handles();
        let handle = handles.get(&fh)?;
        let filled = handle.anchor.as_ref().map_or(Ok(()), |anchor| {
            self.catalog().and_then(|catalog| self.filler.fill(&catalog, anchor, &handle.rel, offset, size, None).map_err(|e| errno(&e)))
        });
        let read = filled.and_then(|()| super::read_file(&handle.file, offset, size));
        drop(handles);
        Some(read)
    }

    /// Write to an open file.
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<usize, Errno> {
        let handles = self.handles();
        let handle = handles.get(&fh).filter(|handle| handle.writable).ok_or(Errno::EBADF)?;
        if let Some(anchor) = &handle.anchor {
            let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
            self.filler.fill(&*self.catalog()?, anchor, &handle.rel, offset, data.len(), Some((offset, len))).map_err(|e| errno(&e))?;
        }
        let written = handle.file.write_all_at(data, offset);
        let anchor = handle.anchor.clone();
        drop(handles);
        written.map_err(|e| io_errno(&e))?;
        if let Some(anchor) = anchor {
            self.committer.touched(&anchor);
        }
        Ok(data.len())
    }

    /// Close a file.
    pub fn release(&self, fh: u64) {
        if let Some(handle) = self.handles().remove(&fh)
            && handle.writable
            && let Some(anchor) = handle.anchor
        {
            self.committer.writing(&anchor, false);
            self.committer.touched(&anchor);
        }
    }

    /// Make a file, open to write.
    pub fn create(&self, parent: u64, name: &OsStr) -> Result<(FileAttr, u64), Errno> {
        if self.inode(parent)? == Inode::Anchors {
            // Not an anchor: a loose file, as an editor writes beside a file
            // anchor to rename over it
            let path = self.loose_path(name.as_bytes()).ok_or(Errno::EROFS)?;
            Self::parents(&path)?;
            let file = File::options().read(true).write(true).create(true).truncate(true).open(&path).map_err(|e| io_errno(&e))?;
            let fh = self.handle(file, None, PathBuf::new(), true);
            return Ok((self.resolve(parent, name)?, fh));
        }
        let (anchor, rel) = self.overlay_of(parent)?;
        let rel = rel.join(name);
        let catalog = self.catalog()?;
        self.prepare(&catalog, &anchor)?;
        let path = self.work_path(&anchor, &rel).ok_or(Errno::EROFS)?;
        Self::parents(&path)?;
        let file = File::options().read(true).write(true).create(true).truncate(true).open(&path).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        let fh = self.handle(file, Some(anchor), rel, true);
        Ok((self.resolve(parent, name)?, fh))
    }

    /// Make a directory: at the top, a new anchor, which the root anchor
    /// names.
    pub fn mkdir(&self, parent: u64, name: &OsStr) -> Result<FileAttr, Errno> {
        if self.inode(parent)? == Inode::Root {
            return self.name_new_anchor(name);
        }
        let (anchor, rel) = self.overlay_of(parent)?;
        let catalog = self.catalog()?;
        self.prepare(&catalog, &anchor)?;
        fs::create_dir_all(self.work_path(&anchor, &rel.join(name)).ok_or(Errno::EROFS)?).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        self.resolve(parent, name)
    }

    /// A new anchor, an empty directory, named at the top.
    fn name_new_anchor(&self, name: &OsStr) -> Result<FileAttr, Errno> {
        use crate::cid::CidVersion;
        let (root, _) = self.overlay_of(super::ROOT)?;
        if super::TOP.iter().any(|(top, _)| OsStr::new(top) == name) {
            return Err(Errno::EEXIST);
        }
        let catalog = self.catalog()?;
        if self.at(&catalog, &root, Path::new(name))?.is_some() {
            return Err(Errno::EEXIST);
        }
        let empty: crate::block::Block = crate::block::Block::hash(
            crate::cid::Cidv1Spec::new(crate::cid::DAG_PB_CODEC, crate::multihash::MultihashFunc::Sha2_256),
            EMPTY_DIR.into(),
        );
        catalog.put_block(&empty, CidVersion::V1).map_err(store_errno)?;
        let anchor = catalog.new_anchor().map_err(store_errno)?;
        catalog.set_anchor(&anchor, &empty.cid().clone().into()).map_err(store_errno)?;
        drop(catalog);
        self.symlink(super::ROOT, name, &Path::new("/anchors").join(anchor.to_string()))?;
        // What mkdir makes must be a directory, so it's the anchor's, as
        // the name's taken to be until the kernel looks it up again
        self.resolve(super::ANCHORS, OsStr::new(&anchor.to_string()))
    }

    /// Make a symlink.
    pub fn symlink(&self, parent: u64, name: &OsStr, target: &Path) -> Result<FileAttr, Errno> {
        let (anchor, rel) = self.overlay_of(parent)?;
        let catalog = self.catalog()?;
        self.prepare(&catalog, &anchor)?;
        let path = self.work_path(&anchor, &rel.join(name)).ok_or(Errno::EROFS)?;
        Self::parents(&path)?;
        std::os::unix::fs::symlink(self.stored(&catalog, target)?, path).map_err(|e| io_errno(&e))?;
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
        if self.inode(parent)? == Inode::Anchors {
            let path = self.loose_path(name.as_bytes()).filter(|path| path.exists()).ok_or(Errno::EPERM)?;
            return fs::remove_file(path).map_err(|e| io_errno(&e));
        }
        let (anchor, rel) = self.overlay_of(parent)?;
        let rel = rel.join(name);
        let catalog = self.catalog()?;
        match self.at(&catalog, &anchor, &rel)?.ok_or(Errno::ENOENT)? {
            At::Work(meta) if meta.is_dir() => return Err(Errno::EISDIR),
            At::Work(_) => {
                self.filler.moved(&catalog, &anchor, &rel, None).map_err(|e| io_errno(&e))?;
                fs::remove_file(self.work_path(&anchor, &rel).ok_or(Errno::EROFS)?).map_err(|e| io_errno(&e))?;
            },
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
        if self.inode(parent)? == Inode::Anchors || self.inode(new_parent)? == Inode::Anchors {
            return self.rename_loose(parent, name, new_parent, new_name, no_replace);
        }
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
        self.filler.moved(&catalog, &anchor, &to, None).map_err(|e| io_errno(&e))?;
        match fs::symlink_metadata(&work_to) {
            Ok(meta) if meta.is_dir() => fs::remove_dir(&work_to).map_err(|e| io_errno(&e))?,
            Ok(_) => fs::remove_file(&work_to).map_err(|e| io_errno(&e))?,
            Err(_) => {},
        }
        catalog.clear_overlay_marks(&anchor, &to).map_err(store_errno)?;
        if fs::symlink_metadata(&work_from).is_ok() {
            Self::parents(&work_to)?;
            fs::rename(&work_from, &work_to).map_err(|e| io_errno(&e))?;
            self.filler.moved(&catalog, &anchor, &from, Some(&to)).map_err(|e| io_errno(&e))?;
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

    /// Where a loose file of `anchors/` is kept.
    pub(super) fn loose_path(&self, name: &[u8]) -> Option<PathBuf> {
        Some(self.work.as_ref()?.join(".loose").join(OsStr::from_bytes(name)))
    }

    /// The loose files of `anchors/`.
    pub(super) fn loose(&self) -> Vec<Vec<u8>> {
        self.work.as_ref()
            .and_then(|work| fs::read_dir(work.join(".loose")).ok())
            .map(|dir| dir.flatten().map(|entry| entry.file_name().as_bytes().to_vec()).collect())
            .unwrap_or_default()
    }

    /// Rename in `anchors/`: a loose file to another name, or over a file
    /// anchor, which is then what it is, as an editor saves. Anchors
    /// themselves don't move.
    fn rename_loose(&self, parent: u64, name: &OsStr, new_parent: u64, new_name: &OsStr, no_replace: bool) -> Result<(), Errno> {
        if self.inode(parent)? != Inode::Anchors || self.inode(new_parent)? != Inode::Anchors {
            return Err(Errno::EXDEV);
        }
        let from = self.loose_path(name.as_bytes()).filter(|path| path.exists()).ok_or(Errno::EPERM)?;
        let replaced = self.resolve(new_parent, new_name).ok().map(|attr| attr.ino.0);
        if no_replace && replaced.is_some() {
            return Err(Errno::EEXIST);
        }
        if let Some(Inode::Path(anchor, rel)) = replaced.map(|ino| self.inode(ino)).transpose()? {
            if self.kind(&*self.catalog()?, &Inode::Path(anchor.clone(), rel.clone()))? == Kind::Directory {
                return Err(Errno::EISDIR);
            }
            let catalog = self.catalog()?;
            let to = self.prepare(&catalog, &anchor)?;
            self.filler.moved(&catalog, &anchor, &rel, None).map_err(|e| io_errno(&e))?;
            drop(catalog);
            Self::parents(&to)?;
            fs::rename(&from, &to).map_err(|e| io_errno(&e))?;
            self.inodes().became(&Inode::Loose(name.as_bytes().to_vec()), Inode::Path(anchor.clone(), rel));
            self.committer.touched(&anchor);
        } else {
            let to = self.loose_path(new_name.as_bytes()).ok_or(Errno::EROFS)?;
            fs::rename(&from, &to).map_err(|e| io_errno(&e))?;
            self.inodes().became(&Inode::Loose(name.as_bytes().to_vec()), Inode::Loose(new_name.as_bytes().to_vec()));
        }
        Ok(())
    }

    /// Change a file's size: copying it to the work directory, if it isn't
    /// there yet.
    pub fn truncate(&self, ino: u64, fh: Option<u64>, size: u64) -> Result<(), Errno> {
        if let Some(fh) = fh {
            let handles = self.handles();
            if let Some(handle) = handles.get(&fh).filter(|handle| handle.writable) {
                if let Some(anchor) = &handle.anchor {
                    self.filler.cut(&*self.catalog()?, anchor, &handle.rel, size).map_err(|e| io_errno(&e))?;
                }
                handle.file.set_len(size).map_err(|e| io_errno(&e))?;
                if let Some(anchor) = &handle.anchor {
                    self.committer.touched(anchor);
                }
                return Ok(());
            }
        }
        if let Inode::Loose(name) = self.inode(ino)? {
            let path = self.loose_path(&name).ok_or(Errno::EROFS)?;
            return File::options().write(true).open(path).and_then(|file| file.set_len(size)).map_err(|e| io_errno(&e));
        }
        let (anchor, rel) = self.overlay_of(ino)?;
        let catalog = self.catalog()?;
        let path = self.materialize(&catalog, &anchor, &rel, size == 0)?;
        self.filler.cut(&catalog, &anchor, &rel, size).map_err(|e| io_errno(&e))?;
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
