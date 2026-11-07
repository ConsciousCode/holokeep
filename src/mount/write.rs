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

use super::{At, Inode, Inodes, Soup, errno, store_errno, to_anchor};

/// An empty UnixFS directory, as dag-pb.
const EMPTY_DIR: &[u8] = &[0x0a, 0x02, 0x08, 0x01];

/// How long an anchor's left quiet, nothing of it open to write, before
/// what's been written is committed: long enough for an editor's save,
/// which writes, renames and removes in a burst, to be one.
const QUIET: Duration = Duration::from_secs(1);

/// How often the committer looks.
const TICK: Duration = Duration::from_millis(250);

/// How many times a commit fetches what it found missing and tries
/// again, before it's left to the next tick: a level of a deep tree each.
const FETCH_ROUNDS: usize = 64;

/// How many chunks of partial files are filled each tick, in the
/// background: what's read and written is filled as it is.
const FILLS: usize = 8;

/// A file open: in an anchor's work directory, and whether it's open to
/// write.
pub struct Handle {
    file: Arc<File>,
    /// The anchor it's of, or none for a loose file.
    anchor: Option<Link>,
    /// Its path within the anchor, wherever it's since been moved. A file
    /// replaced or removed is of no anchor any more, and has no path.
    rel: PathBuf,
    writable: bool,
    /// Whether it's been written to since it was last synced or opened.
    unsynced: bool,
    /// What's left to copy of a partial file replaced or removed, which
    /// only those who have it open can reach.
    orphan: Option<SharedPartial>,
}

/// What's needed of an open file to use it.
struct Opened {
    file: Arc<File>,
    anchor: Option<Link>,
    rel: PathBuf,
    writable: bool,
    orphan: Option<SharedPartial>,
}

impl Opened {
    /// Whether it's still where this says, so what was done by that holds.
    fn is_at(&self, now: &Self) -> bool {
        self.anchor == now.anchor && self.rel == now.rel && self.orphan.is_some() == now.orphan.is_some()
    }
}

impl Handle {
    /// Written to: the anchor it's of, if that makes it unsynced.
    fn written(&mut self) -> Option<&Link> {
        let was = std::mem::replace(&mut self.unsynced, true);
        self.anchor.as_ref().filter(|_| !was)
    }

    /// Synced, or closed: the anchor it's of, if it was unsynced.
    fn settled(&mut self) -> Option<&Link> {
        let was = std::mem::replace(&mut self.unsynced, false);
        self.anchor.as_ref().filter(|_| was)
    }
}

/// Copies files of overlays from what their anchors had as they're read
/// and written, and the rest in the background, so a big file opened to
/// write needn't be copied before it can be.
pub struct Filler {
    work: Option<PathBuf>,
    /// Each file's locked by itself while it's filled, which may mean
    /// fetching it, or waiting for the database, so that isn't what anything
    /// else waits for.
    partials: Mutex<Partials>,
}

/// Partial files, by the anchor they're of and their paths.
type Partials = HashMap<(Vec<u8>, PathBuf), SharedPartial>;

/// A partial file, locked by itself.
type SharedPartial = Arc<Mutex<Partial>>;

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Filler {
    /// Filling files in work directories under `work`, from catalogs which
    /// fetch what isn't here.
    pub fn new(work: Option<PathBuf>) -> Self {
        Self { work, partials: Mutex::new(HashMap::new()) }
    }

    fn partials(&self) -> std::sync::MutexGuard<'_, Partials> {
        locked(&self.partials)
    }

    /// Take up where a mount before left off. A file that was never made
    /// was never written to, so there's nothing to fill.
    pub(super) fn load(&self, catalog: &Catalog) {
        for partial in catalog.partials().unwrap_or_default() {
            let made = self.work.as_ref().is_none_or(|work| fs::symlink_metadata(super::work_path(work, &partial.anchor, &partial.path)).is_ok());
            if !made {
                if let Err(e) = catalog.remove_partial(&partial.anchor, &partial.path) {
                    eprintln!("{} of {} was never made, but is still said to be: {e}", partial.path.display(), partial.anchor);
                }
                continue;
            }
            self.partials().insert((partial.anchor.to_bytes(), partial.path.clone()), Arc::new(Mutex::new(partial)));
        }
    }

    /// A file to fill as it's read and written, which `make` makes. It's
    /// known to be partial before it's there: read in between, what the
    /// anchor had's read, and read after, it's filled first, not read full
    /// of holes.
    fn add(&self, catalog: &Catalog, partial: Partial, make: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let key = (partial.anchor.to_bytes(), partial.path.clone());
        let (anchor, path) = (partial.anchor.clone(), partial.path.clone());
        let shared = Arc::new(Mutex::new(partial));
        let held = locked(&shared);
        self.partials().insert(key.clone(), Arc::clone(&shared));
        let done = catalog.set_partial(&held).map_err(io::Error::other).and_then(|()| make());
        if done.is_err() {
            self.partials().remove(&key);
            let _ = catalog.remove_partial(&anchor, &path);
        }
        drop(held);
        done
    }

    /// Fill the chunks a range of a file is in, if it's partial, so it can
    /// be read or written. Chunks that `writing` will wholly overwrite are
    /// only marked filled.
    pub fn fill(&self, catalog: &Catalog, anchor: &Link, rel: &Path, offset: u64, size: usize, writing: Option<(u64, u64)>) -> io::Result<()> {
        let key = (anchor.to_bytes(), rel.to_path_buf());
        loop {
            let Some(shared) = self.partials().get(&key).cloned() else {
                return Ok(());
            };
            let mut partial = locked(&shared);
            // While waiting for it, it may have gone, or been replaced by
            // what was moved there
            if !self.partials().get(&key).is_some_and(|now| Arc::ptr_eq(now, &shared)) {
                continue;
            }
            let chunks: Vec<u64> = partial.unfilled(offset, u64::try_from(size).unwrap_or(u64::MAX)).collect();
            for chunk in chunks {
                self.fill_chunk(catalog, &mut partial, chunk, writing)?;
            }
            if partial.next_unfilled().is_none() {
                catalog.remove_partial(anchor, rel).map_err(io::Error::other)?;
                self.partials().remove(&key);
            }
            drop(partial);
            return Ok(());
        }
    }

    /// Fill one chunk of a partial file from what it's copied from, then
    /// mark it, before anything's written to it.
    fn fill_chunk(&self, catalog: &Catalog, partial: &mut Partial, chunk: u64, writing: Option<(u64, u64)>) -> io::Result<()> {
        let path = self.work.as_ref().map(|work| super::work_path(work, &partial.anchor, &partial.path));
        Self::copy_chunk(catalog, partial, chunk, writing, || {
            File::options().write(true).open(path.ok_or_else(|| io::Error::other("not writable"))?)
        })?;
        catalog.set_partial(partial).map_err(io::Error::other)
    }

    /// Copy one chunk into the file from what it's copied from, unless
    /// `writing` will wholly overwrite it, and mark it.
    fn copy_chunk(catalog: &Catalog, partial: &mut Partial, chunk: u64, writing: Option<(u64, u64)>, file: impl FnOnce() -> io::Result<File>) -> io::Result<()> {
        let start = chunk.saturating_mul(CHUNK);
        let end = start.saturating_add(CHUNK).min(partial.len);
        let overwritten = writing.is_some_and(|(at, len)| at <= start && at.saturating_add(len) >= end);
        if !overwritten {
            let data = export::read_at(catalog, &partial.base, start, usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX))?;
            file()?.write_all_at(&data, start)?;
        }
        partial.fill(chunk);
        Ok(())
    }

    /// As `fill`, for a file replaced or removed: it's at no path now, and
    /// nothing's kept of how far it's got, since it won't outlive the mount.
    fn fill_orphan(catalog: &Catalog, orphan: &SharedPartial, file: &File, offset: u64, size: usize, writing: Option<(u64, u64)>) -> io::Result<()> {
        let mut partial = locked(orphan);
        let chunks: Vec<u64> = partial.unfilled(offset, u64::try_from(size).unwrap_or(u64::MAX)).collect();
        for chunk in chunks {
            Self::copy_chunk(catalog, &mut partial, chunk, writing, || file.try_clone())?;
        }
        drop(partial);
        Ok(())
    }

    /// Fill some of whatever's partial, a chunk at a time, leaving what's
    /// being filled already. Returns whether there was any.
    fn step(&self, catalog: &Catalog, chunks: usize) -> bool {
        for _ in 0..chunks {
            let shared: Vec<SharedPartial> = self.partials().values().cloned().collect();
            let next = shared.iter().find_map(|partial| {
                let partial = partial.try_lock().ok()?;
                partial.next_unfilled().map(|chunk| (partial.anchor.clone(), partial.path.clone(), chunk))
            });
            let Some((anchor, rel, chunk)) = next else {
                return !shared.is_empty();
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
        let bytes = anchor.to_bytes();
        let shared: Vec<SharedPartial> = self.partials().iter().filter(|((of, _), _)| *of == bytes).map(|(_, partial)| Arc::clone(partial)).collect();
        for partial in shared {
            let (rel, len) = {
                let partial = locked(&partial);
                (partial.path.clone(), partial.len)
            };
            self.fill(catalog, anchor, &rel, 0, usize::try_from(len).unwrap_or(usize::MAX), None)?;
        }
        Ok(())
    }

    /// A partial file cut short: what's past `len` isn't wanted, but the
    /// chunk `len` is in is filled first, keeping what's before it.
    fn cut(&self, catalog: &Catalog, anchor: &Link, rel: &Path, len: u64) -> io::Result<()> {
        self.fill(catalog, anchor, rel, len, 1, None)?;
        let key = (anchor.to_bytes(), rel.to_path_buf());
        let Some(shared) = self.partials().get(&key).cloned() else {
            return Ok(());
        };
        let mut partial = locked(&shared);
        partial.cut(len);
        if partial.next_unfilled().is_none() {
            catalog.remove_partial(anchor, rel).map_err(io::Error::other)?;
            self.partials().remove(&key);
        } else {
            catalog.set_partial(&partial).map_err(io::Error::other)?;
        }
        drop(partial);
        Ok(())
    }

    /// Partial files at a path and under it renamed, or gone, with what
    /// `swap` does as the files move, what's going and coming held till it
    /// has, so nothing's filled from the wrong place. What was at `to` is
    /// forgotten, and with it nothing to fill.
    ///
    /// `retarget` is told what's forgotten, and to follow the rest, in the
    /// one moment the files are found where they've moved to: so whoever has
    /// looked for a file at where it was, not finding it, will find it's
    /// moved if it looks again. See `Soup::read_handle`.
    fn moving(&self, catalog: &Catalog, anchor: &Link, from: &Path, to: Option<&Path>, retarget: impl FnOnce(&[(PathBuf, SharedPartial)]), swap: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let bytes = anchor.to_bytes();
        let shared = {
            let partials = self.partials();
            let mut shared: Vec<_> = partials.iter()
                .filter(|((at, rel), _)| *at == bytes && (rel.starts_with(from) || to.is_some_and(|to| rel.starts_with(to))))
                .map(|(key, partial)| (key.clone(), Arc::clone(partial)))
                .collect();
            drop(partials);
            shared.sort_by(|(a, _), (b, _)| a.cmp(b));
            shared
        };
        let mut held: Vec<_> = shared.iter().map(|(key, partial)| (key, partial, locked(partial))).collect();
        let mut moved = Vec::new();
        let mut orphans = Vec::new();
        for (_, shared, partial) in &mut held {
            catalog.remove_partial(anchor, &partial.path).map_err(io::Error::other)?;
            let rest = to.and_then(|to| Some((to, partial.path.strip_prefix(from).ok()?.to_path_buf())));
            let Some((to, rest)) = rest else {
                orphans.push((partial.path.clone(), Arc::clone(shared)));
                continue;
            };
            partial.path = if rest.as_os_str().is_empty() { to.to_path_buf() } else { to.join(rest) };
            catalog.set_partial(partial).map_err(io::Error::other)?;
            moved.push(((bytes.clone(), partial.path.clone()), Arc::clone(shared)));
        }
        let mut partials = self.partials();
        for (key, _, _) in &held {
            partials.remove(*key);
        }
        partials.extend(moved);
        retarget(&orphans);
        drop(partials);
        let swapped = swap();
        drop(held);
        swapped
    }
}

/// How far apart an anchor's commits are kept, by how often it's been
/// written to: at first only [`QUIET`], then further apart, a step at a
/// time, the while it's written to again as soon as it's committed.
const PACES: [Duration; 5] = [
    Duration::ZERO,
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_mins(2),
    Duration::from_mins(10),
];

/// How many ticks apart to look for what's been set elsewhere, when nothing's
/// been written here: a second or so.
const RECONCILE: u32 = 4;

/// What a work directory's called once it's being let go of, whatever it was.
const DROPPED: &str = ".dropped-";

/// Remove what's left of a work directory being let go of, if there's any.
fn discard(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// How long what's written to an anchor without its ever being quiet waits
/// at most, at its pace's first step, before it's committed anyway.
const STALE: Duration = Duration::from_secs(5);

/// What's known of an anchor written to.
struct Written {
    anchor: Link,
    /// Since when, and when last, if it's written to and not committed.
    dirty: Option<(Instant, Instant)>,
    /// How many of its files are open and written to since they were
    /// synced: what's in them may be halfway through being written. An
    /// application syncs what it's written once it's whole, as a database
    /// does after each transaction; a file closed is whole.
    unsynced: usize,
    /// How many of its files are open to write, whether they've been or not:
    /// what's in the work directory can't be let go of under them.
    open: usize,
    /// How many times it's been written to, ever, to tell whether it was
    /// as it was committed.
    changes: u64,
    /// Which of [`PACES`] it's at.
    pace: usize,
    /// The least time between its commits, as the rules say of where it's
    /// mounted.
    floor: Duration,
    /// Whether it's due for being written to so long without being quiet.
    stale: bool,
    /// When it was last committed.
    committed: Option<Instant>,
}

impl Written {
    const fn new(anchor: Link) -> Self {
        Self { anchor, dirty: None, unsynced: 0, open: 0, changes: 0, pace: 0, floor: Duration::ZERO, stale: false, committed: None }
    }

    /// Whether what's written is due to be committed, at `now`: written
    /// to and whole (no file of it open and written to since synced), its
    /// pace's time since it was last committed, and quiet for a
    /// moment, or written to for long enough without being.
    fn due(&mut self, now: Instant) -> bool {
        let Some((since, last)) = self.dirty else {
            return false;
        };
        let pace = PACES.get(self.pace).copied().unwrap_or(Duration::MAX).max(self.floor);
        let whole = self.unsynced == 0;
        let paced = self.committed.is_none_or(|at| now.saturating_duration_since(at) >= pace);
        let quiet = now.saturating_duration_since(last) >= QUIET;
        let stale = now.saturating_duration_since(since) >= pace.max(STALE);
        self.stale = !quiet && stale;
        whole && paced && (quiet || stale)
    }

    /// Committed at `now`: soon after it was last, or for never being
    /// quiet, a step slower; long after, a step faster.
    fn committed(&mut self, now: Instant) {
        if let Some(at) = self.committed {
            let gap = now.saturating_duration_since(at);
            let pace = PACES.get(self.pace).copied().unwrap_or_default();
            if self.stale || gap < pace.saturating_mul(2).saturating_add(QUIET.saturating_mul(2)) {
                self.pace = self.pace.saturating_add(1).min(PACES.len().saturating_sub(1));
            } else if gap > pace.saturating_mul(10).saturating_add(Duration::from_mins(1)) {
                self.pace = self.pace.saturating_sub(1);
            }
        }
        self.committed = Some(now);
    }
}

/// Commits anchors once what's written to them settles, and is whole.
pub struct Committer {
    open: Arc<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync>,
    filler: Arc<Filler>,
    written: Mutex<HashMap<Vec<u8>, Written>>,
    /// Paths in work directories, and what's under them, known not to be
    /// imported in place since last committed, so needn't be kept before
    /// they're changed.
    fresh: Mutex<std::collections::HashSet<PathBuf>>,
    /// Parts of files written over, each to be kept as a delta on the
    /// part written over it: (older, newer).
    revisions: Mutex<Vec<(Link, Link)>>,
    /// Held by whatever changes anything, so changes happen one at a time,
    /// and so a commit can tell one isn't underway: nothing changes between
    /// its seeing nothing has, and what it's committed being known to have
    /// been imported in place. What only reads goes on beside it.
    writing: Mutex<()>,
    stop: AtomicBool,
}

impl Committer {
    pub fn new(open: Arc<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync>, filler: Arc<Filler>) -> Self {
        Self { open, filler, written: Mutex::new(HashMap::new()), fresh: Mutex::new(std::collections::HashSet::new()), revisions: Mutex::new(Vec::new()), writing: Mutex::new(()), stop: AtomicBool::new(false) }
    }

    pub(super) fn writing(&self) -> std::sync::MutexGuard<'_, ()> {
        locked(&self.writing)
    }

    fn revisions(&self) -> std::sync::MutexGuard<'_, Vec<(Link, Link)>> {
        self.revisions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keep each older part of a file as a delta on the newer one written
    /// over it, where they're kept so it can be. Best done off the thread
    /// writing, since it reads and encodes each.
    fn revise(&self, catalog: &Catalog) {
        let revisions = std::mem::take(&mut *self.revisions());
        for (older, newer) in revisions {
            if let Err(e) = catalog.revise(&older, &newer) {
                eprintln!("{older} is kept whole, not as a delta on {newer}: {e}");
            }
        }
    }

    fn fresh(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<PathBuf>> {
        self.fresh.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A work directory imported in place, as committed: what's in it
    /// must be kept before it's changed.
    fn imported(&self, dir: &Path) {
        self.fresh().retain(|path| !path.starts_with(dir));
    }

    fn written(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, Written>> {
        self.written.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What's known of an anchor, changed by `change`.
    fn of<T>(&self, anchor: &Link, change: impl FnOnce(&mut Written) -> T) -> T {
        let mut written = self.written();
        let it = written.entry(anchor.to_bytes()).or_insert_with(|| Written::new(anchor.clone()));
        let changed = change(it);
        drop(written);
        changed
    }

    /// Note an anchor's been written to.
    fn touched(&self, anchor: &Link) {
        let now = Instant::now();
        self.of(anchor, |it| {
            it.dirty = Some((it.dirty.map_or(now, |(since, _)| since), now));
            it.changes = it.changes.wrapping_add(1);
        });
    }

    /// Note an open file of an anchor's been written to since it was
    /// synced, if `unsynced`, or that one such has been synced or closed.
    fn unsynced(&self, anchor: &Link, unsynced: bool) {
        self.of(anchor, |it| it.unsynced = if unsynced { it.unsynced.saturating_add(1) } else { it.unsynced.saturating_sub(1) });
    }

    /// Note a file of an anchor's been opened to write, or one's closed.
    fn opened(&self, anchor: &Link, opened: bool) {
        self.of(anchor, |it| it.open = if opened { it.open.saturating_add(1) } else { it.open.saturating_sub(1) });
    }

    /// The least time between an anchor's commits, as the rules say.
    pub(super) fn floor(&self, anchor: &Link, floor: Duration) {
        self.of(anchor, |it| it.floor = floor);
    }

    /// How many times an anchor's been written to.
    fn changes(&self, anchor: &Link) -> u64 {
        self.of(anchor, |it| it.changes)
    }

    /// The anchors due to be committed, no longer dirty, with how many
    /// times each had been written to: every one written to if `all`.
    fn due(&self, all: bool, now: Instant) -> Vec<(Link, u64)> {
        let mut written = self.written();
        let mut due = Vec::new();
        for it in written.values_mut() {
            if it.dirty.is_some() && (all || it.due(now)) {
                it.dirty = None;
                due.push((it.anchor.clone(), it.changes));
            }
        }
        drop(written);
        due
    }

    /// Commit what's due, with a catalog opened on this thread: import
    /// each anchor's overlay and set it, unless it's written to as it's
    /// imported. What fails is tried again later.
    pub fn commit(&self, catalog: &mut Catalog, all: bool) {
        self.commit_as_of(catalog, all, Instant::now());
    }

    /// Commit what's due as of `now`.
    pub(super) fn commit_as_of(&self, catalog: &mut Catalog, all: bool, now: Instant) {
        self.revise(catalog);
        for (anchor, changes) in self.due(all, now) {
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
            // From seeing nothing's changed until what's committed is known
            // to be in place, nothing's to change, or it'd be written over
            // with no copy kept. A change waiting for this commit's database
            // transaction would never finish, so it's this that gives way.
            let holding = std::cell::RefCell::new(None);
            let still = || {
                if holding.borrow().is_none() {
                    match self.writing.try_lock() {
                        Ok(guard) => *holding.borrow_mut() = Some(guard),
                        Err(std::sync::TryLockError::Poisoned(poisoned)) => *holding.borrow_mut() = Some(poisoned.into_inner()),
                        Err(std::sync::TryLockError::WouldBlock) => return false,
                    }
                }
                self.changes(&anchor) == changes
            };
            let imported = import(catalog, &mount, &still);
            self.imported(&mount.path);
            let gave_way = holding.borrow().is_none();
            drop(holding);
            match imported {
                Ok(Some(value)) => {
                    let pace = self.of(&anchor, |it| {
                        let was = it.pace;
                        it.committed(now);
                        (was != it.pace).then_some(it.pace)
                    });
                    eprintln!("{anchor} is {value} now");
                    match pace.and_then(|pace| PACES.get(pace)) {
                        Some(&Duration::ZERO) => eprintln!("{anchor} is committed as soon as it's quiet again"),
                        Some(pace) => eprintln!("{anchor} is written to often, so it's committed at most every {}s", pace.as_secs()),
                        None => {},
                    }
                },
                // Written to meanwhile, and so dirty again: it's committed
                // once that's whole. What was underway may change nothing.
                Ok(None) => {
                    if gave_way {
                        self.touched(&anchor);
                    }
                },
                Err(e) => {
                    eprintln!("{anchor} couldn't be committed, so it stays as it was for now: {e}");
                    self.touched(&anchor);
                },
            }
        }
        self.reconcile(catalog);
    }

    /// Bring overlays into step with what's been set elsewhere, as they can
    /// be: what's in the work directory only says what the anchor was, and it
    /// can't go on saying so over what the anchor's become. See
    /// `Self::bring_into_step`.
    fn reconcile(&self, catalog: &mut Catalog) {
        for mount in catalog.mounts().unwrap_or_default().into_iter().filter(|mount| mount.overlay) {
            if let Err(e) = catalog.note_overlay_base(&mount.anchor) {
                eprintln!("{} has no base noted yet: {e}", mount.anchor);
            }
            if !catalog.overlay_behind(&mount.anchor).unwrap_or(false) || self.in_use(&mount.anchor) {
                continue;
            }
            if let Err(e) = self.bring_into_step(catalog, &mount) {
                eprintln!("{} isn't in step with what it's been set to yet: {e}", mount.anchor);
            }
        }
    }

    /// Whether what's in an anchor's work directory is being written, or has
    /// been and isn't committed: that goes first.
    fn in_use(&self, anchor: &Link) -> bool {
        self.of(anchor, |it| it.dirty.is_some() || it.unsynced > 0 || it.open > 0)
    }

    /// Commit whatever's in an overlay's work directory that isn't committed,
    /// as a fork of what's been set elsewhere if it's anything, then let go of
    /// it all, keeping the blocks it backs, so the mount shows what the anchor
    /// is. Each step leaves what the next can start over from: its blocks
    /// moved out, an overlay imports as it did; and with its files gone too,
    /// it's what it was over, so there's nothing to commit.
    fn bring_into_step(&self, catalog: &mut Catalog, mount: &Mount) -> crate::store::Result<()> {
        self.filler.complete(catalog, &mount.anchor)?;
        let Ok(underway) = self.writing.try_lock() else {
            return Ok(());
        };
        let done = self.let_go(catalog, mount);
        drop(underway);
        done
    }

    /// As `bring_into_step`, for what already holds the lock on changes.
    fn let_go(&self, catalog: &mut Catalog, mount: &Mount) -> crate::store::Result<()> {
        let anchor = &mount.anchor;
        if self.in_use(anchor) {
            return Ok(());
        }
        import(catalog, mount, &|| true)?;
        catalog.preserve_in_place(&mount.path)?;
        if let (Some(parent), Some(name)) = (mount.path.parent(), mount.path.file_name())
            && fs::symlink_metadata(&mount.path).is_ok()
        {
            let dropped = parent.join(format!("{DROPPED}{}", name.to_string_lossy()));
            discard(&dropped)?;
            fs::rename(&mount.path, &dropped)?;
            discard(&dropped)?;
        }
        self.imported(&mount.path);
        catalog.overlay_dropped(anchor)?;
        eprintln!("{anchor} is {} now, as set elsewhere", catalog.anchor_value(anchor)?.map_or_else(|| "nothing".to_owned(), |value| value.to_string()));
        Ok(())
    }

    /// Commit every overlay mount, as after a mount that ended before it
    /// could.
    pub fn recover(&self) {
        match (self.open)() {
            Ok(mut catalog) => {
                // What was being let go of when the mount before ended
                if let Some(work) = &self.filler.work {
                    for entry in fs::read_dir(work).into_iter().flatten().flatten() {
                        if entry.file_name().as_bytes().starts_with(DROPPED.as_bytes()) {
                            let _ = discard(&entry.path());
                        }
                    }
                }
                self.filler.load(&catalog);
                for mount in catalog.mounts().unwrap_or_default().into_iter().filter(|mount| mount.overlay) {
                    if let Err(e) = self.filler.complete(&catalog, &mount.anchor) {
                        eprintln!("{} couldn't be committed, not all of it having been copied: {e}", mount.anchor);
                        continue;
                    }
                    if let Err(e) = import(&mut catalog, &mount, &|| true) {
                        eprintln!("{} couldn't be committed: {e}", mount.anchor);
                    }
                    self.imported(&mount.path);
                }
                self.reconcile(&mut catalog);
            },
            Err(e) => eprintln!("not committing what was written before: {e}"),
        }
    }

    /// Commit what's due every so often, until stopped, on a thread of
    /// its own with a catalog of its own.
    pub fn run(self: Arc<Self>) {
        std::thread::spawn(move || {
            let mut catalog = None;
            let mut reconciled = 0u32;
            while !self.stop.load(Ordering::Relaxed) {
                std::thread::sleep(super::write::TICK);
                reconciled = reconciled.wrapping_add(1);
                if !reconciled.is_multiple_of(RECONCILE) && !self.written().values().any(|it| it.dirty.is_some()) && self.filler.partials().is_empty() && self.revisions().is_empty() {
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

/// Blocks here, and only here.
struct Here<'a>(&'a Catalog);

impl export::Fetch for Here<'_> {
    fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>> {
        match self.0.get_block(cid) {
            Ok(Some(block)) => Ok(block.into_data().into_vec()),
            Ok(None) => Err(io::Error::new(io::ErrorKind::NotFound, format!("block {cid} isn't here"))),
            Err(e) => Err(io::Error::other(e)),
        }
    }
}

/// How far back an anchor's history is looked through for the version
/// of a file before the one committed.
const HISTORY: usize = 64;

/// The parts of the file committed at a path of an anchor, about to be
/// written over, each with the part at the same offset of the version
/// of it before: (that older part, the newer). Only what's here is
/// looked at, and nothing if the path's not a file.
fn written_over(catalog: &Catalog, anchor: &Link, rel: &Path) -> Vec<(Link, Link)> {
    let here = Here(catalog);
    let marks = crate::store::overlay::Marks::new();
    let at = |value: &Link| crate::store::overlay::resolve(&here, Some(value.clone()), rel, &marks).ok().flatten().map(|(cid, _)| cid);
    let Some(newer) = catalog.anchor_value(anchor).ok().flatten().as_ref().and_then(at) else {
        return Vec::new();
    };
    let history = catalog.anchor_history(anchor).unwrap_or_default();
    let older = history.iter().rev().take(HISTORY).map(|(_, value)| at(value)).find(|cid| cid.as_ref() != Some(&newer));
    let Some(Some(older)) = older else {
        return Vec::new();
    };
    let (Ok(newer), Ok(older)) = (export::leaves(&here, &newer), export::leaves(&here, &older)) else {
        return Vec::new();
    };
    let older: HashMap<u64, Link> = older.into_iter().collect();
    newer.into_iter().filter_map(|(offset, newer)| older.get(&offset).filter(|older| **older != newer).map(|older| (older.clone(), newer))).collect()
}

/// Import an overlay and set its anchor, unless `still()` says it was
/// written to meanwhile. What it's over may be elsewhere: what's found
/// missing as it's imported is fetched, outside the import's transaction,
/// since the node writing it would wait on that, and it's imported again,
/// as deep as that goes.
fn import(catalog: &mut Catalog, mount: &Mount, still: &dyn Fn() -> bool) -> crate::store::Result<Option<Link>> {
    let mut imported = catalog.remount_if(mount, still);
    for _ in 0..FETCH_ROUNDS {
        let missed = catalog.take_missed();
        if imported.is_ok() || missed.is_empty() || !catalog.fetch_missing(&missed) {
            break;
        }
        imported = catalog.remount_if(mount, still);
    }
    imported
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

    /// The anchor and path of an inode, to change something there: brought
    /// into step first, so what's changed is measured from what was seen.
    fn overlay_of(&self, ino: u64) -> Result<(Link, PathBuf), Errno> {
        let (anchor, rel) = match self.inode(ino)? {
            Inode::Path(anchor, rel, _) if self.work.is_some() => (anchor, rel),
            Inode::Root if self.work.is_some() => (Self::root(&*self.catalog()?)?.ok_or(Errno::EROFS)?, PathBuf::new()),
            _ => return Err(Errno::EROFS),
        };
        self.catch_up(&anchor)?;
        Ok((anchor, rel))
    }

    /// An overlay about to be changed, if it's behind what's been set
    /// elsewhere, with nothing of its own to commit: into step now, not when
    /// next it's looked at, or what's written to what the mount showed would
    /// seem written to what it was over. The caller holds the lock on changes.
    fn catch_up(&self, anchor: &Link) -> Result<(), Errno> {
        let catalog = self.catalog()?;
        if !catalog.overlay_behind(anchor).map_err(store_errno)? || self.committer.in_use(anchor) {
            return Ok(());
        }
        let Some(mount) = catalog.mounts().map_err(store_errno)?.into_iter().find(|mount| mount.overlay && &mount.anchor == anchor) else {
            return Ok(());
        };
        drop(catalog);
        let mut own = (self.open)().map_err(store_errno)?;
        own.wait_for_writers(super::WRITER_WAIT).map_err(store_errno)?;
        self.committer.filler.complete(&own, anchor).map_err(|e| io_errno(&e))?;
        self.committer.let_go(&mut own, &mount).map_err(store_errno)
    }

    /// Before what's at a path of an anchor's work directory, or under it,
    /// is changed, moved or removed: what it was committed as, imported in
    /// place, is kept as blocks of its own, so the anchor's history stays
    /// whole.
    fn keep_committed(&self, catalog: &Catalog, anchor: &Link, rel: &Path) -> Result<(), Errno> {
        let Some(path) = self.work_path(anchor, rel) else {
            return Ok(());
        };
        if self.committer.fresh().iter().any(|fresh| path.starts_with(fresh)) {
            return Ok(());
        }
        catalog.preserve_in_place(&path).map_err(store_errno)?;
        self.committer.revisions().extend(written_over(catalog, anchor, rel));
        self.committer.fresh().insert(path);
        Ok(())
    }

    /// An anchor's work directory, making it an overlay mount if it isn't
    /// one yet. An anchor mounted on files imported in place is theirs to
    /// change, not this.
    fn prepare(&self, catalog: &Catalog, anchor: &Link) -> Result<PathBuf, Errno> {
        let dir = self.work_path(anchor, Path::new("")).ok_or(Errno::EROFS)?;
        match catalog.mounts().map_err(store_errno)?.into_iter().find(|mount| &mount.anchor == anchor) {
            Some(mount) if mount.overlay => {},
            Some(_) => return Err(Errno::EROFS),
            None => {
                catalog
                    .mount(&Mount { anchor: anchor.clone(), path: dir.clone(), chunk_size: crate::import::CHUNK_SIZE, width: crate::dag::FILE_WIDTH, hidden: true, overlay: true })
                    .map_err(store_errno)?;
                catalog.overlay_in_step(anchor).map_err(store_errno)?;
            },
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
                self.keep_committed(catalog, anchor, rel)?;
                self.filler.cut(catalog, anchor, rel, 0).map_err(|e| io_errno(&e))?;
                File::options().write(true).truncate(true).open(&path).map_err(|e| io_errno(&e))?;
            }
            return Ok(path);
        }
        let (cid, _) = Self::base_at(catalog, anchor, rel)?.ok_or(Errno::ENOENT)?;
        let size = if truncate {
            0
        } else {
            match export::stat(catalog, &cid).map_err(|e| errno(&e))? {
                Kind::File(size) => size,
                Kind::Directory => return Err(Errno::EISDIR),
                Kind::Symlink(_) => return Err(Errno::EINVAL),
            }
        };
        Self::parents(&path)?;
        // As big as it is, its chunks copied as they're read and written,
        // and the rest in the background
        let make = || File::create_new(&path).and_then(|file| file.set_len(size));
        if size > 0 {
            self.filler.add(catalog, Partial::new(anchor.clone(), rel.to_path_buf(), cid, size), make).map_err(|e| io_errno(&e))?;
        } else {
            make().map_err(|e| io_errno(&e))?;
        }
        Ok(path)
    }

    /// A handle for a file open, `unsynced` if opening it changed it.
    fn handle(&self, file: File, anchor: Option<Link>, rel: PathBuf, writable: bool, unsynced: bool) -> u64 {
        let fh = self.next_handle.fetch_add(1, Ordering::Relaxed);
        if unsynced && let Some(anchor) = &anchor {
            self.committer.unsynced(anchor, true);
        }
        if writable && let Some(anchor) = &anchor {
            self.committer.opened(anchor, true);
        }
        self.handles().insert(fh, Handle { file: Arc::new(file), anchor, rel, writable, unsynced, orphan: None });
        fh
    }

    /// What's needed of an open file to use it, so the handles aren't locked
    /// meanwhile: waiting for the database, say, nothing else need wait.
    fn handle_of(&self, fh: u64) -> Option<Opened> {
        self.handles().get(&fh).map(|handle| Opened {
            file: Arc::clone(&handle.file),
            anchor: handle.anchor.clone(),
            rel: handle.rel.clone(),
            writable: handle.writable,
            orphan: handle.orphan.clone(),
        })
    }

    /// Fill what's about to be read or written of an open file, if it's
    /// partial.
    fn fill_open(&self, open: &Opened, offset: u64, size: usize, writing: Option<(u64, u64)>) -> Result<(), Errno> {
        if let Some(anchor) = &open.anchor {
            return self.filler.fill(&*self.catalog()?, anchor, &open.rel, offset, size, writing).map_err(|e| io_errno(&e));
        }
        if let Some(orphan) = &open.orphan {
            return Filler::fill_orphan(&*self.catalog()?, orphan, &open.file, offset, size, writing).map_err(|e| io_errno(&e));
        }
        Ok(())
    }

    /// Open files follow a path and what's under it moved, or, with no `to`,
    /// removed. What was at `to`, replaced, is at no path any more: those who
    /// have it open go on with it, as with any unlinked file, but it's not
    /// what's there and it's no part of the anchor.
    fn retarget(&self, anchor: &Link, from: &Path, to: Option<&Path>, orphans: &[(PathBuf, SharedPartial)]) -> (Vec<Link>, Vec<Link>) {
        let (mut settled, mut closed) = (Vec::new(), Vec::new());
        for handle in self.handles().values_mut().filter(|handle| handle.anchor.as_ref() == Some(anchor)) {
            if let Some((to, rest)) = to.and_then(|to| Some((to, handle.rel.strip_prefix(from).ok()?))) {
                handle.rel = if rest.as_os_str().is_empty() { to.to_path_buf() } else { to.join(rest) };
            } else if handle.rel.starts_with(to.unwrap_or(from)) {
                settled.extend(handle.settled().cloned());
                if handle.writable {
                    closed.extend(handle.anchor.clone());
                }
                handle.orphan = orphans.iter().find(|(path, _)| *path == handle.rel).map(|(_, partial)| Arc::clone(partial));
                handle.anchor = None;
            }
        }
        (settled, closed)
    }

    /// Partial files and open files moved, or gone, as `Filler::moving` says,
    /// with `swap` moving the file itself.
    fn moving(&self, catalog: &Catalog, anchor: &Link, from: &Path, to: Option<&Path>, swap: impl FnOnce() -> io::Result<()>) -> Result<(), Errno> {
        let (mut settled, mut closed) = (Vec::new(), Vec::new());
        let done = self.filler.moving(catalog, anchor, from, to, |orphans| (settled, closed) = self.retarget(anchor, from, to, orphans), swap);
        // What's gone needn't be synced for its anchor to be committed
        for anchor in settled {
            self.committer.unsynced(&anchor, false);
        }
        for anchor in closed {
            self.committer.opened(&anchor, false);
        }
        done.map_err(|e| io_errno(&e))
    }

    /// Note an open file's been written to.
    fn note_written(&self, fh: u64) {
        let unsynced = self.handles().get_mut(&fh).and_then(|handle| handle.written().cloned());
        if let Some(anchor) = unsynced {
            self.committer.unsynced(&anchor, true);
        }
    }

    fn pins(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Link>> {
        locked(&self.pinned)
    }

    /// Whether a handle's of a file open to write.
    pub(super) fn is_writable(&self, fh: u64) -> bool {
        self.handles().get(&fh).is_some_and(|handle| handle.writable)
    }

    /// Open a file, to write if `write`: what's written goes to a copy of
    /// it in its anchor's work directory. Returns a handle, or 0 for what's
    /// read straight from the soup.
    pub fn open(&self, ino: u64, write: bool, truncate: bool) -> Result<u64, Errno> {
        if let Inode::Loose(name) = self.inode(ino)? {
            let path = self.loose_path(&name).ok_or(Errno::ENOENT)?;
            let file = File::options().read(true).write(write).truncate(truncate).open(path).map_err(|e| io_errno(&e))?;
            return Ok(self.handle(file, None, PathBuf::new(), write, false));
        }
        if !write {
            if let Inode::Path(anchor, rel, _) = self.inode(ino)?
                && let Some(path) = self.work_path(&anchor, &rel)
                // To write too, as it may be partial, and be replaced while
                // it's open, when what it's short of can only be filled by this
                && let Ok(file) = File::options().read(true).write(true).open(&path).or_else(|_| File::open(&path))
            {
                return Ok(self.handle(file, Some(anchor), rel, false, false));
            }
            if let Inode::Path(anchor, rel, _) = self.inode(ino)?
                && let Some((cid, _)) = Self::base_at(&*self.catalog()?, &anchor, &rel)?
            {
                let fh = self.next_handle.fetch_add(1, Ordering::Relaxed);
                self.pins().insert(fh, cid);
                return Ok(fh);
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
        Ok(self.handle(file, Some(anchor), rel, true, truncate))
    }

    /// Read from an open file, if it's one with a handle.
    pub fn read_handle(&self, fh: u64, offset: u64, size: usize) -> Option<Result<Vec<u8>, Errno>> {
        let pinned = self.pins().get(&fh).cloned();
        if let Some(cid) = pinned {
            return Some(self.catalog().and_then(|catalog| export::read_at(&*catalog, &cid, offset, size).map_err(|e| errno(&e))));
        }
        let mut open = self.handle_of(fh)?;
        loop {
            if let Err(e) = self.fill_open(&open, offset, size, None) {
                return Some(Err(e));
            }
            // Moved while it was being filled, what was filled mayn't have
            // been this, which reads aren't held back from
            match self.handle_of(fh) {
                Some(now) if !now.is_at(&open) => open = now,
                _ => return Some(super::read_file(&open.file, offset, size)),
            }
        }
    }

    /// Write to an open file.
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Result<usize, Errno> {
        let open = self.handle_of(fh).filter(|open| open.writable).ok_or(Errno::EBADF)?;
        if let Some(anchor) = &open.anchor {
            self.keep_committed(&*self.catalog()?, anchor, &open.rel)?;
        }
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.fill_open(&open, offset, data.len(), Some((offset, len)))?;
        self.note_written(fh);
        open.file.write_all_at(data, offset).map_err(|e| io_errno(&e))?;
        if let Some(anchor) = open.anchor {
            self.committer.touched(&anchor);
        }
        Ok(data.len())
    }

    /// Sync an open file, its data alone if `data_only`: what's written
    /// to it is whole, so its anchor can be committed though it's open.
    pub fn fsync(&self, fh: u64, data_only: bool) -> Result<(), Errno> {
        let Some(Opened { file, .. }) = self.handle_of(fh) else {
            // Read straight from the soup: nothing to sync
            return Ok(());
        };
        if data_only { file.sync_data() } else { file.sync_all() }.map_err(|e| io_errno(&e))?;
        let settled = self.handles().get_mut(&fh).and_then(|handle| handle.settled().cloned());
        if let Some(anchor) = settled {
            self.committer.unsynced(&anchor, false);
        }
        Ok(())
    }

    /// Close a file.
    pub fn release(&self, fh: u64) {
        self.pins().remove(&fh);
        if let Some(mut handle) = self.handles().remove(&fh)
            && handle.writable
        {
            if let Some(anchor) = handle.settled() {
                self.committer.unsynced(anchor, false);
            }
            if let Some(anchor) = &handle.anchor {
                self.committer.touched(anchor);
                self.committer.opened(anchor, false);
            }
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
            let fh = self.handle(file, None, PathBuf::new(), true, false);
            return Ok((self.resolve(parent, name)?, fh));
        }
        let (anchor, rel) = self.overlay_of(parent)?;
        let rel = rel.join(name);
        let catalog = self.catalog()?;
        self.prepare(&catalog, &anchor)?;
        self.keep_committed(&catalog, &anchor, &rel)?;
        let path = self.work_path(&anchor, &rel).ok_or(Errno::EROFS)?;
        Self::parents(&path)?;
        let file = File::options().read(true).write(true).create(true).truncate(true).open(&path).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        let fh = self.handle(file, Some(anchor), rel, true, false);
        Ok((self.resolve(parent, name)?, fh))
    }

    /// Make a directory: at the top, a new anchor, which the root anchor
    /// names.
    pub fn mkdir(&self, parent: u64, name: &OsStr) -> Result<FileAttr, Errno> {
        self.mkdir_by(parent, name, None)
    }

    /// Make a directory, as `app` does if it's known: at the top, or
    /// where the rules say to detach it, a new anchor, mounted there.
    pub fn mkdir_by(&self, parent: u64, name: &OsStr, app: Option<&str>) -> Result<FileAttr, Errno> {
        if self.inode(parent)? == Inode::Root {
            return self.anchor_at(parent, name, None);
        }
        let (anchor, rel) = self.overlay_of(parent)?;
        let catalog = self.catalog()?;
        let settings = self.settings_for(&catalog, parent, name.as_bytes(), true, app)?;
        // How many copies is said of an anchor's keep, so takes one
        if settings.detach == Some(true) || (settings.copies.is_some() && settings.detach.is_none()) {
            drop(catalog);
            return self.anchor_at(parent, name, settings.copies);
        }
        self.prepare(&catalog, &anchor)?;
        fs::create_dir_all(self.work_path(&anchor, &rel.join(name)).ok_or(Errno::EROFS)?).map_err(|e| io_errno(&e))?;
        drop(catalog);
        self.committer.touched(&anchor);
        self.resolve(parent, name)
    }

    /// A new anchor, an empty directory, mounted at a name in a directory:
    /// kept, asking for `copies` failures to lose what's in it, if it says.
    fn anchor_at(&self, parent: u64, name: &OsStr, copies: Option<usize>) -> Result<FileAttr, Errno> {
        use crate::cid::CidVersion;
        let (at, rel) = self.overlay_of(parent)?;
        if parent == super::ROOT && super::TOP.iter().any(|(top, _)| OsStr::new(top) == name) {
            return Err(Errno::EEXIST);
        }
        let catalog = self.catalog()?;
        if self.at(&catalog, &at, &rel.join(name))?.is_some() {
            return Err(Errno::EEXIST);
        }
        let empty: crate::block::Block = crate::block::Block::hash(
            crate::cid::Cidv1Spec::new(crate::cid::DAG_PB_CODEC, crate::multihash::MultihashFunc::Sha2_256),
            EMPTY_DIR.into(),
        );
        catalog.put_block(&empty, CidVersion::V1).map_err(store_errno)?;
        let anchor = catalog.new_anchor().map_err(store_errno)?;
        catalog.set_anchor(&anchor, &empty.cid().clone().into()).map_err(store_errno)?;
        if let Some(copies) = copies {
            catalog.keep_copies(&anchor, copies).map_err(store_errno)?;
        }
        drop(catalog);
        self.symlink(parent, name, &Path::new("/anchors").join(anchor.to_string()))?;
        // The link, mounting the anchor
        self.resolve(parent, name)
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
        // What symlink makes must be a symlink, though the kernel's next
        // look finds a mount point, if it's to an anchor
        self.resolve_kept(parent, name)
    }

    /// Mark a path gone if the anchor had anything there, else forget its
    /// marks.
    fn gone(catalog: &Catalog, anchor: &Link, rel: &Path) -> Result<(), Errno> {
        catalog.clear_overlay_marks(anchor, rel).map_err(store_errno)?;
        if Self::base_at(catalog, anchor, rel)?.is_some() {
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
                self.keep_committed(&catalog, &anchor, &rel)?;
                self.moving(&catalog, &anchor, &rel, None, || Ok(()))?;
                fs::remove_file(self.work_path(&anchor, &rel).ok_or(Errno::EROFS)?).map_err(|e| io_errno(&e))?;
            },
            At::Base(..) => {},
        }
        self.prepare(&catalog, &anchor)?;
        Self::gone(&catalog, &anchor, &rel)?;
        drop(catalog);
        self.committer.touched(&anchor);
        Ok(())
    }

    /// Remove an empty directory, or a mount point, whatever's in it: the
    /// link goes, and the anchor is as it was, as an unmount.
    pub fn rmdir(&self, parent: u64, name: &OsStr) -> Result<(), Errno> {
        let (anchor, rel) = self.overlay_of(parent)?;
        let rel = rel.join(name);
        let catalog = self.catalog()?;
        match self.kind_kept(&catalog, &Inode::Path(anchor.clone(), rel.clone(), None))? {
            Kind::Symlink(target) if to_anchor(&target) => {
                drop(catalog);
                return self.unlink(parent, name);
            },
            Kind::Directory => {},
            _ => return Err(Errno::ENOTDIR),
        }
        if !self.overlay_entries(&catalog, &anchor, &rel, &None)?.is_empty() {
            return Err(Errno::ENOTEMPTY);
        }
        if let Some(path) = self.work_path(&anchor, &rel)
            && path.is_dir()
        {
            fs::remove_dir(path).map_err(|e| io_errno(&e))?;
        }
        self.prepare(&catalog, &anchor)?;
        Self::gone(&catalog, &anchor, &rel)?;
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
        let source = self.kind(&catalog, &Inode::Path(anchor.clone(), from.clone(), None))?;
        if self.at(&catalog, &anchor, &to)?.is_some() {
            if no_replace {
                return Err(Errno::EEXIST);
            }
            let replaced = self.kind(&catalog, &Inode::Path(anchor.clone(), to.clone(), None))?;
            match (source == Kind::Directory, replaced == Kind::Directory) {
                (false, true) => return Err(Errno::EISDIR),
                (true, false) => return Err(Errno::ENOTDIR),
                (true, true) if !self.overlay_entries(&catalog, &anchor, &to, &None)?.is_empty() => return Err(Errno::ENOTEMPTY),
                _ => {},
            }
        }
        self.prepare(&catalog, &anchor)?;
        // What's moved and what's replaced leave their paths
        self.keep_committed(&catalog, &anchor, &from)?;
        self.keep_committed(&catalog, &anchor, &to)?;
        let base = Self::base_at(&catalog, &anchor, &from)?;
        let (work_from, work_to) = (self.work_path(&anchor, &from).ok_or(Errno::EROFS)?, self.work_path(&anchor, &to).ok_or(Errno::EROFS)?);
        // It's exactly what was there: what the anchor had, or nothing
        let mark = base.map(|(cid, size)| (cid, size.unwrap_or_default()));
        let marks = || -> Result<(), Errno> {
            catalog.clear_overlay_marks(&anchor, &to).map_err(store_errno)?;
            catalog.move_overlay_marks(&anchor, &from, &to).map_err(store_errno)?;
            catalog.set_overlay_mark(&anchor, &to, &mark).map_err(store_errno)?;
            if Self::base_at(&catalog, &anchor, &from)?.is_some() {
                catalog.set_overlay_mark(&anchor, &from, &None).map_err(store_errno)?;
            }
            Ok(())
        };
        // Whatever's reading must find one or the other at `to`, so what's
        // there is replaced, never removed first. The inodes go with it, so
        // nothing's taken for what it replaced.
        let moved_inodes = |inodes: &mut Inodes| {
            inodes.renamed(&anchor, &from, &to);
            inodes.via_moved(&(parent, name.as_bytes().to_vec()), &(new_parent, new_name.as_bytes().to_vec()));
        };
        if fs::symlink_metadata(&work_from).is_ok() {
            Self::parents(&work_to)?;
            self.moving(&catalog, &anchor, &from, Some(&to), || {
                let mut inodes = self.inodes();
                fs::rename(&work_from, &work_to)?;
                moved_inodes(&mut inodes);
                drop(inodes);
                Ok(())
            })?;
            marks()?;
        } else {
            // Only what the anchor had moves: nothing in the work directory
            // replaces what's there, so it's the marks that say what is
            marks()?;
            self.moving(&catalog, &anchor, &to, None, || {
                let mut inodes = self.inodes();
                match fs::symlink_metadata(&work_to) {
                    Ok(meta) if meta.is_dir() => fs::remove_dir(&work_to)?,
                    Ok(_) => fs::remove_file(&work_to)?,
                    Err(_) => {},
                }
                moved_inodes(&mut inodes);
                drop(inodes);
                Ok(())
            })?;
        }
        drop(catalog);
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
        if let Some(Inode::Path(anchor, rel, _)) = replaced.map(|ino| self.inode(ino)).transpose()? {
            if self.kind(&*self.catalog()?, &Inode::Path(anchor.clone(), rel.clone(), None))? == Kind::Directory {
                return Err(Errno::EISDIR);
            }
            let catalog = self.catalog()?;
            let to = self.prepare(&catalog, &anchor)?;
            self.keep_committed(&catalog, &anchor, &rel)?;
            self.moving(&catalog, &anchor, &rel, None, || Ok(()))?;
            drop(catalog);
            Self::parents(&to)?;
            fs::rename(&from, &to).map_err(|e| io_errno(&e))?;
            self.inodes().became(&Inode::Loose(name.as_bytes().to_vec()), Inode::Path(anchor.clone(), rel, None));
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
        if let Some(Opened { file, anchor, rel, orphan, .. }) = fh.and_then(|fh| self.handle_of(fh)).filter(|open| open.writable) {
            if let Some(anchor) = &anchor {
                let catalog = self.catalog()?;
                self.keep_committed(&catalog, anchor, &rel)?;
                self.filler.cut(&catalog, anchor, &rel, size).map_err(|e| io_errno(&e))?;
            }
            if let Some(orphan) = &orphan {
                Filler::fill_orphan(&*self.catalog()?, orphan, &file, size, 1, None).map_err(|e| io_errno(&e))?;
                locked(orphan).cut(size);
            }
            if let Some(fh) = fh {
                self.note_written(fh);
            }
            file.set_len(size).map_err(|e| io_errno(&e))?;
            if let Some(anchor) = &anchor {
                self.committer.touched(anchor);
            }
            return Ok(());
        }
        if let Inode::Loose(name) = self.inode(ino)? {
            let path = self.loose_path(&name).ok_or(Errno::EROFS)?;
            return File::options().write(true).open(path).and_then(|file| file.set_len(size)).map_err(|e| io_errno(&e));
        }
        let (anchor, rel) = self.overlay_of(ino)?;
        let catalog = self.catalog()?;
        self.keep_committed(&catalog, &anchor, &rel)?;
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
            // What the root names is kept through it
            match (self.open)().and_then(|catalog| catalog.keep_root()) {
                Ok(Some(keep)) => eprintln!("the root anchor is kept now, by {keep}"),
                Ok(None) => {},
                Err(e) => eprintln!("the root anchor couldn't be kept, so what it names may be collected: {e}"),
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn written() -> Written {
        Written::new(crate::claim::anchor().expect("anchor"))
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn whats_open_is_committed_once_synced() {
        let t = Instant::now();
        let mut it = written();
        it.unsynced = 1;
        it.dirty = Some((t, t));
        assert!(!it.due(t + secs(3600)), "open and written, never synced: maybe not whole");
        it.unsynced = 0;
        it.dirty = Some((t, t + secs(1)));
        assert!(!it.due(t + secs(1)), "synced, but not yet quiet");
        assert!(it.due(t + secs(2)));
    }

    #[test]
    fn whats_never_quiet_is_committed_when_stale() {
        let t = Instant::now();
        let mut it = written();
        it.dirty = Some((t, t + secs(4)));
        assert!(!it.due(t + secs(4)));
        it.dirty = Some((t, t + secs(5)));
        assert!(it.due(t + secs(5)), "written to for STALE without a break");
        // Which, again and again, is written to often: never quiet, each
        // commit waits its pace, and the next is slower
        it.committed(t + secs(5));
        let mut last = 5;
        for (at, pace) in [(10, 1), (15, 2), (45, 3), (165, 4), (765, 4)] {
            it.dirty = Some((t + secs(last), t + secs(at)));
            assert!(!it.due(t + secs(at - 1)), "{at}: not before its pace");
            assert!(it.due(t + secs(at)), "{at}");
            it.committed(t + secs(at));
            assert_eq!(it.pace, pace, "{at}");
            last = at;
        }
    }

    #[test]
    fn whats_often_written_is_committed_less_often() {
        let t = Instant::now();
        let mut it = written();
        let mut at = t;
        // Committed again as soon as it's allowed each time: slower and slower
        for pace in 0..PACES.len() {
            it.committed(at);
            at += PACES.get(pace).copied().expect("pace") + secs(1);
        }
        assert_eq!(it.pace, PACES.len() - 1, "at the slowest");
        it.committed(at);
        assert_eq!(it.pace, PACES.len() - 1, "and no slower");
        it.dirty = Some((at, at));
        assert!(!it.due(at + secs(60)), "not till its pace");
        assert!(it.due(at + secs(600)));
        // Left a long while: a step faster each time
        let mut at = at + secs(7200);
        it.committed(at);
        assert_eq!(it.pace, PACES.len() - 2);
        at += secs(7200);
        it.committed(at);
        assert_eq!(it.pace, PACES.len() - 3);
        // An editor's saves, minutes apart, stay prompt
        let mut it = written();
        for minute in 0..10 {
            it.committed(t + secs(60 * minute));
        }
        assert_eq!(it.pace, 0);
    }
}
