//! `hk mount`: the soup as a filesystem, over FUSE.
//!
//! ```text
//! cid/<cid>/…         whatever's at a CID; looked up by name, not listed
//! anchors/<anchor>/…  what each anchor is now, and writable
//! tags/<tag>/<cid>/…  what's tagged so
//! ```
//!
//! Writing to an anchor writes to its overlay (see `store::overlay`): a
//! file opened to write is copied into the anchor's work directory, and
//! what's created, removed and renamed is done there and in the anchor's
//! marks. Once nothing of an anchor's is open to write and it's been quiet
//! a second, the overlay's imported and the anchor set to what it now is,
//! once for what an editor's save does in a burst.
//!
//! UnixFS directories are directories, files files and symlinks symlinks;
//! a block of any other codec reads as its bytes. A file's read fetches
//! only the parts of it the read is in. What isn't here is asked of the
//! running node, which fetches just those blocks from members, all of a
//! read's or a directory's entries at once, and what's
//! another account's is as good as not here, as for `hk cat`. Anchors and
//! tags are looked up again every second, so the mount follows them.

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, KernelConfig, LockOwner, MountOption, OpenFlags,
    RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
    WriteFlags,
};

use crate::cid::{BaseCid as _, CidRef as _};
use crate::export::{self, Fetch, Kind};
use crate::model::Link;
use crate::store::Catalog;
use crate::store::overlay;

mod write;
use write::{Committer, Filler, Handle};

/// How long the kernel may take what it's told as still so.
const TTL: Duration = Duration::from_secs(1);

/// Opens the catalog, on whichever thread the filesystem runs on, since a
/// catalog stays on the thread it's opened on.
pub type Opener = Box<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync>;

thread_local! {
    /// Each soup's catalog, as opened on this thread.
    static CATALOGS: std::cell::RefCell<HashMap<u64, std::rc::Rc<Catalog>>> = std::cell::RefCell::new(HashMap::new());
}

/// Tells soups apart, for their catalogs.
static SOUPS: AtomicU64 = AtomicU64::new(0);

/// Asks the running node to fetch blocks, just them, saying whether it
/// could ask.
pub type Fetcher = Box<dyn Fn(&[Link]) -> bool + Send + Sync>;

/// What an inode is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Inode {
    Root,
    Cids,
    Anchors,
    Tags,
    Tag(Link),
    Node(Link),
    /// A path of what an anchor is, overlay and all.
    Path(Link, PathBuf),
    /// A file of `anchors/` that's no anchor, as an editor writes to save
    /// over a file anchor.
    Loose(Vec<u8>),
}

/// The top level, by inode number.
const TOP: [(&str, u64); 3] = [("cid", 2), ("anchors", 3), ("tags", 4)];

/// Inode numbers, handed out as things are looked up and kept for the
/// mount's life: a CID is the same inode wherever it's reached.
struct Inodes {
    all: Vec<Inode>,
    by_key: HashMap<Vec<u8>, u64>,
}

impl Inodes {
    fn new() -> Self {
        Self { all: vec![Inode::Root, Inode::Cids, Inode::Anchors, Inode::Tags], by_key: HashMap::new() }
    }

    fn get(&self, ino: u64) -> Option<Inode> {
        self.all.get(usize::try_from(ino.checked_sub(1)?).ok()?).cloned()
    }

    /// A path of an anchor renamed: the inodes of it and what's under it
    /// are where they moved to, as the kernel takes them to be.
    fn renamed(&mut self, anchor: &Link, from: &Path, to: &Path) {
        for (index, inode) in self.all.iter_mut().enumerate() {
            let Inode::Path(at, rel) = &*inode else {
                continue;
            };
            let Ok(rest) = rel.strip_prefix(from) else {
                continue;
            };
            if at != anchor {
                continue;
            }
            let moved = Inode::Path(at.clone(), if rest.as_os_str().is_empty() { to.to_path_buf() } else { to.join(rest) });
            self.by_key.remove(&Self::key(inode));
            self.by_key.insert(Self::key(&moved), u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1));
            *inode = moved;
        }
    }

    /// One inode become another, as the kernel takes a renamed one to be.
    fn became(&mut self, from: &Inode, to: Inode) {
        let Some(&ino) = self.by_key.get(&Self::key(from)) else {
            return;
        };
        self.by_key.remove(&Self::key(from));
        self.by_key.insert(Self::key(&to), ino);
        if let Some(inode) = usize::try_from(ino.saturating_sub(1)).ok().and_then(|index| self.all.get_mut(index)) {
            *inode = to;
        }
    }

    fn key(inode: &Inode) -> Vec<u8> {
        match inode {
            Inode::Tag(tag) => [b"t".as_slice(), &tag.to_bytes()].concat(),
            Inode::Node(cid) => [b"n".as_slice(), &cid.to_bytes()].concat(),
            Inode::Path(anchor, rel) => [b"p".as_slice(), &anchor.to_bytes(), &[0], rel.as_os_str().as_bytes()].concat(),
            Inode::Loose(name) => [b"l".as_slice(), name].concat(),
            Inode::Root | Inode::Cids | Inode::Anchors | Inode::Tags => Vec::new(),
        }
    }

    fn of(&mut self, inode: Inode) -> u64 {
        let key = match &inode {
            Inode::Tag(_) | Inode::Node(_) | Inode::Path(..) | Inode::Loose(_) => Self::key(&inode),
            Inode::Root => return 1,
            Inode::Cids => return 2,
            Inode::Anchors => return 3,
            Inode::Tags => return 4,
        };
        if let Some(&ino) = self.by_key.get(&key) {
            return ino;
        }
        self.all.push(inode);
        let ino = u64::try_from(self.all.len()).unwrap_or(u64::MAX);
        self.by_key.insert(key, ino);
        ino
    }
}

/// An entry of a directory: its name, inode number and type.
pub type Entry = (Vec<u8>, u64, FileType);

/// The soup, mounted.
pub struct Soup {
    id: u64,
    open: Arc<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync>,
    /// Where anchors' work directories go, if anchors are writable.
    work: Option<PathBuf>,
    /// Files open, by handle: those written to, or in a work directory.
    handles: Mutex<HashMap<u64, Handle>>,
    committer: Arc<Committer>,
    fetcher: Option<Arc<Fetcher>>,
    /// Files of overlays being copied as they're read and written.
    filler: Arc<write::Filler>,
    inodes: Mutex<Inodes>,
    /// The sizes directories say raw blocks are, by CID, so a listing
    /// needn't fetch every file in it to say how big each is. Advisory,
    /// as a stat's size is: reading reads what's there.
    sizes: Mutex<HashMap<Vec<u8>, u64>>,
    /// Directory listings open, by handle.
    listings: Mutex<HashMap<u64, std::sync::Arc<Vec<Entry>>>>,
    next_handle: AtomicU64,
    uid: u32,
    gid: u32,
    at: SystemTime,
}

/// The catalog, asking the node for what isn't here.
struct Source<'a> {
    catalog: &'a Catalog,
    fetcher: Option<&'a Fetcher>,
}

impl Fetch for Source<'_> {
    fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>> {
        match self.catalog.fetch(cid) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => match self.fetcher {
                Some(fetcher) if fetcher(std::slice::from_ref(cid)) => self.catalog.fetch(cid),
                _ => Err(e),
            },
            result => result,
        }
    }

    fn prefetch(&self, cids: &[Link]) {
        use crate::store::BlockIndex as _;
        let Some(fetcher) = self.fetcher else {
            return;
        };
        let missing: Vec<Link> = cids.iter()
            .filter(|cid| cid.hashcode() != crate::block::IDENTITY && !self.catalog.has(cid.multihash()).unwrap_or(true))
            .cloned()
            .collect();
        if !missing.is_empty() {
            fetcher(&missing);
        }
    }
}

/// Where a path of an anchor is in its work directory, under `work`.
fn work_path(work: &Path, anchor: &Link, rel: &Path) -> PathBuf {
    let dir = work.join(anchor.to_string());
    if rel.as_os_str().is_empty() { dir } else { dir.join(rel) }
}

/// What's at a path of an anchor.
enum At {
    /// Something in its work directory.
    Work(std::fs::Metadata),
    /// A block of what the anchor had, with the size its link says.
    Base(Link, Option<u64>),
}

/// What something in a work directory is.
fn work_kind(path: &Path, meta: &std::fs::Metadata) -> Result<Kind, Errno> {
    if meta.is_dir() {
        Ok(Kind::Directory)
    } else if meta.file_type().is_symlink() {
        Ok(Kind::Symlink(std::fs::read_link(path).map_err(|e| errno(&e))?.into_os_string().into_vec()))
    } else {
        Ok(Kind::File(meta.len()))
    }
}

/// Up to `size` bytes of a file from `offset`.
fn read_file(file: &std::fs::File, offset: u64, size: usize) -> Result<Vec<u8>, Errno> {
    use std::os::unix::fs::FileExt as _;
    let mut buf = vec![0; size];
    let mut read = 0;
    while read < size {
        match file.read_at(buf.get_mut(read..).unwrap_or_default(), offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX))) {
            Ok(0) => break,
            Ok(n) => read = read.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(errno(&e)),
        }
    }
    buf.truncate(read);
    Ok(buf)
}

fn errno(e: &io::Error) -> Errno {
    match e.kind() {
        io::ErrorKind::NotFound => Errno::ENOENT,
        io::ErrorKind::IsADirectory => Errno::EISDIR,
        io::ErrorKind::NotADirectory => Errno::ENOTDIR,
        _ => Errno::EIO,
    }
}

fn store_errno(_: crate::store::Error) -> Errno {
    Errno::EIO
}

impl Soup {
    /// The soup as the account the catalog `open` opens acts for sees
    /// it, asking `fetcher` for what isn't here, if there's a node to ask.
    pub fn new(open: Opener, fetcher: Option<Fetcher>) -> Self {
        let open: Arc<dyn Fn() -> crate::store::Result<Catalog> + Send + Sync> = Arc::from(open);
        let fetcher = fetcher.map(Arc::new);
        let filler = Arc::new(Filler::new(None, fetcher.clone()));
        Self {
            id: SOUPS.fetch_add(1, Ordering::Relaxed),
            committer: Arc::new(Committer::new(Arc::clone(&open), Arc::clone(&filler))),
            filler,
            open,
            work: None,
            handles: Mutex::new(HashMap::new()),
            fetcher,
            inodes: Mutex::new(Inodes::new()),
            sizes: Mutex::new(HashMap::new()),
            listings: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            at: SystemTime::now(),
        }
    }

    /// Anchors writable, their work directories under `work`.
    #[must_use]
    pub fn writable(mut self, work: PathBuf) -> Self {
        self.filler = Arc::new(Filler::new(Some(work.clone()), self.fetcher.clone()));
        self.committer = Arc::new(Committer::new(Arc::clone(&self.open), Arc::clone(&self.filler)));
        self.work = Some(work);
        self
    }

    /// The catalog, as opened on this thread.
    fn catalog(&self) -> Result<std::rc::Rc<Catalog>, Errno> {
        if let Some(catalog) = CATALOGS.with_borrow(|catalogs| catalogs.get(&self.id).cloned()) {
            return Ok(catalog);
        }
        let catalog = std::rc::Rc::new((self.open)().map_err(store_errno)?);
        CATALOGS.with_borrow_mut(|catalogs| catalogs.insert(self.id, std::rc::Rc::clone(&catalog)));
        Ok(catalog)
    }

    fn inodes(&self) -> std::sync::MutexGuard<'_, Inodes> {
        self.inodes.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn inode(&self, ino: u64) -> Result<Inode, Errno> {
        self.inodes().get(ino).ok_or(Errno::ENOENT)
    }

    /// Whether a block's this account's to see, fetching it if it's not
    /// here.
    fn reachable(&self, catalog: &Catalog, cid: &Link) -> Result<bool, Errno> {
        if catalog.visible(cid.multihash()).map_err(store_errno)? {
            return Ok(true);
        }
        match &self.fetcher {
            Some(fetcher) if fetcher(std::slice::from_ref(cid)) => catalog.visible(cid.multihash()).map_err(store_errno),
            _ => Ok(false),
        }
    }

    /// Note the sizes a directory says its raw entries are.
    fn note_sizes(&self, entries: &[export::Listed]) {
        let mut sizes = self.sizes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in entries {
            if let Some(size) = entry.size
                && entry.cid.codec() == crate::cid::RAW_CODEC
            {
                sizes.insert(entry.cid.to_bytes(), size);
            }
        }
    }

    fn kind(&self, catalog: &Catalog, inode: &Inode) -> Result<Kind, Errno> {
        match inode {
            Inode::Node(cid) if cid.codec() == crate::cid::RAW_CODEC => {
                let said = self.sizes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&cid.to_bytes()).copied();
                said.map_or_else(
                    || export::stat(&Source { catalog, fetcher: self.fetcher.as_deref() }, cid).map_err(|e| errno(&e)),
                    |size| Ok(Kind::File(size)),
                )
            },
            Inode::Node(cid) => export::stat(&Source { catalog, fetcher: self.fetcher.as_deref() }, cid).map_err(|e| errno(&e)),
            Inode::Path(anchor, rel) => match self.at(catalog, anchor, rel)?.ok_or(Errno::ENOENT)? {
                At::Work(meta) => work_kind(&self.work_path(anchor, rel).unwrap_or_default(), &meta),
                At::Base(cid, size) => {
                    if let Some(size) = size.filter(|_| cid.codec() == crate::cid::RAW_CODEC) {
                        return Ok(Kind::File(size));
                    }
                    self.kind(catalog, &Inode::Node(cid))
                },
            },
            Inode::Loose(name) => {
                let path = self.loose_path(name).ok_or(Errno::ENOENT)?;
                let meta = std::fs::symlink_metadata(&path).map_err(|e| errno(&e))?;
                work_kind(&path, &meta)
            },
            _ => Ok(Kind::Directory),
        }
    }

    /// Where a path of an anchor is in its work directory, if anchors are
    /// writable.
    fn work_path(&self, anchor: &Link, rel: &Path) -> Option<PathBuf> {
        Some(work_path(self.work.as_ref()?, anchor, rel))
    }

    /// What an anchor is now, if it's anything.
    fn anchor_root(catalog: &Catalog, anchor: &Link) -> Result<Option<Link>, Errno> {
        catalog.claims().map(|claims| claims.value_of(anchor.multihash())).transpose().map_err(store_errno).map(Option::flatten)
    }

    /// What's at a path of an anchor: what's in its work directory, else
    /// what the anchor had there, after marks.
    fn at(&self, catalog: &Catalog, anchor: &Link, rel: &Path) -> Result<Option<At>, Errno> {
        if let Some(path) = self.work_path(anchor, rel) {
            match std::fs::symlink_metadata(&path) {
                Ok(meta) => return Ok(Some(At::Work(meta))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                Err(e) => return Err(errno(&e)),
            }
        }
        Ok(self.base_at(catalog, anchor, rel)?.map(|(cid, size)| At::Base(cid, size)))
    }

    /// What the anchor had at a path, after marks, whatever's in the work
    /// directory.
    fn base_at(&self, catalog: &Catalog, anchor: &Link, rel: &Path) -> Result<overlay::Base, Errno> {
        let marks = catalog.overlay_marks(anchor).map_err(store_errno)?;
        let root = Self::anchor_root(catalog, anchor)?;
        overlay::resolve(&Source { catalog, fetcher: self.fetcher.as_deref() }, root, rel, &marks).map_err(|e| errno(&e))
    }

    /// A directory of an anchor's entries: its work directory's over what
    /// the anchor had there.
    fn overlay_entries(&self, catalog: &Catalog, anchor: &Link, rel: &Path) -> Result<Vec<(Vec<u8>, Inode)>, Errno> {
        let marks = catalog.overlay_marks(anchor).map_err(store_errno)?;
        let root = Self::anchor_root(catalog, anchor)?;
        let source = Source { catalog, fetcher: self.fetcher.as_deref() };
        let mut names: BTreeSet<Vec<u8>> = BTreeSet::new();
        // Under a file in the work directory, the anchor's had nothing
        let shadowed = self.work_path(anchor, rel).is_some_and(|path| std::fs::symlink_metadata(path).is_ok_and(|meta| !meta.is_dir()));
        if !shadowed {
            let entries = overlay::base_entries(&source, root, rel, &marks).map_err(|e| errno(&e))?;
            let listed: Vec<export::Listed> = entries.iter().map(|(name, (cid, size))| export::Listed { name: name.clone(), cid: cid.clone(), size: *size }).collect();
            self.note_sizes(&listed);
            names.extend(entries.into_keys());
        }
        if let Some(path) = self.work_path(anchor, rel)
            && let Ok(dir) = std::fs::read_dir(path)
        {
            for entry in dir.flatten() {
                names.insert(entry.file_name().as_bytes().to_vec());
            }
        }
        Ok(names.into_iter().map(|name| {
            let child = rel.join(OsStr::from_bytes(&name));
            (name, Inode::Path(anchor.clone(), child))
        }).collect())
    }

    fn attr_of(&self, ino: u64, kind: &Kind) -> FileAttr {
        self.attr_with(ino, kind, false)
    }

    /// Attributes, writable ones if `writable`.
    fn attr_with(&self, ino: u64, kind: &Kind, writable: bool) -> FileAttr {
        let (file, dir) = if writable { (0o644, 0o755) } else { (0o444, 0o555) };
        let (kind, size, perm, nlink) = match kind {
            Kind::File(size) => (FileType::RegularFile, *size, file, 1),
            Kind::Directory => (FileType::Directory, 0, dir, 2),
            Kind::Symlink(target) => (FileType::Symlink, u64::try_from(target.len()).unwrap_or(u64::MAX), 0o777, 1),
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: self.at,
            mtime: self.at,
            ctime: self.at,
            crtime: self.at,
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// An inode's attributes.
    pub fn attr(&self, ino: u64) -> Result<FileAttr, Errno> {
        let inode = self.inode(ino)?;
        let kind = self.kind(&*self.catalog()?, &inode)?;
        Ok(self.attr_with(ino, &kind, self.writes(&inode)))
    }

    /// Whether an inode can be written to.
    const fn writes(&self, inode: &Inode) -> bool {
        self.work.is_some() && matches!(inode, Inode::Path(..) | Inode::Loose(_))
    }

    /// What a name in a directory is.
    pub fn resolve(&self, parent: u64, name: &OsStr) -> Result<FileAttr, Errno> {
        let parent = self.inode(parent)?;
        let catalog = self.catalog()?;
        let cid = |name: &OsStr| name.to_str().and_then(|name| name.parse::<Link>().ok()).ok_or(Errno::ENOENT);
        let inode = match parent {
            Inode::Root => {
                let &(_, ino) = TOP.iter().find(|(top, _)| OsStr::new(top) == name).ok_or(Errno::ENOENT)?;
                return Ok(self.attr_of(ino, &Kind::Directory));
            },
            Inode::Cids => {
                let cid = cid(name)?;
                if !self.reachable(&catalog, &cid)? {
                    return Err(Errno::ENOENT);
                }
                Inode::Node(cid)
            },
            Inode::Anchors => match cid(name).ok().map(|anchor| Ok::<_, Errno>((Self::anchor_root(&catalog, &anchor)?, anchor))).transpose()? {
                Some((Some(value), anchor)) => {
                    if !self.reachable(&catalog, &value)? {
                        return Err(Errno::ENOENT);
                    }
                    Inode::Path(anchor, PathBuf::new())
                },
                _ if self.loose_path(name.as_bytes()).is_some_and(|path| path.exists()) => Inode::Loose(name.as_bytes().to_vec()),
                _ => return Err(Errno::ENOENT),
            },
            Inode::Loose(_) => return Err(Errno::ENOTDIR),
            Inode::Path(anchor, rel) => {
                let child = rel.join(name);
                if self.at(&catalog, &anchor, &child)?.is_none() {
                    return Err(Errno::ENOENT);
                }
                Inode::Path(anchor, child)
            },
            Inode::Tags => {
                let claims = catalog.claims().ok_or(Errno::ENOENT)?;
                let tag = name.to_str().and_then(crate::claim::tag).filter(|tag| claims.tagged(tag.multihash()).is_ok_and(|tagged| !tagged.is_empty()));
                Inode::Tag(match tag {
                    Some(tag) => tag,
                    None => cid(name)?,
                })
            },
            Inode::Tag(tag) => {
                let claims = catalog.claims().ok_or(Errno::ENOENT)?;
                let cid = cid(name)?;
                if !claims.tagged(tag.multihash()).map_err(store_errno)?.contains(&cid) || !self.reachable(&catalog, &cid)? {
                    return Err(Errno::ENOENT);
                }
                Inode::Node(cid)
            },
            Inode::Node(dir) => {
                let entries = export::list(&Source { catalog: &catalog, fetcher: self.fetcher.as_deref() }, &dir).map_err(|e| errno(&e))?;
                self.note_sizes(&entries);
                let entry = entries.into_iter().find(|entry| entry.name.as_slice() == name.as_bytes()).ok_or(Errno::ENOENT)?;
                Inode::Node(entry.cid)
            },
        };
        let kind = self.kind(&catalog, &inode)?;
        drop(catalog);
        let writable = self.writes(&inode);
        let ino = self.inodes().of(inode);
        Ok(self.attr_with(ino, &kind, writable))
    }

    /// A directory's entries, but `.` and `..`.
    pub fn list(&self, ino: u64) -> Result<Vec<Entry>, Errno> {
        let inode = self.inode(ino)?;
        let catalog = self.catalog()?;
        let with_kinds = |names: Vec<(Vec<u8>, Inode)>| -> Result<Vec<(Vec<u8>, Inode, Kind)>, Errno> {
            names.into_iter().map(|(name, inode)| Ok((name, inode.clone(), self.kind(&catalog, &inode)?))).collect()
        };
        let children = match inode {
            Inode::Root => TOP.iter().map(|&(name, _)| (name.as_bytes().to_vec(), Inode::Root, Kind::Directory)).collect(),
            // Every CID is in it, so none are listed
            Inode::Cids => Vec::new(),
            Inode::Anchors => {
                let anchors = catalog.claims().map(crate::store::ClaimStore::anchors).transpose().map_err(store_errno)?.unwrap_or_default();
                let mut found = Vec::new();
                for (anchor, value) in anchors {
                    if self.reachable(&catalog, &value)? {
                        found.push((anchor.to_string().into_bytes(), Inode::Path(anchor, PathBuf::new())));
                    }
                }
                found.extend(self.loose().into_iter().map(|name| (name.clone(), Inode::Loose(name))));
                with_kinds(found)?
            },
            Inode::Tags => {
                let tags = catalog.claims().map(crate::store::ClaimStore::all_tags).transpose().map_err(store_errno)?.unwrap_or_default();
                tags.into_iter()
                    .map(|tag| {
                        let name = crate::claim::tag_name(&tag).filter(|name| !name.is_empty() && *name != "." && *name != ".." && !name.contains(['/', '\0']));
                        (name.map_or_else(|| tag.to_string(), str::to_owned).into_bytes(), Inode::Tag(tag), Kind::Directory)
                    })
                    .collect()
            },
            Inode::Tag(tag) => {
                let tagged = catalog.claims().ok_or(Errno::ENOENT)?.tagged(tag.multihash()).map_err(store_errno)?;
                let mut found = Vec::new();
                for cid in tagged {
                    if self.reachable(&catalog, &cid)? {
                        found.push((cid.to_string().into_bytes(), Inode::Node(cid)));
                    }
                }
                with_kinds(found)?
            },
            Inode::Node(dir) => {
                let entries = export::list(&Source { catalog: &catalog, fetcher: self.fetcher.as_deref() }, &dir).map_err(|e| errno(&e))?;
                self.note_sizes(&entries);
                with_kinds(entries.into_iter().map(|entry| (entry.name, Inode::Node(entry.cid))).collect())?
            },
            Inode::Path(anchor, rel) => {
                let entries = self.overlay_entries(&catalog, &anchor, &rel)?;
                with_kinds(entries)?
            },
            Inode::Loose(_) => return Err(Errno::ENOTDIR),
        };
        drop(catalog);
        let mut inodes = self.inodes();
        Ok(children
            .into_iter()
            .map(|(name, inode, kind)| {
                let ino = match inode {
                    Inode::Root => TOP.iter().find(|(top, _)| top.as_bytes() == name).map_or(1, |&(_, ino)| ino),
                    inode => inodes.of(inode),
                };
                let kind = match kind {
                    Kind::File(_) => FileType::RegularFile,
                    Kind::Directory => FileType::Directory,
                    Kind::Symlink(_) => FileType::Symlink,
                };
                (name, ino, kind)
            })
            .collect())
    }

    /// Up to `size` bytes of a file from `offset`.
    pub fn read(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, Errno> {
        match self.inode(ino)? {
            Inode::Node(cid) => {
                let catalog = self.catalog()?;
                export::read_at(&Source { catalog: &catalog, fetcher: self.fetcher.as_deref() }, &cid, offset, size).map_err(|e| errno(&e))
            },
            Inode::Loose(name) => {
                let file = std::fs::File::open(self.loose_path(&name).ok_or(Errno::ENOENT)?).map_err(|e| errno(&e))?;
                read_file(&file, offset, size)
            },
            Inode::Path(anchor, rel) => {
                let catalog = self.catalog()?;
                match self.at(&catalog, &anchor, &rel)?.ok_or(Errno::ENOENT)? {
                    At::Work(meta) if meta.is_dir() => Err(Errno::EISDIR),
                    At::Work(_) => {
                        self.filler.fill(&catalog, &anchor, &rel, offset, size, None).map_err(|e| errno(&e))?;
                        let file = std::fs::File::open(self.work_path(&anchor, &rel).ok_or(Errno::ENOENT)?).map_err(|e| errno(&e))?;
                        read_file(&file, offset, size)
                    },
                    At::Base(cid, _) => export::read_at(&Source { catalog: &catalog, fetcher: self.fetcher.as_deref() }, &cid, offset, size).map_err(|e| errno(&e)),
                }
            },
            _ => Err(Errno::EISDIR),
        }
    }

    /// Where a symlink points.
    pub fn link(&self, ino: u64) -> Result<Vec<u8>, Errno> {
        let inode = self.inode(ino)?;
        match self.kind(&*self.catalog()?, &inode)? {
            Kind::Symlink(target) => Ok(target),
            _ => Err(Errno::EINVAL),
        }
    }
}

impl Drop for Soup {
    fn drop(&mut self) {
        // Only this thread's; the filesystem's thread ends with it
        let _ = CATALOGS.try_with(|catalogs| catalogs.borrow_mut().remove(&self.id));
    }
}

impl Filesystem for Soup {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.resolve(parent.0, name) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr(ino.0) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.link(ino.0) {
            Ok(target) => reply.data(&target),
            Err(e) => reply.error(e),
        }
    }

    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        self.start();
        Ok(())
    }

    fn destroy(&mut self) {
        self.finish();
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let write = flags.0 & libc::O_ACCMODE != libc::O_RDONLY;
        match self.open(ino.0, write, write && flags.0 & libc::O_TRUNC != 0) {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }

    fn read(&self, _req: &Request, ino: INodeNo, fh: FileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock: Option<LockOwner>, reply: ReplyData) {
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        match self.read_handle(fh.0, offset, size).unwrap_or_else(|| self.read(ino.0, offset, size)) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e),
        }
    }

    fn write(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, offset: u64, data: &[u8], _write_flags: WriteFlags, _flags: OpenFlags, _lock: Option<LockOwner>, reply: ReplyWrite) {
        match self.write(fh.0, offset, data) {
            Ok(n) => reply.written(u32::try_from(n).unwrap_or(u32::MAX)),
            Err(e) => reply.error(e),
        }
    }

    fn release(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _flags: OpenFlags, _lock: Option<LockOwner>, _flush: bool, reply: ReplyEmpty) {
        self.release(fh.0);
        reply.ok();
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _lock: LockOwner, reply: ReplyEmpty) {
        reply.ok();
    }

    fn fsync(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        reply.ok();
    }

    fn create(&self, _req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
        match self.create(parent.0, name) {
            Ok((attr, fh)) => reply.created(&TTL, &attr, Generation(0), FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        match self.mkdir(parent.0, name) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn symlink(&self, _req: &Request, parent: INodeNo, link_name: &OsStr, target: &Path, reply: ReplyEntry) {
        match self.symlink(parent.0, link_name, target) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.unlink(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.rmdir(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rename(&self, _req: &Request, parent: INodeNo, name: &OsStr, newparent: INodeNo, newname: &OsStr, flags: RenameFlags, reply: ReplyEmpty) {
        if flags.contains(RenameFlags::RENAME_EXCHANGE) {
            reply.error(Errno::EINVAL);
            return;
        }
        match self.rename(parent.0, name, newparent.0, newname, flags.contains(RenameFlags::RENAME_NOREPLACE)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    // Modes, owners and times aren't kept, as the UnixFS profile doesn't
    // keep them, so only a size changes anything
    #[allow(clippy::too_many_arguments, reason = "the trait's")]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Some(size) = size
            && let Err(e) = self.truncate(ino.0, fh.map(|fh| fh.0), size)
        {
            reply.error(e);
            return;
        }
        match self.attr(ino.0) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        // Listed once when opened, so reading it in parts is consistent
        match self.list(ino.0) {
            Ok(entries) => {
                let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
                self.listings.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(handle, std::sync::Arc::new(entries));
                reply.opened(FileHandle(handle), FopenFlags::empty());
            },
            Err(e) => reply.error(e),
        }
    }

    fn readdir(&self, _req: &Request, ino: INodeNo, fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        let listing = self.listings.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&fh.0).cloned();
        let Some(entries) = listing else {
            reply.error(Errno::EBADF);
            return;
        };
        let dots = [(b".".to_vec(), ino.0, FileType::Directory), (b"..".to_vec(), ino.0, FileType::Directory)];
        for (i, (name, child, kind)) in dots.iter().chain(entries.iter()).enumerate().skip(usize::try_from(offset).unwrap_or(usize::MAX)) {
            if reply.add(INodeNo(*child), u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1), *kind, OsStr::from_bytes(name)) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _flags: OpenFlags, reply: ReplyEmpty) {
        self.listings.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&fh.0);
        reply.ok();
    }
}

/// Mount the soup at `dir` until interrupted, or unmounted
/// (`fusermount3 -u`), then unmount it.
pub fn mount(soup: Soup, dir: &Path) -> io::Result<()> {
    let mut config = fuser::Config::default();
    config.mount_options = vec![MountOption::FSName("holokeep".into()), MountOption::Subtype("hk".into())];
    if soup.work.is_none() {
        config.mount_options.push(MountOption::RO);
    }
    // Signals wait for this thread to take them, so the filesystem's
    // threads, which inherit the mask, don't die of them still mounted
    let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initializes the set, and the rest only read it
    let signals = unsafe {
        libc::sigemptyset(signals.as_mut_ptr());
        let mut signals = signals.assume_init();
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&raw mut signals, signal);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, std::ptr::null_mut());
        signals
    };
    let session = fuser::spawn_mount(soup, dir, &config)?;
    let poll = libc::timespec { tv_sec: 0, tv_nsec: 200_000_000 };
    loop {
        if session.guard.is_finished() {
            // Unmounted from outside
            return session.join();
        }
        // SAFETY: both pointers are to initialized values that outlive the call
        if unsafe { libc::sigtimedwait(&raw const signals, std::ptr::null_mut(), &raw const poll) } > 0 {
            return session.umount_and_join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::cid::{AnyCid, CidVersion};
    use crate::import::Importer;
    use crate::testutil::Scratch;

    fn ino(soup: &Soup, path: &str) -> Result<FileAttr, Errno> {
        let mut attr = soup.attr(1)?;
        for name in path.split('/').filter(|name| !name.is_empty()) {
            attr = soup.resolve(attr.ino.0, OsStr::new(name))?;
        }
        Ok(attr)
    }

    fn names(soup: &Soup, path: &str) -> Vec<String> {
        let attr = ino(soup, path).expect("path");
        soup.list(attr.ino.0).expect("list").into_iter().map(|(name, _, _)| String::from_utf8(name).expect("utf-8")).collect()
    }

    fn read(soup: &Soup, path: &str) -> Vec<u8> {
        let attr = ino(soup, path).expect("path");
        soup.read(attr.ino.0, 0, usize::try_from(attr.size).expect("size")).expect("read")
    }

    #[test]
    fn the_soup_by_cid_anchor_and_tag() {
        let scratch = Scratch::new("mount");
        let t = scratch.path().join("t");
        std::fs::create_dir_all(t.join("sub")).expect("mkdir");
        std::fs::write(t.join("hello"), "hello world").expect("write");
        std::fs::write(t.join("sub/big"), vec![7u8; 300_000]).expect("write");
        std::os::unix::fs::symlink("hello", t.join("link")).expect("symlink");
        let repo = scratch.path().join("repo");
        let mut catalog = Catalog::open_repo(&repo).expect("catalog");
        let root = AnyCid::V1(Importer::default().add_path(&t, &mut catalog, &mut |_, _| {}).expect("import").expect("root").cid);
        let anchor = catalog.new_anchor().expect("anchor");
        catalog.set_anchor(&anchor, &root).expect("set");
        let hello: Block = Block::hash(crate::cid::Cidv1Spec::default(), b"hello world".as_slice().into());
        let hello = catalog.cid_of(hello.cid().multihash()).expect("cid").expect("cid");
        catalog.tag(&hello, &crate::claim::tag("greeting").expect("tag")).expect("tag");
        drop(catalog);
        let soup = Soup::new(Box::new(move || Catalog::open_repo(&repo)), None);

        assert_eq!(names(&soup, ""), ["cid", "anchors", "tags"]);
        assert!(names(&soup, "cid").is_empty());
        let by_cid = format!("cid/{root}");
        assert_eq!(names(&soup, &by_cid), ["hello", "link", "sub"]);
        assert_eq!(read(&soup, &format!("{by_cid}/hello")), b"hello world");
        assert_eq!(read(&soup, &format!("{by_cid}/sub/big")), vec![7u8; 300_000]);
        let big = ino(&soup, &format!("{by_cid}/sub/big")).expect("big");
        assert_eq!(big.kind, FileType::RegularFile);
        assert_eq!(soup.read(big.ino.0, 299_990, 100).expect("read").len(), 10);
        let link = ino(&soup, &format!("{by_cid}/link")).expect("link");
        assert_eq!((link.kind, soup.link(link.ino.0).expect("readlink")), (FileType::Symlink, b"hello".to_vec()));
        // A CID's one inode wherever it's reached, but an anchor's paths are
        // its own, being writable
        assert_eq!(ino(&soup, &format!("tags/greeting/{hello}")).expect("tagged").ino, ino(&soup, &format!("{by_cid}/hello")).expect("cid").ino);
        assert_ne!(ino(&soup, &format!("anchors/{anchor}")).expect("anchor").ino, ino(&soup, &by_cid).expect("cid").ino);
        assert_eq!(names(&soup, "anchors"), [anchor.to_string()]);
        assert_eq!(names(&soup, &format!("anchors/{anchor}/sub")), ["big"]);
        assert_eq!(names(&soup, "tags"), ["greeting"]);
        assert_eq!(names(&soup, "tags/greeting"), [hello.to_string()]);
        assert_eq!(read(&soup, &format!("tags/greeting/{hello}")), b"hello world");

        // The empty identity CID is an empty file, but nothing else not here is anything
        assert_eq!(ino(&soup, "cid/bafkqaaa").expect("identity").size, 0);
        let absent: Block = Block::hash(crate::cid::Cidv1Spec::default(), b"absent".as_slice().into());
        let absent = format!("cid/{}", AnyCid::V1(absent.cid().clone()));
        for missing in ["nope", "cid/nope", &absent, &format!("{by_cid}/nope"), "tags/nope", &format!("anchors/{root}")] {
            assert_eq!(ino(&soup, missing).err(), Some(Errno::ENOENT), "{missing}");
        }
        assert_eq!(soup.read(ino(&soup, &by_cid).expect("dir").ino.0, 0, 1).err(), Some(Errno::EISDIR));
    }

    #[test]
    fn listing_fetches_no_files() {
        use crate::store::BlockIndex as _;
        let scratch = Scratch::new("mount-list");
        let t = scratch.path().join("t");
        std::fs::create_dir_all(t.join("sub")).expect("mkdir");
        for i in 0..5 {
            std::fs::write(t.join(format!("f{i}")), vec![b'x'; 1000 * (i + 1)]).expect("write");
        }
        std::fs::write(t.join("sub/g"), "under").expect("write");
        let mut there = Catalog::open_repo(&scratch.path().join("there")).expect("catalog");
        let root = AnyCid::V1(Importer::default().add_path(&t, &mut there, &mut |_, _| {}).expect("import").expect("root").cid);
        // Here: the structure, none of the files
        let here = scratch.path().join("here");
        let catalog = Catalog::open_repo(&here).expect("catalog");
        for key in there.keys().expect("keys") {
            let cid = there.cid_of(key.as_ref()).expect("cid").expect("cid");
            if cid.codec() != crate::cid::RAW_CODEC {
                catalog.put_block(&there.get_block(&cid).expect("get").expect("block"), CidVersion::V1).expect("put");
            }
        }
        drop(catalog);
        let asked = std::sync::Arc::new(Mutex::new(Vec::<Link>::new()));
        let noted = std::sync::Arc::clone(&asked);
        let fetcher: Fetcher = Box::new(move |cids: &[Link]| {
            noted.lock().expect("lock").extend_from_slice(cids);
            false
        });
        let soup = Soup::new(Box::new(move || Catalog::open_repo(&here)), Some(fetcher));
        let dir = ino(&soup, &format!("cid/{root}")).expect("dir");
        let entries = soup.list(dir.ino.0).expect("list");
        assert_eq!(entries.len(), 6);
        for i in 0..5 {
            let attr = ino(&soup, &format!("cid/{root}/f{i}")).expect("file");
            assert_eq!((attr.kind, attr.size), (FileType::RegularFile, 1000 * (i + 1)));
        }
        assert_eq!(names(&soup, &format!("cid/{root}/sub")), ["g"]);
        assert!(asked.lock().expect("lock").is_empty(), "nothing fetched to list: {:?}", asked.lock().expect("lock"));
        // Reading is what fetches
        let f0 = ino(&soup, &format!("cid/{root}/f0")).expect("file");
        assert_eq!(soup.read(f0.ino.0, 0, 10).err(), Some(Errno::ENOENT));
        assert_eq!(asked.lock().expect("lock").len(), 1);
    }

    /// A soup over an anchor of a small tree, writable, and the anchor.
    fn writable(scratch: &Scratch) -> (Soup, Link, PathBuf) {
        let t = scratch.path().join("t");
        std::fs::create_dir_all(t.join("dir/deep")).expect("mkdir");
        std::fs::write(t.join("a"), "first").expect("write");
        std::fs::write(t.join("big"), vec![3u8; 3_000_000]).expect("write");
        std::fs::write(t.join("dir/b"), "bee").expect("write");
        std::fs::write(t.join("dir/deep/c"), "sea").expect("write");
        let repo = scratch.path().join("repo");
        let mut catalog = Catalog::open_repo(&repo).expect("catalog");
        let importer = Importer { hidden: true, ..Importer::default() };
        let root = AnyCid::V1(importer.add_path(&t, &mut catalog, &mut |_, _| {}).expect("import").expect("root").cid);
        let anchor = catalog.new_anchor().expect("anchor");
        catalog.set_anchor(&anchor, &root).expect("set");
        drop(catalog);
        let opened = repo.clone();
        let soup = Soup::new(Box::new(move || Catalog::open_repo(&opened)), None).writable(repo.join("work"));
        (soup, anchor, repo)
    }

    /// What the anchor is now, imported from scratch for comparing.
    fn expect_tree(scratch: &Scratch, files: &[(&str, &[u8])]) -> Link {
        let t = scratch.path().join("expected");
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).expect("mkdir");
        for (path, data) in files {
            let path = t.join(path);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, data).expect("write");
        }
        let mut catalog = Catalog::standard(crate::store::Db::memory().expect("db")).expect("catalog");
        let importer = Importer { hidden: true, ..Importer::default() };
        AnyCid::V1(importer.add_path(&t, &mut catalog, &mut |_, _| {}).expect("import").expect("root").cid)
    }

    fn value(repo: &Path, anchor: &Link) -> Link {
        Catalog::open_repo(repo).expect("catalog").anchor_value(anchor).expect("value").expect("set")
    }

    #[test]
    fn writing_to_an_anchor_sets_it() {
        let scratch = Scratch::new("mount-write");
        let (soup, anchor, repo) = writable(&scratch);
        let at = |path: &str| ino(&soup, &format!("anchors/{anchor}/{path}"));
        let top = at("").expect("anchor").ino.0;
        let big = vec![3u8; 3_000_000];

        // Rewriting part of a file copies it to write, then reads what's written
        let a = at("a").expect("a");
        assert_eq!(a.perm, 0o644);
        let fh = soup.open(a.ino.0, true, false).expect("open");
        soup.write(fh, 0, b"F").expect("write");
        assert_eq!(soup.read_handle(fh, 0, 100).expect("handle").expect("read"), b"First");
        soup.release(fh);
        assert_eq!(read(&soup, &format!("anchors/{anchor}/a")), b"First");
        soup.commit();
        let first = expect_tree(&scratch, &[("a", b"First"), ("big", &big), ("dir/b", b"bee"), ("dir/deep/c", b"sea")]);
        assert_eq!(value(&repo, &anchor), first);

        // An editor's save: a new file written, renamed over the old one
        let (_, fh) = soup.create(top, OsStr::new(".a.swp")).expect("create");
        soup.write(fh, 0, b"second").expect("write");
        soup.release(fh);
        let swp = at(".a.swp").expect("swp").ino.0;
        soup.rename(top, OsStr::new(".a.swp"), top, OsStr::new("a"), false).expect("rename");
        // The kernel keeps the renamed file's inode, so it's the file's new path
        assert_eq!(soup.read(swp, 0, 100).expect("read"), b"second");
        // A directory made, one removed, and one moved, copying nothing
        let dir = at("dir").expect("dir").ino.0;
        soup.mkdir(top, OsStr::new("new")).expect("mkdir");
        soup.symlink(at("new").expect("new").ino.0, OsStr::new("link"), Path::new("../a")).expect("symlink");
        soup.unlink(dir, OsStr::new("b")).expect("unlink");
        assert_eq!(soup.rmdir(dir, OsStr::new("deep")).err(), Some(Errno::ENOTEMPTY));
        let deep_c = at("dir/deep/c").expect("c").ino.0;
        soup.rename(dir, OsStr::new("deep"), top, OsStr::new("moved"), false).expect("rename");
        assert_eq!(soup.read(deep_c, 0, 100).expect("read"), b"sea", "and what's under a renamed directory");
        assert_eq!(soup.rmdir(top, OsStr::new("dir")).err(), None, "empty now");
        // Truncating, without opening
        soup.truncate(at("big").expect("big").ino.0, None, 10).expect("truncate");
        assert!(!scratch.path().join("repo/work").join(anchor.to_string()).join("moved").exists(), "moved by marks alone");

        assert_eq!(names(&soup, &format!("anchors/{anchor}")), ["a", "big", "moved", "new"]);
        assert_eq!(read(&soup, &format!("anchors/{anchor}/moved/c")), b"sea");
        assert_eq!(at("big").expect("big").size, 10);
        soup.commit();
        let with_link = value(&repo, &anchor);
        // expect_tree writes no symlinks, so compare once it's gone too
        soup.unlink(at("new").expect("new").ino.0, OsStr::new("link")).expect("unlink");
        soup.rmdir(top, OsStr::new("new")).expect("rmdir");
        soup.commit();
        assert_eq!(value(&repo, &anchor), expect_tree(&scratch, &[("a", b"second"), ("big", &big[..10]), ("moved/c", b"sea")]));
        assert_ne!(with_link, value(&repo, &anchor));

        // Anchors, but not what's under cid/, are writable
        let root = value(&repo, &anchor);
        let by_cid = ino(&soup, &format!("cid/{root}/a")).expect("a");
        assert_eq!(soup.open(by_cid.ino.0, true, false).err(), Some(Errno::EROFS));
        assert_eq!(by_cid.perm, 0o444);
    }

    /// What of a file of an anchor is still to be copied, by chunk.
    fn unfilled(repo: &Path) -> Vec<Vec<u64>> {
        Catalog::open_repo(repo).expect("catalog").partials().expect("partials").iter()
            .map(|partial| (0..partial.len.div_ceil(overlay::CHUNK)).filter(|&chunk| !partial.is_filled(chunk)).collect())
            .collect()
    }

    #[test]
    fn a_big_file_is_copied_as_its_read_and_written() {
        let scratch = Scratch::new("mount-partial");
        let (soup, anchor, repo) = writable(&scratch);
        let mut big = vec![3u8; 3_000_000];
        let file = ino(&soup, &format!("anchors/{anchor}/big")).expect("big").ino.0;
        // Opened to write, nothing's copied, but it's as big as it was
        let fh = soup.open(file, true, false).expect("open");
        let work = repo.join("work").join(anchor.to_string()).join("big");
        assert_eq!(std::fs::metadata(&work).expect("work").len(), 3_000_000);
        assert_eq!(unfilled(&repo), [vec![0, 1, 2]]);
        // A write fills the chunk it's in first, and only that
        soup.write(fh, 1_500_000, b"middle").expect("write");
        big[1_500_000..1_500_006].copy_from_slice(b"middle");
        assert_eq!(unfilled(&repo), [vec![0, 2]]);
        // A read fills what it reads
        assert_eq!(soup.read_handle(fh, 2_999_990, 100).expect("handle").expect("read"), &big[2_999_990..]);
        assert_eq!(unfilled(&repo), [vec![0]]);
        // A write over a whole chunk needn't fetch it
        let chunk = usize::try_from(overlay::CHUNK).expect("chunk");
        soup.write(fh, 0, &vec![9u8; chunk]).expect("write");
        big[..chunk].fill(9);
        assert!(unfilled(&repo).is_empty(), "all filled, and forgotten");
        soup.release(fh);
        soup.commit();
        let expected = expect_tree(&scratch, &[("a", b"first"), ("big", &big), ("dir/b", b"bee"), ("dir/deep/c", b"sea")]);
        assert_eq!(value(&repo, &anchor), expected);
    }

    #[test]
    fn whats_left_to_copy_is_copied_when_next_mounted() {
        let scratch = Scratch::new("mount-partial-recover");
        let (soup, anchor, repo) = writable(&scratch);
        let file = ino(&soup, &format!("anchors/{anchor}/big")).expect("big").ino.0;
        let fh = soup.open(file, true, false).expect("open");
        soup.write(fh, 10, b"x").expect("write");
        soup.release(fh);
        // Gone before it committed, or copied the rest
        drop(soup);
        assert_eq!(unfilled(&repo), [vec![1, 2]]);
        let opened = repo.clone();
        let again = Soup::new(Box::new(move || Catalog::open_repo(&opened)), None).writable(repo.join("work"));
        again.committer.recover();
        assert!(unfilled(&repo).is_empty());
        let mut big = vec![3u8; 3_000_000];
        big[10] = b'x';
        assert_eq!(value(&repo, &anchor), expect_tree(&scratch, &[("a", b"first"), ("big", &big), ("dir/b", b"bee"), ("dir/deep/c", b"sea")]));
    }

    #[test]
    fn a_file_anchor_is_written_and_saved_over() {
        let scratch = Scratch::new("mount-file-anchor");
        let repo = scratch.path().join("repo");
        std::fs::write(scratch.path().join("abc.txt"), "before").expect("write");
        let mut catalog = Catalog::open_repo(&repo).expect("catalog");
        let file = AnyCid::V1(Importer::default().add_path(&scratch.path().join("abc.txt"), &mut catalog, &mut |_, _| {}).expect("import").expect("root").cid);
        let anchor = catalog.new_anchor().expect("anchor");
        catalog.set_anchor(&anchor, &file).expect("set");
        drop(catalog);
        let opened = repo.clone();
        let soup = Soup::new(Box::new(move || Catalog::open_repo(&opened)), None).writable(repo.join("work"));
        let anchors = ino(&soup, "anchors").expect("anchors").ino.0;
        let name = anchor.to_string();
        let at = ino(&soup, &format!("anchors/{name}")).expect("anchor");
        assert_eq!(at.kind, FileType::RegularFile);
        // Written in place
        let fh = soup.open(at.ino.0, true, false).expect("open");
        soup.write(fh, 6, b" and after").expect("write");
        soup.release(fh);
        soup.commit();
        assert_eq!(value(&repo, &anchor), expect_file(b"before and after"));
        // Saved over, as an editor does: a loose file beside it, renamed
        let (_, fh) = soup.create(anchors, OsStr::new("abc.txt~tmp")).expect("create");
        soup.write(fh, 0, b"rewritten").expect("write");
        soup.release(fh);
        assert!(names(&soup, "anchors").contains(&"abc.txt~tmp".to_owned()));
        let tmp = ino(&soup, "anchors/abc.txt~tmp").expect("tmp").ino.0;
        soup.rename(anchors, OsStr::new("abc.txt~tmp"), anchors, OsStr::new(&name), false).expect("rename");
        assert_eq!(soup.read(tmp, 0, 100).expect("read"), b"rewritten", "the kernel's inode is the anchor's now");
        assert_eq!(names(&soup, "anchors"), std::slice::from_ref(&name));
        soup.commit();
        assert_eq!(value(&repo, &anchor), expect_file(b"rewritten"));
        // Anchors themselves stay
        assert_eq!(soup.unlink(anchors, OsStr::new(&name)).err(), Some(Errno::EPERM));
        assert_eq!(soup.rename(anchors, OsStr::new(&name), anchors, OsStr::new("elsewhere"), false).err(), Some(Errno::EPERM));
    }

    fn expect_file(data: &[u8]) -> Link {
        AnyCid::V1(Importer::default().add_file(data, &mut crate::dag::NullSink).expect("import").cid)
    }

    #[test]
    fn another_accounts_blocks_arent_there() {
        let scratch = Scratch::new("mount-accounts");
        let repo = scratch.path().to_path_buf();
        let mut catalog = Catalog::open_repo(&repo).expect("catalog");
        let block = Block::hash(crate::cid::Cidv1Spec::default(), b"someone else's".as_slice().into());
        catalog.act_for(1, crate::keys::Key::generate().expect("key")).expect("act");
        catalog.put_block(&block, CidVersion::V1).expect("put");
        drop(catalog);
        let soup = Soup::new(
            Box::new(move || {
                let mut catalog = Catalog::open_repo(&repo)?;
                catalog.act_for(2, crate::keys::Key::generate().map_err(|e| crate::store::Error::Invalid { store: "test", reason: e.to_string() })?)?;
                Ok(catalog)
            }),
            None,
        );
        let cid = AnyCid::V1(block.cid().clone());
        assert_eq!(ino(&soup, &format!("cid/{cid}")).err(), Some(Errno::ENOENT));
    }
}
