//! `hk mount`: the soup as a read-only filesystem, over FUSE.
//!
//! ```text
//! cid/<cid>/…         whatever's at a CID; looked up by name, not listed
//! anchors/<anchor>/…  what each anchor is now
//! tags/<tag>/<cid>/…  what's tagged so
//! ```
//!
//! UnixFS directories are directories, files files and symlinks symlinks;
//! a block of any other codec reads as its bytes. A file's read fetches
//! only the parts of it the read is in. What isn't here is asked of the
//! running node, which fetches just those blocks from members, all of a
//! read's or a directory's entries at once, and what's
//! another account's is as good as not here, as for `hk cat`. Anchors and
//! tags are looked up again every second, so the mount follows them.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenFlags, ReplyAttr,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, Request,
};

use crate::cid::{BaseCid as _, CidRef as _};
use crate::export::{self, Fetch, Kind};
use crate::model::Link;
use crate::store::Catalog;

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

    fn of(&mut self, inode: Inode) -> u64 {
        let key = match &inode {
            Inode::Tag(tag) => [b"t".as_slice(), &tag.to_bytes()].concat(),
            Inode::Node(cid) => [b"n".as_slice(), &cid.to_bytes()].concat(),
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
    open: Opener,
    fetcher: Option<Fetcher>,
    inodes: Mutex<Inodes>,
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
        Self {
            id: SOUPS.fetch_add(1, Ordering::Relaxed),
            open,
            fetcher,
            inodes: Mutex::new(Inodes::new()),
            listings: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            at: SystemTime::now(),
        }
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

    fn kind(&self, catalog: &Catalog, inode: &Inode) -> Result<Kind, Errno> {
        match inode {
            Inode::Node(cid) => export::stat(&Source { catalog, fetcher: self.fetcher.as_ref() }, cid).map_err(|e| errno(&e)),
            _ => Ok(Kind::Directory),
        }
    }

    fn attr_of(&self, ino: u64, kind: &Kind) -> FileAttr {
        let (kind, size, perm, nlink) = match kind {
            Kind::File(size) => (FileType::RegularFile, *size, 0o444, 1),
            Kind::Directory => (FileType::Directory, 0, 0o555, 2),
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
        Ok(self.attr_of(ino, &kind))
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
            Inode::Anchors => {
                let claims = catalog.claims().ok_or(Errno::ENOENT)?;
                let value = claims.value_of(cid(name)?.multihash()).map_err(store_errno)?.ok_or(Errno::ENOENT)?;
                if !self.reachable(&catalog, &value)? {
                    return Err(Errno::ENOENT);
                }
                Inode::Node(value)
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
                let entries = export::list(&Source { catalog: &catalog, fetcher: self.fetcher.as_ref() }, &dir).map_err(|e| errno(&e))?;
                let (_, cid) = entries.into_iter().find(|(entry, _)| entry.as_slice() == name.as_bytes()).ok_or(Errno::ENOENT)?;
                Inode::Node(cid)
            },
        };
        let kind = self.kind(&catalog, &inode)?;
        drop(catalog);
        let ino = self.inodes().of(inode);
        Ok(self.attr_of(ino, &kind))
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
                        found.push((anchor.to_string().into_bytes(), Inode::Node(value)));
                    }
                }
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
                let entries = export::list(&Source { catalog: &catalog, fetcher: self.fetcher.as_ref() }, &dir).map_err(|e| errno(&e))?;
                with_kinds(entries.into_iter().map(|(name, cid)| (name, Inode::Node(cid))).collect())?
            },
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
                export::read_at(&Source { catalog: &catalog, fetcher: self.fetcher.as_ref() }, &cid, offset, size).map_err(|e| errno(&e))
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

    fn read(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock: Option<LockOwner>, reply: ReplyData) {
        match self.read(ino.0, offset, usize::try_from(size).unwrap_or(usize::MAX)) {
            Ok(data) => reply.data(&data),
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
    config.mount_options = vec![MountOption::RO, MountOption::FSName("holokeep".into()), MountOption::Subtype("hk".into())];
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
        // One inode wherever it's reached
        assert_eq!(ino(&soup, &format!("anchors/{anchor}")).expect("anchor").ino, ino(&soup, &by_cid).expect("cid").ino);
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
