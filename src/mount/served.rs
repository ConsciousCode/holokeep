//! Anchors served live, through the mount (see `crate::served`, and the
//! wiki's Servers page).
//!
//! An anchor whose serve claim names this node, and a service this node's
//! configuration has, is a directory of the service's tree: each path of
//! it walked from a root attached for that anchor, and nothing of it
//! cached, so what's seen is what the server says now. The mount speaks
//! to the service itself, as the user it runs as: no one else's
//! credentials are ever used to reach it. A connection that's gone is made
//! again on the next request; meanwhile what's served fails `ENOTCONN`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use fuser::{Errno, FileAttr, FileType, INodeNo};

use super::{Entry, Inode, Inodes, Soup, Via};

use crate::cid::CidRef as _;
use crate::export::Kind;
use crate::model::Link;
use crate::ninep::client::Client;
use crate::ninep::{self, Attr, DirEntry, SetAttr};
use crate::store::Catalog;

/// A connection to a service, and the root it's attached for each anchor,
/// by the anchor's bytes.
pub(super) struct Conn {
    client: Client,
    roots: Mutex<HashMap<Vec<u8>, u32>>,
}

/// What a served anchor is served from, and who's asking.
pub(super) struct Place<'a> {
    pub anchor: &'a Link,
    pub service: &'a str,
}

/// The services a mount reaches anchors' trees through.
pub(super) struct Servers {
    /// The repo, whose configuration says what each service is.
    repo: Option<PathBuf>,
    /// This node's peer ID, as serve claims name it.
    node: Option<Vec<u8>>,
    conns: Mutex<HashMap<String, Arc<Conn>>>,
    /// Files open, by handle: their connection and fid.
    handles: Mutex<HashMap<u64, (Arc<Conn>, u32)>>,
    /// Who's asking, as `Tattach` says: the user's root key, or the device
    /// key, as text, and their uid here.
    uname: Mutex<Option<Vec<u8>>>,
    uid: u32,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An errno from a 9P error, `EIO` if it's none.
pub(super) fn errno(e: io::Error) -> Errno {
    if e.raw_os_error().is_some() { Errno::from(e) } else { Errno::EIO }
}

impl Servers {
    /// None served: what's mounted without a node.
    pub fn none() -> Self {
        Self { repo: None, node: None, conns: Mutex::default(), handles: Mutex::default(), uname: Mutex::default(), uid: rustix::process::getuid().as_raw() }
    }

    /// Anchors served by this node, as its peer ID, from the services the
    /// repo's configuration says.
    pub fn new(repo: PathBuf, node: Vec<u8>) -> Self {
        Self { repo: Some(repo), node: Some(node), ..Self::none() }
    }

    /// The service of this node's an anchor's served from, if it's served
    /// by this node.
    pub fn route(&self, catalog: &Catalog, anchor: &Link) -> Result<Option<String>, Errno> {
        let Some(node) = &self.node else {
            return Ok(None);
        };
        let serving = catalog.serving(anchor).map_err(|_| Errno::EIO)?;
        Ok(serving.filter(|serve| serve.node() == node.as_slice()).map(|serve| serve.service().to_owned()))
    }

    /// Note who's asking, as the catalog says, the first time.
    pub fn know(&self, catalog: &Catalog) {
        let mut uname = lock(&self.uname);
        if uname.is_none() {
            let user = catalog.user().ok().flatten().or_else(|| catalog.signer().map(crate::keys::Key::id));
            *uname = Some(user.map(|user| user.to_string().into_bytes()).unwrap_or_default());
        }
    }

    /// The connection to a service, made again if it's gone.
    fn conn(&self, service: &str) -> Result<Arc<Conn>, Errno> {
        {
            let mut conns = lock(&self.conns);
            if let Some(conn) = conns.get(service) {
                if !conn.client.closed() {
                    return Ok(Arc::clone(conn));
                }
                conns.remove(service);
            }
        }
        let repo = self.repo.as_deref().ok_or(Errno::ENOTCONN)?;
        let client = crate::served::service(repo, service).and_then(|service| crate::served::connect(&service)).map_err(|e| {
            eprintln!("serving: {e}");
            match e {
                crate::served::Error::Unfit(_) | crate::served::Error::Unknown(_) | crate::served::Error::Config(_) => Errno::EACCES,
                crate::served::Error::Io(..) => Errno::ENOTCONN,
            }
        })?;
        let conn = Arc::new(Conn { client, roots: Mutex::default() });
        // Another thread may have connected meanwhile: either does
        Ok(Arc::clone(lock(&self.conns).entry(service.to_owned()).or_insert(conn)))
    }

    /// A fid for a path of a served anchor, which whoever has it clunks.
    pub fn walk(&self, place: &Place<'_>, rel: &Path) -> Result<(Arc<Conn>, u32), Errno> {
        let conn = self.conn(place.service)?;
        let root = {
            let key = place.anchor.to_bytes();
            let known = lock(&conn.roots).get(&key).copied();
            if let Some(root) = known {
                root
            } else {
                let uname = lock(&self.uname).clone().unwrap_or_default();
                let (root, _) = conn.client.attach(&uname, place.anchor.to_string().as_bytes(), self.uid).map_err(errno)?;
                lock(&conn.roots).insert(key, root);
                root
            }
        };
        let names: Vec<&[u8]> = rel.iter().map(OsStr::as_bytes).collect();
        let (fid, _) = conn.client.walk(root, &names).map_err(errno)?;
        Ok((conn, fid))
    }

    /// Do something with a fid for a path, then clunk it.
    fn with<T>(&self, place: &Place<'_>, rel: &Path, f: impl FnOnce(&Client, u32) -> io::Result<T>) -> Result<T, Errno> {
        let (conn, fid) = self.walk(place, rel)?;
        let result = f(&conn.client, fid);
        let _ = conn.client.clunk(fid);
        result.map_err(errno)
    }

    pub fn getattr(&self, place: &Place<'_>, rel: &Path) -> Result<Attr, Errno> {
        self.with(place, rel, Client::getattr)
    }

    pub fn readlink(&self, place: &Place<'_>, rel: &Path) -> Result<Vec<u8>, Errno> {
        self.with(place, rel, Client::readlink)
    }

    /// A directory's entries, but `.` and `..`.
    pub fn list(&self, place: &Place<'_>, rel: &Path) -> Result<Vec<DirEntry>, Errno> {
        let mut entries = self.with(place, rel, |client, fid| {
            client.lopen(fid, 0)?;
            client.readdir_all(fid)
        })?;
        entries.retain(|entry| entry.name != b"." && entry.name != b"..");
        Ok(entries)
    }

    /// Open a path, with Linux's open flags, as a handle.
    pub fn open(&self, place: &Place<'_>, rel: &Path, flags: i32, fh: u64) -> Result<(), Errno> {
        let (conn, fid) = self.walk(place, rel)?;
        if let Err(e) = conn.client.lopen(fid, open_flags(flags)) {
            let _ = conn.client.clunk(fid);
            return Err(errno(e));
        }
        lock(&self.handles).insert(fh, (conn, fid));
        Ok(())
    }

    /// Make a file in a directory, with open flags, a mode and a group,
    /// opened as a handle, and say what it is.
    pub fn create(&self, place: &Place<'_>, dir: &Path, name: &[u8], (flags, mode, gid): (i32, u32, u32), fh: u64) -> Result<Attr, Errno> {
        let (conn, fid) = self.walk(place, dir)?;
        let opened = conn.client.lcreate(fid, name, open_flags(flags), mode, gid).and_then(|_| conn.client.getattr(fid));
        match opened {
            Ok(attr) => {
                lock(&self.handles).insert(fh, (conn, fid));
                Ok(attr)
            },
            Err(e) => {
                let _ = conn.client.clunk(fid);
                Err(errno(e))
            },
        }
    }

    /// Whether a handle's one of a served file.
    pub fn holds(&self, fh: u64) -> bool {
        lock(&self.handles).contains_key(&fh)
    }

    fn handle(&self, fh: u64) -> Option<(Arc<Conn>, u32)> {
        lock(&self.handles).get(&fh).cloned()
    }

    /// Up to `size` bytes from `offset` of an open file, in as many reads
    /// as that takes, short only at its end.
    pub fn read(&self, fh: u64, offset: u64, size: usize) -> Option<Result<Vec<u8>, Errno>> {
        let (conn, fid) = self.handle(fh)?;
        let mut data = Vec::new();
        while data.len() < size {
            let at = offset.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
            let want = u32::try_from(size.saturating_sub(data.len())).unwrap_or(u32::MAX);
            match conn.client.read(fid, at, want) {
                Ok(got) if got.is_empty() => break,
                Ok(got) => data.extend(got),
                Err(e) => return Some(Err(errno(e))),
            }
        }
        Some(Ok(data))
    }

    /// Write to an open file, in as many writes as that takes.
    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> Option<Result<usize, Errno>> {
        let (conn, fid) = self.handle(fh)?;
        let mut written = 0usize;
        while written < data.len() {
            let at = offset.saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
            match conn.client.write(fid, at, data.get(written..).unwrap_or_default()) {
                Ok(0) => return Some(Err(Errno::EIO)),
                Ok(n) => written = written.saturating_add(usize::try_from(n).unwrap_or(usize::MAX)),
                Err(e) => return Some(Err(errno(e))),
            }
        }
        Some(Ok(written))
    }

    pub fn fsync(&self, fh: u64, datasync: bool) -> Option<Result<(), Errno>> {
        let (conn, fid) = self.handle(fh)?;
        Some(conn.client.fsync(fid, datasync).map_err(errno))
    }

    /// Close an open file, if it's one of these.
    pub fn release(&self, fh: u64) -> bool {
        let Some((conn, fid)) = lock(&self.handles).remove(&fh) else {
            return false;
        };
        let _ = conn.client.clunk(fid);
        true
    }

    pub fn mkdir(&self, place: &Place<'_>, dir: &Path, name: &[u8], mode: u32, gid: u32) -> Result<(), Errno> {
        self.with(place, dir, |client, fid| client.mkdir(fid, name, mode, gid).map(drop))
    }

    pub fn symlink(&self, place: &Place<'_>, dir: &Path, name: &[u8], target: &[u8], gid: u32) -> Result<(), Errno> {
        self.with(place, dir, |client, fid| client.symlink(fid, name, target, gid).map(drop))
    }

    pub fn unlink(&self, place: &Place<'_>, dir: &Path, name: &[u8], directory: bool) -> Result<(), Errno> {
        let flags = if directory { ninep::AT_REMOVEDIR } else { 0 };
        self.with(place, dir, |client, fid| client.unlinkat(fid, name, flags))
    }

    /// Rename within one served anchor.
    pub fn rename(&self, place: &Place<'_>, from: (&Path, &[u8]), to: (&Path, &[u8])) -> Result<(), Errno> {
        let (conn, from_fid) = self.walk(place, from.0)?;
        let renamed = match self.walk(place, to.0) {
            Ok((_, to_fid)) => {
                let renamed = conn.client.renameat(from_fid, from.1, to_fid, to.1).map_err(errno);
                let _ = conn.client.clunk(to_fid);
                renamed
            },
            Err(e) => Err(e),
        };
        let _ = conn.client.clunk(from_fid);
        renamed
    }

    pub fn setattr(&self, place: &Place<'_>, rel: &Path, attr: SetAttr) -> Result<(), Errno> {
        self.with(place, rel, |client, fid| client.setattr(fid, attr))
    }
}

/// Linux's open flags, as 9P2000.L carries them: what's to do with the
/// file, not how this process holds it.
const fn open_flags(flags: i32) -> u32 {
    (flags & (libc::O_ACCMODE | libc::O_TRUNC | libc::O_APPEND | libc::O_EXCL | libc::O_DIRECTORY)).cast_unsigned()
}

/// What `setattr` asks of a served file, as 9P2000.L says it: a mode's
/// permissions, a size, and times.
pub(super) fn set_attr(mode: Option<u32>, size: Option<u64>, atime: Option<fuser::TimeOrNow>, mtime: Option<fuser::TimeOrNow>) -> SetAttr {
    let mut attr = SetAttr::default();
    if let Some(mode) = mode {
        attr.valid |= ninep::SETATTR_MODE;
        attr.mode = mode;
    }
    if let Some(size) = size {
        attr.valid |= ninep::SETATTR_SIZE;
        attr.size = size;
    }
    let mut times = |at: Option<fuser::TimeOrNow>, valid: u32, set: u32| -> Option<ninep::Time> {
        match at? {
            fuser::TimeOrNow::Now => {
                attr.valid |= valid;
                None
            },
            fuser::TimeOrNow::SpecificTime(at) => {
                attr.valid |= valid | set;
                let since = at.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
                Some((since.as_secs(), u64::from(since.subsec_nanos())))
            },
        }
    };
    let atime = times(atime, ninep::SETATTR_ATIME, ninep::SETATTR_ATIME_SET);
    let mtime = times(mtime, ninep::SETATTR_MTIME, ninep::SETATTR_MTIME_SET);
    attr.atime = atime.unwrap_or_default();
    attr.mtime = mtime.unwrap_or_default();
    attr
}

/// A time as 9P carries it.
fn time((sec, nsec): ninep::Time) -> SystemTime {
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(sec, u32::try_from(nsec).unwrap_or_default())).unwrap_or(SystemTime::UNIX_EPOCH)
}

/// What kind of file a mode says.
pub(super) const fn file_type(mode: u32) -> FileType {
    match mode & 0o170_000 {
        0o040_000 => FileType::Directory,
        0o120_000 => FileType::Symlink,
        _ => FileType::RegularFile,
    }
}

/// What kind of file a directory entry's type says.
pub(super) const fn entry_type(kind: u8) -> FileType {
    match kind {
        4 => FileType::Directory,
        10 => FileType::Symlink,
        _ => FileType::RegularFile,
    }
}

/// Attributes as the server says, owned by whoever mounted it.
pub(super) fn file_attr(ino: u64, attr: &Attr, uid: u32, gid: u32) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: time(attr.atime),
        mtime: time(attr.mtime),
        ctime: time(attr.ctime),
        crtime: time(attr.btime),
        kind: file_type(attr.mode),
        perm: u16::try_from(attr.mode & 0o7777).unwrap_or(0o644),
        nlink: u32::try_from(attr.nlink).unwrap_or(1).max(1),
        uid,
        gid,
        rdev: 0,
        blksize: u32::try_from(attr.blksize).unwrap_or(4096).max(512),
        flags: 0,
    }
}

/// What a request of something served needs, apart from the mount, so it
/// can be answered on a thread of the pool's: the services, and the inodes
/// and handles it hands out.
#[derive(Clone)]
pub(super) struct Ctx {
    servers: Arc<Servers>,
    inodes: Arc<Mutex<Inodes>>,
    next_handle: Arc<AtomicU64>,
    uid: u32,
    gid: u32,
}

impl Ctx {
    fn inodes(&self) -> std::sync::MutexGuard<'_, Inodes> {
        lock(&self.inodes)
    }

    /// Where a served inode is: its anchor, service, path and where the
    /// anchor's reached; or None if it's not served.
    pub fn at(&self, ino: u64) -> Option<(Link, String, PathBuf, Via)> {
        let inode = self.inodes().get(ino)?;
        match inode {
            Inode::Served(anchor, service, rel, via) => Some((anchor, service, rel, via)),
            _ => None,
        }
    }

    fn handle(&self) -> u64 {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

    /// An inode's attributes, as its server says.
    pub fn attr(&self, ino: u64) -> Result<FileAttr, Errno> {
        let (anchor, service, rel, _) = self.at(ino).ok_or(Errno::ENOENT)?;
        let attr = self.servers.getattr(&Place { anchor: &anchor, service: &service }, &rel)?;
        Ok(file_attr(ino, &attr, self.uid, self.gid))
    }

    /// What's at a path of a served anchor, reached where the anchor is.
    ///
    /// The anchor itself is a directory, without asking, since what a
    /// server's attached to is: it's looked up from what isn't served, on
    /// the mount's own threads, which mustn't wait on a server. What it's
    /// like as its server says is for `attr`, on the pool's.
    pub fn resolve(&self, anchor: Link, service: String, rel: PathBuf, via: Via) -> Result<FileAttr, Errno> {
        let attr = if rel.as_os_str().is_empty() {
            Attr { mode: 0o040_755, nlink: 2, blksize: 4096, ..Attr::default() }
        } else {
            self.servers.getattr(&Place { anchor: &anchor, service: &service }, &rel)?
        };
        let ino = self.inodes().of(Inode::Served(anchor, service, rel, via));
        Ok(file_attr(ino, &attr, self.uid, self.gid))
    }

    /// What a name in a served directory is.
    pub fn lookup(&self, parent: u64, name: &OsStr) -> Result<FileAttr, Errno> {
        let (anchor, service, rel, via) = self.at(parent).ok_or(Errno::ENOENT)?;
        self.resolve(anchor, service, rel.join(name), via)
    }

    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, Errno> {
        let (anchor, service, rel, _) = self.at(ino).ok_or(Errno::ENOENT)?;
        self.servers.readlink(&Place { anchor: &anchor, service: &service }, &rel)
    }

    /// A served directory's entries, but `.` and `..`.
    pub fn list(&self, ino: u64) -> Result<Vec<Entry>, Errno> {
        let (anchor, service, rel, via) = self.at(ino).ok_or(Errno::ENOENT)?;
        let entries = self.servers.list(&Place { anchor: &anchor, service: &service }, &rel)?;
        let mut inodes = self.inodes();
        Ok(entries
            .into_iter()
            .map(|entry| {
                let child = rel.join(OsStr::from_bytes(&entry.name));
                let ino = inodes.of(Inode::Served(anchor.clone(), service.clone(), child, via.clone()));
                (entry.name, ino, entry_type(entry.kind))
            })
            .collect())
    }

    /// Open a served file as a new handle.
    pub fn open(&self, ino: u64, flags: i32) -> Result<u64, Errno> {
        let (anchor, service, rel, _) = self.at(ino).ok_or(Errno::ENOENT)?;
        let fh = self.handle();
        self.servers.open(&Place { anchor: &anchor, service: &service }, &rel, flags, fh).map(|()| fh)
    }

    /// Make and open a file in a served directory.
    pub fn create(&self, parent: u64, name: &OsStr, flags: i32, mode: u32) -> Result<(FileAttr, u64), Errno> {
        let (anchor, service, rel, via) = self.at(parent).ok_or(Errno::ENOENT)?;
        let fh = self.handle();
        let attr = self.servers.create(&Place { anchor: &anchor, service: &service }, &rel, name.as_bytes(), (flags, mode, self.gid), fh)?;
        let ino = self.inodes().of(Inode::Served(anchor, service, rel.join(name), via));
        Ok((file_attr(ino, &attr, self.uid, self.gid), fh))
    }

    /// Make a directory in a served one.
    pub fn mkdir(&self, parent: u64, name: &OsStr, mode: u32) -> Result<FileAttr, Errno> {
        let (anchor, service, rel, via) = self.at(parent).ok_or(Errno::ENOENT)?;
        self.servers.mkdir(&Place { anchor: &anchor, service: &service }, &rel, name.as_bytes(), mode, self.gid)?;
        let child = rel.join(name);
        self.resolve(anchor, service, child, via)
    }

    /// Make a symlink in a served directory: its target as it's given, the
    /// server's to make of.
    pub fn symlink(&self, parent: u64, name: &OsStr, target: &Path) -> Result<FileAttr, Errno> {
        let (anchor, service, rel, via) = self.at(parent).ok_or(Errno::ENOENT)?;
        self.servers.symlink(&Place { anchor: &anchor, service: &service }, &rel, name.as_bytes(), target.as_os_str().as_bytes(), self.gid)?;
        let child = rel.join(name);
        self.resolve(anchor, service, child, via)
    }

    /// Remove a file, or an empty directory, from a served directory.
    pub fn unlink(&self, parent: u64, name: &OsStr, directory: bool) -> Result<(), Errno> {
        let (anchor, service, rel, _) = self.at(parent).ok_or(Errno::ENOENT)?;
        self.servers.unlink(&Place { anchor: &anchor, service: &service }, &rel, name.as_bytes(), directory)
    }

    /// Rename within one served anchor's service, as across filesystems it
    /// can't be.
    pub fn rename(&self, parent: u64, name: &OsStr, new_parent: u64, new_name: &OsStr) -> Result<(), Errno> {
        match (self.at(parent), self.at(new_parent)) {
            (Some((anchor, service, from, _)), Some((to_anchor, to_service, to, _))) if anchor == to_anchor && service == to_service => {
                self.servers.rename(&Place { anchor: &anchor, service: &service }, (&from, name.as_bytes()), (&to, new_name.as_bytes()))
            },
            _ => Err(Errno::EXDEV),
        }
    }

    /// Change a served file's attributes, saying what they are then.
    pub fn setattr(&self, ino: u64, attr: SetAttr) -> Result<FileAttr, Errno> {
        let (anchor, service, rel, _) = self.at(ino).ok_or(Errno::ENOENT)?;
        if attr.valid != 0 {
            self.servers.setattr(&Place { anchor: &anchor, service: &service }, &rel, attr)?;
        }
        self.attr(ino)
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// How many requests of what's served are waited on at once.
const THREADS: usize = 16;

/// Threads answering requests of what's served, apart from the mount's, so
/// a slow server holds up only what's asked of it. Started when first
/// asked, and ended with the mount.
#[derive(Default)]
pub(super) struct Pool {
    jobs: std::sync::OnceLock<Mutex<std::sync::mpsc::Sender<Job>>>,
}

impl Pool {
    pub fn run(&self, job: impl FnOnce() + Send + 'static) {
        let jobs = self.jobs.get_or_init(|| {
            let (send, receive) = std::sync::mpsc::channel::<Job>();
            let receive = Arc::new(Mutex::new(receive));
            for n in 0..THREADS {
                let receive = Arc::clone(&receive);
                let _ = std::thread::Builder::new().name(format!("served-{n}")).spawn(move || {
                    loop {
                        // Taken while it's the only one waiting, then let go
                        let job = lock(&receive).recv();
                        match job {
                            Ok(job) => job(),
                            Err(_) => return,
                        }
                    }
                });
            }
            Mutex::new(send)
        });
        let _ = lock(jobs).send(Box::new(job));
    }
}

impl Soup {
    /// What answering what's served needs, who's asking noted first.
    pub(super) fn served_ctx(&self) -> Ctx {
        if let Ok(catalog) = self.catalog() {
            self.served.know(&catalog);
        }
        Ctx { servers: Arc::clone(&self.served), inodes: Arc::clone(&self.inodes), next_handle: Arc::clone(&self.next_handle), uid: self.uid, gid: self.gid }
    }

    /// As `served_ctx`, if an inode's served.
    pub(super) fn served_ctx_for(&self, ino: u64) -> Option<Ctx> {
        self.is_served(ino).then(|| self.served_ctx())
    }

    /// What a path of a served anchor is.
    pub(super) fn served_kind(&self, catalog: &Catalog, anchor: &Link, service: &str, rel: &Path) -> Result<Kind, Errno> {
        // The anchor itself, as `Ctx::resolve` says
        if rel.as_os_str().is_empty() {
            return Ok(Kind::Directory);
        }
        self.served.know(catalog);
        let place = Place { anchor, service };
        let attr = self.served.getattr(&place, rel)?;
        Ok(match file_type(attr.mode) {
            FileType::Directory => Kind::Directory,
            FileType::Symlink => Kind::Symlink(self.served.readlink(&place, rel)?),
            _ => Kind::File(attr.size),
        })
    }

    /// A path of a served anchor's attributes, as its server says.
    pub(super) fn served_attr(&self, ino: u64) -> Result<FileAttr, Errno> {
        self.served_ctx().attr(ino)
    }

    /// What's at a path of a served anchor, reached where the anchor is.
    pub(super) fn served_resolve(&self, anchor: Link, service: String, rel: PathBuf, via: Via) -> Result<FileAttr, Errno> {
        self.served_ctx().resolve(anchor, service, rel, via)
    }

    /// A served directory's entries, but `.` and `..`.
    pub(super) fn served_list(&self, ino: u64) -> Result<Vec<Entry>, Errno> {
        self.served_ctx().list(ino)
    }

    /// Where a served inode is, if it is one.
    pub(super) fn served_at(&self, ino: u64) -> Option<(Link, String, PathBuf, Via)> {
        match self.inode(ino).ok()? {
            Inode::Served(anchor, service, rel, via) => Some((anchor, service, rel, via)),
            _ => None,
        }
    }

    pub(super) fn is_served(&self, ino: u64) -> bool {
        self.served_at(ino).is_some()
    }

    /// Open a served file, if it is one, as a new handle.
    #[cfg(test)]
    pub(super) fn served_open(&self, ino: u64, flags: i32) -> Option<Result<u64, Errno>> {
        self.served_ctx_for(ino).map(|ctx| ctx.open(ino, flags))
    }

    /// Make and open a file in a served directory, if it is one.
    #[cfg(test)]
    pub(super) fn served_create(&self, parent: u64, name: &OsStr, flags: i32, mode: u32) -> Option<Result<(FileAttr, u64), Errno>> {
        self.served_ctx_for(parent).map(|ctx| ctx.create(parent, name, flags, mode))
    }

    /// Make a directory in a served one, if it is one.
    #[cfg(test)]
    pub(super) fn served_mkdir(&self, parent: u64, name: &OsStr, mode: u32) -> Option<Result<FileAttr, Errno>> {
        self.served_ctx_for(parent).map(|ctx| ctx.mkdir(parent, name, mode))
    }

    /// Remove from a served directory, if it is one.
    #[cfg(test)]
    pub(super) fn served_unlink(&self, parent: u64, name: &OsStr, directory: bool) -> Option<Result<(), Errno>> {
        self.served_ctx_for(parent).map(|ctx| ctx.unlink(parent, name, directory))
    }

    /// Rename in a served anchor, if either directory's served.
    #[cfg(test)]
    pub(super) fn served_rename(&self, parent: u64, name: &OsStr, new_parent: u64, new_name: &OsStr) -> Option<Result<(), Errno>> {
        (self.is_served(parent) || self.is_served(new_parent)).then(|| self.served_ctx().rename(parent, name, new_parent, new_name))
    }

    /// Change a served file's attributes, if it is one.
    #[cfg(test)]
    pub(super) fn served_setattr(&self, ino: u64, attr: SetAttr) -> Option<Result<FileAttr, Errno>> {
        self.served_ctx_for(ino).map(|ctx| ctx.setattr(ino, attr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_waited_on_doesnt_hold_up_the_rest() {
        let pool = Pool::default();
        let (unblock, blocked) = std::sync::mpsc::channel::<()>();
        let (done, finished) = std::sync::mpsc::channel::<&str>();
        // As many as there are threads but one wait on a server that's slow
        let blocked = Arc::new(Mutex::new(blocked));
        for _ in 1..THREADS {
            let (blocked, done) = (Arc::clone(&blocked), done.clone());
            pool.run(move || {
                let _ = lock(&blocked).recv();
                let _ = done.send("slow");
            });
        }
        let quick = done.clone();
        pool.run(move || {
            let _ = quick.send("quick");
        });
        assert_eq!(finished.recv_timeout(Duration::from_secs(5)), Ok("quick"), "answered while the rest wait");
        for _ in 1..THREADS {
            let _ = unblock.send(());
        }
        for _ in 1..THREADS {
            assert_eq!(finished.recv_timeout(Duration::from_secs(5)), Ok("slow"));
        }
    }
}
