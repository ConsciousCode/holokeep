//! A filesystem in memory, served over 9P2000.L: for tests of what speaks
//! to servers.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::client::libc_errno::{EBADF, EEXIST, EINVAL, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
use super::server::{Handler, serve};
use super::{AT_REMOVEDIR, Attr, DirEntry, GETATTR_BASIC, QTDIR, QTSYMLINK, QTTMP, Qid, Rmsg, SETATTR_SIZE, StatFs, Tmsg, dirents};

#[derive(Debug, Clone)]
enum Body {
    Dir(BTreeMap<Vec<u8>, u64>),
    File(Vec<u8>),
    Symlink(Vec<u8>),
}

#[derive(Debug, Clone)]
struct Node {
    body: Body,
    parent: u64,
    version: u32,
    tmp: bool,
}

/// Who attached, as they said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    pub uname: Vec<u8>,
    pub aname: Vec<u8>,
    pub n_uname: u32,
}

/// The filesystem, and what it's been asked.
#[derive(Debug)]
pub struct MemFs {
    nodes: HashMap<u64, Node>,
    next: u64,
    /// Each connection's fids, by connection and fid.
    fids: HashMap<(u64, u32), u64>,
    /// The connection being answered.
    conn: u64,
    conns: u64,
    pub attached: Vec<Attached>,
    /// How long to take over each request.
    pub delay: Duration,
}

const ROOT: u64 = 1;

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFs {
    pub fn new() -> Self {
        let root = Node { body: Body::Dir(BTreeMap::new()), parent: ROOT, version: 0, tmp: false };
        Self { nodes: HashMap::from([(ROOT, root)]), next: ROOT.saturating_add(1), fids: HashMap::new(), conn: 0, conns: 0, attached: Vec::new(), delay: Duration::ZERO }
    }

    /// Add a file, making the directories it's in.
    pub fn file(&mut self, path: &str, data: &[u8]) -> u64 {
        let (dir, name) = self.dirs(path);
        self.add(dir, name, Body::File(data.to_vec()))
    }

    /// Add a file left out of what's kept.
    pub fn tmp(&mut self, path: &str, data: &[u8]) -> u64 {
        let id = self.file(path, data);
        if let Some(node) = self.nodes.get_mut(&id) {
            node.tmp = true;
        }
        id
    }

    pub fn symlink(&mut self, path: &str, target: &str) -> u64 {
        let (dir, name) = self.dirs(path);
        self.add(dir, name, Body::Symlink(target.as_bytes().to_vec()))
    }

    /// A file's contents, if there's a file there.
    pub fn read(&self, path: &str) -> Option<Vec<u8>> {
        let mut at = ROOT;
        for name in path.split('/').filter(|name| !name.is_empty()) {
            at = self.child(at, name.as_bytes()).ok()?;
        }
        match &self.nodes.get(&at)?.body {
            Body::File(data) => Some(data.clone()),
            _ => None,
        }
    }

    fn dirs<'a>(&mut self, path: &'a str) -> (u64, &'a str) {
        let mut parts: Vec<&str> = path.split('/').filter(|name| !name.is_empty()).collect();
        let name = parts.pop().unwrap_or_default();
        let mut at = ROOT;
        for part in parts {
            at = self.child(at, part.as_bytes()).unwrap_or_else(|_| self.add(at, part, Body::Dir(BTreeMap::new())));
        }
        (at, name)
    }

    fn add(&mut self, dir: u64, name: &str, body: Body) -> u64 {
        self.insert(dir, name.as_bytes(), body).unwrap_or_default()
    }

    fn insert(&mut self, dir: u64, name: &[u8], body: Body) -> Result<u64, i32> {
        let id = self.next;
        let Some(Node { body: Body::Dir(entries), version, .. }) = self.nodes.get_mut(&dir) else {
            return Err(ENOTDIR);
        };
        if entries.contains_key(name) {
            return Err(EEXIST);
        }
        entries.insert(name.to_vec(), id);
        *version = version.wrapping_add(1);
        self.next = id.saturating_add(1);
        self.nodes.insert(id, Node { body, parent: dir, version: 0, tmp: false });
        Ok(id)
    }

    fn child(&self, dir: u64, name: &[u8]) -> Result<u64, i32> {
        match self.nodes.get(&dir).map(|node| (&node.body, node.parent)) {
            Some((Body::Dir(_), parent)) if name == b".." => Ok(parent),
            Some((Body::Dir(_), _)) if name == b"." => Ok(dir),
            Some((Body::Dir(entries), _)) => entries.get(name).copied().ok_or(ENOENT),
            Some(_) => Err(ENOTDIR),
            None => Err(ENOENT),
        }
    }

    fn qid(&self, id: u64) -> Qid {
        self.nodes.get(&id).map_or_else(Qid::default, |node| {
            let kind = match node.body {
                Body::Dir(_) => QTDIR,
                Body::Symlink(_) => QTSYMLINK,
                Body::File(_) => 0,
            } | if node.tmp { QTTMP } else { 0 };
            Qid { kind, version: node.version, path: id }
        })
    }

    fn fid(&self, fid: u32) -> Result<u64, i32> {
        self.fids.get(&(self.conn, fid)).copied().ok_or(EBADF)
    }

    fn node(&mut self, id: u64) -> Result<&mut Node, i32> {
        self.nodes.get_mut(&id).ok_or(ENOENT)
    }

    fn remove(&mut self, dir: u64, name: &[u8], want_dir: Option<bool>) -> Result<(), i32> {
        let id = self.child(dir, name)?;
        match (&self.node(id)?.body, want_dir) {
            (Body::Dir(entries), Some(true) | None) if !entries.is_empty() => return Err(ENOTEMPTY),
            (Body::Dir(_), Some(false)) => return Err(EISDIR),
            (Body::File(_) | Body::Symlink(_), Some(true)) => return Err(ENOTDIR),
            _ => {},
        }
        if let Body::Dir(entries) = &mut self.node(dir)?.body {
            entries.remove(name);
        }
        self.nodes.remove(&id);
        Ok(())
    }

    fn attr(&self, id: u64) -> Attr {
        let (mode, size, nlink) = match self.nodes.get(&id).map(|node| &node.body) {
            Some(Body::Dir(entries)) => (0o040_755, u64::try_from(entries.len()).unwrap_or_default(), 2),
            Some(Body::File(data)) => (0o100_644, u64::try_from(data.len()).unwrap_or_default(), 1),
            Some(Body::Symlink(target)) => (0o120_777, u64::try_from(target.len()).unwrap_or_default(), 1),
            None => (0, 0, 0),
        };
        Attr { valid: GETATTR_BASIC, qid: self.qid(id), mode, nlink, size, blksize: 4096, ..Attr::default() }
    }
}

impl Handler for MemFs {
    #[allow(clippy::too_many_lines, reason = "a match on every request, each short")]
    fn handle(&mut self, request: Tmsg) -> Result<Rmsg, i32> {
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        Ok(match request {
            Tmsg::Attach { fid, uname, aname, n_uname, .. } => {
                self.attached.push(Attached { uname, aname, n_uname });
                self.fids.insert((self.conn, fid), ROOT);
                Rmsg::Attach { qid: self.qid(ROOT) }
            },
            Tmsg::Walk { fid, newfid, names } => {
                let mut at = self.fid(fid)?;
                let mut qids = Vec::new();
                for name in &names {
                    match self.child(at, name) {
                        Ok(child) => {
                            at = child;
                            qids.push(self.qid(at));
                        },
                        Err(e) if qids.is_empty() => return Err(e),
                        Err(_) => break,
                    }
                }
                if qids.len() == names.len() {
                    self.fids.insert((self.conn, newfid), at);
                }
                Rmsg::Walk { qids }
            },
            Tmsg::Clunk { fid } => {
                self.fids.remove(&(self.conn, fid)).ok_or(EBADF)?;
                Rmsg::Clunk
            },
            Tmsg::Remove { fid } => {
                let id = self.fid(fid)?;
                self.fids.remove(&(self.conn, fid));
                let parent = self.node(id)?.parent;
                let name = match &self.node(parent)?.body {
                    Body::Dir(entries) => entries.iter().find(|(_, child)| **child == id).map(|(name, _)| name.clone()).ok_or(ENOENT)?,
                    _ => return Err(ENOENT),
                };
                self.remove(parent, &name, None)?;
                Rmsg::Remove
            },
            Tmsg::Statfs { fid } => {
                self.fid(fid)?;
                Rmsg::Statfs(StatFs { bsize: 4096, namelen: 255, ..StatFs::default() })
            },
            Tmsg::Getattr { fid, .. } => Rmsg::Getattr(Box::new(self.attr(self.fid(fid)?))),
            Tmsg::Setattr { fid, attr } => {
                let id = self.fid(fid)?;
                let node = self.node(id)?;
                if attr.valid & SETATTR_SIZE != 0 {
                    match &mut node.body {
                        Body::File(data) => data.resize(usize::try_from(attr.size).map_err(|_| EINVAL)?, 0),
                        _ => return Err(EISDIR),
                    }
                    node.version = node.version.wrapping_add(1);
                }
                Rmsg::Setattr
            },
            Tmsg::Lopen { fid, .. } => Rmsg::Lopen { qid: self.qid(self.fid(fid)?), iounit: 0 },
            Tmsg::Lcreate { fid, name, .. } => {
                let dir = self.fid(fid)?;
                let id = self.insert(dir, &name, Body::File(Vec::new()))?;
                self.fids.insert((self.conn, fid), id);
                Rmsg::Lcreate { qid: self.qid(id), iounit: 0 }
            },
            Tmsg::Read { fid, offset, count } => {
                let id = self.fid(fid)?;
                let Body::File(data) = &self.node(id)?.body else {
                    return Err(EISDIR);
                };
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
                let end = start.saturating_add(usize::try_from(count).unwrap_or(usize::MAX)).min(data.len());
                Rmsg::Read { data: data.get(start..end).unwrap_or_default().to_vec() }
            },
            Tmsg::Write { fid, offset, data } => {
                let id = self.fid(fid)?;
                let node = self.node(id)?;
                let Body::File(file) = &mut node.body else {
                    return Err(EISDIR);
                };
                let start = usize::try_from(offset).map_err(|_| EINVAL)?;
                let end = start.saturating_add(data.len());
                if file.len() < end {
                    file.resize(end, 0);
                }
                file.get_mut(start..end).ok_or(EINVAL)?.copy_from_slice(&data);
                node.version = node.version.wrapping_add(1);
                Rmsg::Write { count: u32::try_from(data.len()).unwrap_or(u32::MAX) }
            },
            Tmsg::Readdir { fid, offset, count } => {
                let id = self.fid(fid)?;
                let Body::Dir(entries) = &self.node(id)?.body else {
                    return Err(ENOTDIR);
                };
                let entries = entries.clone();
                let listed: Vec<DirEntry> = entries
                    .into_iter()
                    .enumerate()
                    .skip(usize::try_from(offset).unwrap_or(usize::MAX))
                    .map(|(i, (name, child))| {
                        let qid = self.qid(child);
                        let kind = if qid.is_dir() { 4 } else if qid.is_symlink() { 10 } else { 8 };
                        DirEntry { qid, offset: u64::try_from(i).unwrap_or_default().saturating_add(1), kind, name }
                    })
                    .collect();
                Rmsg::Readdir { data: dirents(&listed, count).map_err(|_| EINVAL)?.0 }
            },
            Tmsg::Fsync { fid, .. } => {
                self.fid(fid)?;
                Rmsg::Fsync
            },
            Tmsg::Mkdir { dfid, name, .. } => {
                let dir = self.fid(dfid)?;
                let id = self.insert(dir, &name, Body::Dir(BTreeMap::new()))?;
                Rmsg::Mkdir { qid: self.qid(id) }
            },
            Tmsg::Symlink { fid, name, target, .. } => {
                let dir = self.fid(fid)?;
                let id = self.insert(dir, &name, Body::Symlink(target))?;
                Rmsg::Symlink { qid: self.qid(id) }
            },
            Tmsg::Readlink { fid } => match &self.node(self.fid(fid)?)?.body {
                Body::Symlink(target) => Rmsg::Readlink { target: target.clone() },
                _ => return Err(EINVAL),
            },
            Tmsg::Renameat { olddirfid, oldname, newdirfid, newname } => {
                let (from, to) = (self.fid(olddirfid)?, self.fid(newdirfid)?);
                let id = self.child(from, &oldname)?;
                if self.child(to, &newname).is_ok() {
                    self.remove(to, &newname, None)?;
                }
                if let Body::Dir(entries) = &mut self.node(from)?.body {
                    entries.remove(&oldname);
                }
                match &mut self.node(to)?.body {
                    Body::Dir(entries) => {
                        entries.insert(newname, id);
                    },
                    _ => return Err(ENOTDIR),
                }
                self.node(id)?.parent = to;
                Rmsg::Renameat
            },
            Tmsg::Unlinkat { dirfid, name, flags } => {
                let dir = self.fid(dirfid)?;
                self.remove(dir, &name, Some(flags & AT_REMOVEDIR != 0))?;
                Rmsg::Unlinkat
            },
            Tmsg::Version { .. } | Tmsg::Flush { .. } => return Err(EINVAL),
        })
    }
}

/// A filesystem shared with whoever serves it, to look at as it's used,
/// as one connection sees it.
#[derive(Debug, Clone, Default)]
pub struct Shared(pub Arc<Mutex<MemFs>>, u64);

impl Shared {
    pub fn new(fs: MemFs) -> Self {
        Self(Arc::new(Mutex::new(fs)), 0)
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, MemFs> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The same filesystem, for a connection of its own.
    fn connection(&self) -> Self {
        let mut fs = self.lock();
        fs.conns = fs.conns.saturating_add(1);
        Self(Arc::clone(&self.0), fs.conns)
    }
}

impl Handler for Shared {
    fn handle(&mut self, request: Tmsg) -> Result<Rmsg, i32> {
        // Not holding the lock while it sleeps, so a test can look meanwhile
        let delay = self.lock().delay;
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        let mut fs = self.lock();
        fs.conn = self.1;
        let saved = std::mem::replace(&mut fs.delay, Duration::ZERO);
        let answer = fs.handle(request);
        fs.delay = saved;
        answer
    }
}

/// Serve it on a thread, over one end of a socket pair: the other end.
pub fn spawn(fs: Shared) -> UnixStream {
    let (ours, theirs) = UnixStream::pair().unwrap_or_else(|e| panic!("socket pair: {e}"));
    std::thread::spawn(move || {
        let mut handler = fs.connection();
        let (Ok(mut reader), mut writer) = (theirs.try_clone(), theirs) else {
            return;
        };
        let _ = serve(&mut handler, &mut reader, &mut writer);
    });
    ours
}

/// Serve it on a Unix socket at a path, a connection at a time, each on a
/// thread of its own.
pub fn listen(fs: Shared, path: &std::path::Path) -> std::io::Result<()> {
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut handler = fs.connection();
            std::thread::spawn(move || {
                if let Ok(mut reader) = stream.try_clone() {
                    let mut writer = stream;
                    let _ = serve(&mut handler, &mut reader, &mut writer);
                }
            });
        }
    });
    Ok(())
}
