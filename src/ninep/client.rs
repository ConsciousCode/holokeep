//! Speaking 9P2000.L to a server, many requests at once from many threads.
//!
//! A thread reads answers and hands each to whoever's waiting on its tag.
//! A request not answered in time fails with `ETIMEDOUT`, and is flushed;
//! its tag isn't used again until the server's answered it, or the flush,
//! so a late answer can't be taken for another's. Once the connection's
//! gone everything fails with `ENOTCONN`, waiting or not, and the client
//! is done: whoever holds it connects again.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::{Attr, DirEntry, MSIZE, NOFID, NOTAG, Qid, Rmsg, SetAttr, StatFs, Tmsg, VERSION, parse_dirents, read_message, write_message};

/// How long a request is waited on.
pub const TIMEOUT: Duration = Duration::from_secs(10);

type Waiting = Arc<Mutex<HashMap<u16, mpsc::Sender<Rmsg>>>>;

/// A connection to a 9P2000.L server.
pub struct Client {
    writer: Mutex<Box<dyn Write + Send>>,
    waiting: Waiting,
    closed: Arc<AtomicBool>,
    close: Box<dyn Fn() + Send + Sync>,
    next_tag: Mutex<u16>,
    next_fid: AtomicU32,
    msize: u32,
    timeout: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("msize", &self.msize).field("closed", &self.closed.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

fn not_connected() -> io::Error {
    io::Error::from_raw_os_error(libc_errno::ENOTCONN)
}

/// The few errnos this says itself, as Linux numbers them, which is what
/// 9P2000.L carries.
pub mod libc_errno {
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EBADF: i32 = 9;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const EROFS: i32 = 30;
    pub const ENOTEMPTY: i32 = 39;
    pub const EPROTO: i32 = 71;
    pub const EOPNOTSUPP: i32 = 95;
    pub const ENOTCONN: i32 = 107;
    pub const ETIMEDOUT: i32 = 110;
}

impl Client {
    /// Connect to a server listening on a Unix socket.
    pub fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Self::over_unix(stream, TIMEOUT)
    }

    /// Speak over a connected Unix socket, waiting `timeout` on each
    /// request.
    pub fn over_unix(stream: UnixStream, timeout: Duration) -> io::Result<Self> {
        let reader = stream.try_clone()?;
        let closer = stream.try_clone()?;
        Self::new(reader, stream, move || drop(closer.shutdown(std::net::Shutdown::Both)), timeout)
    }

    /// Speak over a stream, read from `reader` and written to `writer`;
    /// `close` ends it, so the reading thread finishes.
    pub fn new(mut reader: impl Read + Send + 'static, mut writer: impl Write + Send + 'static, close: impl Fn() + Send + Sync + 'static, timeout: Duration) -> io::Result<Self> {
        // The version first, before anything else is in flight
        write_message(&mut writer, &Tmsg::Version { msize: MSIZE, version: VERSION.to_vec() }.encode(NOTAG)?)?;
        let msize = match Rmsg::decode(&read_message(&mut reader, MSIZE)?)? {
            (_, Rmsg::Version { msize, version }) if version == VERSION => msize.min(MSIZE),
            (_, Rmsg::Version { version, .. }) => {
                return Err(io::Error::new(io::ErrorKind::Unsupported, format!("the server speaks {}, not 9P2000.L", String::from_utf8_lossy(&version))));
            },
            (_, other) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("9P: {other:?} for a version"))),
        };
        let waiting: Waiting = Arc::default();
        let closed = Arc::new(AtomicBool::new(false));
        let (answers, done) = (Arc::clone(&waiting), Arc::clone(&closed));
        std::thread::Builder::new().name("9p-client".into()).spawn(move || {
            while let Ok(message) = read_message(&mut reader, msize) {
                let Ok((tag, answer)) = Rmsg::decode(&message) else {
                    break;
                };
                let waiter = answers.lock().unwrap_or_else(PoisonError::into_inner).remove(&tag);
                // Whoever gave up on it has gone
                if let Some(waiter) = waiter {
                    let _ = waiter.send(answer);
                }
            }
            done.store(true, Ordering::SeqCst);
            // Everyone waiting hears it's over
            answers.lock().unwrap_or_else(PoisonError::into_inner).clear();
        })?;
        Ok(Self {
            writer: Mutex::new(Box::new(writer)),
            waiting,
            closed,
            close: Box::new(close),
            next_tag: Mutex::new(0),
            next_fid: AtomicU32::new(1),
            msize,
            timeout,
        })
    }

    /// The most a message may be, as agreed.
    pub const fn msize(&self) -> u32 {
        self.msize
    }

    /// Whether the connection's gone.
    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// A fid not yet used.
    pub fn fid(&self) -> u32 {
        loop {
            let fid = self.next_fid.fetch_add(1, Ordering::Relaxed);
            if fid != NOFID {
                return fid;
            }
        }
    }

    /// Send a request, its tag registered to `answer`, returning the tag.
    fn send(&self, request: &Tmsg, answer: mpsc::Sender<Rmsg>) -> io::Result<u16> {
        if self.closed() {
            return Err(not_connected());
        }
        let tag = {
            let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
            let mut next = self.next_tag.lock().unwrap_or_else(PoisonError::into_inner);
            let mut tag = *next;
            // A tag's free once it's answered
            for _ in 0..=u16::MAX {
                if tag != NOTAG && !waiting.contains_key(&tag) {
                    break;
                }
                tag = tag.wrapping_add(1);
            }
            if tag == NOTAG || waiting.contains_key(&tag) {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "9P: every tag's in use"));
            }
            *next = tag.wrapping_add(1);
            drop(next);
            waiting.insert(tag, answer);
            tag
        };
        let message = request.encode(tag)?;
        if usize::try_from(self.msize).is_ok_and(|msize| message.len() > msize) {
            self.waiting.lock().unwrap_or_else(PoisonError::into_inner).remove(&tag);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "9P: a request over the message size"));
        }
        let sent = write_message(&mut *self.writer.lock().unwrap_or_else(PoisonError::into_inner), &message);
        // A stream that can't be written to is gone
        if sent.is_err() {
            self.waiting.lock().unwrap_or_else(PoisonError::into_inner).remove(&tag);
            self.closed.store(true, Ordering::SeqCst);
            return Err(not_connected());
        }
        Ok(tag)
    }

    /// Ask, and wait for the answer: an `Rlerror` is its errno.
    pub fn rpc(&self, request: &Tmsg) -> io::Result<Rmsg> {
        let (answer, answered) = mpsc::channel();
        let tag = self.send(request, answer)?;
        match answered.recv_timeout(self.timeout) {
            Ok(Rmsg::Lerror { ecode }) => Err(io::Error::from_raw_os_error(i32::try_from(ecode).unwrap_or(libc_errno::EIO))),
            Ok(answer) => Ok(answer),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The tag stays taken till it's answered, or the flush is;
                // nobody waits on either
                let (flushed, _) = mpsc::channel();
                let _ = self.send(&Tmsg::Flush { oldtag: tag }, flushed);
                Err(io::Error::from_raw_os_error(libc_errno::ETIMEDOUT))
            },
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(not_connected()),
        }
    }

    /// Attach to the server's tree as a user: a fid for its root.
    pub fn attach(&self, uname: &[u8], aname: &[u8], n_uname: u32) -> io::Result<(u32, Qid)> {
        let fid = self.fid();
        match self.rpc(&Tmsg::Attach { fid, afid: NOFID, uname: uname.to_vec(), aname: aname.to_vec(), n_uname })? {
            Rmsg::Attach { qid } => Ok((fid, qid)),
            other => Err(unexpected(&other)),
        }
    }

    /// Walk from a fid by names to a new fid, and the qid of each step;
    /// no names clones it. A walk that doesn't get all the way is
    /// `ENOENT`, and makes no fid.
    pub fn walk(&self, fid: u32, names: &[&[u8]]) -> io::Result<(u32, Vec<Qid>)> {
        let newfid = self.fid();
        let names: Vec<Vec<u8>> = names.iter().map(|name| name.to_vec()).collect();
        let wanted = names.len();
        match self.rpc(&Tmsg::Walk { fid, newfid, names })? {
            Rmsg::Walk { qids } if qids.len() == wanted => Ok((newfid, qids)),
            Rmsg::Walk { .. } => Err(io::Error::from_raw_os_error(libc_errno::ENOENT)),
            other => Err(unexpected(&other)),
        }
    }

    /// Forget a fid.
    pub fn clunk(&self, fid: u32) -> io::Result<()> {
        self.expect(&Tmsg::Clunk { fid }, |answer| matches!(answer, Rmsg::Clunk))
    }

    pub fn getattr(&self, fid: u32) -> io::Result<Attr> {
        match self.rpc(&Tmsg::Getattr { fid, mask: super::GETATTR_BASIC })? {
            Rmsg::Getattr(attr) => Ok(*attr),
            other => Err(unexpected(&other)),
        }
    }

    pub fn setattr(&self, fid: u32, attr: SetAttr) -> io::Result<()> {
        self.expect(&Tmsg::Setattr { fid, attr }, |answer| matches!(answer, Rmsg::Setattr))
    }

    pub fn statfs(&self, fid: u32) -> io::Result<StatFs> {
        match self.rpc(&Tmsg::Statfs { fid })? {
            Rmsg::Statfs(statfs) => Ok(statfs),
            other => Err(unexpected(&other)),
        }
    }

    /// Open a fid, with Linux's open flags: its qid, and the most to read
    /// or write at once, or 0 to go by the message size.
    pub fn lopen(&self, fid: u32, flags: u32) -> io::Result<(Qid, u32)> {
        match self.rpc(&Tmsg::Lopen { fid, flags })? {
            Rmsg::Lopen { qid, iounit } => Ok((qid, iounit)),
            other => Err(unexpected(&other)),
        }
    }

    /// Create a file in the directory a fid is, which the fid then is,
    /// opened.
    pub fn lcreate(&self, fid: u32, name: &[u8], flags: u32, mode: u32, gid: u32) -> io::Result<(Qid, u32)> {
        match self.rpc(&Tmsg::Lcreate { fid, name: name.to_vec(), flags, mode, gid })? {
            Rmsg::Lcreate { qid, iounit } => Ok((qid, iounit)),
            other => Err(unexpected(&other)),
        }
    }

    /// The most data one read or write carries.
    pub const fn iounit(&self) -> u32 {
        // What a message spends on anything but data
        self.msize.saturating_sub(24)
    }

    /// Read from an open fid, at most what fits in a message.
    pub fn read(&self, fid: u32, offset: u64, count: u32) -> io::Result<Vec<u8>> {
        match self.rpc(&Tmsg::Read { fid, offset, count: count.min(self.iounit()) })? {
            Rmsg::Read { data } => Ok(data),
            other => Err(unexpected(&other)),
        }
    }

    /// Write to an open fid, at most what fits in a message: how much was.
    pub fn write(&self, fid: u32, offset: u64, data: &[u8]) -> io::Result<u32> {
        let most = usize::try_from(self.iounit()).unwrap_or(usize::MAX);
        let data = data.get(..most.min(data.len())).unwrap_or(data);
        match self.rpc(&Tmsg::Write { fid, offset, data: data.to_vec() })? {
            Rmsg::Write { count } => Ok(count),
            other => Err(unexpected(&other)),
        }
    }

    /// Read an open directory's entries from an offset: none at the end.
    pub fn readdir(&self, fid: u32, offset: u64) -> io::Result<Vec<DirEntry>> {
        match self.rpc(&Tmsg::Readdir { fid, offset, count: self.iounit() })? {
            Rmsg::Readdir { data } => parse_dirents(&data),
            other => Err(unexpected(&other)),
        }
    }

    /// Every entry of an open directory.
    pub fn readdir_all(&self, fid: u32) -> io::Result<Vec<DirEntry>> {
        let mut all: Vec<DirEntry> = Vec::new();
        let mut offset = 0;
        loop {
            let entries = self.readdir(fid, offset)?;
            let Some(last) = entries.last() else {
                return Ok(all);
            };
            offset = last.offset;
            all.extend(entries);
        }
    }

    pub fn fsync(&self, fid: u32, datasync: bool) -> io::Result<()> {
        self.expect(&Tmsg::Fsync { fid, datasync: u32::from(datasync) }, |answer| matches!(answer, Rmsg::Fsync))
    }

    pub fn mkdir(&self, dfid: u32, name: &[u8], mode: u32, gid: u32) -> io::Result<Qid> {
        match self.rpc(&Tmsg::Mkdir { dfid, name: name.to_vec(), mode, gid })? {
            Rmsg::Mkdir { qid } => Ok(qid),
            other => Err(unexpected(&other)),
        }
    }

    pub fn symlink(&self, fid: u32, name: &[u8], target: &[u8], gid: u32) -> io::Result<Qid> {
        match self.rpc(&Tmsg::Symlink { fid, name: name.to_vec(), target: target.to_vec(), gid })? {
            Rmsg::Symlink { qid } => Ok(qid),
            other => Err(unexpected(&other)),
        }
    }

    pub fn readlink(&self, fid: u32) -> io::Result<Vec<u8>> {
        match self.rpc(&Tmsg::Readlink { fid })? {
            Rmsg::Readlink { target } => Ok(target),
            other => Err(unexpected(&other)),
        }
    }

    pub fn renameat(&self, olddirfid: u32, oldname: &[u8], newdirfid: u32, newname: &[u8]) -> io::Result<()> {
        self.expect(&Tmsg::Renameat { olddirfid, oldname: oldname.to_vec(), newdirfid, newname: newname.to_vec() }, |answer| matches!(answer, Rmsg::Renameat))
    }

    pub fn unlinkat(&self, dirfid: u32, name: &[u8], flags: u32) -> io::Result<()> {
        self.expect(&Tmsg::Unlinkat { dirfid, name: name.to_vec(), flags }, |answer| matches!(answer, Rmsg::Unlinkat))
    }

    fn expect(&self, request: &Tmsg, ok: impl FnOnce(&Rmsg) -> bool) -> io::Result<()> {
        let answer = self.rpc(request)?;
        if ok(&answer) { Ok(()) } else { Err(unexpected(&answer)) }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        (self.close)();
    }
}

fn unexpected(answer: &Rmsg) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("9P: an unexpected answer, {answer:?}"))
}
