//! 9P2000.L, the dialect of 9P Linux's v9fs speaks: what served anchors
//! are answered in (see the wiki's Servers page).
//!
//! A message is `size[4] type[1] tag[2]` and its fields, little-endian,
//! `size` counting itself. A string is `len[2]` and its bytes, which
//! needn't be UTF-8; a qid is `type[1] version[4] path[8]`. Only what a
//! filesystem client needs is here: no auth files, extended attributes or
//! locks, which a server answers with `Rlerror` if it's asked, and this
//! never asks.
//!
//! `client` speaks it to a server over a stream, many requests at once;
//! `server` answers it, for tests and for services of Holokeep's own.

use std::io::{self, Read, Write};

pub mod client;
pub mod server;

#[cfg(test)]
pub(crate) mod memfs;
#[cfg(test)]
mod tests;

/// The version this speaks.
pub const VERSION: &[u8] = b"9P2000.L";

/// The tag of `Tversion`, which has none.
pub const NOTAG: u16 = 0xffff;

/// No fid, as `Tattach`'s `afid` when there's no auth file.
pub const NOFID: u32 = 0xffff_ffff;

/// No numeric user, as `Tattach`'s `n_uname` when there isn't one.
pub const NONUNAME: u32 = 0xffff_ffff;

/// The most a message may be, unless the server says less.
pub const MSIZE: u32 = 1 << 20;

/// What `size[4] type[1] tag[2]` takes.
const HEADER: usize = 7;

/// Qid types.
pub const QTDIR: u8 = 0x80;
pub const QTSYMLINK: u8 = 0x02;
/// Plan 9's "temporary": left out of the archive, and so never kept.
pub const QTTMP: u8 = 0x04;

/// `Tgetattr` masks: what's asked for, and what's answered.
pub const GETATTR_BASIC: u64 = 0x0000_07ff;

/// `Tsetattr` valid bits.
pub const SETATTR_MODE: u32 = 0x0001;
pub const SETATTR_UID: u32 = 0x0002;
pub const SETATTR_GID: u32 = 0x0004;
pub const SETATTR_SIZE: u32 = 0x0008;
pub const SETATTR_ATIME: u32 = 0x0010;
pub const SETATTR_MTIME: u32 = 0x0020;
pub const SETATTR_CTIME: u32 = 0x0040;
pub const SETATTR_ATIME_SET: u32 = 0x0080;
pub const SETATTR_MTIME_SET: u32 = 0x0100;

/// `Tunlinkat` flag for a directory.
pub const AT_REMOVEDIR: u32 = 0x200;

/// Message types.
mod kind {
    pub const RLERROR: u8 = 7;
    pub const TSTATFS: u8 = 8;
    pub const TLOPEN: u8 = 12;
    pub const TLCREATE: u8 = 14;
    pub const TSYMLINK: u8 = 16;
    pub const TREADLINK: u8 = 22;
    pub const TGETATTR: u8 = 24;
    pub const TSETATTR: u8 = 26;
    pub const TREADDIR: u8 = 40;
    pub const TFSYNC: u8 = 50;
    pub const TMKDIR: u8 = 72;
    pub const TRENAMEAT: u8 = 74;
    pub const TUNLINKAT: u8 = 76;
    pub const TVERSION: u8 = 100;
    pub const TATTACH: u8 = 104;
    pub const TFLUSH: u8 = 108;
    pub const TWALK: u8 = 110;
    pub const TREAD: u8 = 116;
    pub const TWRITE: u8 = 118;
    pub const TCLUNK: u8 = 120;
    pub const TREMOVE: u8 = 122;
}

/// A file's identity to its server: what kind it is, a version which
/// changes as it does, and a path unique among its files.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Qid {
    pub kind: u8,
    pub version: u32,
    pub path: u64,
}

impl Qid {
    pub const fn is_dir(&self) -> bool {
        self.kind & QTDIR != 0
    }

    pub const fn is_symlink(&self) -> bool {
        self.kind & QTSYMLINK != 0
    }

    pub const fn is_tmp(&self) -> bool {
        self.kind & QTTMP != 0
    }
}

/// A time, as seconds and nanoseconds.
pub type Time = (u64, u64);

/// `Rgetattr`'s fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attr {
    pub valid: u64,
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime: Time,
    pub mtime: Time,
    pub ctime: Time,
    pub btime: Time,
    pub generation: u64,
    pub data_version: u64,
}

/// `Tsetattr`'s fields: only those `valid` names are meant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetAttr {
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Time,
    pub mtime: Time,
}

/// `Rstatfs`'s fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatFs {
    pub kind: u32,
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    pub namelen: u32,
}

/// An entry of `Rreaddir`: its qid, the offset to read on from after it,
/// its type as `dirent`'s `d_type`, and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub qid: Qid,
    pub offset: u64,
    pub kind: u8,
    pub name: Vec<u8>,
}

/// A request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tmsg {
    Version { msize: u32, version: Vec<u8> },
    Attach { fid: u32, afid: u32, uname: Vec<u8>, aname: Vec<u8>, n_uname: u32 },
    Flush { oldtag: u16 },
    Walk { fid: u32, newfid: u32, names: Vec<Vec<u8>> },
    Clunk { fid: u32 },
    Remove { fid: u32 },
    Statfs { fid: u32 },
    Getattr { fid: u32, mask: u64 },
    Setattr { fid: u32, attr: SetAttr },
    Lopen { fid: u32, flags: u32 },
    Lcreate { fid: u32, name: Vec<u8>, flags: u32, mode: u32, gid: u32 },
    Read { fid: u32, offset: u64, count: u32 },
    Write { fid: u32, offset: u64, data: Vec<u8> },
    Readdir { fid: u32, offset: u64, count: u32 },
    Fsync { fid: u32, datasync: u32 },
    Mkdir { dfid: u32, name: Vec<u8>, mode: u32, gid: u32 },
    Symlink { fid: u32, name: Vec<u8>, target: Vec<u8>, gid: u32 },
    Readlink { fid: u32 },
    Renameat { olddirfid: u32, oldname: Vec<u8>, newdirfid: u32, newname: Vec<u8> },
    Unlinkat { dirfid: u32, name: Vec<u8>, flags: u32 },
}

/// An answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rmsg {
    Version { msize: u32, version: Vec<u8> },
    Lerror { ecode: u32 },
    Attach { qid: Qid },
    Flush,
    Walk { qids: Vec<Qid> },
    Clunk,
    Remove,
    Statfs(StatFs),
    Getattr(Box<Attr>),
    Setattr,
    Lopen { qid: Qid, iounit: u32 },
    Lcreate { qid: Qid, iounit: u32 },
    Read { data: Vec<u8> },
    Write { count: u32 },
    /// Entries, encoded as they're sent: see `dirents`.
    Readdir { data: Vec<u8> },
    Fsync,
    Mkdir { qid: Qid },
    Symlink { qid: Qid },
    Readlink { target: Vec<u8> },
    Renameat,
    Unlinkat,
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("9P: {what}"))
}

/// Writes fields.
struct Out(Vec<u8>);

impl Out {
    fn new(kind: u8, tag: u16) -> Self {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&[0; 4]);
        out.push(kind);
        out.extend_from_slice(&tag.to_le_bytes());
        Self(out)
    }

    fn u8(&mut self, x: u8) -> &mut Self {
        self.0.push(x);
        self
    }

    fn u16(&mut self, x: u16) -> &mut Self {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }

    fn u32(&mut self, x: u32) -> &mut Self {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }

    fn u64(&mut self, x: u64) -> &mut Self {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }

    fn time(&mut self, (sec, nsec): Time) -> &mut Self {
        self.u64(sec).u64(nsec)
    }

    fn string(&mut self, s: &[u8]) -> io::Result<&mut Self> {
        let len = u16::try_from(s.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "9P: a string over 64 KiB"))?;
        self.u16(len);
        self.0.extend_from_slice(s);
        Ok(self)
    }

    fn data(&mut self, data: &[u8]) -> io::Result<&mut Self> {
        let len = u32::try_from(data.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "9P: data over 4 GiB"))?;
        self.u32(len);
        self.0.extend_from_slice(data);
        Ok(self)
    }

    fn qid(&mut self, qid: &Qid) -> &mut Self {
        self.u8(qid.kind).u32(qid.version).u64(qid.path)
    }

    /// The message, its size filled in.
    fn done(mut self) -> io::Result<Vec<u8>> {
        let size = u32::try_from(self.0.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "9P: a message over 4 GiB"))?;
        if let Some(head) = self.0.first_chunk_mut::<4>() {
            *head = size.to_le_bytes();
        }
        Ok(self.0)
    }
}

/// Reads fields.
struct In<'a>(&'a [u8]);

impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(n).ok_or_else(|| invalid("a message cut short"))?;
        self.0 = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| invalid("a message cut short"))
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn time(&mut self) -> io::Result<Time> {
        Ok((self.u64()?, self.u64()?))
    }

    fn string(&mut self) -> io::Result<Vec<u8>> {
        let len = self.u16()?;
        Ok(self.take(usize::from(len))?.to_vec())
    }

    fn data(&mut self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.u32()?).map_err(|_| invalid("data too big"))?;
        Ok(self.take(len)?.to_vec())
    }

    fn qid(&mut self) -> io::Result<Qid> {
        Ok(Qid { kind: self.u8()?, version: self.u32()?, path: self.u64()? })
    }

    fn end(&self) -> io::Result<()> {
        if self.0.is_empty() { Ok(()) } else { Err(invalid("a message with bytes left over")) }
    }
}

/// A message's type, tag and fields, from a whole message.
fn header(message: &[u8]) -> io::Result<(u8, u16, In<'_>)> {
    let mut input = In(message);
    let size = input.u32()?;
    if usize::try_from(size).ok() != Some(message.len()) {
        return Err(invalid("a message whose size isn't its length"));
    }
    Ok((input.u8()?, input.u16()?, input))
}

impl Tmsg {
    /// The message, with its tag.
    pub fn encode(&self, tag: u16) -> io::Result<Vec<u8>> {
        #[allow(clippy::wildcard_imports, reason = "every message type, matched on")]
        use kind::*;
        let out = match self {
            Self::Version { msize, version } => {
                let mut out = Out::new(TVERSION, tag);
                out.u32(*msize).string(version)?;
                out
            },
            Self::Attach { fid, afid, uname, aname, n_uname } => {
                let mut out = Out::new(TATTACH, tag);
                out.u32(*fid).u32(*afid).string(uname)?.string(aname)?.u32(*n_uname);
                out
            },
            Self::Flush { oldtag } => {
                let mut out = Out::new(TFLUSH, tag);
                out.u16(*oldtag);
                out
            },
            Self::Walk { fid, newfid, names } => {
                let mut out = Out::new(TWALK, tag);
                let count = u16::try_from(names.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "9P: too many names to walk"))?;
                out.u32(*fid).u32(*newfid).u16(count);
                for name in names {
                    out.string(name)?;
                }
                out
            },
            Self::Clunk { fid } => fid_only(TCLUNK, tag, *fid),
            Self::Remove { fid } => fid_only(TREMOVE, tag, *fid),
            Self::Statfs { fid } => fid_only(TSTATFS, tag, *fid),
            Self::Readlink { fid } => fid_only(TREADLINK, tag, *fid),
            Self::Getattr { fid, mask } => {
                let mut out = Out::new(TGETATTR, tag);
                out.u32(*fid).u64(*mask);
                out
            },
            Self::Setattr { fid, attr } => {
                let mut out = Out::new(TSETATTR, tag);
                out.u32(*fid).u32(attr.valid).u32(attr.mode).u32(attr.uid).u32(attr.gid).u64(attr.size).time(attr.atime).time(attr.mtime);
                out
            },
            Self::Lopen { fid, flags } => {
                let mut out = Out::new(TLOPEN, tag);
                out.u32(*fid).u32(*flags);
                out
            },
            Self::Lcreate { fid, name, flags, mode, gid } => {
                let mut out = Out::new(TLCREATE, tag);
                out.u32(*fid).string(name)?.u32(*flags).u32(*mode).u32(*gid);
                out
            },
            Self::Read { fid, offset, count } => {
                let mut out = Out::new(TREAD, tag);
                out.u32(*fid).u64(*offset).u32(*count);
                out
            },
            Self::Write { fid, offset, data } => {
                let mut out = Out::new(TWRITE, tag);
                out.u32(*fid).u64(*offset).data(data)?;
                out
            },
            Self::Readdir { fid, offset, count } => {
                let mut out = Out::new(TREADDIR, tag);
                out.u32(*fid).u64(*offset).u32(*count);
                out
            },
            Self::Fsync { fid, datasync } => {
                let mut out = Out::new(TFSYNC, tag);
                out.u32(*fid).u32(*datasync);
                out
            },
            Self::Mkdir { dfid, name, mode, gid } => {
                let mut out = Out::new(TMKDIR, tag);
                out.u32(*dfid).string(name)?.u32(*mode).u32(*gid);
                out
            },
            Self::Symlink { fid, name, target, gid } => {
                let mut out = Out::new(TSYMLINK, tag);
                out.u32(*fid).string(name)?.string(target)?.u32(*gid);
                out
            },
            Self::Renameat { olddirfid, oldname, newdirfid, newname } => {
                let mut out = Out::new(TRENAMEAT, tag);
                out.u32(*olddirfid).string(oldname)?.u32(*newdirfid).string(newname)?;
                out
            },
            Self::Unlinkat { dirfid, name, flags } => {
                let mut out = Out::new(TUNLINKAT, tag);
                out.u32(*dirfid).string(name)?.u32(*flags);
                out
            },
        };
        out.done()
    }

    /// A whole message's tag and request.
    pub fn decode(message: &[u8]) -> io::Result<(u16, Self)> {
        #[allow(clippy::wildcard_imports, reason = "every message type, matched on")]
        use kind::*;
        let (kind, tag, mut input) = header(message)?;
        let i = &mut input;
        let msg = match kind {
            TVERSION => Self::Version { msize: i.u32()?, version: i.string()? },
            TATTACH => Self::Attach { fid: i.u32()?, afid: i.u32()?, uname: i.string()?, aname: i.string()?, n_uname: i.u32()? },
            TFLUSH => Self::Flush { oldtag: i.u16()? },
            TWALK => {
                let (fid, newfid, count) = (i.u32()?, i.u32()?, i.u16()?);
                let names = (0..count).map(|_| i.string()).collect::<io::Result<_>>()?;
                Self::Walk { fid, newfid, names }
            },
            TCLUNK => Self::Clunk { fid: i.u32()? },
            TREMOVE => Self::Remove { fid: i.u32()? },
            TSTATFS => Self::Statfs { fid: i.u32()? },
            TREADLINK => Self::Readlink { fid: i.u32()? },
            TGETATTR => Self::Getattr { fid: i.u32()?, mask: i.u64()? },
            TSETATTR => Self::Setattr {
                fid: i.u32()?,
                attr: SetAttr { valid: i.u32()?, mode: i.u32()?, uid: i.u32()?, gid: i.u32()?, size: i.u64()?, atime: i.time()?, mtime: i.time()? },
            },
            TLOPEN => Self::Lopen { fid: i.u32()?, flags: i.u32()? },
            TLCREATE => Self::Lcreate { fid: i.u32()?, name: i.string()?, flags: i.u32()?, mode: i.u32()?, gid: i.u32()? },
            TREAD => Self::Read { fid: i.u32()?, offset: i.u64()?, count: i.u32()? },
            TWRITE => Self::Write { fid: i.u32()?, offset: i.u64()?, data: i.data()? },
            TREADDIR => Self::Readdir { fid: i.u32()?, offset: i.u64()?, count: i.u32()? },
            TFSYNC => Self::Fsync { fid: i.u32()?, datasync: i.u32()? },
            TMKDIR => Self::Mkdir { dfid: i.u32()?, name: i.string()?, mode: i.u32()?, gid: i.u32()? },
            TSYMLINK => Self::Symlink { fid: i.u32()?, name: i.string()?, target: i.string()?, gid: i.u32()? },
            TRENAMEAT => Self::Renameat { olddirfid: i.u32()?, oldname: i.string()?, newdirfid: i.u32()?, newname: i.string()? },
            TUNLINKAT => Self::Unlinkat { dirfid: i.u32()?, name: i.string()?, flags: i.u32()? },
            _ => return Err(Unknown(kind, tag).into()),
        };
        input.end()?;
        Ok((tag, msg))
    }
}

/// A request of a type this doesn't know, as its type and tag, so a server
/// can say so to it.
#[derive(Debug, thiserror::Error)]
#[error("9P: a message of unknown type {0}")]
pub struct Unknown(pub u8, pub u16);

impl From<Unknown> for io::Error {
    fn from(unknown: Unknown) -> Self {
        Self::new(io::ErrorKind::Unsupported, unknown)
    }
}

fn fid_only(kind: u8, tag: u16, fid: u32) -> Out {
    let mut out = Out::new(kind, tag);
    out.u32(fid);
    out
}

impl Rmsg {
    /// The answer's type: its request's, plus one.
    const fn kind(&self) -> u8 {
        #[allow(clippy::wildcard_imports, reason = "every message type, matched on")]
        use kind::*;
        let request = match self {
            Self::Lerror { .. } => return RLERROR,
            Self::Version { .. } => TVERSION,
            Self::Attach { .. } => TATTACH,
            Self::Flush => TFLUSH,
            Self::Walk { .. } => TWALK,
            Self::Clunk => TCLUNK,
            Self::Remove => TREMOVE,
            Self::Statfs(_) => TSTATFS,
            Self::Getattr(_) => TGETATTR,
            Self::Setattr => TSETATTR,
            Self::Lopen { .. } => TLOPEN,
            Self::Lcreate { .. } => TLCREATE,
            Self::Read { .. } => TREAD,
            Self::Write { .. } => TWRITE,
            Self::Readdir { .. } => TREADDIR,
            Self::Fsync => TFSYNC,
            Self::Mkdir { .. } => TMKDIR,
            Self::Symlink { .. } => TSYMLINK,
            Self::Readlink { .. } => TREADLINK,
            Self::Renameat => TRENAMEAT,
            Self::Unlinkat => TUNLINKAT,
        };
        request.wrapping_add(1)
    }

    /// The message, with its tag.
    pub fn encode(&self, tag: u16) -> io::Result<Vec<u8>> {
        let mut out = Out::new(self.kind(), tag);
        match self {
            Self::Version { msize, version } => {
                out.u32(*msize).string(version)?;
            },
            Self::Lerror { ecode } => {
                out.u32(*ecode);
            },
            Self::Attach { qid } | Self::Mkdir { qid } | Self::Symlink { qid } => {
                out.qid(qid);
            },
            Self::Walk { qids } => {
                let count = u16::try_from(qids.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "9P: too many qids"))?;
                out.u16(count);
                for qid in qids {
                    out.qid(qid);
                }
            },
            Self::Statfs(s) => {
                out.u32(s.kind).u32(s.bsize).u64(s.blocks).u64(s.bfree).u64(s.bavail).u64(s.files).u64(s.ffree).u64(s.fsid).u32(s.namelen);
            },
            Self::Getattr(a) => {
                out.u64(a.valid).qid(&a.qid).u32(a.mode).u32(a.uid).u32(a.gid).u64(a.nlink).u64(a.rdev).u64(a.size).u64(a.blksize).u64(a.blocks);
                out.time(a.atime).time(a.mtime).time(a.ctime).time(a.btime).u64(a.generation).u64(a.data_version);
            },
            Self::Lopen { qid, iounit } | Self::Lcreate { qid, iounit } => {
                out.qid(qid).u32(*iounit);
            },
            Self::Read { data } | Self::Readdir { data } => {
                out.data(data)?;
            },
            Self::Write { count } => {
                out.u32(*count);
            },
            Self::Readlink { target } => {
                out.string(target)?;
            },
            Self::Flush | Self::Clunk | Self::Remove | Self::Setattr | Self::Fsync | Self::Renameat | Self::Unlinkat => {},
        }
        out.done()
    }

    /// A whole message's tag and answer.
    pub fn decode(message: &[u8]) -> io::Result<(u16, Self)> {
        #[allow(clippy::wildcard_imports, reason = "every message type, matched on")]
        use kind::*;
        let (kind, tag, mut input) = header(message)?;
        let i = &mut input;
        let msg = match kind.wrapping_sub(1) {
            _ if kind == RLERROR => Self::Lerror { ecode: i.u32()? },
            TVERSION => Self::Version { msize: i.u32()?, version: i.string()? },
            TATTACH => Self::Attach { qid: i.qid()? },
            TFLUSH => Self::Flush,
            TWALK => {
                let count = i.u16()?;
                Self::Walk { qids: (0..count).map(|_| i.qid()).collect::<io::Result<_>>()? }
            },
            TCLUNK => Self::Clunk,
            TREMOVE => Self::Remove,
            TSTATFS => Self::Statfs(StatFs {
                kind: i.u32()?,
                bsize: i.u32()?,
                blocks: i.u64()?,
                bfree: i.u64()?,
                bavail: i.u64()?,
                files: i.u64()?,
                ffree: i.u64()?,
                fsid: i.u64()?,
                namelen: i.u32()?,
            }),
            TGETATTR => Self::Getattr(Box::new(Attr {
                valid: i.u64()?,
                qid: i.qid()?,
                mode: i.u32()?,
                uid: i.u32()?,
                gid: i.u32()?,
                nlink: i.u64()?,
                rdev: i.u64()?,
                size: i.u64()?,
                blksize: i.u64()?,
                blocks: i.u64()?,
                atime: i.time()?,
                mtime: i.time()?,
                ctime: i.time()?,
                btime: i.time()?,
                generation: i.u64()?,
                data_version: i.u64()?,
            })),
            TSETATTR => Self::Setattr,
            TLOPEN => Self::Lopen { qid: i.qid()?, iounit: i.u32()? },
            TLCREATE => Self::Lcreate { qid: i.qid()?, iounit: i.u32()? },
            TREAD => Self::Read { data: i.data()? },
            TWRITE => Self::Write { count: i.u32()? },
            TREADDIR => Self::Readdir { data: i.data()? },
            TFSYNC => Self::Fsync,
            TMKDIR => Self::Mkdir { qid: i.qid()? },
            TSYMLINK => Self::Symlink { qid: i.qid()? },
            TREADLINK => Self::Readlink { target: i.string()? },
            TRENAMEAT => Self::Renameat,
            TUNLINKAT => Self::Unlinkat,
            _ => return Err(invalid(&format!("an answer of unknown type {kind}"))),
        };
        input.end()?;
        Ok((tag, msg))
    }
}

/// Directory entries as `Rreaddir` carries them, as many as fit in
/// `count` bytes, and how many that was.
pub fn dirents(entries: &[DirEntry], count: u32) -> io::Result<(Vec<u8>, usize)> {
    let limit = usize::try_from(count).unwrap_or(usize::MAX);
    let mut data = Vec::new();
    let mut taken = 0usize;
    for entry in entries {
        let mut one = Out(Vec::new());
        one.qid(&entry.qid).u64(entry.offset).u8(entry.kind).string(&entry.name)?;
        if data.len().saturating_add(one.0.len()) > limit {
            break;
        }
        data.extend_from_slice(&one.0);
        taken = taken.saturating_add(1);
    }
    Ok((data, taken))
}

/// The entries of an `Rreaddir`.
pub fn parse_dirents(data: &[u8]) -> io::Result<Vec<DirEntry>> {
    let mut input = In(data);
    let mut entries = Vec::new();
    while !input.0.is_empty() {
        entries.push(DirEntry { qid: input.qid()?, offset: input.u64()?, kind: input.u8()?, name: input.string()? });
    }
    Ok(entries)
}

/// Read one whole message, no bigger than `msize`.
pub fn read_message(reader: &mut impl Read, msize: u32) -> io::Result<Vec<u8>> {
    let mut size = [0u8; 4];
    reader.read_exact(&mut size)?;
    let len = u32::from_le_bytes(size);
    if len > msize || usize::try_from(len).is_ok_and(|len| len < HEADER) {
        return Err(invalid(&format!("a message of {len} bytes")));
    }
    let len = usize::try_from(len).map_err(|_| invalid("a message too big"))?;
    let mut message = vec![0u8; len];
    message.get_mut(..4).unwrap_or_default().copy_from_slice(&size);
    reader.read_exact(message.get_mut(4..).unwrap_or_default())?;
    Ok(message)
}

/// Write one whole message.
pub fn write_message(writer: &mut impl Write, message: &[u8]) -> io::Result<()> {
    writer.write_all(message)?;
    writer.flush()
}
