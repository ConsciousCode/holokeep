//! Anchors served by another node: 9P2000.L carried over the mesh,
//! `/holokeep/serve/1.0.0` (see the wiki's Servers page).
//!
//! A mount reaches an anchor served by another node through its own
//! node, on the repo's `serve.sock`: it names the anchor, the service and
//! the serving node, then speaks 9P2000.L. Its node answers `Tversion`
//! itself and sends every other message to the serving node as a request
//! of its own, in a *session* that lasts as long as the mount's
//! connection, the answer coming back as the response.
//!
//! The serving node lets in only a machine hosting the user whose anchor
//! it is, as it does for anything of theirs, and only for an anchor whose
//! serve claim names this node and the service, which its own config
//! has. It connects to the service, a connection for each session, as the
//! user it runs as. What's sent is decoded first, and only what 9P2000.L
//! asks of a filesystem goes on; and who's asking is said by the serving
//! node, never the asker: `Tattach`'s `uname` is the user's root key,
//! `n_uname` none, as they're no user of this machine, and `aname` the
//! anchor. An empty message ends a session.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use libp2p::PeerId;
use libp2p::StreamProtocol;
use libp2p::request_response::ResponseChannel;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::model::Link;
use crate::ninep::client::libc_errno;
use crate::ninep::{self, MSIZE, NOFID, NONUNAME, NOTAG, Rmsg, Tmsg};

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/serve/1.0.0");

/// The most a message relayed may be: what the mount's told it is.
pub const RELAYED: u32 = MSIZE;

/// A message for a served anchor, in a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Asked {
    /// Whose anchor it is, as other requests name a user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<ByteBuf>,
    pub session: u64,
    pub anchor: ByteBuf,
    pub service: String,
    /// A whole 9P2000.L message; empty ends the session.
    pub message: ByteBuf,
}

/// The answer to one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Answered {
    pub message: ByteBuf,
}

/// A message's tag, from its header.
pub fn tag_of(message: &[u8]) -> u16 {
    message.get(5..7).and_then(|tag| tag.try_into().ok()).map_or(NOTAG, u16::from_le_bytes)
}

/// An `Rlerror` for a message, by its tag.
pub fn error_for(message: &[u8], errno: i32) -> Vec<u8> {
    Rmsg::Lerror { ecode: u32::try_from(errno).unwrap_or(5) }.encode(tag_of(message)).unwrap_or_default()
}

/// Whether a request changes anything, which only a writer may ask.
pub const fn writes(request: &Tmsg) -> bool {
    const ACCESS: u32 = 0o3;
    const TRUNC: u32 = 0o1000;
    match request {
        Tmsg::Lopen { flags, .. } => (*flags & ACCESS) != 0 || (*flags & TRUNC) != 0,
        Tmsg::Remove { .. }
        | Tmsg::Setattr { .. }
        | Tmsg::Lcreate { .. }
        | Tmsg::Write { .. }
        | Tmsg::Mkdir { .. }
        | Tmsg::Symlink { .. }
        | Tmsg::Renameat { .. }
        | Tmsg::Unlinkat { .. } => true,
        _ => false,
    }
}

/// What a peer's message becomes, said as this node says it, or why it
/// isn't sent on.
///
/// Only what's decoded goes, what changes anything only if the asker may
/// write, and an attach is as this node says, for the user, of the
/// anchor.
pub fn rewritten(message: &[u8], user: Option<&Link>, anchor: &Link, may_write: bool) -> Result<Vec<u8>, i32> {
    let (tag, request) = Tmsg::decode(message).map_err(|_| libc_errno::EOPNOTSUPP)?;
    if !may_write && writes(&request) {
        return Err(libc_errno::EROFS);
    }
    let request = match request {
        Tmsg::Version { .. } => return Err(libc_errno::EINVAL),
        Tmsg::Attach { fid, .. } => Tmsg::Attach {
            fid,
            afid: NOFID,
            uname: user.map(|user| user.to_string().into_bytes()).unwrap_or_default(),
            aname: anchor.to_string().into_bytes(),
            n_uname: NONUNAME,
        },
        request => request,
    };
    request.encode(tag).map_err(|_| libc_errno::EINVAL)
}

/// Agree on 9P2000.L with a service just connected to.
pub fn handshake(stream: &mut UnixStream) -> io::Result<u32> {
    ninep::write_message(stream, &Tmsg::Version { msize: RELAYED, version: ninep::VERSION.to_vec() }.encode(NOTAG)?)?;
    match Rmsg::decode(&ninep::read_message(stream, RELAYED)?)? {
        (_, Rmsg::Version { msize, version }) if version == ninep::VERSION => Ok(msize),
        _ => Err(io::Error::new(io::ErrorKind::Unsupported, "the service doesn't speak 9P2000.L")),
    }
}

/// A session's connection to a service, who it's for, and who's waiting
/// on what.
struct Session {
    writer: UnixStream,
    /// Who it's for and of what, as the first message said: the user and
    /// the anchor, by their bytes. Its attach was for them, so every other
    /// message must be.
    of: (Vec<u8>, Vec<u8>),
    waiting: HashMap<u16, ResponseChannel<Answered>>,
}

/// What a session's service said, or that it hung up: from the thread
/// reading it.
pub type Heard = (PeerId, u64, Option<Vec<u8>>);

/// The sessions this node serves, by peer and session.
pub struct Sessions {
    sessions: HashMap<(PeerId, u64), Session>,
    heard: tokio::sync::mpsc::UnboundedSender<Heard>,
}

impl Sessions {
    /// Sessions whose services' answers come to `heard`.
    pub fn new(heard: tokio::sync::mpsc::UnboundedSender<Heard>) -> Self {
        Self { sessions: HashMap::new(), heard }
    }

    /// Who an open session is for and of what (see `Session::of`).
    pub fn of(&self, peer: &PeerId, session: u64) -> Option<&(Vec<u8>, Vec<u8>)> {
        self.sessions.get(&(*peer, session)).map(|open| &open.of)
    }

    /// Open a session on a service for a user, of an anchor, connected to
    /// as this process's user, if it's fit to be.
    pub fn start(&mut self, peer: PeerId, session: u64, of: (Vec<u8>, Vec<u8>), repo: &Path, service: &str) -> Result<(), i32> {
        let service = crate::served::service(repo, service).map_err(|e| {
            eprintln!("serving {peer}: {e}");
            libc_errno::EACCES
        })?;
        let mut stream = crate::served::connect_raw(&service).map_err(|e| {
            eprintln!("serving {peer}: {e}");
            libc_errno::ENOTCONN
        })?;
        let msize = handshake(&mut stream).map_err(|_| libc_errno::ENOTCONN)?;
        let mut reader = stream.try_clone().map_err(|_| libc_errno::ENOTCONN)?;
        let heard = self.heard.clone();
        std::thread::Builder::new()
            .name("served-session".into())
            .spawn(move || {
                while let Ok(message) = ninep::read_message(&mut reader, msize) {
                    if heard.send((peer, session, Some(message))).is_err() {
                        return;
                    }
                }
                let _ = heard.send((peer, session, None));
            })
            .map_err(|_| libc_errno::ENOTCONN)?;
        self.sessions.insert((peer, session), Session { writer: stream, of, waiting: HashMap::new() });
        Ok(())
    }

    /// Send a message on a session, its answer to go to `channel`; or the
    /// channel back, with why not.
    pub fn send(&mut self, peer: PeerId, session: u64, message: &[u8], channel: ResponseChannel<Answered>) -> Result<(), (ResponseChannel<Answered>, i32)> {
        let Some(open) = self.sessions.get_mut(&(peer, session)) else {
            return Err((channel, libc_errno::ENOTCONN));
        };
        if ninep::write_message(&mut open.writer, message).is_err() {
            self.sessions.remove(&(peer, session));
            return Err((channel, libc_errno::ENOTCONN));
        }
        open.waiting.insert(tag_of(message), channel);
        Ok(())
    }

    /// Who's waiting on an answer heard, and the answer.
    pub fn answered(&mut self, peer: PeerId, session: u64, message: &[u8]) -> Option<ResponseChannel<Answered>> {
        self.sessions.get_mut(&(peer, session))?.waiting.remove(&tag_of(message))
    }

    /// End a session, giving back everyone still waiting on it, each with
    /// its answer: that it's not connected.
    pub fn end(&mut self, peer: PeerId, session: u64) -> Vec<(ResponseChannel<Answered>, Answered)> {
        let Some(open) = self.sessions.remove(&(peer, session)) else {
            return Vec::new();
        };
        let _ = open.writer.shutdown(std::net::Shutdown::Both);
        open.waiting
            .into_iter()
            .map(|(tag, channel)| {
                let gone = Rmsg::Lerror { ecode: u32::try_from(libc_errno::ENOTCONN).unwrap_or(5) }.encode(tag).unwrap_or_default();
                (channel, Answered { message: ByteBuf::from(gone) })
            })
            .collect()
    }

    /// End every session of a peer that's gone.
    pub fn gone(&mut self, peer: &PeerId) {
        let ended: Vec<(PeerId, u64)> = self.sessions.keys().filter(|(of, _)| of == peer).copied().collect();
        for (peer, session) in ended {
            self.end(peer, session);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whats_relayed_is_said_as_the_serving_node_says() {
        let anchor: Link = crate::claim::anchor().expect("anchor");
        let user: Link = crate::claim::anchor().expect("a CID");
        let attach = Tmsg::Attach { fid: 1, afid: 7, uname: b"root".to_vec(), aname: b"/etc".to_vec(), n_uname: 0 }.encode(3).expect("encode");
        let (tag, said) = Tmsg::decode(&rewritten(&attach, Some(&user), &anchor, true).expect("rewritten")).expect("decode");
        assert_eq!(tag, 3);
        assert_eq!(
            said,
            Tmsg::Attach { fid: 1, afid: NOFID, uname: user.to_string().into_bytes(), aname: anchor.to_string().into_bytes(), n_uname: NONUNAME },
            "no root, no other tree, no uid of this machine's"
        );
        let walk = Tmsg::Walk { fid: 1, newfid: 2, names: vec![b"a".to_vec()] }.encode(4).expect("encode");
        assert_eq!(rewritten(&walk, Some(&user), &anchor, false).expect("rewritten"), walk, "the rest as it is");
        let version = Tmsg::Version { msize: 1, version: b"9P2000".to_vec() }.encode(NOTAG).expect("encode");
        assert_eq!(rewritten(&version, None, &anchor, true), Err(libc_errno::EINVAL));
        // A message of a type it doesn't know, as an auth or a lock
        let mut unknown = Tmsg::Clunk { fid: 1 }.encode(5).expect("encode");
        if let Some(kind) = unknown.get_mut(4) {
            *kind = 102;
        }
        assert_eq!(rewritten(&unknown, None, &anchor, true), Err(libc_errno::EOPNOTSUPP));
        assert_eq!(tag_of(&error_for(&walk, 13)), 4);
        // Only a writer changes anything
        let write = Tmsg::Write { fid: 2, offset: 0, data: b"x".to_vec() }.encode(6).expect("encode");
        assert_eq!(rewritten(&write, Some(&user), &anchor, false), Err(libc_errno::EROFS));
        assert_eq!(rewritten(&write, Some(&user), &anchor, true).expect("rewritten"), write);
        let reading = Tmsg::Lopen { fid: 2, flags: 0 }.encode(7).expect("encode");
        assert!(rewritten(&reading, Some(&user), &anchor, false).is_ok());
        for flags in [1, 2, 0o1000] {
            let opening = Tmsg::Lopen { fid: 2, flags }.encode(7).expect("encode");
            assert_eq!(rewritten(&opening, Some(&user), &anchor, false), Err(libc_errno::EROFS), "{flags:o}");
        }
    }
}
