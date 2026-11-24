//! Anchors served across the mesh (see `crate::net::serve`): answering
//! another node's messages for what this node serves, and sending this
//! node's for what another does.

use std::path::PathBuf;

use libp2p::PeerId;
use libp2p::request_response::{self, ResponseChannel};
use serde_bytes::ByteBuf;

use super::{Event, Node};
use crate::cid::{Cid as _, CidRef as _};
use crate::model::Link;
use crate::net::mesh::{Error, Result};
use crate::net::serve::{Answered, Asked, error_for, rewritten};
use crate::ninep::client::libc_errno;

impl Node {
    /// Serve anchors from the services the config of the repo in `dir`
    /// says.
    pub fn set_repo(&mut self, dir: PathBuf) {
        self.repo = Some(dir);
    }

    /// Send a message for an anchor a peer serves, in a session of this
    /// node's: its answer comes as `Event::Served`.
    pub fn ask_served(&mut self, peer: &PeerId, session: u64, anchor: &Link, service: &str, message: Vec<u8>) -> Result<()> {
        if !self.swarm.is_connected(peer) {
            return Err(Error::Invalid(format!("{peer} isn't connected")));
        }
        let user = self.local(self.catalog.uid())?.user_bytes().map(ByteBuf::from);
        let asked = Asked { user, session, anchor: ByteBuf::from(anchor.to_bytes()), service: service.to_owned(), message: ByteBuf::from(message.clone()) };
        let request = self.swarm.behaviour_mut().serve.send_request(peer, asked);
        self.asking_served.insert(request, (session, message));
        Ok(())
    }

    /// End a session of this node's with a peer.
    pub fn end_served(&mut self, peer: &PeerId, session: u64, anchor: &Link, service: &str) {
        if self.swarm.is_connected(peer) {
            let asked = Asked { user: None, session, anchor: ByteBuf::from(anchor.to_bytes()), service: service.to_owned(), message: ByteBuf::new() };
            self.swarm.behaviour_mut().serve.send_request(peer, asked);
        }
    }

    pub(super) fn on_serve(&mut self, event: request_response::Event<Asked, Answered>) -> Result<Option<Event>> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                self.serve_asked(peer, &request, channel)?;
                Ok(None)
            },
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                // Nothing, from a session that's ended, is that
                Ok(self.asking_served.remove(&request_id).map(|(session, message)| {
                    let answer = if response.message.is_empty() { error_for(&message, libc_errno::ENOTCONN) } else { response.message.into_vec() };
                    Event::Served { session, message: answer }
                }))
            },
            // What it was is answered, so whoever asked isn't left waiting
            request_response::Event::OutboundFailure { request_id, .. } => {
                Ok(self.asking_served.remove(&request_id).map(|(session, message)| Event::Served { session, message: error_for(&message, libc_errno::ENOTCONN) }))
            },
            _ => Ok(None),
        }
    }

    /// Answer a peer's message for an anchor this node serves, if it's let
    /// in to it, by sending it on to the service, as this node says it.
    fn serve_asked(&mut self, peer: PeerId, request: &Asked, channel: ResponseChannel<Answered>) -> Result<()> {
        let refuse = |node: &mut Self, channel, errno| {
            let _ = node.swarm.behaviour_mut().serve.send_response(channel, Answered { message: ByteBuf::from(error_for(&request.message, errno)) });
        };
        if request.message.is_empty() {
            for (waiting, gone) in self.sessions.end(peer, request.session) {
                let _ = self.swarm.behaviour_mut().serve.send_response(waiting, gone);
            }
            let _ = self.swarm.behaviour_mut().serve.send_response(channel, Answered::default());
            return Ok(());
        }
        // A machine hosting the user whose anchor it is, and only for what
        // this node's own account serves, from its own config
        let local = self.serving(&peer, request.user.as_ref().map(|user| user.as_slice()))?;
        let (Some(local), Some(repo)) = (local, self.repo.clone()) else {
            refuse(self, channel, libc_errno::EACCES);
            return Ok(());
        };
        let Ok(anchor) = Link::decode(&request.anchor) else {
            refuse(self, channel, libc_errno::EINVAL);
            return Ok(());
        };
        let me = self.peer_id().to_bytes();
        let serving = self.catalog.viewing(local.uid, |catalog| catalog.serving(&anchor))??;
        if local.uid != self.catalog.uid() || !serving.is_some_and(|serve| serve.node() == me.as_slice() && serve.service() == request.service) {
            refuse(self, channel, libc_errno::EACCES);
            return Ok(());
        }
        let message = match rewritten(&request.message, local.user.as_ref(), &anchor) {
            Ok(message) => message,
            Err(errno) => {
                refuse(self, channel, errno);
                return Ok(());
            },
        };
        if !self.sessions.open(&peer, request.session)
            && let Err(errno) = self.sessions.start(peer, request.session, &repo, &request.service)
        {
            refuse(self, channel, errno);
            return Ok(());
        }
        if let Err((channel, errno)) = self.sessions.send(peer, request.session, &message, channel) {
            refuse(self, channel, errno);
        }
        Ok(())
    }

    /// What a session's service said, sent back to whoever's waiting; or
    /// that it hung up, which ends the session.
    pub(super) fn on_heard(&mut self, peer: PeerId, session: u64, message: Option<Vec<u8>>) {
        match message {
            Some(message) => {
                if let Some(channel) = self.sessions.answered(peer, session, &message) {
                    let _ = self.swarm.behaviour_mut().serve.send_response(channel, Answered { message: ByteBuf::from(message) });
                }
            },
            None => {
                // Each waiting is answered, so its asker isn't left to time out
                for (channel, gone) in self.sessions.end(peer, session) {
                    let _ = self.swarm.behaviour_mut().serve.send_response(channel, gone);
                }
            },
        }
    }
}
