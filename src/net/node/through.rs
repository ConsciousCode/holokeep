//! Fetching from Amino through a member that's in it, for one that isn't:
//! `/holokeep/amino-fetch/1.0.0`.
//!
//! A node not in Amino asks the members hosting its user, one at a time,
//! to fetch from Amino what it wants; one that's in Amino fetches it, as
//! for itself, shared back or kept to itself as asked, and says what came
//! of it, and the asker then has it from the mesh as anything else. One
//! that isn't says so, and the next is asked. So a household's machines
//! needn't each be in Amino: one with its ports open, a relay say, is
//! their way in. Only members hosting the asker's user are asked or
//! answered, so what's wanted goes no further than the user's own
//! machines before Amino.

use std::collections::{HashMap, HashSet};

use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::{Event, FetchId, Node, Result};
use crate::cid::{Cid as _, CidRef as _};
use crate::model::Link;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/amino-fetch/1.0.0");

/// How long a member's answer is waited for: as long as a fetch from
/// Amino goes on, which is as long as blocks keep coming.
pub const ANSWER: std::time::Duration = std::time::Duration::from_hours(6);

/// What a member's asked to fetch from Amino: these blocks, or the whole
/// DAGs under them, shared back or not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asked {
    roots: Vec<ByteBuf>,
    dag: bool,
    share: bool,
}

/// What came of it: whether the member's in Amino, how many blocks it
/// fetched, and what it couldn't.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Answered {
    in_amino: bool,
    fetched: u64,
    missing: Vec<ByteBuf>,
}

/// An answer to send once Amino's fetched what was asked.
pub type Done = (ResponseChannel<Answered>, Answered);

/// Fetches from Amino through members, by id; who's being asked for
/// each; the fetches from the mesh that finish them, by their own ids;
/// and members' fetches through this node, answered once done.
pub struct Forwarded {
    forwards: HashMap<FetchId, Forward>,
    forwarding: HashMap<OutboundRequestId, FetchId>,
    pub renamed: HashMap<FetchId, FetchId>,
    done: tokio::sync::mpsc::UnboundedSender<Done>,
    pub answers: tokio::sync::mpsc::UnboundedReceiver<Done>,
}

impl Forwarded {
    pub fn new() -> Self {
        let (done, answers) = tokio::sync::mpsc::unbounded_channel();
        Self { forwards: HashMap::new(), forwarding: HashMap::new(), renamed: HashMap::new(), done, answers }
    }
}

/// A fetch from Amino through a member, under way.
pub struct Forward {
    roots: Vec<Link>,
    dag: bool,
    share: bool,
    /// Who's been asked.
    asked: HashSet<PeerId>,
}

impl Node {
    /// Fetch these blocks, or the whole DAGs under them, from Amino through
    /// a member that's in it, sharing what's fetched back or not. It's done
    /// when `next` returns `Fetched` with the id, once what the member
    /// fetched has been had of the mesh, or no member could.
    pub fn fetch_through_amino(&mut self, roots: Vec<Link>, dag: bool, share: bool) -> Result<FetchId> {
        let id = self.next_fetch;
        self.next_fetch = id.wrapping_add(1);
        self.forwarded.forwards.insert(id, Forward { roots, dag, share, asked: HashSet::new() });
        self.forward(id)?;
        Ok(id)
    }

    /// Ask the next member hosting this node's user that hasn't been, or,
    /// with none left, finish: none could fetch any of it.
    fn forward(&mut self, id: FetchId) -> Result<()> {
        let Some(local) = self.serving_local()? else {
            self.unforwarded(id);
            return Ok(());
        };
        let ours: Vec<PeerId> = self.swarm.connected_peers().copied().filter(|peer| !self.is_client(peer) && !self.visitors.contains_key(peer) && self.hosts(peer, &local)).collect();
        let Some(forward) = self.forwarded.forwards.get_mut(&id) else {
            return Ok(());
        };
        let Some(peer) = ours.into_iter().find(|peer| !forward.asked.contains(peer)) else {
            self.unforwarded(id);
            return Ok(());
        };
        forward.asked.insert(peer);
        let asked = Asked { roots: forward.roots.iter().map(|root| ByteBuf::from(root.to_bytes())).collect(), dag: forward.dag, share: forward.share };
        let request = self.swarm.behaviour_mut().through.send_request(&peer, asked);
        self.forwarded.forwarding.insert(request, id);
        Ok(())
    }

    /// No member could fetch it: it's all missing.
    fn unforwarded(&mut self, id: FetchId) {
        if let Some(forward) = self.forwarded.forwards.remove(&id) {
            self.ready.push_back(Event::Fetched { id, fetched: 0, missing: forward.roots });
        }
    }

    pub(super) fn on_through(&mut self, event: request_response::Event<Asked, Answered>) -> Result<Option<super::Event>> {
        self.through_event(event).map(|()| None)
    }

    fn through_event(&mut self, event: request_response::Event<Asked, Answered>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => self.through_asked(peer, &request, channel),
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                let Some(id) = self.forwarded.forwarding.remove(&request_id) else {
                    return Ok(());
                };
                if !response.in_amino {
                    return self.forward(id);
                }
                // Fetched there, it's had of the mesh, under the same id
                let Some(forward) = self.forwarded.forwards.remove(&id) else {
                    return Ok(());
                };
                let fetch = match (forward.dag, forward.roots.as_slice()) {
                    (true, [root]) => super::Fetch::new(root.clone()),
                    _ => super::Fetch::blocks(forward.roots),
                };
                let uid = self.catalog.uid();
                let mesh = self.start_fetch(uid, fetch)?;
                self.forwarded.renamed.insert(mesh, id);
                Ok(())
            },
            request_response::Event::OutboundFailure { request_id, .. } => self.forwarded.forwarding.remove(&request_id).map_or(Ok(()), |id| self.forward(id)),
            _ => Ok(()),
        }
    }

    /// A member asks this node to fetch from Amino for it: if it hosts
    /// this node's user and this node's in Amino, it's fetched, and
    /// answered once it's done.
    fn through_asked(&mut self, peer: PeerId, request: &Asked, channel: ResponseChannel<Answered>) -> Result<()> {
        let ours = self.serving_local()?.is_some_and(|local| !self.is_client(&peer) && self.hosts(&peer, &local));
        let roots: Option<Vec<Link>> = request.roots.iter().map(|root| Link::decode(root).ok()).collect();
        let (Some(amino), true, Some(roots)) = (super::super::amino::handle(), ours, roots) else {
            let _ = self.swarm.behaviour_mut().through.send_response(channel, Answered::default());
            return Ok(());
        };
        let answer = amino.fetch(roots, request.dag, request.share);
        let done = self.forwarded.done.clone();
        tokio::spawn(async move {
            let answered = answer.await.map_or_else(
                |_| Answered::default(),
                |fetched| Answered { in_amino: true, fetched: u64::try_from(fetched.fetched).unwrap_or(u64::MAX), missing: fetched.missing.iter().map(|cid| ByteBuf::from(cid.to_bytes())).collect() },
            );
            let _ = done.send((channel, answered));
        });
        Ok(())
    }

    /// The account this node serves as its own, whose user's machines ask
    /// and are asked.
    fn serving_local(&self) -> Result<Option<super::Local>> {
        let uid = self.catalog.uid();
        Ok(self.locals()?.into_iter().find(|local| local.uid == uid))
    }
}
