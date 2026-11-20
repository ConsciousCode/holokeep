//! Thin clients: clients with no repo of their own, as a sandbox without
//! a disk to keep one on, asking their member for what they read and
//! sending it what they write.
//!
//! - A thin client is a directory holding a key, its peer ID the device
//!   key a user certified, and the ticket it joined with (`hk node join
//!   --thin`), which says where its member listens for clients. Its member
//!   lets it in as it does any client.
//! - It reads blocks as any client does, asking its member, which fetches
//!   what it lacks of the user's from the user's other machines. A thin
//!   client asks again a while, rather than waiting on a fetch of its own.
//! - It writes blocks by pushing them to its member, which holds them for
//!   the client's account, as it holds what any machine pushes.
//! - What it says, keeps, tags and anchors, it asks its member to say as
//!   its account, which the member signs for with the account's key there,
//!   as for a host's users sharing a repo (`hk node run --shared`). What
//!   that needs of a DAG, the member fetches first.
//!
//! Each command connects anew: a thin client keeps nothing between them
//! but its key and ticket.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::time::Duration;

use futures::StreamExt as _;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, ping, tcp};
use serde::{Deserialize, Serialize};

use super::blocks::{Blocks, Want};
use super::durability::{Kept, Push};
use super::mesh::{self, Error, Result, Ticket};
use super::node::exchange;
use crate::block::Block;
use crate::cid::{Cid as _, CidRef as _};
use crate::dag::BlockSink;
use crate::model::Link;

/// What a client asks its member to say or tell it.
pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/ask/1.0.0");

/// The ticket a thin client joined with, in its directory.
const TICKET: &str = "thin.ticket";

/// How long to wait for the member to connect.
const CONNECT: Duration = Duration::from_secs(20);

/// How long a member may take to answer: what it's asked to keep, it may
/// fetch first.
pub const ANSWER: Duration = Duration::from_mins(10);

/// How long to keep asking for blocks the member is fetching.
const PATIENCE: Duration = Duration::from_secs(30);

/// About the most block data to push at once, or to hold read ahead.
const BUDGET: usize = 4 << 20;

/// A command, as words, which `crate::account` answers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ask {
    pub words: Vec<String>,
}

/// An answer, by lines; an error by a line starting "error: ".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Answer {
    pub lines: Vec<String>,
}

/// Whether a directory is a thin client's.
pub fn is_thin(dir: &Path) -> bool {
    dir.join(TICKET).is_file()
}

/// Make a directory a thin client of the member a client's ticket is
/// from, or of the same member again, wherever it listens now. Returns
/// the ticket.
pub fn join(dir: &Path, text: &str) -> Result<Ticket> {
    let ticket = Ticket::decode(text)?;
    if !ticket.client || ticket.swarm_key.is_some() || ticket.user.is_none() {
        return Err(Error::Invalid("not a client's ticket: `hk node invite --client` makes one".into()));
    }
    if dir.join("blocks.db").exists() {
        return Err(Error::Invalid(format!("{} is a repo: a thin client has a directory of its own", dir.display())));
    }
    if is_thin(dir) {
        let had = Ticket::decode(&std::fs::read_to_string(dir.join(TICKET))?)?;
        if had.inviter != ticket.inviter {
            return Err(Error::Invalid(format!("this is a thin client of {}", had.inviter)));
        }
    }
    // The key the ticket's for
    mesh::node_key(dir)?;
    let fresh = dir.join(format!("{TICKET}.new"));
    let _ = std::fs::remove_file(&fresh);
    mesh::write_secret(&fresh, text.trim().as_bytes())?;
    std::fs::rename(&fresh, dir.join(TICKET))?;
    Ok(ticket)
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    ping: ping::Behaviour,
    blocks: request_response::cbor::Behaviour<Want, Blocks>,
    push: request_response::cbor::Behaviour<Push, Kept>,
    asks: request_response::cbor::Behaviour<Ask, Answer>,
}

/// A thin client, connecting to its member.
pub struct Thin {
    swarm: Swarm<Behaviour>,
    member: PeerId,
    addrs: Vec<Multiaddr>,
    /// Whose blocks it reads and writes, by the user's key CID's bytes.
    user: Vec<u8>,
}

impl Thin {
    /// A thin client over a transport, of a member listening at `addrs`,
    /// for a user.
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, member: PeerId, addrs: Vec<Multiaddr>, user: &Link) -> Self {
        let config = || request_response::Config::default().with_request_timeout(ANSWER);
        let behaviour = Behaviour {
            ping: ping::Behaviour::default(),
            blocks: exchange(super::blocks::PROTOCOL, config()),
            push: exchange(super::durability::PUSH, config()),
            asks: exchange(PROTOCOL, config()),
        };
        let swarm = Swarm::new(transport, behaviour, key.public().to_peer_id(), libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_mins(1)));
        Self { swarm, member, addrs, user: user.to_bytes() }
    }

    /// The thin client a directory is, over TCP.
    pub fn open(dir: &Path) -> Result<Self> {
        let ticket = Ticket::decode(&std::fs::read_to_string(dir.join(TICKET))?)?;
        let key = mesh::node_key(dir)?;
        let (user, _) = ticket.user.as_ref().ok_or_else(|| Error::Invalid("the ticket says whose device this is not".into()))?;
        let addrs = ticket.members.get(&ticket.inviter).cloned().unwrap_or_default();
        let base = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        Ok(Self::new(super::clients::client_transport(base, &key)?, &key, ticket.inviter, addrs, user))
    }

    pub const fn member(&self) -> PeerId {
        self.member
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Connect to the member.
    pub async fn connect(&mut self) -> Result<()> {
        if self.swarm.is_connected(&self.member) {
            return Ok(());
        }
        if self.addrs.is_empty() {
            return Err(Error::Invalid(format!("the ticket says nowhere to find {}: invite this client again once it listens for clients", self.member)));
        }
        let member = self.member;
        self.swarm.dial(DialOpts::peer_id(member).addresses(self.addrs.clone()).build()).map_err(|e| Error::Invalid(format!("dialing {member}: {e}")))?;
        let connected = async {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == member => return Ok(()),
                    SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } if peer_id == member => {
                        return Err(Error::Invalid(format!("couldn't connect to {member}: {error}")));
                    },
                    _ => {},
                }
            }
        };
        tokio::time::timeout(CONNECT, connected).await.map_err(|_| Error::Invalid(format!("{member} didn't answer: is it running `hk node run --clients`?")))?
    }

    /// Drive the swarm until `pick` takes an event, or the member's gone.
    async fn wait<T>(&mut self, mut pick: impl FnMut(BehaviourEvent) -> Option<Result<T>>) -> Result<T> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => {
                    if let Some(picked) = pick(event) {
                        return picked;
                    }
                },
                SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } if peer_id == self.member => {
                    return Err(Error::Invalid(format!("{} closed the connection: is this client still let in?", self.member)));
                },
                _ => {},
            }
        }
    }

    /// Ask the member to say or tell something as this client's account,
    /// returning its answer's lines.
    pub async fn ask(&mut self, words: Vec<String>) -> Result<Vec<String>> {
        self.connect().await?;
        let member = self.member;
        let sent = self.swarm.behaviour_mut().asks.send_request(&member, Ask { words });
        let lines = self.wait(|event| match event {
            BehaviourEvent::Asks(request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. }) if request_id == sent => Some(Ok(response.lines)),
            BehaviourEvent::Asks(request_response::Event::OutboundFailure { request_id, error, .. }) if request_id == sent => Some(Err(failed(member, &error))),
            _ => None,
        }).await?;
        if let Some(error) = lines.first().and_then(|line| line.strip_prefix("error: ")) {
            return Err(Error::Invalid(error.to_owned()));
        }
        Ok(lines)
    }

    /// Ask the member once for blocks, at most a batch of them: those it
    /// sent, verified, and those it said it hasn't. What it left out for
    /// room is in neither.
    async fn want(&mut self, cids: &[Link]) -> Result<(Vec<Block>, HashSet<Vec<u8>>)> {
        self.connect().await?;
        let member = self.member;
        let want = Want::of(cids).for_user(Some(&self.user));
        let sent: OutboundRequestId = self.swarm.behaviour_mut().blocks.send_request(&member, want);
        let answer = self.wait(|event| match event {
            BehaviourEvent::Blocks(request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. }) if request_id == sent => Some(Ok(response)),
            BehaviourEvent::Blocks(request_response::Event::OutboundFailure { request_id, error, .. }) if request_id == sent => Some(Err(failed(member, &error))),
            _ => None,
        }).await?;
        let mut found = Vec::new();
        for (cid, data) in answer.found() {
            let Ok(link) = Link::decode(cid) else {
                continue;
            };
            if let Ok(block) = Block::verify(link.into(), data.into()) {
                found.push(block);
            }
        }
        let missing = answer.missing().iter().map(|cid| cid.multihash().to_bytes()).collect();
        Ok((found, missing))
    }

    /// Blocks, from the member, asking again a while for those it hasn't,
    /// which it's fetching meanwhile from the user's other machines.
    pub async fn get(&mut self, cids: &[Link]) -> Result<Vec<Block>> {
        let mut wanted: Vec<Link> = cids.to_vec();
        let mut found = Vec::new();
        let deadline = tokio::time::Instant::now().checked_add(PATIENCE).unwrap_or_else(tokio::time::Instant::now);
        let mut pause = Duration::from_millis(100);
        while !wanted.is_empty() {
            let (blocks, missing) = self.want(&wanted).await?;
            let got: HashSet<Vec<u8>> = blocks.iter().map(|block| block.cid().multihash().to_bytes()).collect();
            found.extend(blocks);
            wanted.retain(|cid| !got.contains(&cid.multihash().to_bytes()));
            // Left out for room only: ask again at once
            if got.is_empty() || wanted.iter().all(|cid| missing.contains(&cid.multihash().to_bytes())) {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(pause).await;
                pause = pause.saturating_mul(2).min(Duration::from_secs(2));
            }
        }
        if let Some(first) = wanted.first() {
            return Err(Error::Invalid(format!("{} blocks aren't on {} or the user's machines it reached, {first} among them", wanted.len(), self.member)));
        }
        Ok(found)
    }

    /// Push blocks to the member, to hold for this client's account.
    pub async fn push(&mut self, blocks: Vec<Block>) -> Result<()> {
        for push in Push::bare(blocks) {
            self.connect().await?;
            let member = self.member;
            let count = push.len();
            let push = push.for_user(Some(&self.user));
            let sent = self.swarm.behaviour_mut().push.send_request(&member, push);
            let kept = self.wait(|event| match event {
                BehaviourEvent::Push(request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. }) if request_id == sent => Some(Ok(response)),
                BehaviourEvent::Push(request_response::Event::OutboundFailure { request_id, error, .. }) if request_id == sent => Some(Err(failed(member, &error))),
                _ => None,
            }).await?;
            if kept.keys().len() < count {
                return Err(Error::Invalid(format!("{member} kept {} of {count} blocks: short of space, or of the account's quota", kept.keys().len())));
            }
        }
        Ok(())
    }
}

fn failed(member: PeerId, error: &request_response::OutboundFailure) -> Error {
    Error::Invalid(format!("asking {member}: {error}"))
}

/// A thin client, driven a command at a time.
pub struct Blocking {
    runtime: tokio::runtime::Runtime,
    thin: RefCell<Thin>,
    /// Blocks read ahead, by multihash bytes.
    ahead: RefCell<HashMap<Vec<u8>, Block>>,
}

impl Blocking {
    /// Connect the thin client a directory is to its member.
    pub fn connect(dir: &Path) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let mut thin = {
            let _entered = runtime.enter();
            Thin::open(dir)?
        };
        runtime.block_on(thin.connect())?;
        Ok(Self { runtime, thin: RefCell::new(thin), ahead: RefCell::new(HashMap::new()) })
    }

    pub fn member(&self) -> PeerId {
        self.thin.borrow().member()
    }

    pub fn ask(&self, words: Vec<String>) -> Result<Vec<String>> {
        self.runtime.block_on(self.thin.borrow_mut().ask(words))
    }

    pub fn get(&self, cids: &[Link]) -> Result<Vec<Block>> {
        self.runtime.block_on(self.thin.borrow_mut().get(cids))
    }

    pub fn push(&self, blocks: Vec<Block>) -> Result<()> {
        self.runtime.block_on(self.thin.borrow_mut().push(blocks))
    }
}

impl crate::export::Fetch for Blocking {
    fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>> {
        if let Some(block) = self.ahead.borrow_mut().remove(&cid.multihash().to_bytes()) {
            return Ok(block.data().to_vec());
        }
        let block = self.get(std::slice::from_ref(cid)).map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;
        block.into_iter().next().map(|block| block.data().to_vec()).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("block {cid} not found")))
    }

    /// Read ahead a few of what's next, so they come in one answer rather
    /// than one each; not so many a sandbox runs out of memory.
    fn prefetch(&self, cids: &[Link]) {
        let next: Vec<Link> = {
            let ahead = self.ahead.borrow();
            cids.iter().filter(|cid| !ahead.contains_key(&cid.multihash().to_bytes())).take(16usize.saturating_sub(ahead.len())).cloned().collect()
        };
        if next.is_empty() {
            return;
        }
        if let Ok(blocks) = self.get(&next) {
            self.ahead.borrow_mut().extend(blocks.into_iter().map(|block| (block.cid().multihash().to_bytes(), block)));
        }
    }
}

/// Where a thin client puts what it imports: pushed to its member a few
/// megabytes at a time.
pub struct Sink<'a> {
    client: &'a Blocking,
    pending: Vec<Block>,
    size: usize,
}

impl<'a> Sink<'a> {
    pub const fn new(client: &'a Blocking) -> Self {
        Self { client, pending: Vec::new(), size: 0 }
    }

    /// Push what's left.
    pub fn finish(mut self) -> io::Result<()> {
        self.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.size = 0;
        self.client.push(std::mem::take(&mut self.pending)).map_err(io::Error::other)
    }
}

impl BlockSink for Sink<'_> {
    fn put(&mut self, block: Block) -> io::Result<()> {
        self.size = self.size.saturating_add(block.data().len());
        self.pending.push(block);
        if self.size >= BUDGET {
            self.flush()?;
        }
        Ok(())
    }
}
