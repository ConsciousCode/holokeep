//! Thin clients: clients with no repo of their own, as a sandbox without
//! a disk to keep one on, asking their member for what they read and
//! sending it what they write.
//!
//! - A thin client is a directory holding a key, its peer ID the device
//!   key a user certified, and the ticket it joined with (`hk node join
//!   --thin`), which says where its members listen for clients: its
//!   inviter, and others serving its user. Each command connects to
//!   whichever answers first, which lets it in as it does any client.
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
//! - A visitor's thin client, a key outside the mesh, can't ask its member
//!   to say anything: it signs its sets itself, and pushes them with what
//!   they reach, which the member holds for the user whose view it is, if
//!   they let the visitor write it.
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

/// A visitor's ticket, from its directory, for another visitor: a
/// visitor's names no one, and certifies nothing, so it's anyone's the
/// owner's shares let in. None, if it's a client's.
pub fn visitor_ticket(dir: &Path) -> Result<Option<String>> {
    let text = std::fs::read_to_string(dir.join(TICKET))?;
    let ticket = Ticket::decode(&text)?;
    Ok(ticket.user.as_ref().is_some_and(|(_, certificates)| certificates.is_empty()).then(|| text.trim().to_owned()))
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

/// A thin client, connecting to whichever of its members answers first.
pub struct Thin {
    swarm: Swarm<Behaviour>,
    /// The member it's connected to, once it is.
    member: PeerId,
    /// Where each member it may connect to listens for clients.
    members: Vec<(PeerId, Vec<Multiaddr>)>,
    /// Whose blocks it reads and writes, by the user's key CID's bytes.
    user: Vec<u8>,
    /// How long to keep asking for blocks the member hasn't.
    patience: Duration,
    /// Its own key, to sign with, if it's a visitor: a key outside the
    /// mesh, which nothing's certified as a device of anyone's.
    visitor: Option<crate::keys::Key>,
}

impl Thin {
    /// A thin client over a transport, of members listening for clients
    /// where they say, the first preferred, for a user.
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, members: Vec<(PeerId, Vec<Multiaddr>)>, user: &Link) -> Self {
        let config = || request_response::Config::default().with_request_timeout(ANSWER);
        let behaviour = Behaviour {
            ping: ping::Behaviour::default(),
            blocks: exchange(super::blocks::PROTOCOL, config()),
            push: exchange(super::durability::PUSH, config()),
            asks: exchange(PROTOCOL, config()),
        };
        let swarm = Swarm::new(transport, behaviour, key.public().to_peer_id(), libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_mins(1)));
        let member = members.first().map_or_else(PeerId::random, |(member, _)| *member);
        Self { swarm, member, members, user: user.to_bytes(), patience: PATIENCE, visitor: None }
    }

    /// A visitor's, signing its own sets with its key.
    #[must_use]
    pub fn as_visitor(mut self, key: crate::keys::Key) -> Self {
        self.visitor = Some(key);
        self
    }

    /// Whether it's a visitor's.
    pub const fn is_visitor(&self) -> bool {
        self.visitor.is_some()
    }

    /// The thin client a directory is, over TCP.
    pub fn open(dir: &Path) -> Result<Self> {
        let ticket = Ticket::decode(&std::fs::read_to_string(dir.join(TICKET))?)?;
        let key = mesh::node_key(dir)?;
        let (user, _) = ticket.user.as_ref().ok_or_else(|| Error::Invalid("the ticket says whose device this is not".into()))?;
        // Its inviter first, then whoever else serves its user
        let mut members: Vec<(PeerId, Vec<Multiaddr>)> = ticket.members.iter().map(|(peer, addrs)| (*peer, addrs.clone())).collect();
        members.sort_by_key(|(peer, _)| *peer != ticket.inviter);
        let base = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        let thin = Self::new(super::clients::client_transport(base, &key)?, &key, members, user);
        // A visitor's ticket certifies nothing: its key's its own
        let certified = ticket.user.as_ref().is_some_and(|(_, certificates)| !certificates.is_empty());
        if certified {
            return Ok(thin);
        }
        let bytes = key.to_protobuf_encoding().map_err(|e| Error::Invalid(e.to_string()))?;
        let key = crate::keys::Key::from_protobuf(&bytes).ok_or_else(|| Error::Invalid("this client's key isn't ed25519".into()))?;
        Ok(thin.as_visitor(key))
    }

    /// Ask for blocks the member hasn't for this long, not the usual 30 s.
    #[must_use]
    pub const fn with_patience(mut self, patience: Duration) -> Self {
        self.patience = patience;
        self
    }

    /// The member it's connected to, or will try first.
    pub const fn member(&self) -> PeerId {
        self.member
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Connect to a member: every one at once, keeping whichever answers
    /// first, its inviter if they come together.
    pub async fn connect(&mut self) -> Result<()> {
        if self.swarm.is_connected(&self.member) {
            return Ok(());
        }
        let mut trying = HashSet::new();
        for (member, addrs) in self.members.iter().filter(|(_, addrs)| !addrs.is_empty()) {
            if self.swarm.dial(DialOpts::peer_id(*member).addresses(addrs.clone()).build()).is_ok() {
                trying.insert(*member);
            }
        }
        if trying.is_empty() {
            return Err(Error::Invalid("the ticket says nowhere to find a member: invite this client again once its member listens for clients".into()));
        }
        let mut errors = Vec::new();
        let connected = async {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if trying.contains(&peer_id) => return Ok(peer_id),
                    SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } if trying.remove(&peer_id) => {
                        errors.push(format!("{peer_id}: {error}"));
                        if trying.is_empty() {
                            return Err(Error::Invalid(format!("couldn't connect to a member: {}", errors.join("; "))));
                        }
                    },
                    _ => {},
                }
            }
        };
        let member = tokio::time::timeout(CONNECT, connected).await.map_err(|_| Error::Invalid("no member answered: is one running `hk node run --clients`?".into()))??;
        self.member = member;
        // One connection's all it needs
        let others: Vec<PeerId> = self.members.iter().map(|(peer, _)| *peer).filter(|peer| *peer != member).collect();
        for peer in others {
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        Ok(())
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
        let deadline = tokio::time::Instant::now().checked_add(self.patience).unwrap_or_else(tokio::time::Instant::now);
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
            if kept.keys().is_empty() && self.visitor.is_some() {
                return Err(Error::Invalid(format!("{member} took none of it: a visitor writes only where it's been let write a view (`hk anchor shared`)")));
            }
            if kept.keys().len() < count {
                return Err(Error::Invalid(format!("{member} kept {} of {count} blocks: short of space, or of the account's quota", kept.keys().len())));
            }
        }
        Ok(())
    }
}

impl Thin {
    /// Set a view of an anchor shared with this visitor to a value, as
    /// itself: a set signed with its own key, after the view's heads,
    /// pushed to the member, which counts it in the owner's view if the
    /// visitor may write it. What it reaches must be pushed first, or be
    /// the owner's already. Returns the set's CID.
    pub async fn set_own(&mut self, view: &Link, value: &Link) -> Result<Link> {
        let key = self.visitor.clone().ok_or_else(|| Error::Invalid("a client of the mesh sets anchors through its account".into()))?;
        let (anchor, owner) = viewed(view)?;
        if !self.holds(view, crate::grants::WRITE).await? {
            return Err(Error::Invalid(format!("{} hasn't let this key write {view}", crate::keys::peer_id(&owner))));
        }
        let mut prev = Vec::new();
        let mut latest = 0;
        for line in self.ask(vec!["anchor".to_owned(), "heads".to_owned(), view.to_string()]).await? {
            let (set, at) = line.split_once('\t').ok_or_else(|| Error::Invalid(format!("the member said {line:?} of a head")))?;
            prev.push(set.parse::<Link>().map_err(|_| Error::Invalid(format!("not a CID: {set}")))?);
            latest = latest.max(at.parse::<u64>().map_err(|_| Error::Invalid(format!("not a time: {at}")))?.saturating_add(1));
        }
        let at = now().max(latest);
        let set = crate::claim::Set::new([anchor], value.clone(), at).ok_or_else(|| Error::Invalid("a set names an anchor".into()))?.after(Some(prev)).for_view(Some(owner));
        let set = crate::claim::Claim::Set(set);
        self.sign_and_push(&key, &set, at).await?;
        let heads = self.ask(vec!["anchor".to_owned(), "heads".to_owned(), view.to_string()]).await?;
        if !heads.iter().any(|line| line.split('\t').next() == Some(&set.cid().to_string())) {
            return Err(Error::Invalid(format!("{} took the set, but it doesn't count in {view}: was write taken away?", self.member)));
        }
        Ok(set.cid())
    }

    /// Give or take away commands on a view of an anchor shared with this
    /// visitor, as itself: a grant signed with its own key, after the
    /// mesh's grants, pushed to the member, which counts in the owner's
    /// view if the visitor may give or take them away there. Taking write
    /// away, what the target set till then stands. Returns its CID.
    pub async fn share_own(&mut self, view: &Link, who: &Link, add: &[String], del: &[String]) -> Result<Link> {
        let key = self.visitor.clone().ok_or_else(|| Error::Invalid("a client of the mesh shares through its account".into()))?;
        let (anchor, owner) = viewed(view)?;
        for need in std::iter::once(crate::grants::ANCHOR_GRANT).chain(add.iter().chain(del).map(String::as_str)) {
            if !self.holds(view, need).await? {
                return Err(Error::Invalid(format!("{} hasn't let this key give or take away {need} on {view}", crate::keys::peer_id(&owner))));
            }
        }
        let stands = if del.iter().any(|command| crate::claim::covers(command, crate::grants::WRITE)) {
            let latest = self.ask(vec!["anchor".to_owned(), "latest".to_owned(), view.to_string(), who.to_string()]).await?;
            latest.iter().map(|set| set.parse::<Link>().map_err(|_| Error::Invalid(format!("not a CID: {set}")))).collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let heads = self.ask(vec!["grant".to_owned(), "heads".to_owned()]).await?;
        let heads = heads.iter().map(|head| head.parse::<Link>().map_err(|_| Error::Invalid(format!("not a CID: {head}")))).collect::<Result<Vec<_>>>()?;
        let grant = crate::claim::Grant::new([who.clone()], Some(anchor), add.iter().cloned(), del.iter().cloned(), stands, heads)
            .ok_or_else(|| Error::Invalid("a grant names someone, and commands on an anchor given or taken away, not both".into()))?;
        let grant = crate::claim::Claim::Grant(grant);
        self.sign_and_push(&key, &grant, now()).await?;
        let heads = self.ask(vec!["grant".to_owned(), "heads".to_owned()]).await?;
        if !heads.contains(&grant.cid().to_string()) {
            return Err(Error::Invalid(format!("{} didn't take the grant", self.member)));
        }
        Ok(grant.cid())
    }

    /// Whether this visitor holds a command on a view, as the member says.
    async fn holds(&mut self, view: &Link, command: &str) -> Result<bool> {
        let view = view.to_string();
        Ok(self.ask(vec!["shared".to_owned()]).await?.iter().any(|line| {
            let mut fields = line.split('\t');
            fields.next() == Some(view.as_str()) && fields.nth(1).is_some_and(|held| held.split(' ').any(|held| crate::claim::covers(held, command)))
        }))
    }

    /// Sign a claim with this visitor's key, after its last sign, and push
    /// both to the member.
    async fn sign_and_push(&mut self, key: &crate::keys::Key, claim: &crate::claim::Claim, at: u64) -> Result<()> {
        let signed = match self.ask(vec!["signed".to_owned()]).await?.first() {
            Some(sign) => Some(sign.parse::<Link>().map_err(|_| Error::Invalid(format!("not a CID: {sign}")))?),
            None => None,
        };
        let sign = crate::claim::Sign::new(key, [claim.cid()], signed, at).ok_or_else(|| Error::Invalid("nothing to sign".into()))?;
        self.push(vec![claim.block(), crate::claim::Claim::Sign(sign).block()]).await
    }
}

/// The anchor a view is of, and whose view it is.
fn viewed(view: &Link) -> Result<(Link, Link)> {
    crate::claim::viewed(view).ok_or_else(|| Error::Invalid(format!("{view} isn't a view of an anchor: `hk anchor shared` lists those shared with this key")))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
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

    pub fn is_visitor(&self) -> bool {
        self.thin.borrow().is_visitor()
    }

    pub fn set_own(&self, view: &Link, value: &Link) -> Result<Link> {
        self.runtime.block_on(self.thin.borrow_mut().set_own(view, value))
    }

    pub fn share_own(&self, view: &Link, who: &Link, add: &[String], del: &[String]) -> Result<Link> {
        self.runtime.block_on(self.thin.borrow_mut().share_own(view, who, add, del))
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
