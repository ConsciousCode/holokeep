//! A node in the mesh: a libp2p swarm over a private network, letting in
//! only members.
//!
//! - `pnet` encrypts every connection with the swarm key before anything
//!   else, so only the mesh can speak to it; it works over TCP, not QUIC.
//! - The allow list shuts out peers which have the key but aren't
//!   members.
//! - Members tell each other of the members they know, whenever they
//!   connect, so a machine invited by one is let in by all.
//! - mDNS finds members on the LAN; identify tells each where the others
//!   listen; Kademlia, under its own protocol name so it's no part of
//!   Amino, finds members' addresses as they move.
//! - Members want blocks of each other; see `blocks`.
//! - Members keep each other's blocks durable; see `durability`.
//! - Members tell each other of structure linking to what they hold; see
//!   `structure`.
//! - Members let go of copies the mesh can spare when space runs short;
//!   see `trim`.

use std::path::PathBuf;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::time::Duration;

use futures::{AsyncRead, AsyncWrite, StreamExt};
use libp2p::allow_block_list::{self, AllowedPeers};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::upgrade::Version;
use libp2p::identity::Keypair;
use libp2p::pnet::{PnetConfig, PreSharedKey};
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, Transport, identify, kad, mdns, noise, ping, tcp, yamux};
use serde::{Deserialize, Serialize};

use super::blocks::{self, Blocks, Fetch, Want};
use super::collect::{self, Condemn, Condemned, Verdict};
use super::durability::{self, Advert, Audit, Haves, Kept, Push, Report, Sightings, Trickle};
use crate::multihash::Multihash;
use crate::store::BlockIndex;
use super::mesh::{Error, Members, Result};
use super::structure::{self, Cursors, Notice, Wants};
use super::trim::{self, Ack, Dropped, Grant, Intent, Trim, Watermarks};
use crate::model::Link;
use crate::store::{Catalog, ExternalFile};

const IDENTIFY: &str = "/holokeep/id/1.0.0";
const KAD: StreamProtocol = StreamProtocol::new("/holokeep/kad/1.0.0");
const MEMBERS: StreamProtocol = StreamProtocol::new("/holokeep/members/1.0.0");

/// How long a connection with nothing going on is kept: the mesh is small
/// and stays connected.
const IDLE: Duration = Duration::from_hours(1);

/// The members one node knows of, as it tells another.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Roster {
    members: Vec<(String, Vec<String>)>,
}

impl Roster {
    fn from_members(members: &BTreeMap<PeerId, Vec<Multiaddr>>) -> Self {
        let members = members.iter().map(|(peer, addrs)| (peer.to_string(), addrs.iter().map(ToString::to_string).collect()));
        Self { members: members.collect() }
    }

    /// The members named, skipping anything malformed: it came from a
    /// member, but not necessarily one running this version.
    fn to_members(&self) -> BTreeMap<PeerId, Vec<Multiaddr>> {
        self.members
            .iter()
            .filter_map(|(peer, addrs)| Some((PeerId::from_str(peer).ok()?, addrs.iter().filter_map(|addr| addr.parse().ok()).collect())))
            .collect()
    }
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    allowed: allow_block_list::Behaviour<AllowedPeers>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    members: request_response::cbor::Behaviour<Roster, Roster>,
    blocks: request_response::cbor::Behaviour<Want, Blocks>,
    adverts: request_response::cbor::Behaviour<Advert, Haves>,
    push: request_response::cbor::Behaviour<Push, Kept>,
    notices: request_response::cbor::Behaviour<Notice, Wants>,
    trim: request_response::cbor::Behaviour<Intent, Grant>,
    dropped: request_response::cbor::Behaviour<Dropped, Ack>,
    condemn: request_response::cbor::Behaviour<Condemn, Verdict>,
}

/// A fetch, as the node knows it.
pub type FetchId = u64;

/// An audit, as the node knows it.
pub type AuditId = u64;

/// A trim, as the node knows it.
pub type TrimId = u64;

/// What happened, as far as the mesh is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Listening(Multiaddr),
    Connected(PeerId),
    Disconnected(PeerId),
    /// Members learned of from another.
    Learned(Vec<PeerId>),
    /// A connection which failed or was refused, and why.
    Failed(Option<PeerId>, String),
    /// A fetch finished: how many blocks it fetched, and those no member
    /// had.
    Fetched { id: FetchId, fetched: usize, missing: Vec<Link> },
    /// An audit finished.
    Audited { id: AuditId, report: Report },
    /// A trim finished.
    Trimmed { id: TrimId, report: trim::Report },
    /// Garbage was let go of, as members answered.
    Collected { collected: usize },
}

/// A transport for the mesh, over some base transport: the private
/// network, then noise, then yamux.
pub fn transport<T>(base: T, key: &Keypair, swarm_key: PreSharedKey) -> Result<Boxed<(PeerId, StreamMuxerBox)>>
where
    T: Transport + Send + Unpin + 'static,
    T::Error: Send + Sync + 'static,
    T::Output: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    T::ListenerUpgrade: Send,
    T::Dial: Send,
{
    let pnet = PnetConfig::new(swarm_key);
    let noise = noise::Config::new(key).map_err(|e| Error::Invalid(format!("noise: {e}")))?;
    Ok(base
        .and_then(move |socket, _| pnet.handshake(socket))
        .upgrade(Version::V1)
        .authenticate(noise)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed())
}

pub struct Node {
    swarm: Swarm<Behaviour>,
    members: Members,
    catalog: Catalog,
    fetches: BTreeMap<FetchId, Fetch>,
    next_fetch: FetchId,
    sightings: Sightings,
    audits: BTreeMap<AuditId, Audit>,
    next_audit: AuditId,
    trickle: Trickle,
    trims: BTreeMap<TrimId, Trim>,
    next_trim: TrimId,
    marks: Watermarks,
    /// Blocks members let go of which this node holds, to audit soon.
    suspects: Vec<Multihash>,
    /// The trickle's audit under way, and whether more arrived than it
    /// took in.
    trickling: Option<(AuditId, bool)>,
    cursors: Cursors,
    /// Notices sent: to whom, and for one from a cursor, where it moves to
    /// once answered.
    notices: HashMap<request_response::OutboundRequestId, (PeerId, Option<i64>)>,
    /// Members with a notice from their cursor unanswered.
    noticing: HashSet<PeerId>,
    condemned: Condemned,
    /// Files imported in place found changed, for whoever runs the node
    /// to import again if they're mounted.
    changed: Vec<PathBuf>,
    /// Condemnations asked of members and unanswered: whom, and of what.
    condemning: HashMap<request_response::OutboundRequestId, (PeerId, collect::BatchId)>,
    /// Events which happened outside `next`, for it to return first.
    ready: VecDeque<Event>,
}

impl Node {
    /// A node over TCP, finding members on the LAN by mDNS.
    pub fn tcp(key: &Keypair, swarm_key: PreSharedKey, catalog: Catalog, members: Members) -> Result<Self> {
        let base = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        Self::new(transport(base, key, swarm_key)?, key, catalog, members, true)
    }

    /// A node over a transport, with or without mDNS.
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, catalog: Catalog, members: Members, lan: bool) -> Result<Self> {
        let peer = key.public().to_peer_id();
        let mdns = if lan { Some(mdns::tokio::Behaviour::new(mdns::Config::default(), peer)?) } else { None };
        let mut kad = kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), kad::Config::new(KAD));
        kad.set_mode(Some(kad::Mode::Server));
        let behaviour = Behaviour {
            allowed: allow_block_list::Behaviour::default(),
            identify: identify::Behaviour::new(identify::Config::new(IDENTIFY.into(), key.public())),
            ping: ping::Behaviour::default(),
            mdns: mdns.into(),
            kad,
            members: request_response::cbor::Behaviour::new([(MEMBERS, ProtocolSupport::Full)], request_response::Config::default()),
            blocks: request_response::cbor::Behaviour::new(
                [(blocks::PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_mins(1)),
            ),
            adverts: request_response::cbor::Behaviour::new(
                [(durability::ADVERTS, ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_mins(1)),
            ),
            push: request_response::cbor::Behaviour::new(
                [(durability::PUSH, ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_mins(1)),
            ),
            notices: request_response::cbor::Behaviour::new(
                [(structure::PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_mins(1)),
            ),
            trim: request_response::cbor::Behaviour::new(
                [(trim::PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_mins(1)),
            ),
            dropped: request_response::cbor::Behaviour::new(
                [(trim::DROPPED, ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_mins(1)),
            ),
            condemn: request_response::cbor::Behaviour::new(
                [(collect::PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_mins(1)),
            ),
        };
        let config = libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(IDLE);
        let swarm = Swarm::new(transport, behaviour, peer, config);
        let sightings = Sightings::open(catalog.db().clone())?;
        let cursors = Cursors::open(catalog.db().clone(), members.mesh())?;
        let condemned = Condemned::open(catalog.db().clone())?;
        let mut node = Self {
            swarm,
            members,
            catalog,
            fetches: BTreeMap::new(),
            next_fetch: 0,
            sightings,
            audits: BTreeMap::new(),
            next_audit: 0,
            trickle: Trickle::default(),
            trims: BTreeMap::new(),
            next_trim: 0,
            marks: Watermarks::default(),
            suspects: Vec::new(),
            trickling: None,
            cursors,
            notices: HashMap::new(),
            noticing: HashSet::new(),
            condemned,
            changed: Vec::new(),
            condemning: HashMap::new(),
            ready: VecDeque::new(),
        };
        node.reload()?;
        Ok(node)
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub const fn members(&self) -> &Members {
        &self.members
    }

    pub const fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub const fn catalog_mut(&mut self) -> &mut Catalog {
        &mut self.catalog
    }

    pub const fn sightings(&self) -> &Sightings {
        &self.sightings
    }

    /// Notice each connected member of structure which arrived since it
    /// was last noticed, unless it's still to answer the last.
    pub fn announce(&mut self) -> Result<()> {
        for peer in self.connected() {
            self.announce_to(peer)?;
        }
        Ok(())
    }

    fn announce_to(&mut self, peer: PeerId) -> Result<()> {
        if self.noticing.contains(&peer) {
            return Ok(());
        }
        let mut cursor = self.cursors.get(&peer)?;
        loop {
            let (arrived, latest) = self.catalog.structure_since(cursor, structure::BATCH)?;
            if latest == cursor {
                return Ok(());
            }
            // Fewer than a batch arrived, so they make one notice at most
            if let Some(notice) = structure::notices(&self.catalog, &arrived)?.into_iter().next() {
                let request = self.swarm.behaviour_mut().notices.send_request(&peer, notice);
                self.notices.insert(request, (peer, Some(latest)));
                self.noticing.insert(peer);
                return Ok(());
            }
            // Nothing that links anywhere
            self.cursors.set(&peer, latest)?;
            cursor = latest;
        }
    }

    /// Notice a member of the structure here linking to blocks it's been
    /// sent.
    fn notice_backrefs(&mut self, peer: PeerId, keys: &[Vec<u8>]) -> Result<()> {
        let linking = structure::backrefs(&self.catalog, keys.iter().map(Vec::as_slice))?;
        for notice in structure::notices(&self.catalog, &linking)? {
            let request = self.swarm.behaviour_mut().notices.send_request(&peer, notice);
            self.notices.insert(request, (peer, None));
        }
        Ok(())
    }

    fn on_notice(&mut self, event: request_response::Event<Notice, Wants>) -> Result<()> {
        match event {
            request_response::Event::Message { message: request_response::Message::Request { request, channel, .. }, .. } => {
                let wants = structure::answer(&self.catalog, &request)?;
                // The noticer may be gone already
                let _ = self.swarm.behaviour_mut().notices.send_response(channel, wants);
            },
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                let Some((peer, cursor)) = self.notices.remove(&request_id) else {
                    return Ok(());
                };
                for push in structure::pushes(&self.catalog, &response)? {
                    self.swarm.behaviour_mut().push.send_request(&peer, push);
                }
                if let Some(cursor) = cursor {
                    self.cursors.set(&peer, cursor)?;
                    self.noticing.remove(&peer);
                    self.announce_to(peer)?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                // Noticed again from its cursor, later
                if let Some((peer, Some(_))) = self.notices.remove(&request_id) {
                    self.noticing.remove(&peer);
                }
            },
            _ => {},
        }
        Ok(())
    }

    /// Whether an audit is under way.
    pub fn auditing(&self) -> bool {
        !self.audits.is_empty()
    }

    /// Audit what this node holds, advertising what would take fewer than
    /// `copies` failures to lose and sending copies to members to raise
    /// it. It's done when `next` returns `Audited` with the id.
    pub fn audit(&mut self, copies: usize) -> Result<AuditId> {
        let keys = self.catalog.keys()?;
        self.audit_of_keys(copies, keys)
    }

    /// One tick of the trickle: audit what's arrived since the last, and a
    /// sample of the rest. Nothing, while no member's connected to send
    /// copies to; what's arrived waits. See `Trickle`.
    pub fn trickle(&mut self, copies: usize) -> Result<Option<AuditId>> {
        // Files imported in place are the user's to change, and nothing may
        // read them to notice
        let files = self.catalog.external_files(Some(durability::EXTERNAL))?;
        self.forget_changed(&files)?;
        if self.connected().is_empty() {
            return Ok(None);
        }
        let cursor = self.sightings.fresh_cursor()?;
        let (mut keys, latest) = self.catalog.fresh_since(cursor, durability::FRESH)?;
        self.sightings.set_fresh_cursor(latest)?;
        let more = keys.len() >= durability::FRESH;
        keys.append(&mut self.suspects);
        keys.extend(self.catalog.sample(Trickle::sample_size(self.catalog.block_count()?))?);
        // Before it starts, since one with nothing to ask finishes at once
        self.trickling = Some((self.next_audit, more));
        self.audit_of_keys(copies, keys).map(Some)
    }

    /// Forget whichever of these files imported in place have gone or
    /// changed, telling members what that leaves no longer here, so they
    /// make up the copies. Returns how many blocks that was.
    pub fn forget_changed(&mut self, files: &[ExternalFile]) -> Result<usize> {
        self.changed.extend(files.iter().filter(|file| file.changed()).map(|file| file.path.clone()));
        let lost = self.catalog.forget_changed(files)?;
        for key in &lost {
            self.sightings.forget(key.as_ref())?;
            self.condemned.pardon(key.as_ref())?;
        }
        if !lost.is_empty() {
            let dropped = trim::dropped(&lost);
            for peer in self.connected() {
                self.swarm.behaviour_mut().dropped.send_request(&peer, dropped.clone());
            }
        }
        Ok(lost.len())
    }

    /// The files imported in place found changed since this was last asked.
    pub fn take_changed(&mut self) -> Vec<PathBuf> {
        std::mem::take(&mut self.changed)
    }

    /// Whether blocks have arrived which the trickle's yet to audit, as from
    /// a command run since; if so it's alarmed, to audit them soon.
    pub fn arrived(&mut self) -> Result<bool> {
        let cursor = self.sightings.fresh_cursor()?;
        let arrived = !self.catalog.fresh_since(cursor, 1)?.0.is_empty();
        if arrived {
            self.trickle.alarm();
        }
        Ok(arrived)
    }

    /// Keep the repo's free space between watermarks: trim below `low`
    /// until above `high`, and offer others only what's above `high`.
    pub const fn set_watermarks(&mut self, low: u64, high: u64) {
        self.marks = Watermarks::new(low, high);
    }

    /// Whether the repo's short of space and should trim, by the
    /// watermarks: from below the low until above the high.
    pub fn pressed(&mut self) -> Result<bool> {
        let free = self.catalog.offer()?.free;
        Ok(free.is_some_and(|free| self.marks.update(free)))
    }

    pub const fn watermarks(&self) -> Watermarks {
        self.marks
    }

    pub fn trimming(&self) -> bool {
        !self.trims.is_empty()
    }

    /// Let go of what the mesh can spare of these blocks' copies here. It's
    /// done when `next` returns `Trimmed` with the id.
    pub fn trim(&mut self, copies: usize, keys: Vec<Multihash>) -> Result<TrimId> {
        let id = self.next_trim;
        self.next_trim = id.wrapping_add(1);
        let peers = self.connected();
        let (mut trim, intents) = Trim::start(&self.catalog, &self.sightings, &peers, copies, keys)?;
        for intent in intents {
            for peer in &peers {
                let request = self.swarm.behaviour_mut().trim.send_request(peer, intent.clone());
                trim.sent(request);
            }
        }
        self.trims.insert(id, trim);
        self.drive_trim(id)?;
        Ok(id)
    }

    /// Let go of what's spare of a sample of what's here, under pressure,
    /// or of everything when asked.
    pub fn trim_some(&mut self, copies: usize, all: bool) -> Result<TrimId> {
        let keys = if all { self.catalog.keys()? } else { self.catalog.sample(durability::FRESH)? };
        self.trim(copies, keys)
    }

    /// Once every member's answered a trim's intent, let go of what can
    /// go, tell the members, and finish.
    fn drive_trim(&mut self, id: TrimId) -> Result<()> {
        let Some(trim) = self.trims.get_mut(&id) else {
            return Ok(());
        };
        if trim.waiting() {
            return Ok(());
        }
        let dropping = self.catalog.drop_all(&trim.decide())?;
        for key in &dropping.dropped {
            if !self.catalog.has(key.as_ref())? {
                self.sightings.forget(key.as_ref())?;
            }
        }
        let gone = dropping.dropped;
        trim.dropped(gone.len(), dropping.freed);
        let report = trim.report();
        self.trims.remove(&id);
        if !gone.is_empty() {
            let dropped = trim::dropped(&gone);
            for peer in self.connected() {
                self.swarm.behaviour_mut().dropped.send_request(&peer, dropped.clone());
            }
        }
        self.ready.push_back(Event::Trimmed { id, report });
        Ok(())
    }

    fn on_trim(&mut self, event: request_response::Event<Intent, Grant>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let me = self.peer_id();
                let mut trims: Vec<&mut Trim> = self.trims.values_mut().collect();
                let mut grant = trim::answer(&self.catalog, &me, &peer, &request, &mut trims)?;
                // Copies about to be collected aren't worth trimming others for
                grant.withhold(|key| <Multihash>::decode(key).is_ok_and(|key| self.condemned.is_condemned(key.as_ref()).unwrap_or(true)));
                // The asker may be gone already
                let _ = self.swarm.behaviour_mut().trim.send_response(channel, grant);
            },
            request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some((&id, trim)) = self.trims.iter_mut().find(|(_, trim)| trim.asked(request_id)) {
                    trim.granted(request_id, peer, response);
                    self.drive_trim(id)?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some((&id, trim)) = self.trims.iter_mut().find(|(_, trim)| trim.asked(request_id)) {
                    trim.failed(request_id);
                    self.drive_trim(id)?;
                }
            },
            _ => {},
        }
        Ok(())
    }

    /// A member let go of copies: forget them, and audit soon what's here.
    fn on_dropped(&mut self, event: request_response::Event<Dropped, Ack>) -> Result<()> {
        if let request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } = event {
            for key in request.keys() {
                self.sightings.unsee(key.as_ref(), &peer)?;
                if self.catalog.has(key.as_ref())? {
                    self.suspects.push(key);
                }
            }
            if !self.suspects.is_empty() {
                self.trickle.alarm();
            }
            let _ = self.swarm.behaviour_mut().dropped.send_response(channel, Ack {});
        }
        Ok(())
    }

    pub const fn condemned(&self) -> &Condemned {
        &self.condemned
    }

    /// Wait this long before letting go of what's condemned instead.
    pub fn set_grace(&mut self, grace: Duration) -> Result<()> {
        self.condemned = Condemned::open(self.catalog.db().clone())?.with_grace(grace);
        Ok(())
    }

    /// Whether members are still to say whether they keep what was asked.
    pub fn condemning(&self) -> bool {
        !self.condemning.is_empty()
    }

    /// One round of collecting garbage, of a sample of what's here or of
    /// everything: condemn what nothing here references, let go of what's
    /// due, and ask connected members whether they keep what's condemned.
    /// See `collect`.
    pub fn collect(&mut self, all: bool) -> Result<collect::Report> {
        let keys = if all { self.catalog.keys()? } else { self.catalog.sample(durability::FRESH)? };
        let mut report = collect::judge(&self.catalog, &self.condemned, &keys, None)?;
        report.add(&self.collect_due()?);
        self.ask_condemned()?;
        Ok(report)
    }

    /// Let go of what's condemned and due, which nothing here references
    /// still, and condemn what that leaves unreferenced as of when what
    /// linked to it was: until nothing more's due.
    fn collect_due(&mut self) -> Result<collect::Report> {
        let mut report = collect::Report::default();
        let me = self.peer_id();
        // Members of every mesh this node is in, since what's here may be
        // kept in any of them
        let members: Vec<PeerId> = self.members.everyone()?.into_iter().filter(|&peer| peer != me).collect();
        loop {
            let due = self.condemned.due(&members)?;
            if due.is_empty() {
                return Ok(report);
            }
            let mut gone = Vec::new();
            for (since, keys) in due {
                let mut going = Vec::new();
                for key in keys {
                    if collect::unreferenced(&self.catalog, key.as_ref())? {
                        going.push(key.clone());
                    } else {
                        report.pardoned = report.pardoned.saturating_add(1);
                    }
                    self.condemned.pardon(key.as_ref())?;
                }
                let (dropping, children) = self.catalog.collect_all(&going)?;
                report.collected = report.collected.saturating_add(dropping.dropped.len());
                report.freed = report.freed.saturating_add(dropping.freed);
                let orphans = collect::judge(&self.catalog, &self.condemned, &children, Some(since))?;
                report.condemned = report.condemned.saturating_add(orphans.condemned);
                gone.extend(dropping.dropped);
            }
            for key in &gone {
                if !self.catalog.has(key.as_ref())? {
                    self.sightings.forget(key.as_ref())?;
                }
            }
            if !gone.is_empty() {
                let dropped = trim::dropped(&gone);
                for peer in self.connected() {
                    self.swarm.behaviour_mut().dropped.send_request(&peer, dropped.clone());
                }
                self.ready.push_back(Event::Collected { collected: gone.len() });
            }
        }
    }

    /// Ask each connected member of the batches it's yet to answer for,
    /// one request each, unless it's still answering.
    fn ask_condemned(&mut self) -> Result<()> {
        let asking: HashSet<PeerId> = self.condemning.values().map(|&(peer, _)| peer).collect();
        for peer in self.connected() {
            if asking.contains(&peer) {
                continue;
            }
            for (batch, keys) in self.condemned.unasked(&peer, 8)? {
                let request = self.swarm.behaviour_mut().condemn.send_request(&peer, collect::ask(&keys));
                self.condemning.insert(request, (peer, batch));
            }
        }
        Ok(())
    }

    fn on_condemn(&mut self, event: request_response::Event<Condemn, Verdict>) -> Result<()> {
        match event {
            request_response::Event::Message { message: request_response::Message::Request { request, channel, .. }, .. } => {
                let verdict = collect::answer(&self.catalog, &request)?;
                // The asker may be gone already
                let _ = self.swarm.behaviour_mut().condemn.send_response(channel, verdict);
            },
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some((peer, batch)) = self.condemning.remove(&request_id) {
                    self.condemned.heard(batch, &peer, &response)?;
                    // What that makes due goes now, and what it leaves
                    // unreferenced is asked of at once
                    self.collect_due()?;
                    if !self.condemning.values().any(|&(asked, _)| asked == peer) {
                        self.ask_condemned()?;
                    }
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                // Asked again next round
                self.condemning.remove(&request_id);
            },
            _ => {},
        }
        Ok(())
    }

    /// How long until the trickle's next tick.
    pub fn trickle_delay(&self) -> Duration {
        self.trickle.delay()
    }

    /// The trickle's interval, as it stands.
    pub const fn trickle_interval(&self) -> Duration {
        self.trickle.interval()
    }

    fn audit_of_keys(&mut self, copies: usize, mut keys: Vec<Multihash>) -> Result<AuditId> {
        // What's to be collected isn't worth more copies
        keys.retain(|key| !self.condemned.is_condemned(key.as_ref()).unwrap_or(false));
        // Nor is another account's this mesh's to copy
        keys.retain(|key| self.catalog.visible(key.as_ref()).unwrap_or(false));
        let id = self.next_audit;
        self.next_audit = id.wrapping_add(1);
        let mut peers = self.connected();
        peers.sort();
        let (mut audit, adverts) = Audit::start(&self.catalog, &self.sightings, self.peer_id(), &peers, copies, keys)?;
        for advert in &adverts {
            for &peer in &peers {
                let request = self.swarm.behaviour_mut().adverts.send_request(&peer, advert.clone());
                audit.sent_advert(request, peer, advert);
            }
        }
        self.audits.insert(id, audit);
        self.drive_audit(id)?;
        Ok(id)
    }

    /// Send what an audit has to push, once it's heard back, or finish it.
    fn drive_audit(&mut self, id: AuditId) -> Result<()> {
        let Some(audit) = self.audits.get_mut(&id) else {
            return Ok(());
        };
        if audit.waiting() {
            return Ok(());
        }
        if let Some(pushes) = audit.decide(&self.catalog)? {
            for (peer, push, keys) in pushes {
                let request = self.swarm.behaviour_mut().push.send_request(&peer, push);
                audit.sent_push(request, peer, keys);
            }
        } else {
            let report = audit.report();
            self.audits.remove(&id);
            if let Some((trickled, more)) = self.trickling
                && trickled == id
            {
                self.trickle.observe(&report, more);
                self.trickling = None;
            }
            self.ready.push_back(Event::Audited { id, report });
        }
        Ok(())
    }

    fn on_advert(&mut self, event: request_response::Event<Advert, Haves>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let haves = durability::answer_advert(&self.catalog, &self.sightings, &peer, &request, &self.marks)?;
                // The advertiser may be gone already
                let _ = self.swarm.behaviour_mut().adverts.send_response(channel, haves);
                return Ok(());
            },
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some(audit) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
                    audit.haves(&self.sightings, request_id, response)?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some(audit) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
                    audit.advert_failed(request_id);
                }
            },
            _ => return Ok(()),
        }
        self.drive_audits()
    }

    fn on_push(&mut self, event: request_response::Event<Push, Kept>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let kept = durability::answer_push(&self.catalog, &self.sightings, &peer, request, &self.marks)?;
                let _ = self.swarm.behaviour_mut().push.send_response(channel, kept);
                return Ok(());
            },
            request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response }, .. } => {
                // What links to what's pushed goes after it, copies or
                // not: claims about it may have been noticed before it
                // was there to want them for
                let kept = response.keys();
                if let Some(audit) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
                    audit.kept(&self.sightings, request_id, response)?;
                } else {
                    response.sight(&self.catalog, &self.sightings, &peer)?;
                }
                self.notice_backrefs(peer, &kept)?;
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some(audit) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
                    audit.push_failed(request_id);
                }
            },
            _ => return Ok(()),
        }
        self.drive_audits()
    }

    /// Drive every audit which is no longer waiting.
    fn drive_audits(&mut self) -> Result<()> {
        let ids: Vec<AuditId> = self.audits.keys().copied().collect();
        for id in ids {
            self.drive_audit(id)?;
        }
        Ok(())
    }

    /// The audit which sent an advert or push.
    fn audit_of(&self, request: request_response::OutboundRequestId) -> Option<AuditId> {
        self.audits.iter().find(|(_, audit)| audit.asked(request)).map(|(&id, _)| id)
    }

    /// Fetch the DAG under a root from other members, keeping what's
    /// fetched. It's done when `next` returns `Fetched` with the id.
    pub fn fetch(&mut self, root: Link) -> Result<FetchId> {
        let id = self.next_fetch;
        self.next_fetch = id.wrapping_add(1);
        self.fetches.insert(id, Fetch::new(root));
        self.drive(id)?;
        Ok(id)
    }

    /// Fetch just these blocks from other members, not what they link
    /// to. It's done when `next` returns `Fetched` with the id.
    pub fn fetch_blocks(&mut self, blocks: Vec<Link>) -> Result<FetchId> {
        let id = self.next_fetch;
        self.next_fetch = id.wrapping_add(1);
        self.fetches.insert(id, Fetch::blocks(blocks));
        self.drive(id)?;
        Ok(id)
    }

    /// Send what a fetch has to ask, or finish it.
    fn drive(&mut self, id: FetchId) -> Result<()> {
        let mut peers = self.connected();
        peers.sort();
        let Some(fetch) = self.fetches.get_mut(&id) else {
            return Ok(());
        };
        for (peer, batch) in fetch.plan(&self.catalog, &peers)? {
            let request = self.swarm.behaviour_mut().blocks.send_request(&peer, Fetch::want(&batch));
            fetch.sent(request, batch);
        }
        if fetch.done()
            && let Some(fetch) = self.fetches.remove(&id)
        {
            let (fetched, missing) = fetch.outcome();
            self.ready.push_back(Event::Fetched { id, fetched, missing });
        }
        Ok(())
    }

    /// The fetch which sent a want.
    fn fetch_of(&self, request: request_response::OutboundRequestId) -> Option<FetchId> {
        self.fetches.iter().find(|(_, fetch)| fetch.asked(request)).map(|(&id, _)| id)
    }

    /// Let in every member, and learn where they listen, as of the list.
    pub fn reload(&mut self) -> Result<()> {
        for (peer, addrs) in self.members.list()? {
            self.swarm.behaviour_mut().allowed.allow_peer(peer);
            for addr in addrs {
                self.swarm.behaviour_mut().kad.add_address(&peer, addr);
            }
        }
        Ok(())
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.listen_on(addr).map(drop).map_err(|e| Error::Invalid(format!("listen: {e}")))
    }

    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }

    pub fn connected(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    /// Dial every member with an address which isn't connected.
    pub fn dial_members(&mut self) -> Result<()> {
        let me = self.peer_id();
        for (peer, addrs) in self.members.list()? {
            if peer != me && !addrs.is_empty() && !self.swarm.is_connected(&peer) {
                self.dial(peer, addrs);
            }
        }
        Ok(())
    }

    fn dial(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) {
        let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer).addresses(addrs).build();
        // A failed dial is reported as an event
        let _ = self.swarm.dial(opts);
    }

    /// The members this node knows of, itself as listening where it is.
    fn roster(&self) -> Result<Roster> {
        let mut members = self.members.list()?;
        members.insert(self.peer_id(), self.listeners());
        Ok(Roster::from_members(&members))
    }

    /// Take in another member's roster, letting in and dialing whoever's
    /// new.
    fn learn(&mut self, roster: &Roster) -> Result<Vec<PeerId>> {
        let mut theirs = roster.to_members();
        theirs.remove(&self.peer_id());
        let new = self.members.merge(&theirs)?;
        self.reload()?;
        for peer in &new {
            if let Some(addrs) = theirs.get(peer).filter(|addrs| !addrs.is_empty()) {
                self.dial(*peer, addrs.clone());
            }
        }
        Ok(new)
    }

    /// The next thing that happens which the mesh cares about.
    pub async fn next(&mut self) -> Result<Event> {
        loop {
            if let Some(event) = self.ready.pop_front() {
                return Ok(event);
            }
            let Some(event) = self.swarm.next().await else {
                return Err(Error::Invalid("the swarm stopped".into()));
            };
            if let Some(event) = self.handle(event)? {
                return Ok(event);
            }
        }
    }

    /// A member's newly connected: tell it of the members, notice it of
    /// what it's missed, and vouch for its sightings from now on.
    fn on_connected(&mut self, peer: PeerId) -> Result<()> {
        let roster = self.roster()?;
        self.swarm.behaviour_mut().members.send_request(&peer, roster);
        self.announce_to(peer)?;
        self.sightings.connected(peer);
        self.trickle.alarm();
        Ok(())
    }

    /// Peers found on the LAN: dial whichever are members.
    fn on_discovered(&mut self, found: Vec<(PeerId, Multiaddr)>) -> Result<()> {
        let mut dial: BTreeMap<PeerId, Vec<Multiaddr>> = BTreeMap::new();
        for (peer, addr) in found {
            if self.members.contains(&peer)? {
                self.members.add_addr(&peer, &addr)?;
                dial.entry(peer).or_default().push(addr);
            }
        }
        for (peer, addrs) in dial {
            if !self.swarm.is_connected(&peer) {
                self.dial(peer, addrs);
            }
        }
        Ok(())
    }

    fn on_disconnected(&mut self, peer: &PeerId) {
        self.noticing.remove(peer);
        self.sightings.disconnected(peer);
        self.trickle.alarm();
    }

    fn handle(&mut self, event: SwarmEvent<BehaviourEvent>) -> Result<Option<Event>> {
        Ok(match event {
            SwarmEvent::NewListenAddr { address, .. } => Some(Event::Listening(address)),
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, .. } => {
                if endpoint.is_dialer() {
                    self.members.add_addr(&peer_id, endpoint.get_remote_address())?;
                }
                if num_established.get() > 1 {
                    return Ok(None);
                }
                self.on_connected(peer_id)?;
                Some(Event::Connected(peer_id))
            },
            SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                self.on_disconnected(&peer_id);
                Some(Event::Disconnected(peer_id))
            },
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => Some(Event::Failed(peer_id, error.to_string())),
            SwarmEvent::IncomingConnectionError { error, .. } => Some(Event::Failed(None, error.to_string())),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                for addr in info.listen_addrs {
                    self.members.add_addr(&peer_id, &addr)?;
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                }
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
                self.on_discovered(found)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Members(request_response::Event::Message { message, .. })) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let new = self.learn(&request)?;
                    let roster = self.roster()?;
                    // The asker may be gone already
                    let _ = self.swarm.behaviour_mut().members.send_response(channel, roster);
                    (!new.is_empty()).then_some(Event::Learned(new))
                },
                request_response::Message::Response { response, .. } => {
                    let new = self.learn(&response)?;
                    (!new.is_empty()).then_some(Event::Learned(new))
                },
            },
            SwarmEvent::Behaviour(BehaviourEvent::Blocks(request_response::Event::Message { peer, message, .. })) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let answer = blocks::answer(&self.catalog, &request);
                    let served = answer.served();
                    // The asker may be gone already
                    let _ = self.swarm.behaviour_mut().blocks.send_response(channel, answer);
                    self.notice_backrefs(peer, &served)?;
                    None
                },
                request_response::Message::Response { request_id, response } => {
                    if let Some(id) = self.fetch_of(request_id) {
                        if let Some(fetch) = self.fetches.get_mut(&id) {
                            fetch.received(&self.catalog, &self.sightings, &peer, request_id, response)?;
                        }
                        self.drive(id)?;
                    }
                    None
                },
            },
            SwarmEvent::Behaviour(BehaviourEvent::Blocks(request_response::Event::OutboundFailure { request_id, .. })) => {
                if let Some(id) = self.fetch_of(request_id) {
                    if let Some(fetch) = self.fetches.get_mut(&id) {
                        fetch.failed(request_id);
                    }
                    self.drive(id)?;
                }
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Adverts(event)) => {
                self.on_advert(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Push(event)) => {
                self.on_push(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Notices(event)) => {
                self.on_notice(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Trim(event)) => {
                self.on_trim(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Dropped(event)) => {
                self.on_dropped(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Condemn(event)) => {
                self.on_condemn(event)?;
                None
            },
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests;
