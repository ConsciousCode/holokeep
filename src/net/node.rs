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
//! - A member configured to relay (`relay = true`), reachable where the
//!   others aren't, relays between members which can't reach each other:
//!   each member keeps a reservation on every relay it's connected to,
//!   and listens through it. A relayed connection is the private network,
//!   noise and yamux over the circuit, end to end, so the relay sees how
//!   much passes and when, and nothing of what; and once two members are
//!   connected through it, they try to punch through to each other
//!   (`DCUtR`), dropping the circuit once they're connected directly. A
//!   member found on the LAN or where it listens is dialled directly as
//!   ever, so a relay's used only where nothing better is.
//! - Members want blocks of each other; see `blocks`.
//! - Members keep each other's blocks durable; see `durability`.
//! - Members tell each other of structure linking to what they hold; see
//!   `structure`.
//! - Members let go of copies the mesh can spare when space runs short;
//!   see `trim`.
//! - A node serves several accounts, users sharing its machine, and
//!   members tell each other which users they host; a user's blocks go
//!   only to machines hosting the user. See `hosts`.
//! - A member lets in clients, its users' devices which are no members,
//!   where it listens for them; a client connects to that member alone.
//!   See `clients`.

use std::path::PathBuf;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::time::{Duration, Instant};

use futures::{AsyncRead, AsyncWrite, StreamExt};
use libp2p::allow_block_list::{self, AllowedPeers};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::pnet::PreSharedKey;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::core::transport::ListenerId;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, Transport, dcutr, identify, kad, mdns, ping, relay, tcp};
use serde::{Deserialize, Serialize};

use super::blocks::{self, Blocks, Fetch, Want};
use super::check::{Asking, Check, CheckId};
use super::clock::{self, Clocks, Offset, Told};
use super::clients::{Gate, Ports};
use super::collect::{self, Condemn, Condemned, Verdict};
use super::durability::{self, Advert, Audit, Haves, Kept, Push, Report, Sightings, Trickle};
use super::grants::{Have, Sent};
use super::hosts::{self, Host, Hosts};
use crate::multihash::Multihash;
use crate::store::BlockIndex;
use super::mesh::{Error, Members, Result, unless_busy};
use super::structure::{self, Cursors, Notice, Wants};
use super::trim::{self, Ack, Dropped, Grant, Intent, Trim, Watermarks};
use crate::cid::{Cid as _, CidRef};
use crate::model::Link;
use crate::store::{Catalog, ExternalFile};

const IDENTIFY: &str = "/holokeep/id/1.0.0";
const KAD: StreamProtocol = StreamProtocol::new("/holokeep/kad/1.0.0");
const MEMBERS: StreamProtocol = StreamProtocol::new("/holokeep/members/1.0.0");

/// How long a connection with nothing going on is kept: the mesh is small
/// and stays connected.
const IDLE: Duration = Duration::from_hours(1);

/// How often a connection's pinged, and how long an answer's waited for:
/// a connection whose ping fails is closed, as one to a peer that slept
/// or moved networks is dead long before TCP says so, and the peer's
/// dialled again wherever it is now.
const PING: Duration = Duration::from_secs(10);

/// What's tunable of a node's connections (`ping` and `idle` in
/// `config.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tunables {
    /// How often a connection's pinged, and how long an answer's waited
    /// for.
    pub ping: Duration,
    /// How long a connection with nothing going on is kept open.
    pub idle: Duration,
    /// Whether to relay between members which can't reach each other.
    pub relay: bool,
}

impl Default for Tunables {
    fn default() -> Self {
        Self { ping: PING, idle: IDLE, relay: false }
    }
}

/// How a relay relays between members: as long and as much as they like,
/// since only members reach it, where libp2p's defaults are a few
/// minutes and kilobytes, enough to punch through and no more.
fn relay_config() -> relay::Config {
    relay::Config {
        max_circuit_duration: Duration::from_hours(24),
        max_circuit_bytes: 0,
        reservation_rate_limiters: Vec::new(),
        circuit_src_rate_limiters: Vec::new(),
        ..relay::Config::default()
    }
}

/// The members one node knows of, as it tells another.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Roster {
    members: Vec<(String, Vec<String>)>,
    /// Where members listen for clients, as far as the sender knows:
    /// omitted by older builds. A client's member tells it only of those
    /// serving its user, and of no members otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    clients: Vec<(String, Vec<String>)>,
}

impl Roster {
    fn from_members(members: &BTreeMap<PeerId, Vec<Multiaddr>>) -> Self {
        let members = members.iter().map(|(peer, addrs)| (peer.to_string(), addrs.iter().map(ToString::to_string).collect()));
        Self { members: members.collect(), clients: Vec::new() }
    }

    /// The same, saying too where members listen for clients.
    fn with_clients(mut self, clients: &BTreeMap<PeerId, Vec<Multiaddr>>) -> Self {
        self.clients = Self::from_members(clients).members;
        self
    }

    /// Where it says members listen for clients.
    fn to_clients(&self) -> BTreeMap<PeerId, Vec<Multiaddr>> {
        Self { members: self.clients.clone(), clients: Vec::new() }.to_members()
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

/// The most a request or answer may be. An answer to a want, or a push,
/// carries a few megabytes of blocks, and at least one however large,
/// where libp2p's codec allows a megabyte.
const MESSAGE: u64 = 64 << 20;

/// A request and response protocol in CBOR, its messages as large as
/// blocks need.
pub(crate) fn exchange<Req, Resp>(protocol: StreamProtocol, config: request_response::Config) -> request_response::cbor::Behaviour<Req, Resp>
where
    Req: Send + Serialize + serde::de::DeserializeOwned,
    Resp: Send + Serialize + serde::de::DeserializeOwned,
{
    let codec = request_response::cbor::codec::Codec::default().set_request_size_maximum(MESSAGE).set_response_size_maximum(MESSAGE);
    request_response::Behaviour::with_codec(codec, [(protocol, ProtocolSupport::Full)], config)
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    allowed: allow_block_list::Behaviour<AllowedPeers>,
    gate: Gate,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    relay: Toggle<relay::Behaviour>,
    relayed: Toggle<relay::client::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    members: request_response::cbor::Behaviour<Roster, Roster>,
    blocks: request_response::cbor::Behaviour<Want, Blocks>,
    adverts: request_response::cbor::Behaviour<Advert, Haves>,
    push: request_response::cbor::Behaviour<Push, Kept>,
    notices: request_response::cbor::Behaviour<Notice, Wants>,
    trim: request_response::cbor::Behaviour<Intent, Grant>,
    dropped: request_response::cbor::Behaviour<Dropped, Ack>,
    condemn: request_response::cbor::Behaviour<Condemn, Verdict>,
    hosts: request_response::cbor::Behaviour<Hosts, Hosts>,
    grants: request_response::cbor::Behaviour<Have, Sent>,
    asks: request_response::cbor::Behaviour<super::thin::Ask, super::thin::Answer>,
    clock: request_response::cbor::Behaviour<clock::Asked, Told>,
    serve: request_response::cbor::Behaviour<super::serve::Asked, super::serve::Answered>,
}

/// The least and most time between dials of a member that isn't
/// connected: each failed dial doubles it, from the least, so a member
/// that was restarting is reached within seconds and one that's offline
/// is tried once a minute.
const REDIAL_LEAST: Duration = Duration::from_secs(2);
const REDIAL_MOST: Duration = Duration::from_mins(1);

/// When each member not connected is next to be dialled, and how long
/// after that if that fails too.
#[derive(Debug, Default)]
struct Redial {
    due: HashMap<PeerId, (Instant, Duration)>,
}

impl Redial {
    /// Whether a member's due a dial: never dialled, or its wait's over.
    fn due(&self, peer: &PeerId, now: Instant) -> bool {
        self.due.get(peer).is_none_or(|(at, _)| *at <= now)
    }

    /// A member's dialled: not again till its wait's over, which doubles
    /// for the dial after.
    fn dialled(&mut self, peer: PeerId, now: Instant) {
        let wait = self.due.get(&peer).map_or(REDIAL_LEAST, |(_, wait)| *wait);
        self.due.insert(peer, (now.checked_add(wait).unwrap_or(now), wait.saturating_mul(2).min(REDIAL_MOST)));
    }

    /// A member's connected, or was and isn't: dialled at once when it
    /// next needs to be, as it may only have moved networks.
    fn reset(&mut self, peer: &PeerId) {
        self.due.remove(peer);
    }
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
    /// A check of who holds blocks finished.
    Checked { id: CheckId, known: crate::health::Known },
    /// Garbage was let go of, as members answered.
    Collected { collected: usize },
    /// This machine's clock was found far from the mesh's, or back near
    /// it: how far ahead the mesh's is, in microseconds, and of how many
    /// members.
    Skewed { ahead: i64, members: usize, far: bool },
    /// The answer to a message for an anchor another node serves, in a
    /// session of this node's.
    Served { session: u64, message: Vec<u8> },
}

/// A transport for the mesh, over some base transport: the private
/// network, then noise, then yamux; where clients connect, as `clients`
/// says, no private network.
pub fn transport<T>(base: T, key: &Keypair, swarm_key: PreSharedKey, clients: Ports) -> Result<Boxed<(PeerId, StreamMuxerBox)>>
where
    T: Transport + Send + Unpin + 'static,
    T::Error: Send + Sync + 'static,
    T::Output: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    T::ListenerUpgrade: Send,
    T::Dial: Send,
{
    super::clients::transport(base, key, swarm_key, clients)
}

/// One of the accounts a node serves, by uid, and who it acts for: its
/// user's key, or until it has one, its device's, as a vault's account
/// does. Until it has a user, its blocks are any member's, as before
/// there were users.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Local {
    uid: u32,
    user: Option<Link>,
    /// Whether it has a user, a root key, so is a mesh's partition.
    rooted: bool,
}

impl Local {
    /// The user's key CID's bytes, as a request names it.
    fn user_bytes(&self) -> Option<Vec<u8>> {
        self.user.as_ref().map(CidRef::to_bytes)
    }
}

/// What a member hosts, as far as it's said.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Hosting {
    /// An older build, which doesn't say: the mesh was for one user, so
    /// it hosts the user this node's own account is for.
    Older,
    /// These users, by their keys' CIDs' bytes, as it's shown.
    Users(std::collections::BTreeSet<Vec<u8>>),
}

/// Who a node hosts, by (user, device), as key CIDs' bytes.
type Hosted = Vec<(Vec<u8>, Vec<u8>)>;

/// Audits or trims run as one, one for each account served: done when
/// every part is.
#[derive(Debug, Default)]
struct Group<R> {
    parts: std::collections::BTreeSet<u64>,
    report: R,
}

pub struct Node {
    swarm: Swarm<Behaviour>,
    members: Members,
    catalog: Catalog,
    /// Fetches, and for which account each is.
    fetches: BTreeMap<FetchId, (u32, Fetch)>,
    next_fetch: FetchId,
    sightings: Sightings,
    /// Audits, and for which account each is.
    audits: BTreeMap<AuditId, (u32, Audit)>,
    /// Audits of every account served, made of an audit of each.
    audit_groups: BTreeMap<AuditId, Group<Report>>,
    next_audit: AuditId,
    /// Checks of who holds blocks, waiting on answers.
    checks: BTreeMap<CheckId, Check>,
    next_check: CheckId,
    trickle: Trickle,
    /// Trims, and for which account each is.
    trims: BTreeMap<TrimId, (u32, Trim)>,
    trim_groups: BTreeMap<TrimId, Group<trim::Report>>,
    next_trim: TrimId,
    marks: Watermarks,
    /// Blocks members let go of which this node holds, to audit soon.
    suspects: Vec<Multihash>,
    /// The fetch asking members for what a scan found gone, if it's underway.
    lost_scan: Option<FetchId>,
    /// How far through lost claims this has looked for what's here.
    lost_cursor: i64,
    /// The trickle's audit under way, and whether more arrived than it
    /// took in.
    trickling: Option<(AuditId, bool)>,
    cursors: Cursors,
    /// Notices sent: to whom, for which account, and for one from a
    /// cursor, where it moves to once answered.
    notices: HashMap<request_response::OutboundRequestId, (PeerId, u32, Option<i64>)>,
    /// Members with a notice from their cursor unanswered, for each
    /// account.
    noticing: HashSet<(PeerId, u32)>,
    /// Pushes sent, and for which account each was.
    pushed: HashMap<request_response::OutboundRequestId, u32>,
    /// The accounts served besides the catalog's own, by uid, and the
    /// keys this node acts for each with.
    others: Vec<(u32, crate::keys::Key)>,
    /// Who this node last told members it hosts, by (user, device), and
    /// what it told them.
    told: (Hosted, Hosts),
    /// What each connected member hosts, as it's said.
    hosting: HashMap<PeerId, Hosting>,
    /// Connected members which know what this node hosts as it now is, so
    /// may be asked things: until then, nothing's asked of one.
    heard: HashSet<PeerId>,
    /// Members told what this node hosts, yet to answer, and what each was
    /// told.
    telling: HashMap<request_response::OutboundRequestId, (PeerId, Hosts)>,
    condemned: Condemned,
    /// Files imported in place found changed, for whoever runs the node
    /// to import again if they're mounted.
    changed: Vec<PathBuf>,
    /// Condemnations asked of members and unanswered: whom, and of what.
    condemning: HashMap<request_response::OutboundRequestId, (PeerId, collect::BatchId)>,
    /// The mesh's first grant and its grants, worked out, once it has
    /// them: who's in it is what they say.
    granted: Option<(Link, crate::grants::State)>,
    /// The claims shared with each guest a member hosts that it's been
    /// noticed of and answered, by (member, guest's key CID's bytes): what's
    /// noticed again is only what's new, until the grants change.
    guests_noticed: HashMap<(PeerId, Vec<u8>), HashSet<Vec<u8>>>,
    /// Notices of what's shared with guests, unanswered: to whom, for
    /// which guest, and what they notice.
    guest_notices: HashMap<request_response::OutboundRequestId, (PeerId, Link, Vec<Vec<u8>>)>,
    /// Pushes of what's shared with guests, unanswered: what's kept of
    /// them isn't a copy.
    guest_pushes: HashSet<request_response::OutboundRequestId>,
    /// Where this listens for clients, by port, as its transport and gate
    /// know it, and its listeners for them.
    ports: Ports,
    client_listeners: HashSet<ListenerId>,
    /// The clients let in, by their device's peer ID, and the account each
    /// acts for: certified by its user, and still so.
    clients: HashMap<PeerId, u32>,
    /// Visitors let in, by peer ID, with the key each is: keys no user of
    /// the mesh, nor ever named by its grants, that a user served here
    /// shares a view of an anchor with, to read.
    visitors: HashMap<PeerId, Link>,
    /// What clients asked which waits on fetches.
    asked: Vec<asks::Asked>,
    /// The member this node's a client of, if it's a client, and the port
    /// it listens for clients on, as last connected to.
    client_of: Option<PeerId>,
    member_ports: HashMap<PeerId, u64>,
    /// Where other members say they listen for clients.
    client_addrs: BTreeMap<PeerId, Vec<Multiaddr>>,
    /// Events which happened outside `next`, for it to return first.
    ready: VecDeque<Event>,
    /// How far members' clocks are from this machine's, and when each
    /// ask for the time unanswered was made, by this machine's clock.
    clocks: Clocks,
    clocking: HashMap<request_response::OutboundRequestId, (PeerId, u64)>,
    /// The sessions of anchors this node serves to others, and what their
    /// services say, as it's heard.
    sessions: super::serve::Sessions,
    services_heard: tokio::sync::mpsc::UnboundedReceiver<super::serve::Heard>,
    /// Messages for anchors other nodes serve, unanswered: their sessions,
    /// and the messages, so a failure's answered.
    asking_served: HashMap<request_response::OutboundRequestId, (u64, Vec<u8>)>,
    /// The repo's directory, whose config says what this node serves.
    repo: Option<PathBuf>,
    /// Whether this machine's clock was last found far from the mesh's.
    skewed: bool,
    redial: Redial,
    /// Where this listens through each relay, and the relayed connections
    /// open, to drop once their peers are connected directly.
    relays: HashMap<PeerId, (ListenerId, Multiaddr)>,
    /// Where each peer this dialled was reached, directly.
    dialled_at: HashMap<PeerId, Multiaddr>,
    circuits: HashMap<libp2p::swarm::ConnectionId, PeerId>,
    /// The catalog's generation when members were last noticed of what
    /// arrived.
    noticed: i64,
}

impl Node {
    /// A node over TCP, finding members on the LAN by mDNS, and reaching
    /// them through relays where it can't otherwise; or a client's, with
    /// no private network, finding its member where it was told.
    pub fn tcp(key: &Keypair, swarm_key: PreSharedKey, catalog: Catalog, members: Members, tunables: Tunables) -> Result<Self> {
        // Addresses may name hosts, /dns4/relay.example.com/tcp/4011
        let base = libp2p::dns::tokio::Transport::system(tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)))?;
        if members.client_of()?.is_some() {
            return Self::new(super::clients::client_transport(base, key)?, key, catalog, members, false, Ports::default(), tunables);
        }
        let ports = Ports::default();
        let (relayed, client) = relay::client::new(key.public().to_peer_id());
        Self::relayed(transport(relayed.or_transport(base), key, swarm_key, ports.clone())?, client, key, catalog, members, true, ports, tunables)
    }

    /// A node over a transport, with or without mDNS, its transport
    /// leaving the private network out on `ports`, where clients connect.
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, catalog: Catalog, members: Members, lan: bool, ports: Ports, tunables: Tunables) -> Result<Self> {
        Self::with(transport, None, key, catalog, members, lan, ports, tunables)
    }

    /// A node as `new`, reaching members through relays too: `transport`
    /// is over the relay client's transport, which `client` goes with.
    #[allow(clippy::too_many_arguments)]
    pub fn relayed(transport: Boxed<(PeerId, StreamMuxerBox)>, client: relay::client::Behaviour, key: &Keypair, catalog: Catalog, members: Members, lan: bool, ports: Ports, tunables: Tunables) -> Result<Self> {
        Self::with(transport, Some(client), key, catalog, members, lan, ports, tunables)
    }

    #[allow(clippy::too_many_arguments)]
    fn with(transport: Boxed<(PeerId, StreamMuxerBox)>, relayed: Option<relay::client::Behaviour>, key: &Keypair, catalog: Catalog, members: Members, lan: bool, ports: Ports, tunables: Tunables) -> Result<Self> {
        let peer = key.public().to_peer_id();
        let client_of = members.client_of()?;
        let mdns = if lan && client_of.is_none() { Some(mdns::tokio::Behaviour::new(mdns::Config::default(), peer)?) } else { None };
        let mut kad = kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), kad::Config::new(KAD));
        // A client's no member for others to find
        kad.set_mode(Some(if client_of.is_some() { kad::Mode::Client } else { kad::Mode::Server }));
        let behaviour = Behaviour {
            allowed: allow_block_list::Behaviour::default(),
            gate: Gate::new(ports.clone()),
            identify: identify::Behaviour::new(identify::Config::new(IDENTIFY.into(), key.public())),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(tunables.ping).with_timeout(tunables.ping)),
            mdns: mdns.into(),
            // A client relays nothing, and is relayed nowhere
            relay: (tunables.relay && client_of.is_none()).then(|| relay::Behaviour::new(peer, relay_config())).into(),
            dcutr: relayed.is_some().then(|| dcutr::Behaviour::new(peer)).into(),
            relayed: relayed.into(),
            kad,
            members: exchange(MEMBERS, request_response::Config::default()),
            blocks: exchange(blocks::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            adverts: exchange(durability::ADVERTS, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            push: exchange(durability::PUSH, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            notices: exchange(structure::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            trim: exchange(trim::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            dropped: exchange(trim::DROPPED, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            condemn: exchange(collect::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            hosts: exchange(hosts::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_secs(20))),
            grants: exchange(super::grants::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_mins(1))),
            asks: exchange(super::thin::PROTOCOL, request_response::Config::default().with_request_timeout(super::thin::ANSWER)),
            clock: exchange(clock::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_secs(10))),
            // Longer than a mount waits, so it's the mount that gives up
            serve: exchange(super::serve::PROTOCOL, request_response::Config::default().with_request_timeout(Duration::from_secs(30))),
        };
        let (heard_from, heard) = tokio::sync::mpsc::unbounded_channel();
        let config = libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(tunables.idle);
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
            audit_groups: BTreeMap::new(),
            next_audit: 0,
            checks: BTreeMap::new(),
            next_check: 0,
            trickle: Trickle::default(),
            trims: BTreeMap::new(),
            trim_groups: BTreeMap::new(),
            next_trim: 0,
            marks: Watermarks::default(),
            suspects: Vec::new(),
            lost_scan: None,
            lost_cursor: 0,
            trickling: None,
            cursors,
            notices: HashMap::new(),
            noticing: HashSet::new(),
            pushed: HashMap::new(),
            others: Vec::new(),
            told: (Vec::new(), Hosts::default()),
            hosting: HashMap::new(),
            heard: HashSet::new(),
            telling: HashMap::new(),
            condemned,
            changed: Vec::new(),
            condemning: HashMap::new(),
            granted: None,
            guests_noticed: HashMap::new(),
            guest_notices: HashMap::new(),
            guest_pushes: HashSet::new(),
            ports,
            client_listeners: HashSet::new(),
            clients: HashMap::new(),
            asked: Vec::new(),
            visitors: HashMap::new(),
            client_of,
            member_ports: HashMap::new(),
            client_addrs: BTreeMap::new(),
            ready: VecDeque::new(),
            clocks: Clocks::default(),
            clocking: HashMap::new(),
            sessions: super::serve::Sessions::new(heard_from),
            services_heard: heard,
            asking_served: HashMap::new(),
            repo: None,
            skewed: false,
            redial: Redial::default(),
            relays: HashMap::new(),
            dialled_at: HashMap::new(),
            circuits: HashMap::new(),
            noticed: 0,
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

    /// Serve these accounts too, besides the catalog's own, acting for
    /// each with its key here: users sharing this machine.
    pub fn serve(&mut self, others: Vec<(u32, crate::keys::Key)>) -> Result<()> {
        self.others = others;
        self.reload_clients()?;
        self.tell_hosts()
    }

    /// Whether a peer's a client, not a member: asked nothing a member is,
    /// and counted on for nothing.
    pub fn is_client(&self, peer: &PeerId) -> bool {
        self.clients.contains_key(peer)
    }

    /// The clients let in, and the account each acts for.
    pub const fn clients(&self) -> &HashMap<PeerId, u32> {
        &self.clients
    }

    /// Let in the clients this node was told to, each still a device of
    /// an account's user here, whom the mesh recognizes; and no others,
    /// shutting out any whose device was revoked. A client never has
    /// clients.
    fn reload_clients(&mut self) -> Result<()> {
        let mut clients = HashMap::new();
        if self.client_of.is_none() {
            let me = self.peer_id();
            let served = self.accounts();
            let members = self.members.list()?;
            // With grants, they say who's a client, of whichever account's
            // user certified it; the clients this node was told of only
            // where they don't
            let candidates: Vec<(PeerId, Vec<u32>)> = match self.granted_clients() {
                Some(granted) => granted.into_iter().map(|peer| (peer, served.clone())).collect(),
                None => self.members.clients()?.into_iter().map(|(peer, uid)| (peer, vec![uid])).collect(),
            };
            for (peer, uids) in candidates {
                if peer == me || members.contains_key(&peer) {
                    continue;
                }
                let Some(device) = crate::keys::from_peer_id(&peer.to_string()) else {
                    continue;
                };
                for uid in uids.into_iter().filter(|uid| served.contains(uid)) {
                    let local = self.local(uid)?;
                    if !local.rooted || !self.recognizes(&local) {
                        continue;
                    }
                    if self.catalog.viewing(uid, |catalog| catalog.claims().map_or(Ok(false), |claims| claims.authorized(&device)))?? {
                        clients.insert(peer, uid);
                        break;
                    }
                }
            }
        }
        let visitors = self.find_visitors(&clients)?;
        let gone: Vec<PeerId> = self.clients.keys().chain(self.visitors.keys()).filter(|peer| !clients.contains_key(*peer) && !visitors.contains_key(*peer)).copied().collect();
        for peer in gone {
            self.swarm.behaviour_mut().allowed.disallow_peer(peer);
        }
        for peer in clients.keys().chain(visitors.keys()) {
            self.swarm.behaviour_mut().allowed.allow_peer(*peer);
        }
        // Visitors connect where clients do
        let peers: HashSet<PeerId> = clients.keys().chain(visitors.keys()).copied().collect();
        self.swarm.behaviour_mut().gate.set_clients(peers.clone());
        self.sightings.uncount(peers)?;
        self.clients = clients;
        self.visitors = visitors;
        Ok(())
    }

    /// The visitors to let in: keys a user served here, whom the mesh
    /// recognizes, shares a view of an anchor with, which the grants say
    /// may read it, being neither users of the mesh nor named by its
    /// grants; and neither members nor clients.
    fn find_visitors(&self, clients: &HashMap<PeerId, u32>) -> Result<HashMap<PeerId, Link>> {
        let mut visitors = HashMap::new();
        let (None, Some((_, state))) = (self.client_of, &self.granted) else {
            return Ok(visitors);
        };
        let owners: Vec<Link> = self.locals()?.into_iter().filter(|local| local.rooted && self.recognizes(local)).filter_map(|local| local.user).collect();
        let members = self.members.list()?;
        let me = self.peer_id();
        for share in state.shares() {
            if share.held.is_empty() || !owners.contains(&share.owner) || state.holds(&share.user, crate::grants::USER) {
                continue;
            }
            let Ok(peer) = PeerId::from_bytes(&share.user.multihash().to_bytes()) else {
                continue;
            };
            if peer != me && !members.contains_key(&peer) && !clients.contains_key(&peer) {
                visitors.insert(peer, share.user);
            }
        }
        Ok(visitors)
    }

    /// Whether a visitor sent something it's not to: anything but asking
    /// for blocks, asking over `ask`, and pushing what it writes. Dropped
    /// unanswered.
    fn trespasses(&self, event: &BehaviourEvent) -> bool {
        const fn from<Req, Resp>(event: &request_response::Event<Req, Resp>) -> Option<PeerId> {
            match event {
                request_response::Event::Message { peer, .. } => Some(*peer),
                _ => None,
            }
        }
        let peer = match event {
            BehaviourEvent::Identify(identify::Event::Received { peer_id, .. }) => Some(*peer_id),
            BehaviourEvent::Members(event) => from(event),
            BehaviourEvent::Adverts(event) => from(event),
            BehaviourEvent::Notices(event) => from(event),
            BehaviourEvent::Trim(event) => from(event),
            BehaviourEvent::Dropped(event) => from(event),
            BehaviourEvent::Condemn(event) => from(event),
            BehaviourEvent::Hosts(event) => from(event),
            BehaviourEvent::Grants(event) => from(event),
            BehaviourEvent::Clock(event) => from(event),
            BehaviourEvent::Serve(event) => from(event),
            _ => None,
        };
        peer.is_some_and(|peer| self.visitors.contains_key(&peer))
    }

    /// Whether a peer's a visitor: no member, no client, let in to read
    /// what's shared with its key, and nothing else.
    pub fn is_visitor(&self, peer: &PeerId) -> bool {
        self.visitors.contains_key(peer)
    }

    /// The visitors let in, by peer ID, with their keys.
    pub const fn visitors(&self) -> &HashMap<PeerId, Link> {
        &self.visitors
    }

    /// The visitors connected now.
    pub fn visiting(&self) -> Vec<PeerId> {
        self.visitors.keys().filter(|peer| self.swarm.is_connected(peer)).copied().collect()
    }

    /// The uids of the accounts served, the catalog's own first.
    pub fn accounts(&self) -> Vec<u32> {
        let home = self.catalog.uid();
        std::iter::once(home).chain(self.others.iter().map(|&(uid, _)| uid).filter(|&uid| uid != home)).collect()
    }

    /// The accounts served, the catalog's own first.
    fn locals(&self) -> Result<Vec<Local>> {
        self.accounts().into_iter().map(|uid| self.local(uid)).collect()
    }

    fn local(&self, uid: u32) -> Result<Local> {
        let account = match self.catalog.claims() {
            Some(claims) => claims.account(uid)?,
            None => None,
        };
        let rooted = account.as_ref().is_some_and(|account| account.user.is_some());
        Ok(Local { uid, user: account.as_ref().and_then(|account| account.acts_for().cloned()), rooted })
    }

    /// Whether a member hosts an account's user, so may have its blocks.
    fn hosts(&self, peer: &PeerId, local: &Local) -> bool {
        let (Some(user), true) = (local.user_bytes(), local.rooted) else {
            return true;
        };
        if !self.recognizes(local) {
            return false;
        }
        // A visitor hosts no one, whatever it says
        if self.visitors.contains_key(peer) {
            return false;
        }
        // A client let in hosts its account's user, and no other, as a
        // thin client can't say
        if let Some(&uid) = self.clients.get(peer) {
            return uid == local.uid;
        }
        match self.hosting.get(peer) {
            Some(Hosting::Users(users)) => users.contains(&user),
            // As when a mesh was for one user; one that's yet to say isn't
            // asked anything, so asks nothing of a newer build
            Some(Hosting::Older) | None => local.uid == self.catalog.uid(),
        }
    }

    /// Whether the mesh's grants say an account's user is one of its users:
    /// any, before it has grants.
    fn recognizes(&self, local: &Local) -> bool {
        match (&self.granted, &local.user) {
            (Some((_, state)), Some(user)) if local.rooted => state.holds(user, crate::grants::USER),
            _ => true,
        }
    }

    /// The machines the mesh's grants say are in it, given /mesh/machine
    /// itself, not by holding /mesh, as an operator does, if it has grants.
    fn machines(&self) -> Option<std::collections::BTreeSet<PeerId>> {
        let (_, state) = self.granted.as_ref()?;
        Some(state.holders().into_iter()
            .filter(|(_, held)| held.iter().any(|command| command == crate::grants::MACHINE))
            .filter_map(|(who, _)| PeerId::from_bytes(&who.multihash().to_bytes()).ok())
            .collect())
    }

    /// The clients the mesh's grants say there are, if it has grants.
    fn granted_clients(&self) -> Option<std::collections::BTreeSet<PeerId>> {
        let (_, state) = self.granted.as_ref()?;
        Some(state.holders().into_iter()
            .filter(|(_, held)| held.iter().any(|command| command == crate::grants::CLIENT))
            .filter_map(|(who, _)| PeerId::from_bytes(&who.multihash().to_bytes()).ok())
            .collect())
    }

    /// Where other members say they listen for clients.
    pub const fn client_addrs(&self) -> &BTreeMap<PeerId, Vec<Multiaddr>> {
        &self.client_addrs
    }

    /// Where the members serving an account's user listen for clients,
    /// this one among them: where a client of it may connect.
    pub fn client_roster(&self, uid: u32) -> Result<BTreeMap<PeerId, Vec<Multiaddr>>> {
        let local = self.local(uid)?;
        let mut roster: BTreeMap<PeerId, Vec<Multiaddr>> = self.client_addrs.iter()
            .filter(|(peer, addrs)| !addrs.is_empty() && self.hosts(peer, &local))
            .map(|(peer, addrs)| (*peer, addrs.clone()))
            .collect();
        if !self.client_listeners().is_empty() {
            roster.insert(self.peer_id(), self.client_listeners());
        }
        Ok(roster)
    }

    /// A client's member says where members serving its user listen for
    /// clients: connect to them too.
    fn learn_members(&mut self, from: &PeerId, roster: &Roster) -> Result<()> {
        if self.client_of.is_none() || !self.members.contains(from)? {
            return Ok(());
        }
        let mut theirs = roster.to_clients();
        theirs.remove(&self.peer_id());
        theirs.retain(|_, addrs| !addrs.is_empty());
        self.members.merge(&theirs)?;
        for (peer, addrs) in theirs {
            self.swarm.behaviour_mut().allowed.allow_peer(peer);
            if !self.swarm.is_connected(&peer) {
                self.dial(peer, addrs);
            }
        }
        Ok(())
    }

    /// Every grant of the mesh here, and what makes each count, as sent
    /// to another member: by CID, with the bytes.
    fn grant_evidence(&self) -> Result<Vec<(Link, Vec<u8>)>> {
        let Some((_, state)) = &self.granted else {
            return Ok(Vec::new());
        };
        let grants: Vec<Link> = state.grants().chain(state.waiting()).cloned().collect();
        Ok(self.catalog.grant_blocks(&grants, &state.users())?)
    }

    /// Work out the mesh's grants afresh, if it has them, and list as
    /// members the machines they say are in it, and only those, shutting
    /// out any other. Returns whether any grants, or anything bearing on
    /// whether they count, arrived since: a revocation, or a signing again.
    fn refresh_grants(&mut self) -> Result<bool> {
        // The grants worked out, and what's sent of them: evidence alone
        // may hold a grant before it's worked out, as what's about a key
        // whose certificate goes with them
        let cids = |node: &Self| -> Result<(Vec<Link>, Vec<Link>)> {
            let grants = node.granted.as_ref().map(|(_, state)| state.grants().chain(state.waiting()).cloned().collect()).unwrap_or_default();
            Ok((grants, node.grant_evidence()?.into_iter().map(|(cid, _)| cid).collect()))
        };
        let before = cids(self)?;
        // What a grant gave till a time that's passed, gone: news as much
        let lapsed = self.granted.as_ref().and_then(|(_, state)| state.next_expiry()).is_some_and(|until| until <= now_secs());
        self.granted = match self.members.genesis()? {
            Some(genesis) => {
                let state = self.catalog.grant_state(&genesis)?;
                if state.is_none() {
                    eprintln!("the mesh's first grant, {genesis}, isn't here: its members are its roster, as before grants");
                }
                state.map(|state| (genesis, state))
            },
            None => None,
        };
        let after = cids(self)?;
        let changed = before != after || lapsed;
        // Who may read and write whose views of anchors, for counting sets:
        // only a mesh with grants says, so another mesh's daemon leaves it
        if changed && let Some((_, state)) = &self.granted {
            self.catalog.set_access(state)?;
            // What's shared with whom may have changed
            self.guests_noticed.clear();
        }
        // A client's member is the one it was told, whoever the machines are
        let (Some(machines), None) = (self.machines(), self.client_of) else {
            return Ok(changed);
        };
        let me = self.peer_id();
        for peer in self.members.list()?.into_keys() {
            if !machines.contains(&peer) {
                // As forgetting it: copies it was believed to hold don't count
                self.members.remove(&peer)?;
                self.sightings.forget_peer(&peer)?;
                self.swarm.behaviour_mut().allowed.disallow_peer(peer);
                let _ = self.swarm.disconnect_peer_id(peer);
            }
        }
        for peer in machines {
            if peer != me {
                self.members.add(&peer)?;
            }
        }
        Ok(changed)
    }

    /// Tell a member which grants this has, and what makes them count, if
    /// the mesh has any: it answers with what it has that this hasn't.
    fn ask_grants(&mut self, peer: PeerId) -> Result<()> {
        let evidence = self.grant_evidence()?;
        let have = match (&self.granted, self.members.genesis()?) {
            (Some((genesis, _)), _) => Have::new(genesis, evidence.into_iter().map(|(cid, _)| cid)),
            // Its first grant known, as a ticket says, but not yet here
            (None, Some(genesis)) => Have::new(&genesis, []),
            (None, None) => return Ok(()),
        };
        self.swarm.behaviour_mut().grants.send_request(&peer, have);
        Ok(())
    }

    /// Take in grants a member sent, and what makes them count; if that's
    /// news, work them out again, and tell every member.
    fn took_grants(&mut self, sent: &Sent) -> Result<()> {
        if sent.is_empty() {
            return Ok(());
        }
        for claim in sent.claims() {
            self.catalog.put_block(&claim.block(), crate::cid::CidVersion::V1)?;
        }
        if self.refresh_grants()? {
            self.reload_allowed()?;
            for peer in self.connected() {
                self.ask_grants(peer)?;
            }
            unless_busy(self.announce(), "noticing guests of what's shared with them")?;
        }
        Ok(())
    }

    fn on_grants(&mut self, event: request_response::Event<Have, Sent>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let known = self.members.genesis()?;
                let (sent, behind) = match &self.granted {
                    None if known.as_ref().is_some_and(|genesis| request.of(genesis)) => (Sent::default(), !request.grants().is_empty()),
                    Some((genesis, _)) if request.of(genesis) => {
                        let theirs: HashSet<Vec<u8>> = request.grants().iter().map(CidRef::to_bytes).collect();
                        let mine = self.grant_evidence()?;
                        let ours: HashSet<Vec<u8>> = mine.iter().map(|(cid, _)| cid.to_bytes()).collect();
                        let behind = theirs.iter().any(|cid| !ours.contains(cid));
                        let missing = mine.into_iter().filter(|(cid, _)| !theirs.contains(&cid.to_bytes())).collect();
                        (Sent::new(missing), behind)
                    },
                    _ => (Sent::default(), false),
                };
                // The asker may be gone already
                let _ = self.swarm.behaviour_mut().grants.send_response(channel, sent);
                if behind {
                    self.ask_grants(peer)?;
                }
            },
            request_response::Event::Message { message: request_response::Message::Response { response, .. }, .. } => self.took_grants(&response)?,
            _ => {},
        }
        Ok(())
    }

    /// The users a member hosts who share a view of an anchor with another
    /// user this node hosts: their guests here, and this node's users
    /// theirs there. What's shared between them goes to and from it, as
    /// what one user has for another is withheld from the other's account,
    /// even where it's hosted too.
    fn guests_of(&self, peer: &PeerId) -> Result<Vec<Link>> {
        let (true, Some(Hosting::Users(users))) = (self.heard.contains(peer), self.hosting.get(peer)) else {
            return Ok(Vec::new());
        };
        let mut related = HashSet::new();
        for local in self.locals()? {
            if let (Some(user), true) = (&local.user, local.rooted) {
                related.extend(self.catalog.related(user)?.iter().map(CidRef::to_bytes));
            }
        }
        Ok(users.iter().filter(|user| related.contains(*user)).filter_map(|user| Link::decode(user).ok()).collect())
    }

    /// The guest a member asks as, by the user it names, if it's one.
    fn guest_of(&self, peer: &PeerId, user: Option<&[u8]>) -> Result<Option<Link>> {
        let Some(user) = user else {
            return Ok(None);
        };
        Ok(self.guests_of(peer)?.into_iter().find(|guest| guest.to_bytes() == user))
    }

    /// The account a member notices or pushes what's shared with its user
    /// for, as a guest of theirs: by the user it names, if one served here
    /// shares a view of an anchor with one the member hosts.
    fn hosting_guest(&self, peer: &PeerId, user: Option<&[u8]>) -> Result<Option<Local>> {
        let Some(user) = user else {
            return Ok(None);
        };
        let Some(local) = self.locals()?.into_iter().find(|local| local.rooted && local.user_bytes().as_deref() == Some(user)) else {
            return Ok(None);
        };
        let Some(ours) = &local.user else {
            return Ok(None);
        };
        let related: HashSet<Vec<u8>> = self.catalog.related(ours)?.iter().map(CidRef::to_bytes).collect();
        let theirs = self.guests_of(peer)?;
        Ok(theirs.iter().any(|guest| related.contains(&guest.to_bytes())).then_some(local))
    }

    /// The connected members a fetch for an account asks: those hosting its
    /// user, then those hosting users who share views of anchors with it,
    /// of whom it's a guest.
    fn fetch_peers(&self, local: &Local) -> Result<Vec<PeerId>> {
        let mut peers = self.peers_for(local);
        if let (Some(user), true) = (&local.user, local.rooted) {
            let related: HashSet<Vec<u8>> = self.catalog.related(user)?.iter().map(CidRef::to_bytes).collect();
            let mut guests = Vec::new();
            for peer in self.connected() {
                if !peers.contains(&peer) && self.guests_of(&peer)?.iter().any(|guest| related.contains(&guest.to_bytes())) {
                    guests.push(peer);
                }
            }
            guests.sort();
            peers.extend(guests);
        }
        Ok(peers)
    }

    /// Notice a member of the claims shared with each guest of this node's
    /// users it hosts, those it's not been noticed of.
    fn announce_guests(&mut self, peer: PeerId) -> Result<()> {
        for guest in self.guests_of(&peer)? {
            let key = (peer, guest.to_bytes());
            if self.guest_notices.values().any(|(to, of, _)| *to == peer && of == &guest) {
                continue;
            }
            let noticed = self.guests_noticed.get(&key);
            let new: Vec<Link> = self.catalog.guest_claims(&guest)?.into_iter()
                .filter(|cid| noticed.is_none_or(|noticed| !noticed.contains(&cid.to_bytes())))
                .collect();
            if new.is_empty() {
                continue;
            }
            let batches = self.catalog.as_guest(&guest, |catalog| structure::notices(catalog, &new))??;
            for notice in batches {
                let cids = notice.cids();
                let request = self.swarm.behaviour_mut().notices.send_request(&peer, notice.for_user(Some(&key.1)).guest());
                self.guest_notices.insert(request, (peer, guest.clone(), cids));
            }
        }
        Ok(())
    }

    /// The connected members which may be asked of an account's blocks,
    /// and its clients.
    fn peers_for(&self, local: &Local) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> = self.connected().into_iter().filter(|peer| self.heard.contains(peer) && self.hosts(peer, local)).collect();
        peers.sort();
        peers
    }

    /// The connected members which may keep an account's blocks, and be
    /// counted on to: not its clients, whose copies are no one's.
    fn machines_for(&self, local: &Local) -> Vec<PeerId> {
        let mut peers = self.peers_for(local);
        peers.retain(|peer| !self.is_client(peer));
        peers
    }

    /// The account a member asks of, by the user it names, or naming none,
    /// as an older build, the catalog's own: if the member hosts its user.
    fn serving(&self, peer: &PeerId, user: Option<&[u8]>) -> Result<Option<Local>> {
        let mut locals = self.locals()?.into_iter();
        let local = match user {
            Some(user) => locals.find(|local| local.user_bytes().as_deref() == Some(user)),
            None => locals.next(),
        };
        Ok(local.filter(|local| self.hosts(peer, local)))
    }

    /// Tell connected members what this node hosts, if that's changed
    /// since they were told: until they answer, nothing's asked of them.
    fn tell_hosts(&mut self) -> Result<()> {
        let me = self.peer_id();
        let mut who = Vec::new();
        let mut keys = Vec::new();
        for local in self.locals()? {
            let Some(user) = local.user else {
                continue;
            };
            let key = if local.uid == self.catalog.uid() {
                self.catalog.signer()
            } else {
                self.others.iter().find(|(uid, _)| *uid == local.uid).map(|(_, key)| key)
            };
            if let Some(key) = key {
                who.push((user.to_bytes(), key.id().to_bytes()));
                keys.push((user, key));
            }
        }
        if who == self.told.0 {
            return Ok(());
        }
        let hosts = Hosts::new(keys.iter().map(|(user, key)| Host::new(&me, user, key)).collect());
        self.told = (who, hosts);
        self.heard.clear();
        for peer in self.connected() {
            self.tell(peer);
        }
        Ok(())
    }

    /// Tell a member what this node hosts.
    fn tell(&mut self, peer: PeerId) {
        let hosts = self.told.1.clone();
        let request = self.swarm.behaviour_mut().hosts.send_request(&peer, hosts.clone());
        self.telling.insert(request, (peer, hosts));
    }

    /// Take in what a member says it hosts: those of the users served here,
    /// and of the mesh's other users, whose devices, as certified here,
    /// signed for it. Of the others, only what's shared with them is its.
    fn heard_hosts(&mut self, peer: PeerId, hosts: &Hosts) -> Result<()> {
        let locals = self.locals()?;
        let mut users = std::collections::BTreeSet::new();
        for host in hosts.hosts() {
            let Some((user, device)) = host.verify(&peer) else {
                continue;
            };
            let certified = if let Some(local) = locals.iter().find(|local| local.user.as_ref() == Some(&user)) {
                self.catalog.viewing(local.uid, |catalog| catalog.claims().map_or(Ok(false), |claims| claims.authorized(&device)))??
            } else {
                let recognized = self.granted.as_ref().is_some_and(|(_, state)| state.holds(&user, crate::grants::USER));
                recognized && self.catalog.claims().map_or(Ok(false), |claims| claims.authorizes(&user, &device))?
            };
            // A client acts for its account's user alone
            let client = self.clients.get(&peer).map(|&uid| locals.iter().any(|local| local.uid == uid && local.user.as_ref() == Some(&user)));
            if certified && client.is_none_or(|ok| ok) {
                users.insert(user.to_bytes());
            }
        }
        self.hosting.insert(peer, Hosting::Users(users));
        Ok(())
    }

    /// A member knows what this hosts: go on with what's waiting on it.
    fn heard_by(&mut self, peer: PeerId) -> Result<()> {
        self.heard.insert(peer);
        unless_busy(self.announce_to(peer), "telling a member what's here")?;
        self.redrive()
    }

    fn on_hosts(&mut self, event: request_response::Event<Hosts, Hosts>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                self.heard_hosts(peer, &request)?;
                self.tell_hosts()?;
                // The asker may be gone already
                let _ = self.swarm.behaviour_mut().hosts.send_response(channel, self.told.1.clone());
                if self.heard.contains(&peer) {
                    unless_busy(self.announce_to(peer), "telling a member what's here")?;
                }
            },
            request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some((_, told)) = self.telling.remove(&request_id) {
                    self.heard_hosts(peer, &response)?;
                    // Told what this hosted before isn't knowing it now
                    if told == self.told.1 {
                        self.heard_by(peer)?;
                    }
                }
            },
            request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
                let Some(_) = self.telling.remove(&request_id) else {
                    return Ok(());
                };
                if matches!(error, request_response::OutboundFailure::UnsupportedProtocols) {
                    self.hosting.insert(peer, Hosting::Older);
                    self.heard_by(peer)?;
                } else {
                    // Told again on the next announce
                    self.redrive()?;
                }
            },
            _ => {},
        }
        Ok(())
    }

    /// Notice each connected member of structure which arrived since it
    /// was last noticed, unless it's still to answer the last, and ask
    /// each the time.
    pub fn announce(&mut self) -> Result<()> {
        self.measure_clocks();
        // A device revoked since is a client no more
        self.reload_clients()?;
        self.tell_hosts()?;
        let telling: HashSet<PeerId> = self.telling.values().map(|(peer, _)| *peer).collect();
        for peer in self.connected() {
            if self.heard.contains(&peer) {
                self.announce_to(peer)?;
            } else if !telling.contains(&peer) {
                self.tell(peer);
            }
        }
        Ok(())
    }

    /// Notice each connected member of what's arrived, if anything's been
    /// written since this last looked, by this process or another, such
    /// as a mount committing: soon, rather than at the next announce.
    pub fn announce_written(&mut self) -> Result<()> {
        let generation = self.catalog.generation()?;
        if generation == self.noticed {
            return Ok(());
        }
        self.noticed = generation;
        for peer in self.connected() {
            self.announce_to(peer)?;
        }
        Ok(())
    }

    /// Notice a member of what's arrived, of each account whose user it
    /// hosts, once it knows what this node hosts.
    fn announce_to(&mut self, peer: PeerId) -> Result<()> {
        if !self.heard.contains(&peer) {
            return Ok(());
        }
        for local in self.locals()? {
            if self.hosts(&peer, &local) {
                self.announce_as(peer, &local)?;
            }
        }
        self.announce_guests(peer)
    }

    /// The cursor a member's noticed from for an account: the catalog's
    /// own, as before there were others, or another's of its own.
    fn cursor_of(&self, uid: u32) -> Option<u32> {
        (uid != self.catalog.uid()).then_some(uid)
    }

    fn announce_as(&mut self, peer: PeerId, local: &Local) -> Result<()> {
        if self.noticing.contains(&(peer, local.uid)) {
            return Ok(());
        }
        let account = self.cursor_of(local.uid);
        let mut cursor = self.cursors.get(&peer, account)?;
        loop {
            let (arrived, latest) = self.catalog.structure_since(cursor, structure::BATCH)?;
            if latest == cursor {
                return Ok(());
            }
            // Fewer than a batch arrived, so they make one notice at most
            let notice = self.catalog.viewing(local.uid, |catalog| structure::notices(catalog, &arrived))??.into_iter().next();
            if let Some(notice) = notice {
                let request = self.swarm.behaviour_mut().notices.send_request(&peer, notice.for_user(local.user_bytes().as_deref()));
                self.notices.insert(request, (peer, local.uid, Some(latest)));
                self.noticing.insert((peer, local.uid));
                return Ok(());
            }
            // Nothing that links anywhere
            self.cursors.set(&peer, account, latest)?;
            cursor = latest;
        }
    }

    /// Notice a member of the structure here linking to blocks of an
    /// account's it's been sent.
    fn notice_backrefs(&mut self, peer: PeerId, keys: &[Vec<u8>], local: &Local) -> Result<()> {
        let notices = self.catalog.viewing(local.uid, |catalog| {
            let linking = structure::backrefs(catalog, keys.iter().map(Vec::as_slice))?;
            structure::notices(catalog, &linking)
        })??;
        for notice in notices {
            let request = self.swarm.behaviour_mut().notices.send_request(&peer, notice.for_user(local.user_bytes().as_deref()));
            self.notices.insert(request, (peer, local.uid, None));
        }
        Ok(())
    }

    fn on_notice(&mut self, event: request_response::Event<Notice, Wants>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let wants = if request.is_guest() {
                    match self.hosting_guest(&peer, request.user())? {
                        Some(local) => self.catalog.viewing(local.uid, |catalog| structure::answer_guest(catalog, &request))??,
                        None => Wants::default(),
                    }
                } else {
                    match self.serving(&peer, request.user())? {
                        Some(local) => self.catalog.viewing(local.uid, |catalog| structure::answer(catalog, &request))??,
                        None => Wants::default(),
                    }
                };
                // The noticer may be gone already
                let _ = self.swarm.behaviour_mut().notices.send_response(channel, wants);
            },
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some((peer, guest, cids)) = self.guest_notices.remove(&request_id) {
                    for push in self.catalog.as_guest(&guest, |catalog| structure::guest_pushes(catalog, &response))?? {
                        let request = self.swarm.behaviour_mut().push.send_request(&peer, push.for_user(Some(&guest.to_bytes())));
                        self.guest_pushes.insert(request);
                    }
                    self.guests_noticed.entry((peer, guest.to_bytes())).or_default().extend(cids);
                    return Ok(());
                }
                let Some((peer, uid, cursor)) = self.notices.remove(&request_id) else {
                    return Ok(());
                };
                let local = self.local(uid)?;
                for push in self.catalog.viewing(uid, |catalog| structure::pushes(catalog, &response))?? {
                    let request = self.swarm.behaviour_mut().push.send_request(&peer, push.for_user(local.user_bytes().as_deref()));
                    self.pushed.insert(request, uid);
                }
                if let Some(cursor) = cursor {
                    self.cursors.set(&peer, self.cursor_of(uid), cursor)?;
                    self.noticing.remove(&(peer, uid));
                    self.announce_as(peer, &local)?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                // Noticed again, later
                self.guest_notices.remove(&request_id);
                if let Some((peer, uid, Some(_))) = self.notices.remove(&request_id) {
                    self.noticing.remove(&(peer, uid));
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
        keys.extend(self.reported_lost_here()?);
        keys.extend(self.catalog.sample(Trickle::sample_size(self.catalog.block_count()?))?);
        // Before it starts, since one with nothing to ask finishes at once
        self.trickling = Some((self.next_audit, more));
        self.audit_of_keys(copies, keys).map(Some)
    }

    /// No longer take a peer for a member, as one that won't be back: it
    /// holds up nothing now, and isn't believed to hold anything. One that's
    /// connected is plainly there. A client is no longer let in.
    /// Take a member to be reached at these addresses too, as told by
    /// someone who knows, since a member behind no NAT, such as a relay,
    /// can't say where it is to members it can't reach: dialling it now
    /// if it isn't connected, and telling every member connected, so
    /// they know too.
    pub fn reach_member(&mut self, peer: &PeerId, addrs: &[Multiaddr]) -> Result<()> {
        if !self.members.contains(peer)? {
            return Err(Error::Invalid(format!("{peer} isn't a member")));
        }
        for addr in addrs {
            self.members.add_addr(peer, addr)?;
            self.swarm.behaviour_mut().kad.add_address(peer, addr.clone());
        }
        self.redial.reset(peer);
        self.dial_members()?;
        let roster = self.roster()?;
        for member in self.connected() {
            if !self.is_client(&member) && member != *peer {
                self.swarm.behaviour_mut().members.send_request(&member, roster.clone());
            }
        }
        Ok(())
    }

    pub fn forget_member(&mut self, peer: &PeerId) -> Result<()> {
        if self.granted_clients().is_some_and(|clients| clients.contains(peer)) {
            return Err(Error::Invalid(format!("the mesh's grants say {peer} is a client: take that away with `hk node grant rm {peer} /mesh/client`")));
        }
        // A client's shut out at once, connected or not
        if self.members.remove_client(peer)? {
            return self.reload_clients();
        }
        if self.connected().contains(peer) {
            return Err(Error::Invalid(format!("{peer} is connected")));
        }
        if self.machines().is_some_and(|machines| machines.contains(peer)) {
            return Err(Error::Invalid(format!("the mesh's grants say {peer} is one of its machines: take that away with `hk node grant rm {peer} /mesh/machine`")));
        }
        if !self.members.forget(peer)? {
            return Err(Error::Invalid(format!("{peer} isn't a member")));
        }
        self.sightings.forget_peer(peer)?;
        self.swarm.behaviour_mut().allowed.disallow_peer(*peer);
        Ok(())
    }

    /// Look for what's gone without being let go of, and report what no
    /// member has, once they've been asked: see `Catalog::lost_candidates`.
    /// With a member away, it could be with them, so this waits for next time.
    pub fn scan_lost(&mut self) -> Result<()> {
        if self.lost_scan.is_some() {
            return Ok(());
        }
        let candidates = self.catalog.lost_candidates()?;
        if candidates.is_empty() {
            return Ok(());
        }
        let me = self.peer_id();
        let members: Vec<PeerId> = self.members.list()?.into_keys().filter(|peer| *peer != me).collect();
        if members.is_empty() {
            return self.report_lost(&candidates);
        }
        let connected = self.connected();
        let away = members.iter().filter(|peer| !connected.contains(peer)).count();
        if away > 0 {
            eprintln!("{} blocks may be lost, or with the {away} members away", candidates.len());
            return Ok(());
        }
        self.lost_scan = Some(self.fetch_blocks(candidates)?);
        Ok(())
    }

    fn report_lost(&mut self, blocks: &[Link]) -> Result<()> {
        let mut reported = 0usize;
        self.catalog.batch(|catalog| {
            for cid in blocks {
                if catalog.report_lost(cid)?.is_some() {
                    reported = reported.saturating_add(1);
                }
            }
            Ok::<_, crate::store::Error>(())
        })?;
        if reported > 0 {
            eprintln!("reported {reported} blocks lost, which no member has");
        }
        Ok(())
    }

    /// What's newly reported lost that's here after all, to audit: if it's
    /// short of copies, as what's reported lost by another surely is, it's
    /// then copied to someone, so that's the end of it.
    fn reported_lost_here(&mut self) -> Result<Vec<Multihash>> {
        let Some(claims) = self.catalog.claims() else {
            return Ok(Vec::new());
        };
        let (mut keys, latest) = claims.lost_since(self.lost_cursor, durability::FRESH)?;
        self.lost_cursor = latest;
        keys.retain(|key| self.catalog.has(key.as_ref()).unwrap_or(false));
        Ok(keys)
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

    /// Keep the repo's space as the watermarks say: free space between
    /// them, and what's stored under the target, if there is one.
    pub const fn set_watermarks(&mut self, marks: Watermarks) {
        self.marks = marks;
    }

    /// Whether the repo's short of space and should trim, by the
    /// watermarks: from below the low until above the high, or from past
    /// the target until a tenth under it.
    pub fn pressed(&mut self) -> Result<bool> {
        let free = self.catalog.offer()?.free;
        let used = if self.marks.target.is_some() { self.catalog.stored()? } else { 0 };
        Ok(self.marks.update(free, used))
    }

    pub const fn watermarks(&self) -> Watermarks {
        self.marks
    }

    pub fn trimming(&self) -> bool {
        !self.trims.is_empty()
    }

    /// Let go of what the mesh can spare of these blocks' copies here, and,
    /// `hand_off`, of whatever members with room take copies of first. It's
    /// done when `next` returns `Trimmed` with the id.
    pub fn trim(&mut self, copies: usize, keys: &[Multihash], hand_off: bool) -> Result<TrimId> {
        self.tell_hosts()?;
        let group = self.next_trim;
        self.next_trim = group.wrapping_add(1);
        let mut parts = std::collections::BTreeSet::new();
        // Each account's, among the members hosting its user
        let mut trims = Vec::new();
        for local in self.locals()? {
            let id = self.next_trim;
            self.next_trim = id.wrapping_add(1);
            let peers = self.machines_for(&local);
            let (mut trim, intents) = self.catalog.viewing(local.uid, |catalog| Trim::start(catalog, &self.sightings, &peers, copies, hand_off, keys.iter().cloned()))??;
            for intent in intents {
                let intent = intent.for_user(local.user_bytes().as_deref());
                for peer in &peers {
                    let request = self.swarm.behaviour_mut().trim.send_request(peer, intent.clone());
                    trim.sent(request);
                }
            }
            trims.push((id, local.uid, trim));
            parts.insert(id);
        }
        self.trim_groups.insert(group, Group { parts, report: trim::Report::default() });
        for (id, uid, trim) in trims {
            self.trims.insert(id, (uid, trim));
            self.drive_trim(id)?;
        }
        self.trim_part_done(group, None);
        Ok(group)
    }

    /// A part of a trim group finished, if any did: once every part has,
    /// the group has.
    fn trim_part_done(&mut self, group_or_part: TrimId, done: Option<trim::Report>) {
        let found = match done {
            Some(_) => self.trim_groups.iter().find(|(_, group)| group.parts.contains(&group_or_part)).map(|(&id, _)| id),
            None => Some(group_or_part),
        };
        let Some(id) = found else {
            return;
        };
        let Some(group) = self.trim_groups.get_mut(&id) else {
            return;
        };
        if let Some(report) = done {
            group.parts.remove(&group_or_part);
            group.report.considered = group.report.considered.saturating_add(report.considered);
            group.report.dropped = group.report.dropped.saturating_add(report.dropped);
            group.report.handed = group.report.handed.saturating_add(report.handed);
            group.report.freed = group.report.freed.saturating_add(report.freed);
        }
        if group.parts.is_empty()
            && let Some(group) = self.trim_groups.remove(&id)
        {
            self.ready.push_back(Event::Trimmed { id, report: group.report });
        }
    }

    /// Under pressure, let go of a sample of what's here, handing off what
    /// isn't spare; or, when asked, of whatever's spare of everything.
    pub fn trim_some(&mut self, copies: usize, all: bool) -> Result<TrimId> {
        let keys = if all { self.catalog.keys()? } else { self.catalog.sample(trim::BATCH)? };
        self.trim(copies, &keys, !all)
    }

    /// Once every member's answered a trim's intent, let go of what can go
    /// and hand off what's to be; once members have answered for that, let
    /// go of what they kept, and finish.
    fn drive_trim(&mut self, id: TrimId) -> Result<()> {
        let Some(&(uid, _)) = self.trims.get(&id) else {
            return Ok(());
        };
        let user = self.local(uid)?.user_bytes();
        let Some((_, trim)) = self.trims.get_mut(&id) else {
            return Ok(());
        };
        if trim.waiting() {
            return Ok(());
        }
        if !trim.decided() {
            let (now, hand) = self.catalog.viewing(uid, |catalog| trim.decide(catalog))??;
            let pushes = self.catalog.viewing(uid, |catalog| -> Result<Vec<(PeerId, Push)>> {
                let mut pushes = Vec::new();
                for (peer, keys) in hand {
                    let mut blocks = Vec::new();
                    for key in &keys {
                        blocks.extend(catalog.read_block(key.as_ref())?);
                    }
                    pushes.extend(Push::batches(catalog, blocks)?.into_iter().map(|push| (peer, push)));
                }
                Ok(pushes)
            })??;
            for (peer, push) in pushes {
                let request = self.swarm.behaviour_mut().push.send_request(&peer, push.for_user(user.as_deref()));
                trim.sent_push(request);
                self.pushed.insert(request, uid);
            }
            self.trimmed(id, &now, false)?;
            if self.trims.get(&id).is_some_and(|(_, trim)| trim.waiting()) {
                return Ok(());
            }
        }
        let handed = self.trims.get(&id).map(|(_, trim)| trim.handed()).unwrap_or_default();
        self.trimmed(id, &handed, true)?;
        if let Some((_, trim)) = self.trims.remove(&id) {
            self.trim_part_done(id, Some(trim.report()));
        }
        Ok(())
    }

    /// Let go of the copies here of what a trim says can go, and tell the
    /// members.
    fn trimmed(&mut self, id: TrimId, keys: &[Multihash], handed: bool) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let dropping = self.catalog.drop_all(keys)?;
        for key in &dropping.dropped {
            if !self.catalog.has(key.as_ref())? {
                self.sightings.forget(key.as_ref())?;
            }
        }
        let gone = dropping.dropped;
        if let Some((_, trim)) = self.trims.get_mut(&id) {
            trim.dropped(gone.len(), if handed { gone.len() } else { 0 }, dropping.freed);
        }
        if !gone.is_empty() {
            let dropped = trim::dropped(&gone);
            for peer in self.connected() {
                self.swarm.behaviour_mut().dropped.send_request(&peer, dropped.clone());
            }
        }
        Ok(())
    }

    fn on_trim(&mut self, event: request_response::Event<Intent, Grant>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let me = self.peer_id();
                let mut grant = match self.serving(&peer, request.user())? {
                    Some(local) => {
                        let mut trims: Vec<&mut Trim> = self.trims.values_mut().map(|(_, trim)| trim).collect();
                        self.catalog.viewing(local.uid, |catalog| trim::answer(catalog, &me, &peer, &request, &mut trims, &self.marks))??
                    },
                    None => Grant::default(),
                };
                // Copies about to be collected aren't worth trimming others for
                grant.withhold(|key| <Multihash>::decode(key).is_ok_and(|key| self.condemned.is_condemned(key.as_ref()).unwrap_or(true)));
                // The asker may be gone already
                let _ = self.swarm.behaviour_mut().trim.send_response(channel, grant);
            },
            request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some((&id, (_, trim))) = self.trims.iter_mut().find(|(_, (_, trim))| trim.asked(request_id)) {
                    trim.granted(request_id, peer, response);
                    self.drive_trim(id)?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some((&id, (_, trim))) = self.trims.iter_mut().find(|(_, (_, trim))| trim.asked(request_id)) {
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
            if asking.contains(&peer) || self.is_client(&peer) {
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
                // Kept by any account here is kept
                let mut verdict = Verdict::default();
                for uid in self.accounts() {
                    verdict.join(self.catalog.viewing(uid, |catalog| collect::answer(catalog, &request))??);
                }
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

    /// Audit these blocks: each account's, among the members hosting its
    /// user, as one.
    fn audit_of_keys(&mut self, copies: usize, mut keys: Vec<Multihash>) -> Result<AuditId> {
        // What's to be collected isn't worth more copies
        keys.retain(|key| !self.condemned.is_condemned(key.as_ref()).unwrap_or(false));
        self.tell_hosts()?;
        let group = self.next_audit;
        self.next_audit = group.wrapping_add(1);
        let me = self.peer_id();
        let mut audits = Vec::new();
        for local in self.locals()? {
            // Nor is another account's this one's to copy
            let theirs: Vec<Multihash> = self.catalog.viewing(local.uid, |catalog| keys.iter().filter(|key| catalog.visible(key.as_ref()).unwrap_or(false)).cloned().collect())?;
            let id = self.next_audit;
            self.next_audit = id.wrapping_add(1);
            let peers = self.machines_for(&local);
            let (mut audit, adverts) = self.catalog.viewing(local.uid, |catalog| Audit::start(catalog, &self.sightings, (me, self.client_of.is_none()), &peers, copies, theirs))??;
            for advert in adverts {
                let advert = advert.for_user(local.user_bytes().as_deref());
                for &peer in &peers {
                    let request = self.swarm.behaviour_mut().adverts.send_request(&peer, advert.clone());
                    audit.sent_advert(request, peer, &advert);
                }
            }
            audits.push((id, local.uid, audit));
        }
        self.audit_groups.insert(group, Group { parts: audits.iter().map(|(id, ..)| *id).collect(), report: Report::default() });
        for (id, uid, audit) in audits {
            self.audits.insert(id, (uid, audit));
            self.drive_audit(id)?;
        }
        self.audit_part_done(group, None);
        Ok(group)
    }

    /// A part of an audit group finished, if any did: once every part has,
    /// the group has.
    fn audit_part_done(&mut self, group_or_part: AuditId, done: Option<Report>) {
        let found = match done {
            Some(_) => self.audit_groups.iter().find(|(_, group)| group.parts.contains(&group_or_part)).map(|(&id, _)| id),
            None => Some(group_or_part),
        };
        let Some(id) = found else {
            return;
        };
        let Some(group) = self.audit_groups.get_mut(&id) else {
            return;
        };
        if let Some(report) = done {
            group.parts.remove(&group_or_part);
            group.report.advertised = group.report.advertised.saturating_add(report.advertised);
            group.report.copied = group.report.copied.saturating_add(report.copied);
            group.report.short = group.report.short.saturating_add(report.short);
        }
        if group.parts.is_empty()
            && let Some(group) = self.audit_groups.remove(&id)
        {
            let report = group.report;
            if let Some((trickled, more)) = self.trickling
                && trickled == id
            {
                self.trickle.observe(&report, more);
                self.trickling = None;
            }
            self.ready.push_back(Event::Audited { id, report });
        }
    }

    /// Send what an audit has to push, once it's heard back, or finish it.
    fn drive_audit(&mut self, id: AuditId) -> Result<()> {
        let Some(&(uid, _)) = self.audits.get(&id) else {
            return Ok(());
        };
        let user = self.local(uid)?.user_bytes();
        let Some((_, audit)) = self.audits.get_mut(&id) else {
            return Ok(());
        };
        if audit.waiting() {
            return Ok(());
        }
        if let Some(pushes) = self.catalog.viewing(uid, |catalog| audit.decide(catalog))?? {
            for (peer, push, keys) in pushes {
                let request = self.swarm.behaviour_mut().push.send_request(&peer, push.for_user(user.as_deref()));
                audit.sent_push(request, peer, keys);
                self.pushed.insert(request, uid);
            }
        } else {
            let report = audit.report();
            self.audits.remove(&id);
            self.audit_part_done(id, Some(report));
        }
        Ok(())
    }

    fn on_advert(&mut self, event: request_response::Event<Advert, Haves>) -> Result<()> {
        match event {
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } if self.check_of(request_id).is_some() => {
                if let Some(id) = self.check_of(request_id)
                    && let Some(check) = self.checks.get_mut(&id)
                {
                    unless_busy(check.answered(&self.catalog, &self.sightings, request_id, response), "noting what a member has")?;
                    self.finish_check(id);
                }
                return Ok(());
            },
            request_response::Event::OutboundFailure { request_id, .. } if self.check_of(request_id).is_some() => {
                if let Some(id) = self.check_of(request_id)
                    && let Some(check) = self.checks.get_mut(&id)
                {
                    check.failed(request_id);
                    self.finish_check(id);
                }
                return Ok(());
            },
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let haves = match self.serving(&peer, request.user())? {
                    Some(local) => self.catalog.viewing(local.uid, |catalog| durability::answer_advert(catalog, &self.sightings, &peer, &request, &self.marks))??,
                    None => Haves::default(),
                };
                // The advertiser may be gone already
                let _ = self.swarm.behaviour_mut().adverts.send_response(channel, haves);
                return Ok(());
            },
            request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some((_, audit)) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
                    unless_busy(audit.haves(&self.sightings, request_id, response), "noting what a member has")?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some((_, audit)) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
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
                if let Some(key) = self.visitors.get(&peer).cloned() {
                    return self.on_visitor_push(&key, request, channel);
                }
                if request.is_guest() {
                    let Some(local) = self.hosting_guest(&peer, request.user())? else {
                        let _ = self.swarm.behaviour_mut().push.send_response(channel, Kept::default());
                        return Ok(());
                    };
                    let (kept, claims) = self.catalog.viewing(local.uid, |catalog| durability::answer_guest_push(catalog, request))??;
                    let _ = self.swarm.behaviour_mut().push.send_response(channel, kept);
                    return self.took_guest_claims(&local, &claims);
                }
                let size = request.size();
                let kept = match self.serving(&peer, request.user())? {
                    Some(local) => self.catalog.viewing(local.uid, |catalog| durability::answer_push(catalog, &self.sightings, &peer, request, &self.marks))??,
                    None => Kept::default(),
                };
                // Counted against the target till it's measured again
                if !kept.is_empty() {
                    self.marks.took(size);
                }
                let _ = self.swarm.behaviour_mut().push.send_response(channel, kept);
                return Ok(());
            },
            request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response }, .. } => {
                // What links to what's pushed goes after it, copies or
                // not: claims about it may have been noticed before it
                // was there to want them for
                if self.guest_pushes.remove(&request_id) {
                    return Ok(());
                }
                let kept = response.keys();
                let uid = self.pushed.remove(&request_id);
                let handed = self.trims.iter().find(|(_, (_, trim))| trim.pushed(request_id)).map(|(&id, _)| id);
                if let Some((_, trim)) = handed.and_then(|id| self.trims.get_mut(&id)) {
                    trim.kept(request_id, peer, &response);
                    response.sight(&self.catalog, &self.sightings, &peer)?;
                } else if let Some((_, audit)) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
                    unless_busy(audit.kept(&self.sightings, request_id, response), "noting what a member kept")?;
                } else {
                    response.sight(&self.catalog, &self.sightings, &peer)?;
                }
                if let Some(uid) = uid {
                    let local = self.local(uid)?;
                    self.notice_backrefs(peer, &kept, &local)?;
                }
                if let Some(id) = handed {
                    self.drive_trim(id)?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                self.pushed.remove(&request_id);
                self.guest_pushes.remove(&request_id);
                let handed = self.trims.iter().find(|(_, (_, trim))| trim.pushed(request_id)).map(|(&id, _)| id);
                if let Some((_, trim)) = handed.and_then(|id| self.trims.get_mut(&id)) {
                    trim.push_failed(request_id);
                } else if let Some((_, audit)) = self.audit_of(request_id).and_then(|id| self.audits.get_mut(&id)) {
                    audit.push_failed(request_id);
                }
                if let Some(id) = handed {
                    self.drive_trim(id)?;
                }
            },
            _ => return Ok(()),
        }
        self.drive_audits()
    }

    /// Find which members hold these blocks of the catalog's own account:
    /// those sighted, and, as `asking` says, what connected members hosting
    /// its user answer. It's done when `next` returns `Checked` with the id.
    pub fn check(&mut self, keys: &[Multihash], asking: Asking) -> Result<CheckId> {
        let local = self.local(self.catalog.uid())?;
        let members = self.machines_for(&local);
        let user = local.user_bytes();
        let (mut check, adverts) = Check::start(&self.catalog, &self.sightings, self.client_of.is_none(), &members, keys, asking)?;
        for (peer, advert) in adverts {
            let advert = advert.for_user(user.as_deref());
            let request = self.swarm.behaviour_mut().adverts.send_request(&peer, advert.clone());
            check.sent(request, peer, &advert);
        }
        let id = self.next_check;
        self.next_check = id.wrapping_add(1);
        self.checks.insert(id, check);
        self.finish_check(id);
        Ok(id)
    }

    /// Finish a check, if it's heard back from everyone asked.
    fn finish_check(&mut self, id: CheckId) {
        if self.checks.get(&id).is_some_and(Check::done)
            && let Some(check) = self.checks.remove(&id)
        {
            self.ready.push_back(Event::Checked { id, known: check.known() });
        }
    }

    /// The check which sent an advert.
    fn check_of(&self, request: request_response::OutboundRequestId) -> Option<CheckId> {
        self.checks.iter().find(|(_, check)| check.asked(request)).map(|(&id, _)| id)
    }

    /// Whether this node's copies count, as a member's do, and a client's
    /// don't.
    pub const fn copies_count(&self) -> bool {
        self.client_of.is_none()
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
        self.audits.iter().find(|(_, (_, audit))| audit.asked(request)).map(|(&id, _)| id)
    }

    /// Fetch the DAG under a root from other members, keeping what's
    /// fetched. It's done when `next` returns `Fetched` with the id.
    pub fn fetch(&mut self, root: Link) -> Result<FetchId> {
        self.fetch_for(self.catalog.uid(), root)
    }

    /// Fetch the DAG under a root for one of the accounts served, from the
    /// members hosting its user, as `fetch` does.
    pub fn fetch_for(&mut self, uid: u32, root: Link) -> Result<FetchId> {
        self.start_fetch(uid, Fetch::new(root))
    }

    /// Fetch just these blocks from other members, not what they link
    /// to. It's done when `next` returns `Fetched` with the id.
    pub fn fetch_blocks(&mut self, blocks: Vec<Link>) -> Result<FetchId> {
        self.fetch_blocks_for(self.catalog.uid(), blocks)
    }

    /// Fetch just these blocks for one of the accounts served.
    pub fn fetch_blocks_for(&mut self, uid: u32, blocks: Vec<Link>) -> Result<FetchId> {
        self.start_fetch(uid, Fetch::blocks(blocks))
    }

    /// Claims a guest's machine pushed: what a set of theirs for an
    /// account's user's own view is, is fetched, from them if need be, as
    /// it counts in the user's view, and so is theirs to keep.
    fn took_guest_claims(&mut self, local: &Local, claims: &[crate::claim::Claim]) -> Result<()> {
        let Some(user) = &local.user else {
            return Ok(());
        };
        for claim in claims {
            if let crate::claim::Claim::Set(set) = claim
                && set.owner() == Some(user)
                && !self.catalog.has(set.value().multihash())?
            {
                self.fetch_for(local.uid, set.value().clone())?;
            }
        }
        Ok(())
    }

    fn start_fetch(&mut self, uid: u32, fetch: Fetch) -> Result<FetchId> {
        self.tell_hosts()?;
        let uid = if self.accounts().contains(&uid) { uid } else { self.catalog.uid() };
        let id = self.next_fetch;
        self.next_fetch = id.wrapping_add(1);
        self.fetches.insert(id, (uid, fetch));
        self.drive(id)?;
        Ok(id)
    }

    /// Send what a fetch has to ask, or finish it.
    fn drive(&mut self, id: FetchId) -> Result<()> {
        // A member yet to say what it hosts may host whose this is
        if !self.telling.is_empty() {
            return Ok(());
        }
        let Some(&(uid, _)) = self.fetches.get(&id) else {
            return Ok(());
        };
        let local = self.local(uid)?;
        let peers = self.fetch_peers(&local)?;
        let user = local.user_bytes();
        let Some((_, fetch)) = self.fetches.get_mut(&id) else {
            return Ok(());
        };
        for (peer, batch) in self.catalog.viewing(uid, |catalog| fetch.plan(catalog, &peers))?? {
            let request = self.swarm.behaviour_mut().blocks.send_request(&peer, Fetch::want(&batch).for_user(user.as_deref()));
            fetch.sent(request, batch);
        }
        if fetch.done()
            && let Some((_, fetch)) = self.fetches.remove(&id)
        {
            let (fetched, missing) = fetch.outcome();
            if self.lost_scan == Some(id) {
                self.lost_scan = None;
                // What couldn't be written now, the next scan finds
                match self.report_lost(&missing) {
                    Err(e) if e.is_busy() => eprintln!("reporting what's lost: {e}"),
                    done => done?,
                }
            }
            // What a client asked waits on it, which isn't the daemon's
            if !self.fetched_for_ask(id)? {
                self.ready.push_back(Event::Fetched { id, fetched, missing });
            }
        }
        Ok(())
    }

    /// The fetch which sent a want.
    fn fetch_of(&self, request: request_response::OutboundRequestId) -> Option<FetchId> {
        self.fetches.iter().find(|(_, (_, fetch))| fetch.asked(request)).map(|(&id, _)| id)
    }

    /// Work the grants out again if what one gave till a time has gone
    /// since: who's let in, and what they may see, with it.
    pub fn expire(&mut self) -> Result<()> {
        if self.granted.as_ref().and_then(|(_, state)| state.next_expiry()).is_some_and(|until| until <= now_secs()) {
            self.reload()?;
        }
        Ok(())
    }

    /// Let what's expired go (see `expire`), and publish again what's
    /// changed of what's published (see `keep_published`).
    pub fn tend(&mut self, repo: &std::path::Path) -> Result<()> {
        self.expire()?;
        self.keep_published(repo).map(drop)
    }

    /// Publish again each anchor this account's vault keeps published
    /// whose value's changed since (see `crate::cap`): only what's changed
    /// is sealed, so one that hasn't costs a look. What isn't all here yet
    /// waits. Returns how many were published.
    pub fn keep_published(&mut self, repo: &std::path::Path) -> Result<usize> {
        // A protected mesh's node acts for a vault, which publishes nothing
        // of its own: what it publishes is its account's, from theirs
        if crate::vault::is_vault(self.catalog.uid()) {
            return Ok(0);
        }
        let busy = |e: crate::cap::Error| match e {
            crate::cap::Error::Store(e) => Error::Store(e),
            crate::cap::Error::Io(e) => Error::Io(e),
            e => Error::Invalid(e.to_string()),
        };
        let vault = crate::vault::Vault::open(repo, self.catalog.uid()).map_err(|e| Error::Invalid(e.to_string()))?;
        let mut done = 0usize;
        // What writers wrote first, to publish with the rest
        for taken in crate::cap::take_in(&mut self.catalog, &vault).map_err(busy)? {
            eprintln!("took in what a writer wrote of {}, {}", taken.anchor, taken.set);
        }
        for (anchor, _) in crate::cap::published(&mut self.catalog, &vault).map_err(busy)? {
            let Some(value) = self.catalog.anchor_value(&anchor)? else {
                continue;
            };
            match crate::cap::publish_mounted(&mut self.catalog, &vault, &anchor, &value) {
                Ok(publications) => {
                    for (anchor, publication) in publications.iter().filter(|(_, publication)| publication.fresh) {
                        eprintln!("published {anchor} again, its head {}", publication.set);
                        done = done.saturating_add(1);
                    }
                },
                Err(crate::cap::Error::Store(e)) if e.is_busy() => return Err(Error::Store(e)),
                Err(e) => eprintln!("{anchor} isn't published as it is yet: {e}"),
            }
        }
        Ok(done)
    }

    /// Ask each member connected for the time, to measure how far its
    /// clock is from this machine's (see `clock`), unless it's still to
    /// answer the last ask.
    pub fn measure_clocks(&mut self) {
        let asking: HashSet<PeerId> = self.clocking.values().map(|(peer, _)| *peer).collect();
        for peer in self.connected().into_iter().filter(|peer| !self.clients.contains_key(peer) && !asking.contains(peer)) {
            let id = self.swarm.behaviour_mut().clock.send_request(&peer, clock::Asked::default());
            self.clocking.insert(id, (peer, clock::now()));
        }
    }

    /// What's been measured of members' clocks.
    pub const fn clocks(&self) -> &Clocks {
        &self.clocks
    }

    /// Answer an ask for the time, or take in an answer: saying so if
    /// this machine's clock has gone far from the mesh's, or come back.
    fn on_clock(&mut self, event: request_response::Event<clock::Asked, Told>) -> Option<Event> {
        match event {
            request_response::Event::Message { message: request_response::Message::Request { channel, .. }, .. } => {
                let got = clock::now();
                let _ = self.swarm.behaviour_mut().clock.send_response(channel, Told { got, sent: clock::now() });
                None
            },
            request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response }, .. } => {
                let heard = clock::now();
                let (asked_of, asked) = self.clocking.remove(&request_id)?;
                if asked_of != peer {
                    return None;
                }
                self.clocks.record(peer, Offset::of(asked, response, heard));
                let (ahead, members) = self.clocks.mesh()?;
                let far = ahead.unsigned_abs() > clock::SKEW.unsigned_abs();
                (far != self.skewed).then(|| {
                    self.skewed = far;
                    Event::Skewed { ahead, members, far }
                })
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                self.clocking.remove(&request_id);
                None
            },
            _ => None,
        }
    }

    /// Let in every member, and learn where they listen, as of the list,
    /// and of the mesh's grants, if it has them: telling every member,
    /// if they've changed.
    pub fn reload(&mut self) -> Result<()> {
        if self.refresh_grants()? {
            for peer in self.connected() {
                self.ask_grants(peer)?;
            }
            unless_busy(self.announce(), "noticing guests of what's shared with them")?;
        }
        self.reload_allowed()
    }

    /// Let in every member, and learn where they listen.
    fn reload_allowed(&mut self) -> Result<()> {
        for (peer, addrs) in self.members.list()? {
            self.swarm.behaviour_mut().allowed.allow_peer(peer);
            for addr in addrs {
                self.swarm.behaviour_mut().kad.add_address(&peer, addr);
            }
        }
        self.reload_clients()
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.listen_on(addr).map(drop).map_err(|e| Error::Invalid(format!("listen: {e}")))
    }

    /// Listen for clients too, apart from members: see `clients`.
    pub fn listen_for_clients(&mut self, addr: Multiaddr) -> Result<()> {
        if self.client_of.is_some() {
            return Err(Error::Invalid("a client has no clients".into()));
        }
        self.ports.add(&addr);
        let id = self.swarm.listen_on(addr).map_err(|e| Error::Invalid(format!("listen: {e}")))?;
        self.client_listeners.insert(id);
        Ok(())
    }

    /// Where this listens for members, but for through relays, which
    /// members work out for themselves.
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().filter(|addr| !self.ports.contains(addr) && !is_relayed(addr)).cloned().collect()
    }

    /// Where this listens through relays.
    pub fn relayed_listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().filter(|addr| is_relayed(addr)).cloned().collect()
    }

    /// Where this listens for clients.
    pub fn client_listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().filter(|addr| self.ports.contains(addr)).cloned().collect()
    }

    /// The member this is a client of, if it's a client.
    pub const fn client_of(&self) -> Option<PeerId> {
        self.client_of
    }

    /// The members and clients connected: not visitors, who are told
    /// nothing unasked.
    pub fn connected(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().filter(|peer| !self.visitors.contains_key(peer)).collect()
    }

    /// The accounts served here, by uid, whose users a member hosts, as
    /// far as it's said.
    pub fn hosted_by(&self, peer: &PeerId) -> Result<Vec<u32>> {
        Ok(self.locals()?.into_iter().filter(|local| local.rooted && self.hosts(peer, local)).map(|local| local.uid).collect())
    }

    /// The connected members which know what this node hosts, so may be
    /// asked things.
    pub fn ready(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().filter(|peer| self.heard.contains(peer)).collect()
    }

    /// Dial every member with an address which isn't connected: where
    /// it's been, and through every relay this listens through, where it
    /// may be listening too.
    pub fn dial_members(&mut self) -> Result<()> {
        let (me, now) = (self.peer_id(), Instant::now());
        let relays: Vec<(PeerId, Multiaddr)> = self.relays.iter().map(|(relay, (_, through))| (*relay, through.clone())).collect();
        for (peer, mut addrs) in self.members.list()? {
            // Connected through a relay alone, it's dialled where it's
            // reached directly, if it can be
            if self.relayed_only(&peer) {
                addrs.retain(|addr| !is_relayed(addr));
            } else {
                addrs.extend(relays.iter().filter(|(relay, _)| *relay != peer).map(|(_, through)| through.clone().with(libp2p::multiaddr::Protocol::P2p(peer))));
            }
            if peer != me && !addrs.is_empty() && (!self.swarm.is_connected(&peer) || self.relayed_only(&peer)) && self.redial.due(&peer, now) {
                self.dial(peer, addrs);
            }
        }
        Ok(())
    }

    /// The relays this listens through.
    pub fn relays(&self) -> Vec<PeerId> {
        let mut relays: Vec<PeerId> = self.relays.keys().copied().collect();
        relays.sort();
        relays
    }

    /// Whether this relays between members.
    pub fn relaying(&self) -> bool {
        self.swarm.behaviour().relay.is_enabled()
    }

    /// Whether a peer's connected through relays and no other way.
    pub fn relayed_only(&self, peer: &PeerId) -> bool {
        self.circuits.values().any(|through| through == peer)
    }

    /// Dial a peer, unless it's connected, or connected only through a
    /// relay, where it's dialled directly regardless.
    fn dial(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) {
        use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
        self.redial.dialled(peer, Instant::now());
        let condition = if self.relayed_only(&peer) { PeerCondition::Always } else { PeerCondition::DisconnectedAndNotDialing };
        let opts = DialOpts::peer_id(peer).condition(condition).addresses(addrs).build();
        // A failed dial is reported as an event
        let _ = self.swarm.dial(opts);
    }

    /// The members this node knows of, itself as listening where it is.
    fn roster(&self) -> Result<Roster> {
        let mut members = self.members.list()?;
        members.insert(self.peer_id(), self.listeners());
        let mut clients: BTreeMap<PeerId, Vec<Multiaddr>> = self.client_addrs.iter().filter(|(peer, _)| members.contains_key(*peer)).map(|(peer, addrs)| (*peer, addrs.clone())).collect();
        if !self.client_listeners().is_empty() {
            clients.insert(self.peer_id(), self.client_listeners());
        }
        Ok(Roster::from_members(&members).with_clients(&clients))
    }

    /// Take in another member's roster, letting in and dialing whoever's
    /// new.
    fn learn(&mut self, roster: &Roster) -> Result<Vec<PeerId>> {
        let mut theirs = roster.to_members();
        theirs.remove(&self.peer_id());
        // With grants, they say who's a member; a roster only where
        if let Some(machines) = self.machines() {
            theirs.retain(|peer, _| machines.contains(peer));
        }
        let new = self.members.merge(&theirs)?;
        for (peer, addrs) in roster.to_clients() {
            if peer != self.peer_id() && self.members.contains(&peer)? {
                self.client_addrs.insert(peer, addrs);
            }
        }
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
            let (swarm, heard) = (&mut self.swarm, &mut self.services_heard);
            let event = tokio::select! {
                event = swarm.next() => event,
                Some((peer, session, message)) = heard.recv() => {
                    self.on_heard(peer, session, message);
                    continue;
                },
            };
            let Some(event) = event else {
                return Err(Error::Invalid("the swarm stopped".into()));
            };
            match self.handle(event) {
                Ok(Some(event)) => return Ok(event),
                Ok(None) => {},
                // What it was for is asked again, by this node on its next
                // `redrive`, or by whoever asked it
                Err(e) if e.is_busy() => unless_busy(Err(e), "what a member sent or said")?,
                Err(e) => return Err(e),
            }
        }
    }

    /// Go on with every fetch, audit and trim that's no longer waiting on
    /// anyone, as may be if what would have gone on with it failed. Doing
    /// so again is harmless.
    pub fn redrive(&mut self) -> Result<()> {
        let fetches: Vec<FetchId> = self.fetches.keys().copied().collect();
        for id in fetches {
            self.drive(id)?;
        }
        self.drive_audits()?;
        let trims: Vec<TrimId> = self.trims.keys().copied().collect();
        for id in trims {
            self.drive_trim(id)?;
        }
        Ok(())
    }

    /// A member's newly connected: tell it of the members, notice it of
    /// what it's missed, and vouch for its sightings from now on.
    fn on_connected(&mut self, peer: PeerId) -> Result<()> {
        self.redial.reset(&peer);
        // A visitor's told nothing: it asks for what's shared with it
        if self.visitors.contains_key(&peer) {
            return Ok(());
        }
        // A client's told of no members, and tells its member of none
        if !self.is_client(&peer) && self.client_of.is_none() {
            let roster = self.roster()?;
            self.swarm.behaviour_mut().members.send_request(&peer, roster);
        }
        // A client's told where else it may connect, and of nothing more
        if let Some(&uid) = self.clients.get(&peer) {
            let roster = Roster::default().with_clients(&self.client_roster(uid)?);
            self.swarm.behaviour_mut().members.send_request(&peer, roster);
        }
        self.ask_grants(peer)?;
        // What's here is noticed once it knows what this node hosts
        self.tell_hosts()?;
        self.tell(peer);
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
            if !self.swarm.is_connected(&peer) || self.relayed_only(&peer) {
                self.dial(peer, addrs);
            }
        }
        Ok(())
    }

    fn on_disconnected(&mut self, peer: &PeerId) {
        self.redial.reset(peer);
        self.noticing.retain(|(noticed, _)| noticed != peer);
        self.guests_noticed.retain(|(noticed, _), _| noticed != peer);
        self.hosting.remove(peer);
        self.heard.remove(peer);
        self.sightings.disconnected(peer);
        self.trickle.alarm();
    }

    /// A want asked of this node, answered as the account whose user it
    /// names, or a fetch's answered.
    fn on_blocks(&mut self, event: request_response::Event<Want, Blocks>) -> Result<()> {
        match event {
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } if self.visitors.contains_key(&peer) => {
                // A visitor reads what's shared with its key, and nothing else
                let key = self.visitors.get(&peer).cloned().ok_or_else(|| Error::Invalid("visitor gone".into()))?;
                let answer = self.catalog.as_guest(&key, |catalog| blocks::answer(catalog, &request))?.without_copies();
                let _ = self.swarm.behaviour_mut().blocks.send_response(channel, answer);
            },
            request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                let Some(local) = self.serving(&peer, request.user())? else {
                    // A guest sees what's shared with them; another account's
                    // is otherwise as good as not here
                    let answer = match self.guest_of(&peer, request.user())? {
                        Some(guest) => self.catalog.as_guest(&guest, |catalog| blocks::answer(catalog, &request))?.without_copies(),
                        None => blocks::refuse(&request),
                    };
                    let _ = self.swarm.behaviour_mut().blocks.send_response(channel, answer);
                    return Ok(());
                };
                let answer = self.catalog.viewing(local.uid, |catalog| blocks::answer(catalog, &request))?;
                let served = answer.served();
                // A client reads through this node alone: what of its user's
                // isn't here is fetched from the user's other machines, to
                // be here when it asks again
                let missing = if self.is_client(&peer) { answer.missing() } else { Vec::new() };
                // The asker may be gone already
                let _ = self.swarm.behaviour_mut().blocks.send_response(channel, answer);
                self.notice_backrefs(peer, &served, &local)?;
                if !missing.is_empty() {
                    self.fetch_blocks_for(local.uid, missing)?;
                }
            },
            request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response }, .. } => {
                if let Some(id) = self.fetch_of(request_id) {
                    let received = match self.fetches.get_mut(&id) {
                        Some((uid, fetch)) => self.catalog.viewing(*uid, |catalog| fetch.received(catalog, &self.sightings, &peer, request_id, response)).map_err(Error::from).and_then(|received| received),
                        None => Ok(()),
                    };
                    // What couldn't be kept is wanted still, and asked for
                    // again on the next `redrive`, not at once, which
                    // would only send it all over again meanwhile
                    if !received.as_ref().is_err_and(Error::is_busy) {
                        self.drive(id)?;
                    }
                    received?;
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some(id) = self.fetch_of(request_id) {
                    if let Some((_, fetch)) = self.fetches.get_mut(&id) {
                        fetch.failed(request_id);
                    }
                    self.drive(id)?;
                }
            },
            _ => {},
        }
        Ok(())
    }

    /// Where a member says it listens: where to find it again. A client
    /// listens nowhere, and is found nowhere; a client's member listens
    /// for clients on one port, where it's found again wherever it moves.
    fn on_identified(&mut self, peer: PeerId, addrs: &[Multiaddr]) -> Result<()> {
        if self.is_client(&peer) {
            return Ok(());
        }
        if self.client_of.is_some() {
            let port = self.member_ports.get(&peer).copied();
            for addr in addrs.iter().filter(|addr| port.is_some() && super::clients::port(addr) == port) {
                self.members.add_addr(&peer, addr)?;
            }
            return Ok(());
        }
        for addr in addrs {
            self.members.add_addr(&peer, addr)?;
            self.swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
        }
        Ok(())
    }

    /// A peer's identified itself: if it's a member that relays, keep a
    /// reservation on it, listening through it, unless this already does;
    /// and if this relays, take where the member saw it, at a port it
    /// listens on, as where it's reached, which is what it tells those it
    /// keeps reservations for to give out.
    fn reserve(&mut self, peer: PeerId, info: &identify::Info) {
        // Dialling a member where it said it listens can reach this node
        // itself, as at a loopback address, which isn't where it's reached
        if peer == self.peer_id() {
            return;
        }
        if self.swarm.behaviour().relay.is_enabled() && !is_loopback(&info.observed_addr) && !self.is_client(&peer) && !self.visitors.contains_key(&peer) && !is_relayed(&info.observed_addr) {
            let ports: HashSet<u64> = self.listeners().iter().filter_map(super::clients::port).collect();
            if super::clients::port(&info.observed_addr).is_some_and(|port| ports.contains(&port)) {
                self.swarm.add_external_address(info.observed_addr.clone());
            }
        }
        let relays = info.protocols.contains(&relay::HOP_PROTOCOL_NAME);
        if !relays || !self.swarm.behaviour().relayed.is_enabled() || self.relays.contains_key(&peer) || !self.members.contains(&peer).unwrap_or(false) {
            return;
        }
        // Over the connection to it, so where it's said to be reached
        // matters only once that's gone: where this dialled it, or else
        // anywhere it says it listens, but for loopback
        let listening = info.listen_addrs.iter().filter(|addr| !is_relayed(addr));
        let Some(at) = self.dialled_at.get(&peer).or_else(|| listening.clone().find(|addr| !is_loopback(addr))).or_else(|| listening.clone().next()) else {
            return;
        };
        let at = at.clone().with_p2p(peer).unwrap_or_else(|at| at).with(libp2p::multiaddr::Protocol::P2pCircuit);
        if let Ok(listener) = self.swarm.listen_on(at.clone()) {
            self.relays.insert(peer, (listener, at));
        }
    }

    /// A connection's established: if through a relay, kept track of till
    /// its peer's connected directly; if direct, its peer's circuits
    /// dropped, as no longer needed, and where it was dialled noted.
    fn through_relay(&mut self, peer: PeerId, connection: libp2p::swarm::ConnectionId, endpoint: &libp2p::core::ConnectedPoint) {
        if endpoint.is_relayed() {
            self.circuits.insert(connection, peer);
            return;
        }
        if endpoint.is_dialer() {
            self.dialled_at.insert(peer, endpoint.get_remote_address().clone());
        }
        let circuits: Vec<_> = self.circuits.iter().filter(|(_, through)| **through == peer).map(|(circuit, _)| *circuit).collect();
        for circuit in circuits {
            self.swarm.close_connection(circuit);
        }
    }

    /// A member's roster, or its answer to this one's. A client's told of
    /// no members, and can't make any.
    fn on_roster(&mut self, peer: PeerId, message: request_response::Message<Roster, Roster>) -> Result<Option<Event>> {
        Ok(match message {
            request_response::Message::Request { request, channel, .. } if self.client_of.is_some() => {
                let _ = self.swarm.behaviour_mut().members.send_response(channel, Roster::default());
                self.learn_members(&peer, &request)?;
                None
            },
            request_response::Message::Request { channel, .. } if self.is_client(&peer) => {
                let _ = self.swarm.behaviour_mut().members.send_response(channel, Roster::default());
                None
            },
            request_response::Message::Response { .. } if self.client_of.is_some() || self.is_client(&peer) => None,
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
        })
    }

    fn handle(&mut self, event: SwarmEvent<BehaviourEvent>) -> Result<Option<Event>> {
        Ok(match event {
            SwarmEvent::Behaviour(event) if self.trespasses(&event) => None,
            SwarmEvent::NewListenAddr { listener_id, address } => {
                if self.client_listeners.contains(&listener_id) {
                    self.ports.add(&address);
                }
                // Members not reached may be reached through it, at once
                if self.relays.values().any(|(relay, _)| *relay == listener_id) {
                    self.redial = Redial::default();
                }
                Some(Event::Listening(address))
            },
            SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, .. } => {
                self.through_relay(peer_id, connection_id, &endpoint);
                if endpoint.is_dialer() {
                    unless_busy(self.members.add_addr(&peer_id, endpoint.get_remote_address()), "noting a member's address")?;
                    if let (Some(_), Some(port)) = (self.client_of, super::clients::port(endpoint.get_remote_address())) {
                        self.member_ports.insert(peer_id, port);
                    }
                }
                if num_established.get() > 1 {
                    return Ok(None);
                }
                self.on_connected(peer_id)?;
                Some(Event::Connected(peer_id))
            },
            SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established, .. } => {
                self.circuits.remove(&connection_id);
                if num_established > 0 {
                    return Ok(None);
                }
                self.on_disconnected(&peer_id);
                self.sessions.gone(&peer_id);
                self.clocks.forget(&peer_id);
                Some(Event::Disconnected(peer_id))
            },
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => Some(Event::Failed(peer_id, error.to_string())),
            SwarmEvent::IncomingConnectionError { error, .. } => Some(Event::Failed(None, error.to_string())),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                self.on_identified(peer_id, &info.listen_addrs)?;
                self.reserve(peer_id, &info);
                None
            },
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                self.relays.retain(|_, (listener, _)| *listener != listener_id);
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { connection, result: Err(_), .. })) => {
                self.swarm.close_connection(connection);
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(found))) => {
                self.on_discovered(found)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Members(request_response::Event::Message { peer, message, .. })) => self.on_roster(peer, message)?,
            SwarmEvent::Behaviour(BehaviourEvent::Blocks(event)) => {
                self.on_blocks(event)?;
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
            SwarmEvent::Behaviour(BehaviourEvent::Hosts(event)) => {
                self.on_hosts(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Grants(event)) => {
                self.on_grants(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Asks(event)) => {
                self.on_ask(event)?;
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Clock(event)) => self.on_clock(event),
            SwarmEvent::Behaviour(BehaviourEvent::Serve(event)) => self.on_serve(event)?,
            _ => None,
        })
    }
}

mod serving;

mod asks;

#[cfg(test)]
mod tests;

/// Whether an address is a loopback one.
fn is_loopback(addr: &Multiaddr) -> bool {
    addr.iter().any(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// Whether an address is through a relay.
fn is_relayed(addr: &Multiaddr) -> bool {
    addr.iter().any(|protocol| protocol == libp2p::multiaddr::Protocol::P2pCircuit)
}

/// Seconds since the epoch, by this machine's clock.
fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}
