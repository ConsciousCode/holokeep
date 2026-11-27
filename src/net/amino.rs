//! Amino: the public IPFS network, apart from the mesh.
//!
//! A swarm of its own, with a key of its own (`amino.key`), so nothing
//! links it to the mesh's, and no private network, letting in anyone, who
//! reaches nothing but this: its Kademlia DHT (`/ipfs/kad/1.0.0`) and
//! Bitswap (`/ipfs/bitswap/1.2.0`), beside identify and ping.
//!
//! What's served to its peers is what's public (see `Catalog::is_public`)
//! and what was fetched from them to be shared (see
//! `Catalog::shared_fetch`). Everything else, private or missing, is
//! answered alike: not had, and only after a floor of time each, so how
//! long an answer takes says nothing of whether it's private either.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, autonat, identify, kad, ping};

use super::bitswap::{self, Entry, Message, Presence, WantType};
use super::mesh::{Error, Result};
use crate::cid::{AnyCid, BaseCid as _, CidRef as _, CidVersion};
use crate::model::Link;
use crate::store::{BlockIndex as _, Catalog};

/// Amino's DHT, as its peers speak it.
pub const KAD: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

/// Where the swarm listens, by default.
pub const LISTEN: &str = "/ip4/0.0.0.0/tcp/4015";

/// The swarm's key, beside the repo's others.
const KEY: &str = "amino.key";

/// Amino's bootstrap peers, as Kubo has them.
pub const BOOTSTRAP: [&str; 5] = [
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
];

/// The least time before saying what isn't had, and the most more at
/// random, so a block private here is said not to be as a missing one is.
const NOT_HAD: Duration = Duration::from_millis(50);
const NOT_HAD_JITTER_MS: u64 = 50;

/// The most wants of one message looked at; the rest are dropped.
const WANTS: usize = 1024;

/// The most block bytes in one message sent.
const BUDGET: usize = 2 << 20;

/// How long a fetch waits with nothing arriving before it says what it
/// couldn't fetch: however long it takes otherwise, a big DAG being many
/// blocks.
#[cfg(not(test))]
const IDLE: Duration = Duration::from_secs(20);
#[cfg(test)]
const IDLE: Duration = Duration::from_secs(1);

/// How many of what a fetch wants whoever's connected is asked whether
/// they have, to find sources besides the providers.
const PROBE: usize = 16;

/// The most blocks a fetch wants of its sources and hasn't had at once:
/// Kubo keeps the first 1024 of a peer's wants and drops the rest.
const WINDOW: usize = 256;

/// How long a block wanted of a source is waited for before it's wanted
/// of the next: the source may be slow or gone, or its answer lost, as
/// when a stream is reset, and Kubo's server doesn't send again.
const REWANT: Duration = Duration::from_secs(3);

/// How often what's to be announced is looked at again.
const ANNOUNCE: Duration = Duration::from_mins(1);

/// How soon it's looked at again once the catalog's changed: what's made
/// public is announced in seconds, however busy the catalog.
const ANNOUNCE_SOON: Duration = Duration::from_secs(5);

/// The most providers of a block asked.
const PROVIDERS: usize = 20;

/// How long a fetch goes with nothing arriving, from no source found or
/// none with much of it, before who has a block it's waiting on is sought,
/// in the DHT and of a router: a DAG's roots may be had by many who hold
/// little under them, as whoever's visited a site's front page.
#[cfg(not(test))]
const STALLED: Duration = Duration::from_secs(2);
#[cfg(test)]
const STALLED: Duration = Duration::from_millis(200);

/// The most blocks wanted of a gateway at once, over HTTP, where each is
/// a request of its own.
const GATEWAY_WINDOW: usize = 8;

/// How many blocks running a gateway may not have before it's asked no
/// more: a gateway with none of it says so as quickly as one with all.
const GATEWAY_FAILS: usize = 16;

/// How often it's sought again, of another block, while nothing arrives.
#[cfg(not(test))]
const SEEK_AGAIN: Duration = Duration::from_secs(5);
#[cfg(test)]
const SEEK_AGAIN: Duration = Duration::from_millis(500);

/// What's asked of the swarm from outside it: to fetch these, or the whole
/// DAGs under them, sharing what's fetched or not.
pub struct Ask {
    roots: Vec<Link>,
    dag: bool,
    share: bool,
    reply: tokio::sync::oneshot::Sender<Fetched>,
}

/// What came of a fetch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fetched {
    pub fetched: usize,
    pub missing: Vec<Link>,
}

/// How the swarm is, for `hk node amino`.
#[derive(Debug, Clone)]
pub struct Status {
    pub peer: PeerId,
    pub listening: Vec<Multiaddr>,
    /// Where it's taken to be reached, which a provider record says.
    pub reached: Vec<Multiaddr>,
    /// Whether it's a server of the DHT, answering others' queries.
    pub server: bool,
    /// The peers in its routing table.
    pub routing: usize,
    /// What it provides on the DHT.
    pub providing: usize,
    /// Who's connected, where, and as what, as identify says.
    pub peers: Vec<(PeerId, Option<Multiaddr>, Option<String>)>,
    /// The last dial that failed, and why.
    pub failed: Option<String>,
    /// How many times a router's been asked who has a block.
    pub routed: usize,
}

/// A way to ask the running swarm to fetch, or how it is.
#[derive(Clone)]
pub struct Handle {
    asks: tokio::sync::mpsc::UnboundedSender<Ask>,
    statuses: tokio::sync::mpsc::UnboundedSender<tokio::sync::oneshot::Sender<Status>>,
}

impl Handle {
    /// Fetch these blocks, or with `dag` the whole DAGs under them, from
    /// Amino, sharing them back unless not to: what came of it, once it's
    /// done, or none if the swarm's gone.
    pub fn fetch(&self, roots: Vec<Link>, dag: bool, share: bool) -> tokio::sync::oneshot::Receiver<Fetched> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        let _ = self.asks.send(Ask { roots, dag, share, reply });
        answer
    }

    /// How the swarm is, or none if it's gone.
    pub fn status(&self) -> tokio::sync::oneshot::Receiver<Status> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        let _ = self.statuses.send(reply);
        answer
    }
}

/// The running swarm's handle, once there is one: there's one to a daemon.
static HANDLE: OnceLock<Handle> = OnceLock::new();

/// The running swarm, to fetch from Amino, if this process takes part.
pub fn handle() -> Option<&'static Handle> {
    HANDLE.get()
}

/// A fetch under way. Whoever's connected is asked whether they have the
/// roots; the blocks are wanted only of its sources, a window at a time,
/// each of one source in turn, as Kubo's sessions do: wanting every block
/// of everyone connected floods them, and has each answer it isn't had.
struct Fetching {
    /// Which fetch it is, however many have come and gone.
    id: u64,
    /// Whether a router's being asked who has some of it.
    routing: bool,
    /// When who has a block it's waiting on was last sought, and which
    /// blocks have been.
    sought_at: Option<Instant>,
    sought: HashSet<Vec<u8>>,
    /// What's wanted and not yet here, by multihash.
    wanted: BTreeMap<Vec<u8>, Link>,
    /// Of those, what's wanted of a source now: of which, and since when.
    window: BTreeMap<Vec<u8>, (PeerId, Instant)>,
    /// Who has it, as far as is known: the roots' providers, and whoever's
    /// sent any of it or said they have it.
    sources: Vec<PeerId>,
    /// Which source's next.
    turn: usize,
    /// Trustless gateways a router found, had of over HTTP.
    gateways: Vec<Gateway>,
    /// What's being had of a gateway now.
    over_http: HashSet<Vec<u8>>,
    /// Who's been asked whether they have any of it, or found by a router.
    asked: HashSet<PeerId>,
    dag: bool,
    share: bool,
    fetched: usize,
    last: Instant,
    /// When whoever's connected was last asked.
    asked_at: Instant,
    reply: Option<tokio::sync::oneshot::Sender<Fetched>>,
}

impl Fetching {
    /// Take a peer for a source: whether it's new.
    fn source(&mut self, peer: PeerId) -> bool {
        let new = !self.sources.contains(&peer);
        if new {
            self.sources.push(peer);
        }
        new
    }

    /// The source whose turn it is, other than this one if there's another.
    fn next(&mut self, not: Option<PeerId>) -> Option<PeerId> {
        for _ in 0..self.sources.len() {
            let peer = *self.sources.get(self.turn.checked_rem(self.sources.len())?)?;
            self.turn = self.turn.wrapping_add(1);
            if Some(peer) != not || self.sources.len() == 1 {
                return Some(peer);
            }
        }
        None
    }

    /// The window filled from what's wanted: which source to want each of.
    fn fill(&mut self, now: Instant) -> Vec<(PeerId, Link)> {
        let room = WINDOW.saturating_sub(self.window.len());
        let more: Vec<(Vec<u8>, Link)> = self.wanted.iter().filter(|(key, _)| !self.window.contains_key(*key)).take(room).map(|(key, cid)| (key.clone(), cid.clone())).collect();
        let mut wants = Vec::new();
        for (key, cid) in more {
            let Some(peer) = self.next(None) else {
                break;
            };
            self.window.insert(key, (peer, now));
            wants.push((peer, cid));
        }
        wants
    }

    /// Want again of another source what's in the window, if its source
    /// hasn't sent it in time, or says it hasn't it.
    fn again(&mut self, now: Instant, which: impl Fn(&[u8], PeerId, Instant) -> bool) -> Vec<(PeerId, Link)> {
        let stale: Vec<(Vec<u8>, PeerId)> = self.window.iter().filter(|(key, (peer, at))| which(key, *peer, *at)).map(|(key, (peer, _))| (key.clone(), *peer)).collect();
        let mut wants = Vec::new();
        for (key, was) in stale {
            let (Some(cid), Some(peer)) = (self.wanted.get(&key).cloned(), self.next(Some(was))) else {
                continue;
            };
            self.window.insert(key, (peer, now));
            wants.push((peer, cid));
        }
        wants
    }
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    /// Where it's reached, as peers dialling back find: so the DHT takes
    /// it for a server only if it's reached where it's seen. Being seen
    /// at a port it listens on isn't enough, as it dials from that port,
    /// and a firewall or NAT lets the answers back in but no one else.
    autonat: autonat::Behaviour,
    streams: libp2p_stream::Behaviour,
    inbound: inbound::Behaviour,
}

/// The swarm's key: generated, and kept, the first time it's asked for.
///
/// # Errors
///
/// If it can't be read or written.
pub fn key(dir: &std::path::Path) -> Result<Keypair> {
    let path = dir.join(KEY);
    match std::fs::read(&path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes).map_err(|e| Error::Invalid(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = Keypair::generate_ed25519();
            let bytes = key.to_protobuf_encoding().map_err(|e| Error::Invalid(e.to_string()))?;
            super::mesh::write_secret(&path, &bytes)?;
            Ok(key)
        },
        Err(e) => Err(e.into()),
    }
}

/// A transport for Amino: TCP, names resolved, noise and yamux.
///
/// # Errors
///
/// If the system's DNS configuration can't be read.
pub fn transport(key: &Keypair) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
    use libp2p::Transport as _;
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true));
    let noise = libp2p::noise::Config::new(key).map_err(|e| Error::Invalid(format!("noise: {e}")))?;
    Ok(libp2p::dns::tokio::Transport::system(tcp)?
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise)
        .multiplex(libp2p::yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed())
}

/// What happens that whoever runs the swarm may care about.
#[derive(Debug)]
pub enum Event {
    Listening(Multiaddr),
    /// A message, its wants answered already.
    Received(PeerId, Message),
}

/// A message read from a peer, or the end of what it sent.
type Read = (PeerId, Message);

/// A trustless gateway a fetch has blocks of over HTTP: where, how many
/// it's being asked for now, which it hasn't had, and how many of those
/// running.
struct Gateway {
    url: String,
    asked: usize,
    lacks: HashSet<Vec<u8>>,
    failed: usize,
}

/// A block had of a gateway for a fetch, or not: the fetch, the gateway,
/// the block's CID, and what it sent.
type OverHttp = (u64, String, Link, Option<Vec<u8>>);

/// A search of the DHT for providers: for which fetch, and whether of its
/// roots, which it isn't idle while it waits on, or of a block it's
/// stalled on.
#[derive(Debug, Clone, Copy)]
struct Search {
    fetch: usize,
    roots: bool,
}

/// The providers a router found for a fetch, and where they're reached.
type Route = (u64, routers::Found);

/// The swarm, and what it answers from.
pub struct Amino {
    swarm: Swarm<Behaviour>,
    catalog: Catalog,
    control: libp2p_stream::Control,
    /// Bitswap's incoming streams, till the swarm runs and a task of
    /// their own takes them.
    incoming: Option<tokio::sync::mpsc::UnboundedReceiver<inbound::Incoming>>,
    read: tokio::sync::mpsc::UnboundedSender<Read>,
    reads: tokio::sync::mpsc::UnboundedReceiver<Read>,
    asks: tokio::sync::mpsc::UnboundedReceiver<Ask>,
    statuses: tokio::sync::mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<Status>>,
    handle: Handle,
    /// Each connected peer's address and agent, as far as they're known.
    connected: HashMap<PeerId, (Option<Multiaddr>, Option<String>)>,
    failed: Option<String>,
    fetches: Vec<Fetching>,
    /// The next fetch's id.
    next_fetch: u64,
    /// The routers asked who provides what a fetch gets nothing of.
    routers: Vec<String>,
    /// What they've found, for which fetch, as it's found.
    route: tokio::sync::mpsc::UnboundedSender<Route>,
    routes: tokio::sync::mpsc::UnboundedReceiver<Route>,
    /// What gateways have sent, or not, as it comes.
    http: tokio::sync::mpsc::UnboundedSender<OverHttp>,
    https: tokio::sync::mpsc::UnboundedReceiver<OverHttp>,
    routed: usize,
    /// The peers a router found that are being dialled, and the fetches
    /// they're to be asked for once connected.
    dialling: HashMap<PeerId, Vec<u64>>,
    /// Which fetch each search for providers is for.
    searches: HashMap<kad::QueryId, Search>,
    /// What's announced as here, by multihash, and when that was last
    /// looked at.
    providing: HashSet<Vec<u8>>,
    announced_at: Option<Instant>,
    /// The catalog's generation when what's announced was looked at.
    announced_of: Option<i64>,
    /// Whether it's a server of the DHT reached where it listens.
    serving: bool,
}

impl Amino {
    /// A swarm over a transport, answering from the catalog, which knows
    /// these peers to start from.
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, catalog: Catalog, bootstrap: &[Multiaddr]) -> Self {
        let peer = key.public().to_peer_id();
        let (streams, incoming) = tokio::sync::mpsc::unbounded_channel();
        let mut kad = kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), kad::Config::new(KAD));
        for addr in bootstrap {
            if let Some(libp2p::multiaddr::Protocol::P2p(id)) = addr.iter().last() {
                kad.add_address(&id, addr.clone());
            }
        }
        let behaviour = Behaviour {
            identify: identify::Behaviour::new(identify::Config::new("ipfs/0.1.0".to_owned(), key.public()).with_agent_version(format!("holokeep/{}", env!("CARGO_PKG_VERSION")))),
            ping: ping::Behaviour::default(),
            kad,
            autonat: autonat::Behaviour::new(peer, autonat::Config::default()),
            streams: libp2p_stream::Behaviour::new(),
            inbound: inbound::Behaviour::new(StreamProtocol::new(bitswap::PROTOCOL), streams),
        };
        let swarm = Swarm::new(transport, behaviour, peer, libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_mins(1)));
        let control = swarm.behaviour().streams.new_control();
        let (read, reads) = tokio::sync::mpsc::unbounded_channel();
        let (ask, asks) = tokio::sync::mpsc::unbounded_channel();
        let (status, statuses) = tokio::sync::mpsc::unbounded_channel();
        let handle = Handle { asks: ask, statuses: status };
        let (route, routes) = tokio::sync::mpsc::unbounded_channel();
        let (http, https) = tokio::sync::mpsc::unbounded_channel();
        let mut amino = Self {
            swarm,
            catalog,
            control,
            incoming: Some(incoming),
            read,
            reads,
            asks,
            statuses,
            handle,
            connected: HashMap::new(),
            failed: None,
            fetches: Vec::new(),
            next_fetch: 0,
            routers: Vec::new(),
            route,
            routes,
            http,
            https,
            routed: 0,
            dialling: HashMap::new(),
            searches: HashMap::new(),
            providing: HashSet::new(),
            announced_at: None,
            announced_of: None,
            serving: false,
        };
        if !bootstrap.is_empty() {
            // Joining the DHT, which the behaviour does again now and then
            let _ = amino.swarm.behaviour_mut().kad.bootstrap();
        }
        amino
    }

    /// Ask these routers (`https://…`) who provides what a fetch gets
    /// nothing of otherwise.
    pub fn route_by(&mut self, routers: Vec<String>) {
        self.routers = routers;
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub const fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Be a server of the DHT whatever it's seen as, reached where it
    /// listens, which is what's announced with what's provided: as on a LAN,
    /// where what's reached isn't a public address.
    pub fn serve_dht(&mut self) {
        self.serving = true;
        self.swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));
        let listening: Vec<Multiaddr> = self.swarm.listeners().cloned().collect();
        for addr in listening {
            self.swarm.add_external_address(addr);
        }
    }

    /// Announce what's to be as here, and stop announcing what's no longer
    /// to be: the DHT republishes what's announced as it goes. Returns
    /// whether anything changed.
    pub fn announce(&mut self) -> bool {
        let Ok(announced) = self.catalog.announced() else {
            return false;
        };
        let now: HashSet<Vec<u8>> = announced.iter().map(|cid| cid.multihash().to_bytes()).collect();
        let mut changed = false;
        for key in now.difference(&self.providing) {
            let _ = self.swarm.behaviour_mut().kad.start_providing(kad::RecordKey::new(key));
            changed = true;
        }
        for key in self.providing.difference(&now) {
            self.swarm.behaviour_mut().kad.stop_providing(&kad::RecordKey::new(key));
            changed = true;
        }
        self.providing = now;
        changed
    }

    /// How it is now.
    fn status(&mut self) -> Status {
        let kad = &mut self.swarm.behaviour_mut().kad;
        let server = kad.mode() == kad::Mode::Server;
        let routing = kad.kbuckets().map(|bucket| bucket.num_entries()).sum();
        let mut peers: Vec<_> = self.connected.iter().map(|(peer, (addr, agent))| (*peer, addr.clone(), agent.clone())).collect();
        peers.sort_by_key(|(peer, ..)| *peer);
        Status {
            peer: *self.swarm.local_peer_id(),
            listening: self.swarm.listeners().cloned().collect(),
            reached: self.swarm.external_addresses().cloned().collect(),
            server,
            routing,
            providing: self.providing.len(),
            peers,
            failed: self.failed.clone(),
            routed: self.routed,
        }
    }

    /// A way to ask it to fetch, from outside.
    pub fn fetcher(&self) -> Handle {
        self.handle.clone()
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.listen_on(addr).map(drop).map_err(|e| Error::Invalid(format!("listen: {e}")))
    }

    /// Dial a peer where it is.
    pub fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr).map_err(|e| Error::Invalid(format!("dial: {e}")))
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.swarm.is_connected(peer)
    }

    /// Send a peer a message, on a stream of its own.
    pub fn send(&self, peer: PeerId, message: Message) {
        if message.is_empty() {
            return;
        }
        let mut control = self.control.clone();
        tokio::spawn(async move {
            if let Ok(mut stream) = control.open_stream(peer, StreamProtocol::new(bitswap::PROTOCOL)).await {
                let _ = bitswap::write(&mut stream, &message).await;
                let _ = futures::AsyncWriteExt::close(&mut stream).await;
            }
        });
    }

    /// The next thing that happens which the runner cares about; what else
    /// happens is dealt with on the way.
    pub async fn next(&mut self) -> Result<Event> {
        if let Some(incoming) = self.incoming.take() {
            tokio::spawn(accept(incoming, self.read.clone()));
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                Some(ask) = self.asks.recv() => self.begin(ask),
                Some(reply) = self.statuses.recv() => {
                    let _ = reply.send(self.status());
                },
                _ = tick.tick() => {
                    self.finish();
                    let generation = self.catalog.generation().ok();
                    let changed = generation != self.announced_of;
                    if self.announced_at.is_none_or(|at| at.elapsed() >= ANNOUNCE || (changed && at.elapsed() >= ANNOUNCE_SOON)) {
                        self.announced_at = Some(Instant::now());
                        self.announced_of = generation;
                        self.announce();
                    }
                },
                event = self.swarm.select_next_some() => {
                    if let Some(event) = self.handle(event) {
                        return Ok(event);
                    }
                },
                Some((fetch, found)) = self.routes.recv() => self.found(fetch, found),
                Some((fetch, gateway, cid, data)) = self.https.recv() => self.over_http(fetch, &gateway, &cid, data),
                Some((peer, message)) = self.reads.recv() => {
                    self.answer(peer, &message);
                    self.received(Some(peer), &message);
                    return Ok(Event::Received(peer, message));
                },
            }
        }
    }

    fn handle(&mut self, event: SwarmEvent<BehaviourEvent>) -> Option<Event> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                let anywhere = address.iter().any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Ip4(ip) if ip.is_unspecified() || ip.is_loopback()));
                if self.serving && !anywhere {
                    self.swarm.add_external_address(address.clone());
                }
                Some(Event::Listening(address))
            },
            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::GetProviders(result), step, .. })) => {
                if let (Some(&Search { fetch, .. }), Ok(kad::GetProvidersOk::FoundProviders { providers, .. })) = (self.searches.get(&id), result) {
                    for provider in providers.into_iter().take(PROVIDERS) {
                        self.ask(fetch, provider);
                    }
                }
                // Over, the fetch may be found to have waited long enough
                if step.last {
                    self.searches.remove(&id);
                }
                None
            },
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                self.connected.entry(peer_id).or_default().0 = Some(endpoint.get_remote_address().clone());
                // Found by a router, and dialled to be asked
                for id in self.dialling.remove(&peer_id).unwrap_or_default() {
                    if let Some(fetch) = self.fetch_of(id) {
                        self.ask(fetch, peer_id);
                    }
                }
                None
            },
            SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                self.connected.remove(&peer_id);
                None
            },
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer) = peer_id
                    && !self.swarm.is_connected(&peer)
                {
                    self.dialling.remove(&peer);
                }
                self.failed = Some(format!("{}: {error}", peer_id.map_or_else(|| "a peer".to_owned(), |peer| peer.to_string())));
                None
            },
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                if let Some(known) = self.connected.get_mut(&peer_id) {
                    known.1 = Some(info.agent_version);
                }
                // A server of the DHT, wherever it's connected from, joins
                // the routing table where it says it listens: as one found
                // by a router does, so the DHT finds more next time
                if info.protocols.contains(&KAD) {
                    let kad = &mut self.swarm.behaviour_mut().kad;
                    for addr in info.listen_addrs.into_iter().filter(routers::dialable) {
                        kad.add_address(&peer_id, addr);
                    }
                }
                None
            },
            _ => None,
        }
    }

    /// Answer what a peer wants: what's served at once, and what isn't had
    /// after the floor.
    fn answer(&self, peer: PeerId, message: &Message) {
        let (now, later) = answers(&self.catalog, message);
        for message in now {
            self.send(peer, message);
        }
        if !later.is_empty() {
            let mut control = self.control.clone();
            let wait = NOT_HAD.saturating_add(Duration::from_millis(jitter(NOT_HAD_JITTER_MS)));
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                if let Ok(mut stream) = control.open_stream(peer, StreamProtocol::new(bitswap::PROTOCOL)).await {
                    let _ = bitswap::write(&mut stream, &later).await;
                    let _ = futures::AsyncWriteExt::close(&mut stream).await;
                }
            });
        }
    }
}

impl Amino {
    /// Begin a fetch: what of it isn't here is wanted of whoever's
    /// connected, and of the providers of each root, as they're found.
    fn begin(&mut self, ask: Ask) {
        let mut wanted = BTreeMap::new();
        for root in &ask.roots {
            let missing = if ask.dag {
                self.catalog.missing_under(root).unwrap_or_else(|_| vec![root.clone()])
            } else if self.catalog.has(root.multihash()).unwrap_or(false) {
                Vec::new()
            } else {
                vec![root.clone()]
            };
            for cid in missing {
                wanted.insert(cid.multihash().to_bytes(), cid);
            }
        }
        if wanted.is_empty() {
            let _ = ask.reply.send(Fetched::default());
            return;
        }
        let now = Instant::now();
        let fetch = self.fetches.len();
        let id = self.next_fetch;
        self.next_fetch = self.next_fetch.wrapping_add(1);
        self.fetches.push(Fetching {
            id,
            routing: false,
            sought_at: None,
            sought: HashSet::new(),
            gateways: Vec::new(),
            over_http: HashSet::new(),
            wanted,
            window: BTreeMap::new(),
            sources: Vec::new(),
            turn: 0,
            asked: HashSet::new(),
            dag: ask.dag,
            share: ask.share,
            fetched: 0,
            last: now,
            asked_at: now,
            reply: Some(ask.reply),
        });
        for root in &ask.roots {
            let search = self.swarm.behaviour_mut().kad.get_providers(kad::RecordKey::new(&root.multihash().to_bytes()));
            self.searches.insert(search, Search { fetch, roots: true });
        }
        self.ask_connected(fetch);
    }

    /// Which of the fetches under way this is, if it's still under way.
    fn fetch_of(&self, id: u64) -> Option<usize> {
        self.fetches.iter().position(|fetching| fetching.id == id && fetching.reply.is_some())
    }

    /// Seek who has a block a stalled fetch is waiting on, one not sought
    /// before: in the DHT, and of the routers, in a thread of their own,
    /// what they find coming back to `found`.
    fn seek(&mut self, fetch: usize) {
        let Some(fetching) = self.fetches.get_mut(fetch) else {
            return;
        };
        fetching.sought_at = Some(Instant::now());
        // What's wanted of a source now first, as what's waited on longest
        let Some(cid) = fetching.window.keys().chain(fetching.wanted.keys()).find(|key| !fetching.sought.contains(*key)).and_then(|key| fetching.wanted.get(key)).cloned() else {
            return;
        };
        fetching.sought.insert(cid.multihash().to_bytes());
        let search = self.swarm.behaviour_mut().kad.get_providers(kad::RecordKey::new(&cid.multihash().to_bytes()));
        self.searches.insert(search, Search { fetch, roots: false });
        if self.routers.is_empty() || fetching.routing {
            return;
        }
        fetching.routing = true;
        self.routed = self.routed.saturating_add(1);
        let (id, routers, route, cid) = (fetching.id, self.routers.clone(), self.route.clone(), cid.to_string());
        tokio::task::spawn_blocking(move || {
            let mut found = routers::Found::default();
            for router in &routers {
                found.extend(routers::ask(router, &cid));
            }
            let _ = route.send((id, found));
        });
    }

    /// Take the providers a router found for a fetch: each asked if it's
    /// connected, and dialled to be asked once it is if not.
    fn found(&mut self, id: u64, found: routers::Found) {
        let Some(fetch) = self.fetch_of(id) else {
            return;
        };
        let me = *self.swarm.local_peer_id();
        let routers::Found { peers, gateways } = found;
        let found: Vec<_> = peers.into_iter().filter(|(peer, _)| *peer != me).take(PROVIDERS).collect();
        if let Some(fetching) = self.fetches.get_mut(fetch) {
            fetching.routing = false;
            // Waited on afresh while any it hadn't known of are dialled:
            // only then, so routers finding none new end it as idle
            let mut new = false;
            for (peer, _) in &found {
                new |= fetching.asked.insert(*peer) && !fetching.sources.contains(peer);
            }
            for url in gateways.into_iter().take(PROVIDERS) {
                if !fetching.gateways.iter().any(|gateway| gateway.url == url) {
                    fetching.gateways.push(Gateway { url, asked: 0, lacks: HashSet::new(), failed: 0 });
                    new = true;
                }
            }
            if new {
                fetching.last = Instant::now();
            }
        }
        self.over_gateways(fetch);
        for (peer, addrs) in found {
            if self.swarm.is_connected(&peer) {
                self.ask(fetch, peer);
                continue;
            }
            let dialling = self.dialling.contains_key(&peer);
            self.dialling.entry(peer).or_default().push(id);
            if !dialling {
                let _ = self.swarm.dial(libp2p::swarm::dial_opts::DialOpts::peer_id(peer).addresses(addrs).build());
            }
        }
    }

    /// Want of each gateway a fetch has what's wanted, as many at once as
    /// it may be asked, each in a thread of its own, what's sent coming
    /// back to `over_http`.
    fn over_gateways(&mut self, fetch: usize) {
        let Some(fetching) = self.fetches.get_mut(fetch).filter(|fetching| fetching.reply.is_some()) else {
            return;
        };
        for gateway in &mut fetching.gateways {
            while gateway.asked < GATEWAY_WINDOW && gateway.failed < GATEWAY_FAILS {
                let Some((key, cid)) = fetching.wanted.iter().find(|(key, _)| !fetching.over_http.contains(*key) && !gateway.lacks.contains(*key)) else {
                    break;
                };
                fetching.over_http.insert(key.clone());
                gateway.asked = gateway.asked.saturating_add(1);
                let (id, url, cid, http) = (fetching.id, gateway.url.clone(), cid.clone(), self.http.clone());
                tokio::task::spawn_blocking(move || {
                    let data = routers::block(&url, &cid.to_string());
                    let _ = http.send((id, url, cid, data));
                });
            }
        }
    }

    /// Take what a gateway sent for a fetch, as from Bitswap, if it's the
    /// block it's said to be, and want more of it; if not, it's taken not
    /// to have it, and once it's had none of many running, asked no more.
    fn over_http(&mut self, id: u64, url: &str, cid: &Link, data: Option<Vec<u8>>) {
        let Some(fetch) = self.fetch_of(id) else {
            return;
        };
        let key = cid.multihash().to_bytes();
        let block = data.filter(|data| block_of(cid, data).is_some());
        if let Some(fetching) = self.fetches.get_mut(fetch) {
            fetching.over_http.remove(&key);
            if let Some(gateway) = fetching.gateways.iter_mut().find(|gateway| gateway.url == url) {
                gateway.asked = gateway.asked.saturating_sub(1);
                if block.is_some() {
                    gateway.failed = 0;
                } else {
                    gateway.failed = gateway.failed.saturating_add(1);
                    gateway.lacks.insert(key);
                }
            }
        }
        match block {
            // Taking it wants more of every gateway
            Some(data) => self.received(None, &Message { blocks: vec![(cid.clone(), data)], ..Message::default() }),
            None => self.over_gateways(fetch),
        }
    }

    /// Ask whoever's connected and hasn't been whether they have some of
    /// what a fetch wants, not to be told if they haven't: what's wanted,
    /// rather than the roots, which may be here already.
    fn ask_connected(&mut self, fetch: usize) {
        let Some(fetching) = self.fetches.get_mut(fetch) else {
            return;
        };
        let wants: Vec<Entry> = fetching.wanted.values().take(PROBE).map(|cid| Entry { cid: cid.clone(), priority: 1, cancel: false, want: WantType::Have, send_dont_have: false }).collect();
        let peers: Vec<PeerId> = self.swarm.connected_peers().copied().filter(|peer| fetching.asked.insert(*peer)).collect();
        for peer in peers {
            self.send(peer, Message { wants: wants.clone(), ..Message::default() });
        }
    }

    /// Take a peer for a source of a fetch, wanting of it what's its turn.
    fn ask(&mut self, fetch: usize, peer: PeerId) {
        let Some(fetching) = self.fetches.get_mut(fetch).filter(|fetching| fetching.reply.is_some()) else {
            return;
        };
        if fetching.source(peer) {
            let wants = fetching.fill(Instant::now());
            self.want(wants);
        }
    }

    /// Want each block of its peer, one message to each.
    fn want(&self, wants: Vec<(PeerId, Link)>) {
        let mut by_peer: HashMap<PeerId, Vec<Entry>> = HashMap::new();
        for (peer, cid) in wants {
            by_peer.entry(peer).or_default().push(Entry { cid, priority: 1, cancel: false, want: WantType::Block, send_dont_have: true });
        }
        for (peer, wants) in by_peer {
            self.send(peer, Message { wants, ..Message::default() });
        }
    }

    /// Take in what's arrived that's wanted: kept, shared if it's to be,
    /// and for a DAG, what it links to that isn't here wanted too; whoever
    /// sent it, or says they have it, taken for a source; and the window
    /// filled again, and more wanted of its gateways. A block from a
    /// gateway is from no peer.
    fn received(&mut self, from: Option<PeerId>, message: &Message) {
        let now = Instant::now();
        let mut touched = BTreeSet::new();
        let mut wants = Vec::new();
        for (peer, cid, presence) in from.iter().flat_map(|&peer| message.presences.iter().map(move |(cid, presence)| (peer, cid, presence))) {
            let key = cid.multihash().to_bytes();
            for (fetch, fetching) in self.fetches.iter_mut().enumerate() {
                if fetching.reply.is_none() || !fetching.wanted.contains_key(&key) {
                    continue;
                }
                match presence {
                    Presence::Have => {
                        fetching.source(peer);
                        touched.insert(fetch);
                    },
                    // Wanted of it and not had, it's wanted of another
                    Presence::DontHave => wants.extend(fetching.again(now, |k, of, _| k == key.as_slice() && of == peer)),
                }
            }
        }
        for (cid, data) in &message.blocks {
            let key = cid.multihash().to_bytes();
            let fetching: Vec<usize> = (0..self.fetches.len()).filter(|&fetch| self.fetches.get(fetch).is_some_and(|f| f.reply.is_some() && f.wanted.contains_key(&key))).collect();
            if fetching.is_empty() {
                continue;
            }
            let Some(block) = block_of(cid, data) else {
                continue;
            };
            let version = if matches!(cid, AnyCid::V0(_)) { CidVersion::V0 } else { CidVersion::V1 };
            if self.catalog.put_block(&block, version).is_err() {
                continue;
            }
            let links = crate::links::links(cid.codec(), data).unwrap_or_default();
            for fetch in fetching {
                let Some(fetching) = self.fetches.get_mut(fetch) else {
                    continue;
                };
                fetching.wanted.remove(&key);
                fetching.window.remove(&key);
                fetching.fetched = fetching.fetched.saturating_add(1);
                fetching.last = now;
                if let Some(peer) = from {
                    fetching.source(peer);
                }
                touched.insert(fetch);
                if fetching.share {
                    let _ = self.catalog.share_fetched(std::slice::from_ref(cid));
                }
                if !fetching.dag {
                    continue;
                }
                for link in &links {
                    if !self.catalog.has(link.multihash()).unwrap_or(false) {
                        fetching.wanted.insert(link.multihash().to_bytes(), link.clone());
                    }
                }
            }
        }
        for &fetch in &touched {
            if let Some(fetching) = self.fetches.get_mut(fetch).filter(|fetching| fetching.reply.is_some()) {
                wants.extend(fetching.fill(now));
            }
        }
        self.want(wants);
        for fetch in touched {
            self.over_gateways(fetch);
        }
    }

    /// Say what came of each fetch that's done: nothing left to want, or
    /// waited long enough.
    fn finish(&mut self) {
        let now = Instant::now();
        let mut done = Vec::new();
        let mut again = Vec::new();
        let mut unsourced = Vec::new();
        let mut stalled = Vec::new();
        for (index, fetching) in self.fetches.iter_mut().enumerate() {
            // Nothing coming, from no source or none with much of it, who
            // has what it's waiting on is sought
            let seek = now.duration_since(fetching.last) >= STALLED && fetching.sought_at.is_none_or(|at| now.duration_since(at) >= SEEK_AGAIN);
            // Not idle while its roots' providers are still being looked
            // for, a router's being asked, or it's yet to be sought at all
            let first = seek && fetching.sought_at.is_none();
            let searching = first || fetching.routing || !fetching.over_http.is_empty() || self.searches.values().any(|search| search.roots && search.fetch == index);
            let idle = !searching && now.duration_since(fetching.last) > IDLE;
            let over = fetching.wanted.is_empty() || idle;
            if over && let Some(reply) = fetching.reply.take() {
                let _ = reply.send(Fetched { fetched: fetching.fetched, missing: fetching.wanted.values().cloned().collect() });
                done.push(index);
            } else if fetching.reply.is_some() {
                again.extend(fetching.again(now, |_, _, at| now.duration_since(at) >= REWANT));
                again.extend(fetching.fill(now));
                if fetching.sources.is_empty() && now.duration_since(fetching.asked_at) >= REWANT {
                    fetching.asked_at = now;
                    unsourced.push(index);
                }
                if seek {
                    stalled.push(index);
                }
            }
        }
        self.want(again);
        // With no source yet, whoever's connected since is asked too
        for fetch in unsourced {
            self.ask_connected(fetch);
        }
        for fetch in stalled {
            self.seek(fetch);
        }
        // Done with, the searches for them go, and once none's under way the
        // list starts again
        self.searches.retain(|_, search| !done.contains(&search.fetch));
        if self.fetches.iter().all(|fetching| fetching.reply.is_none()) {
            self.fetches.clear();
            self.searches.clear();
            self.dialling.clear();
        }
    }
}

/// Read each of Bitswap's incoming streams, every message on it.
async fn accept(mut incoming: tokio::sync::mpsc::UnboundedReceiver<inbound::Incoming>, read: tokio::sync::mpsc::UnboundedSender<Read>) {
    while let Some((peer, mut stream)) = incoming.recv().await {
        let read = read.clone();
        tokio::spawn(async move {
            while let Ok(Some(message)) = bitswap::read(&mut stream).await {
                if read.send((peer, message)).is_err() {
                    break;
                }
            }
        });
    }
}

/// A block of what's received, by its CID, which is what its data hashes
/// to, as decoding made it.
fn block_of(cid: &Link, data: &[u8]) -> Option<crate::block::Block> {
    let function = crate::multihash::MultihashFunc::try_from(cid.hashcode()).ok()?;
    let block = crate::block::Block::hash(crate::cid::Cidv1Spec::new(cid.codec(), function), data.into());
    (block.cid().multihash() == cid.multihash()).then_some(block)
}

/// A random number of milliseconds, below `most`.
fn jitter(most: u64) -> u64 {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    u64::from_le_bytes(bytes).checked_rem(most).unwrap_or_default()
}

/// What to say to a peer's wants: what to send at once, and what after.
///
/// At once, messages of blocks and what's had, each within the budget;
/// after the floor, one of what isn't had. Whether something's servable is worked out the same
/// way whatever it is, so what's private takes as long to judge as what's
/// missing; only what's servable is read.
pub fn answers(catalog: &Catalog, message: &Message) -> (Vec<Message>, Message) {
    let (mut now, mut current, mut later) = (Vec::new(), Message::default(), Message::default());
    let mut size = 0usize;
    for want in message.wants.iter().filter(|want| !want.cancel).take(WANTS) {
        let Entry { cid, want: kind, send_dont_have, .. } = want;
        let public = catalog.is_public(cid).unwrap_or(false);
        let shared = catalog.shared_fetch(cid).unwrap_or(false);
        let here = catalog.has(cid.multihash()).unwrap_or(false);
        let block = match (kind, (public | shared) & here) {
            (WantType::Block, true) => catalog.get_block(cid).ok().flatten(),
            _ => None,
        };
        match (kind, (public | shared) & here, block) {
            (WantType::Have, true, _) => current.presences.push((cid.clone(), Presence::Have)),
            (WantType::Block, true, Some(block)) => {
                if size.saturating_add(block.len()) > BUDGET && !current.blocks.is_empty() {
                    now.push(std::mem::take(&mut current));
                    size = 0;
                }
                size = size.saturating_add(block.len());
                current.blocks.push((cid.clone(), block.data().to_vec()));
            },
            _ if *send_dont_have => later.presences.push((cid.clone(), Presence::DontHave)),
            _ => {},
        }
    }
    if !current.is_empty() {
        now.push(current);
    }
    (now, later)
}

/// Run the swarm for the repo, on a thread of its own.
///
/// It listens on `addr`, joining Amino by these peers, or its own
/// bootstrap peers if none are said; asking these routers who provides
/// what a fetch gets nothing of, or its own if none are said and it's
/// joined by its own peers; a server of its DHT, reached where it
/// listens, if `server`.
///
/// # Errors
///
/// If the repo won't open, or the key can't be had.
pub fn open(repo: &std::path::Path, addr: Multiaddr, bootstrap: Option<Vec<Multiaddr>>, routers: Option<Vec<String>>, server: bool) -> Result<()> {
    drop(Catalog::open_repo(repo)?);
    let key = key(repo)?;
    let repo = repo.to_path_buf();
    std::thread::Builder::new().name("amino".to_owned()).spawn(move || {
        let run = || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(async {
                // An Amino of its own, joined by peers of its own, asks no
                // router of the real one's unless told to
                let routers = routers.unwrap_or_else(|| if bootstrap.is_none() { routers::ROUTERS.iter().map(|&router| router.to_owned()).collect() } else { Vec::new() });
                let bootstrap = bootstrap.unwrap_or_else(|| BOOTSTRAP.iter().filter_map(|addr| addr.parse().ok()).collect());
                let mut amino = Amino::new(transport(&key)?, &key, Catalog::open_repo(&repo)?, &bootstrap);
                amino.route_by(routers);
                amino.listen(addr)?;
                if server {
                    amino.serve_dht();
                }
                let _ = HANDLE.set(amino.fetcher());
                eprintln!("in Amino as {}", amino.peer_id());
                loop {
                    if let Event::Listening(at) = amino.next().await? {
                        eprintln!("Amino listening at {at}");
                    }
                }
            })
        };
        if let Err(e) = run() {
            eprintln!("out of Amino: {e}");
        }
    })?;
    Ok(())
}

mod inbound;
pub mod routers;

#[cfg(test)]
mod tests;
