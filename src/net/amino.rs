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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, identify, kad, ping};

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

/// How long a fetch waits with nothing arriving, and at most in all,
/// before it says what it couldn't fetch.
#[cfg(not(test))]
const IDLE: Duration = Duration::from_secs(20);
#[cfg(test)]
const IDLE: Duration = Duration::from_secs(1);
const LONGEST: Duration = Duration::from_mins(5);

/// The most providers of a root asked.
const PROVIDERS: usize = 20;

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

/// A way to ask the running swarm to fetch.
#[derive(Clone)]
pub struct Handle {
    asks: tokio::sync::mpsc::UnboundedSender<Ask>,
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
}

/// The running swarm's handle, once there is one: there's one to a daemon.
static HANDLE: OnceLock<Handle> = OnceLock::new();

/// The running swarm, to fetch from Amino, if this process takes part.
pub fn handle() -> Option<&'static Handle> {
    HANDLE.get()
}

/// A fetch under way.
struct Fetching {
    /// What's wanted and not yet here, by multihash.
    wanted: BTreeMap<Vec<u8>, Link>,
    dag: bool,
    share: bool,
    fetched: usize,
    /// Who's asked, providers and whoever sent any of it.
    asked: HashSet<PeerId>,
    began: Instant,
    last: Instant,
    reply: Option<tokio::sync::oneshot::Sender<Fetched>>,
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    streams: libp2p_stream::Behaviour,
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

/// The swarm, and what it answers from.
pub struct Amino {
    swarm: Swarm<Behaviour>,
    catalog: Catalog,
    control: libp2p_stream::Control,
    incoming: libp2p_stream::IncomingStreams,
    read: tokio::sync::mpsc::UnboundedSender<Read>,
    reads: tokio::sync::mpsc::UnboundedReceiver<Read>,
    /// The ports it listens on, so an address it's seen at on one of them
    /// may be where it's reached.
    ports: Vec<u16>,
    asks: tokio::sync::mpsc::UnboundedReceiver<Ask>,
    handle: Handle,
    fetches: Vec<Fetching>,
    /// Which fetch each search for providers is for.
    searches: HashMap<kad::QueryId, usize>,
}

impl Amino {
    /// A swarm over a transport, answering from the catalog, which knows
    /// these peers to start from.
    ///
    /// # Errors
    ///
    /// If Bitswap's protocol can't be taken.
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, catalog: Catalog, bootstrap: &[Multiaddr]) -> Result<Self> {
        let peer = key.public().to_peer_id();
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
            streams: libp2p_stream::Behaviour::new(),
        };
        let swarm = Swarm::new(transport, behaviour, peer, libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_mins(1)));
        let mut control = swarm.behaviour().streams.new_control();
        let incoming = control.accept(StreamProtocol::new(bitswap::PROTOCOL)).map_err(|e| Error::Invalid(e.to_string()))?;
        let (read, reads) = tokio::sync::mpsc::unbounded_channel();
        let (ask, asks) = tokio::sync::mpsc::unbounded_channel();
        let handle = Handle { asks: ask };
        let mut amino = Self { swarm, catalog, control, incoming, read, reads, ports: Vec::new(), asks, handle, fetches: Vec::new(), searches: HashMap::new() };
        if !bootstrap.is_empty() {
            // Joining the DHT, which the behaviour does again now and then
            let _ = amino.swarm.behaviour_mut().kad.bootstrap();
        }
        Ok(amino)
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub const fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// A way to ask it to fetch, from outside.
    pub fn fetcher(&self) -> Handle {
        self.handle.clone()
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        if let Some(port) = addr.iter().find_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
            _ => None,
        }) {
            self.ports.push(port);
        }
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
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                Some(ask) = self.asks.recv() => self.begin(ask),
                _ = tick.tick() => self.finish(),
                event = self.swarm.select_next_some() => {
                    if let Some(event) = self.handle(event) {
                        return Ok(event);
                    }
                },
                Some((peer, stream)) = self.incoming.next() => {
                    let read = self.read.clone();
                    tokio::spawn(async move {
                        let mut stream = stream;
                        while let Ok(Some(message)) = bitswap::read(&mut stream).await {
                            if read.send((peer, message)).is_err() {
                                break;
                            }
                        }
                    });
                },
                Some((peer, message)) = self.reads.recv() => {
                    self.answer(peer, &message);
                    self.received(peer, &message);
                    return Ok(Event::Received(peer, message));
                },
            }
        }
    }

    fn handle(&mut self, event: SwarmEvent<BehaviourEvent>) -> Option<Event> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => Some(Event::Listening(address)),
            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })), .. })) => {
                if let Some(&fetch) = self.searches.get(&id) {
                    for provider in providers.into_iter().take(PROVIDERS) {
                        self.ask(fetch, provider);
                    }
                }
                None
            },
            // Seen at a port it listens on, it's reached there: so the DHT
            // takes it for a server, as it should for a public address
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                let observed = &info.observed_addr;
                let port = observed.iter().find_map(|protocol| match protocol {
                    libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                    _ => None,
                });
                let local = observed.iter().any(|protocol| match protocol {
                    libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
                    libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
                    _ => false,
                });
                if port.is_some_and(|port| self.ports.contains(&port)) && !local {
                    self.swarm.add_external_address(observed.clone());
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
        self.fetches.push(Fetching { wanted, dag: ask.dag, share: ask.share, fetched: 0, asked: HashSet::new(), began: now, last: now, reply: Some(ask.reply) });
        for root in &ask.roots {
            let search = self.swarm.behaviour_mut().kad.get_providers(kad::RecordKey::new(&root.multihash().to_bytes()));
            self.searches.insert(search, fetch);
        }
        let connected: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
        for peer in connected {
            self.ask(fetch, peer);
        }
    }

    /// Want what a fetch still wants of a peer, if it hasn't been asked.
    fn ask(&mut self, fetch: usize, peer: PeerId) {
        let Some(fetching) = self.fetches.get_mut(fetch).filter(|fetching| fetching.reply.is_some()) else {
            return;
        };
        if !fetching.asked.insert(peer) {
            return;
        }
        let wants = fetching.wanted.values().map(|cid| Entry { cid: cid.clone(), priority: 1, cancel: false, want: WantType::Block, send_dont_have: true }).collect();
        self.send(peer, Message { wants, ..Message::default() });
    }

    /// Take in what's arrived that's wanted: kept, shared if it's to be,
    /// and for a DAG, what it links to that isn't here wanted too, of
    /// whoever sent it and whoever else was asked.
    fn received(&mut self, peer: PeerId, message: &Message) {
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
                fetching.fetched = fetching.fetched.saturating_add(1);
                fetching.last = Instant::now();
                fetching.asked.insert(peer);
                if fetching.share {
                    let _ = self.catalog.share_fetched(std::slice::from_ref(cid));
                }
                if !fetching.dag {
                    continue;
                }
                let mut more = Vec::new();
                for link in &links {
                    if !self.catalog.has(link.multihash()).unwrap_or(false) && fetching.wanted.insert(link.multihash().to_bytes(), link.clone()).is_none() {
                        more.push(Entry { cid: link.clone(), priority: 1, cancel: false, want: WantType::Block, send_dont_have: true });
                    }
                }
                if !more.is_empty() {
                    let asked: Vec<PeerId> = fetching.asked.iter().copied().collect();
                    for to in asked {
                        self.send(to, Message { wants: more.clone(), ..Message::default() });
                    }
                }
            }
        }
    }

    /// Say what came of each fetch that's done: nothing left to want, or
    /// waited long enough.
    fn finish(&mut self) {
        let now = Instant::now();
        let mut done = Vec::new();
        for (index, fetching) in self.fetches.iter_mut().enumerate() {
            let over = fetching.wanted.is_empty() || now.duration_since(fetching.last) > IDLE || now.duration_since(fetching.began) > LONGEST;
            if over && let Some(reply) = fetching.reply.take() {
                let _ = reply.send(Fetched { fetched: fetching.fetched, missing: fetching.wanted.values().cloned().collect() });
                done.push(index);
            }
        }
        // Done with, the searches for them go, and once none's under way the
        // list starts again
        self.searches.retain(|_, fetch| !done.contains(fetch));
        if self.fetches.iter().all(|fetching| fetching.reply.is_none()) {
            self.fetches.clear();
            self.searches.clear();
        }
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

/// Run the swarm for the repo, listening on `addr`, on a thread of its own,
/// joining Amino by these peers, or its own bootstrap peers if none are
/// said.
///
/// # Errors
///
/// If the repo won't open, or the key can't be had.
pub fn open(repo: &std::path::Path, addr: Multiaddr, bootstrap: Option<Vec<Multiaddr>>) -> Result<()> {
    drop(Catalog::open_repo(repo)?);
    let key = key(repo)?;
    let repo = repo.to_path_buf();
    std::thread::Builder::new().name("amino".to_owned()).spawn(move || {
        let run = || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(async {
                let bootstrap = bootstrap.unwrap_or_else(|| BOOTSTRAP.iter().filter_map(|addr| addr.parse().ok()).collect());
                let mut amino = Amino::new(transport(&key)?, &key, Catalog::open_repo(&repo)?, &bootstrap)?;
                amino.listen(addr)?;
                let _ = HANDLE.set(amino.fetcher());
                eprintln!("in Amino as {}", amino.peer_id());
                loop {
                    if let Event::Listening(at) = amino.next().await? {
                        eprintln!("Amino reaches this at {at}");
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

#[cfg(test)]
mod tests;
