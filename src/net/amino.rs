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

use std::time::Duration;

use futures::StreamExt as _;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, identify, kad, ping};

use super::bitswap::{self, Entry, Message, Presence, WantType};
use super::mesh::{Error, Result};
use crate::cid::CidRef as _;
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
        let mut amino = Self { swarm, catalog, control, incoming, read, reads, ports: Vec::new() };
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
        loop {
            tokio::select! {
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
                    return Ok(Event::Received(peer, message));
                },
            }
        }
    }

    fn handle(&mut self, event: SwarmEvent<BehaviourEvent>) -> Option<Event> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => Some(Event::Listening(address)),
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
