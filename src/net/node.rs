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

use std::collections::BTreeMap;
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

use super::mesh::{Error, Members, Result};

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
}

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
}

impl Node {
    /// A node over TCP, finding members on the LAN by mDNS.
    pub fn tcp(key: &Keypair, swarm_key: PreSharedKey, members: Members) -> Result<Self> {
        let base = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        Self::new(transport(base, key, swarm_key)?, key, members, true)
    }

    /// A node over a transport, with or without mDNS.
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, members: Members, lan: bool) -> Result<Self> {
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
        };
        let config = libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(IDLE);
        let mut node = Self { swarm: Swarm::new(transport, behaviour, peer, config), members };
        node.reload()?;
        Ok(node)
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub const fn members(&self) -> &Members {
        &self.members
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
            let Some(event) = self.swarm.next().await else {
                return Err(Error::Invalid("the swarm stopped".into()));
            };
            if let Some(event) = self.handle(event)? {
                return Ok(event);
            }
        }
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
                let roster = self.roster()?;
                self.swarm.behaviour_mut().members.send_request(&peer_id, roster);
                Some(Event::Connected(peer_id))
            },
            SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => Some(Event::Disconnected(peer_id)),
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
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests;
