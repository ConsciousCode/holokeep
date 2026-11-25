//! Clients: devices of a member's users which aren't machines, so are no
//! members, connecting to one member and seeing only what their user may.
//!
//! - A member listens for clients apart, on a port of their own, where
//!   connections skip the private network: a client hasn't the swarm key,
//!   which would let it in as a member. Noise still authenticates either
//!   end, by its key.
//! - A client is a device key, its peer ID, which a user certified and
//!   the member was told to let in (`hk node invite --client`). The gate
//!   lets clients in only where clients connect, and members only where
//!   members do, so neither passes for the other.
//! - Once in, a client is as a machine hosting its user alone, saying so
//!   as any does, but it's asked nothing a member is: no copies go to it
//!   for durability, what it holds counts for nothing, it's told of no
//!   members, and its roster isn't heeded.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::Either;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, PortUse};
use libp2p::core::upgrade::Version;
use libp2p::core::{ConnectedPoint, Endpoint};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::pnet::{PnetConfig, PreSharedKey};
use libp2p::swarm::{ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm, dummy};
use libp2p::{Multiaddr, PeerId, Transport, noise, yamux};

use super::mesh::{Error, Result};

/// Where a member listens for clients, by port: shared between its
/// transport, which leaves the private network out there, and its gate.
#[derive(Debug, Clone, Default)]
pub struct Ports(Arc<RwLock<HashSet<u64>>>);

impl Ports {
    /// Listen for clients on an address's port too.
    pub fn add(&self, addr: &Multiaddr) {
        if let (Some(port), Ok(mut ports)) = (port(addr), self.0.write()) {
            ports.insert(port);
        }
    }

    /// Whether an address is where clients connect.
    pub fn contains(&self, addr: &Multiaddr) -> bool {
        port(addr).is_some_and(|port| self.0.read().is_ok_and(|ports| ports.contains(&port)))
    }
}

/// An address's port, TCP's or the in-memory transport's, as tests use;
/// nothing listens on port 0, which asks for any. An address through a
/// relay has no port of this node's, whatever port the relay's on.
pub fn port(addr: &Multiaddr) -> Option<u64> {
    if addr.iter().any(|protocol| protocol == Protocol::P2pCircuit) {
        return None;
    }
    addr.iter().find_map(|protocol| match protocol {
        Protocol::Tcp(port) => Some(u64::from(port)),
        Protocol::Memory(port) => Some(port),
        _ => None,
    }).filter(|&port| port != 0)
}

/// A member's transport, over some base transport: the private network,
/// then noise, then yamux; but where clients connect, no private network.
pub fn transport<T>(base: T, key: &Keypair, swarm_key: PreSharedKey, clients: Ports) -> Result<Boxed<(PeerId, StreamMuxerBox)>>
where
    T: Transport + Send + Unpin + 'static,
    T::Error: Send + Sync + 'static,
    T::Output: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    T::ListenerUpgrade: Send,
    T::Dial: Send,
{
    let pnet = PnetConfig::new(swarm_key);
    let noise = noise::Config::new(key).map_err(|e| Error::Invalid(format!("noise: {e}")))?;
    Ok(base
        .and_then(move |socket, endpoint: ConnectedPoint| {
            let client = matches!(&endpoint, ConnectedPoint::Listener { local_addr, .. } if clients.contains(local_addr));
            if client {
                Either::Left(futures::future::ok(Either::Left(socket)))
            } else {
                Either::Right(futures::TryFutureExt::map_ok(pnet.handshake(socket), Either::Right))
            }
        })
        .upgrade(Version::V1)
        .authenticate(noise)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed())
}

/// A client's transport: noise, then yamux, with no private network.
pub fn client_transport<T>(base: T, key: &Keypair) -> Result<Boxed<(PeerId, StreamMuxerBox)>>
where
    T: Transport + Send + Unpin + 'static,
    T::Error: Send + Sync + 'static,
    T::Output: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    T::ListenerUpgrade: Send,
    T::Dial: Send,
{
    let noise = noise::Config::new(key).map_err(|e| Error::Invalid(format!("noise: {e}")))?;
    Ok(base
        .upgrade(Version::V1)
        .authenticate(noise)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed())
}

/// Who came in where they're not to: a client where members connect, or
/// another where clients do.
#[derive(Debug)]
struct Misplaced(PeerId);

impl std::fmt::Display for Misplaced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} connected where it isn't let in", self.0)
    }
}

impl std::error::Error for Misplaced {}

/// Lets clients in only where clients connect, and others only where
/// members do. Who's let in at all is the allow list's to say.
#[derive(Debug, Default)]
pub struct Gate {
    ports: Ports,
    clients: HashSet<PeerId>,
}

impl Gate {
    pub fn new(ports: Ports) -> Self {
        Self { ports, clients: HashSet::new() }
    }

    pub fn set_clients(&mut self, clients: HashSet<PeerId>) {
        self.clients = clients;
    }
}

impl NetworkBehaviour for Gate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_established_inbound_connection(&mut self, _: ConnectionId, peer: PeerId, local: &Multiaddr, _: &Multiaddr) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        if self.ports.contains(local) != self.clients.contains(&peer) {
            return Err(ConnectionDenied::new(Misplaced(peer)));
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(&mut self, _: ConnectionId, peer: PeerId, _: &Multiaddr, _: Endpoint, _: PortUse) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        // Clients aren't dialled: they dial
        if self.clients.contains(&peer) {
            return Err(ConnectionDenied::new(Misplaced(peer)));
        }
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(&mut self, _: PeerId, _: ConnectionId, event: THandlerOutEvent<Self>) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}
