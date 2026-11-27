//! Incoming streams of one protocol, each handed over as soon as it's
//! negotiated, however many come at once. libp2p-stream hands them over
//! through a channel with no room, resetting whichever comes while one's
//! waiting; and Kubo sends each Bitswap answer on a stream of its own,
//! several at a time, and doesn't send again what a reset lost.

use std::convert::Infallible;
use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::upgrade::{DeniedUpgrade, ReadyUpgrade};
use libp2p::core::Endpoint;
use libp2p::swarm::handler::{ConnectionEvent, FullyNegotiatedInbound};
use libp2p::swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm, NetworkBehaviour, Stream, StreamProtocol, SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent,
    ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc::UnboundedSender;

/// A stream that's come, and who from.
pub type Incoming = (PeerId, Stream);

/// Takes a protocol's incoming streams, on every connection.
pub struct Behaviour {
    protocol: StreamProtocol,
    streams: UnboundedSender<Incoming>,
}

impl Behaviour {
    pub const fn new(protocol: StreamProtocol, streams: UnboundedSender<Incoming>) -> Self {
        Self { protocol, streams }
    }

    fn handler(&self, peer: PeerId) -> Handler {
        Handler { peer, protocol: self.protocol.clone(), streams: self.streams.clone() }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(&mut self, _: ConnectionId, peer: PeerId, _: &Multiaddr, _: &Multiaddr) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.handler(peer))
    }

    fn handle_established_outbound_connection(&mut self, _: ConnectionId, peer: PeerId, _: &Multiaddr, _: Endpoint, _: PortUse) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.handler(peer))
    }

    fn on_swarm_event(&mut self, _: FromSwarm<'_>) {}

    fn on_connection_handler_event(&mut self, _: PeerId, _: ConnectionId, event: THandlerOutEvent<Self>) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

/// One connection's: each stream negotiated straight onto the channel.
pub struct Handler {
    peer: PeerId,
    protocol: StreamProtocol,
    streams: UnboundedSender<Incoming>,
}

impl ConnectionHandler for Handler {
    type FromBehaviour = Infallible;
    type ToBehaviour = Infallible;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = DeniedUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = Infallible;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(self.protocol.clone()), ())
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>> {
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {}
    }

    fn on_connection_event(&mut self, event: ConnectionEvent<'_, Self::InboundProtocol, Self::OutboundProtocol, Self::InboundOpenInfo, Self::OutboundOpenInfo>) {
        if let ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound { protocol: stream, .. }) = event {
            // Gone only as the swarm is, when the stream may go too
            let _ = self.streams.send((self.peer, stream));
        }
    }
}
