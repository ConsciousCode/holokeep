//! Saying which users a machine hosts: `/holokeep/hosts/1.0.0`.
//!
//! A mesh is its machines, and a machine may serve several of the mesh's
//! users, an account of the repo for each. On connecting, and whenever
//! what it hosts changes, each tells the other which users it hosts: for
//! each, the device key the machine acts for the user with, and that
//! key's signature over the machine's peer ID, so only a machine holding
//! one of a user's device keys can say it hosts them. A user's blocks are
//! served, noticed and pushed only to machines hosting the user.
//!
//! A machine checks what it's told only of the users it hosts itself,
//! against their certificates here: of anyone else's, it has nothing to
//! serve.
//!
//! A machine of an older build doesn't speak this, and is taken to host
//! the user the mesh was for, as it did.

use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::cid::{Cid as _, CidRef as _};
use crate::keys::Key;
use crate::model::Link;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/hosts/1.0.0");

/// What a device key signs to say its machine hosts its user.
const CONTEXT: &[u8] = b"holokeep hosts\x00";

/// The users a machine hosts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hosts {
    hosts: Vec<Host>,
}

/// One user a machine hosts: the user's key and the device key it acts
/// with, as CIDs, and the device's signature over the machine's peer ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    user: ByteBuf,
    device: ByteBuf,
    sig: ByteBuf,
}

/// Give a request type an optional `user`, saying whose blocks it's
/// about: `user()` and `for_user()`.
macro_rules! for_user {
    ($type:ty) => {
        impl $type {
            /// Whose blocks this is about, by the user's key CID's bytes:
            /// none from an older build, for the user the mesh was for.
            pub fn user(&self) -> Option<&[u8]> {
                self.user.as_ref().map(|user| user.as_slice())
            }

            /// Say whose blocks this is about.
            #[must_use]
            pub fn for_user(mut self, user: Option<&[u8]>) -> Self {
                self.user = user.map(|user| serde_bytes::ByteBuf::from(user.to_vec()));
                self
            }
        }
    };
}
pub(crate) use for_user;

fn message(machine: &PeerId) -> Vec<u8> {
    [CONTEXT, &machine.to_bytes()].concat()
}

impl Host {
    /// Say a machine hosts a user, signing with the device key it acts
    /// for the user with.
    pub fn new(machine: &PeerId, user: &Link, device: &Key) -> Self {
        Self {
            user: ByteBuf::from(user.to_bytes()),
            device: ByteBuf::from(device.id().to_bytes()),
            sig: ByteBuf::from(device.sign(&message(machine))),
        }
    }

    /// The user, and the device it's hosted with, if its signature's the
    /// device's, over the machine's peer ID.
    pub fn verify(&self, machine: &PeerId) -> Option<(Link, Link)> {
        let user = Link::decode(&self.user).ok()?;
        let device = Link::decode(&self.device).ok()?;
        crate::keys::verify(&device, &message(machine), &self.sig).then_some((user, device))
    }
}

impl Hosts {
    pub const fn new(hosts: Vec<Host>) -> Self {
        Self { hosts }
    }

    pub fn hosts(&self) -> &[Host] {
        &self.hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_machine_signed_for_hosts_the_user() {
        let (user, device) = (Key::generate().expect("key"), Key::generate().expect("key"));
        let (machine, other) = (PeerId::random(), PeerId::random());
        let host = Host::new(&machine, &user.id(), &device);
        assert_eq!(host.verify(&machine), Some((user.id(), device.id())));
        assert_eq!(host.verify(&other), None, "another machine can't say so with it");
        let mut forged = host;
        forged.device = ByteBuf::from(Key::generate().expect("key").id().to_bytes());
        assert_eq!(forged.verify(&machine), None, "nor another key");
    }
}
