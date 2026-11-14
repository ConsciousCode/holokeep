//! Sharing a mesh's grants: `/holokeep/grants/1.0.0`.
//!
//! Once a mesh has grants (see `crate::grants`), who's in it is what they
//! say, so every machine needs every grant, with what makes each count:
//! the signs of it, and the certificates and revocations of the keys that
//! signed them. On connecting, and whenever its grants change, a machine
//! tells each member which grants it has, by CID, under the mesh's first;
//! the member answers with the grants it has that the asker doesn't, and
//! if the asker has some it doesn't, asks back in turn.
//!
//! Grants are few, so they're named in full each time, not by heads.
//! A machine of an older build doesn't speak this, and a machine of
//! another mesh, or none with grants, is answered with nothing.

use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::cid::{Cid as _, CidRef as _};
use crate::claim::Claim;
use crate::model::Link;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/grants/1.0.0");

/// The grants a machine has of a mesh, by CID, under its first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Have {
    mesh: ByteBuf,
    have: Vec<ByteBuf>,
}

/// Grants the asker didn't have, and what makes them count, as (CID,
/// bytes): every one a claim.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sent {
    blocks: Vec<(ByteBuf, ByteBuf)>,
}

impl Have {
    pub fn new(genesis: &Link, have: impl IntoIterator<Item = Link>) -> Self {
        Self { mesh: ByteBuf::from(genesis.to_bytes()), have: have.into_iter().map(|cid| ByteBuf::from(cid.to_bytes())).collect() }
    }

    /// Whether it's of this mesh.
    pub fn of(&self, genesis: &Link) -> bool {
        self.mesh.as_slice() == genesis.to_bytes()
    }

    /// The grants it has, by CID, those that are CIDs.
    pub fn grants(&self) -> Vec<Link> {
        self.have.iter().filter_map(|cid| Link::decode(cid).ok()).collect()
    }
}

impl Sent {
    pub fn new(blocks: Vec<(Link, Vec<u8>)>) -> Self {
        Self { blocks: blocks.into_iter().map(|(cid, data)| (ByteBuf::from(cid.to_bytes()), ByteBuf::from(data))).collect() }
    }

    /// The claims sent, those which are claims with the CIDs they're sent
    /// under.
    pub fn claims(&self) -> Vec<Claim> {
        self.blocks
            .iter()
            .filter_map(|(cid, data)| {
                let claim = Claim::parse(data)?;
                (claim.cid().to_bytes() == cid.as_slice()).then_some(claim)
            })
            .collect()
    }

    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_claims_under_their_own_cids_are_taken() {
        let key = crate::keys::Key::generate().expect("key");
        let grant = Claim::Grant(crate::claim::Grant::new([key.id()], None, ["/".to_owned()], [], [], []).expect("grant"));
        let other = Claim::Grant(crate::claim::Grant::new([key.id()], None, ["/mesh".to_owned()], [], [], []).expect("grant"));
        let sent = Sent::new(vec![(grant.cid(), grant.block().data().to_vec()), (grant.cid(), other.block().data().to_vec()), (other.cid(), b"junk".to_vec())]);
        assert_eq!(sent.claims(), std::slice::from_ref(&grant));
        let have = Have::new(&grant.cid(), [other.cid()]);
        assert!(have.of(&grant.cid()) && !have.of(&other.cid()));
        assert_eq!(have.grants(), [other.cid()]);
    }
}
