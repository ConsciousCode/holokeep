//! Implementation of dag-pb using our homegrown protobuf primitives.

use bytes::{Bytes, BytesMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::cid::{AnyCid, CidRef, Cid};
use crate::canon::{Canon, CanonBuilder};

use super::error::{InnerError, Origin, Error, CidError, try_context};
use super::pb::{self, PbField, PbDecode, PbType, PbEncode, Uint64, Utf8Bytes};

// AnyCid doesn't appear in protobuf, so we impl it here.
impl<D: AsRef<[u8]>> PbEncode for AnyCid<D> {
    fn pb_size(&self) -> u64 {
        self.size() as u64
    }

    fn pb_encode(&self, buf: &mut BytesMut) {
        self.write(buf)
    }
}
impl PbDecode for AnyCid<Bytes> {
    type Output = Self;
    type Error = CidError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self, Self::Error> {
        let mut bytes = Bytes::pb_decode(buf)?;
        Ok(AnyCid::read(&mut bytes)?)
    }
}

/// Fields of PbLink message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(super) enum PbLinkF {
    Hash = 1,
    Name = 2,
    Tsize = 3,
}

/// PbLink dag-pb message.
#[derive(Debug, Clone)]
pub struct PbLink {
    /// Multihash of the target object.
    pub hash: AnyCid<Bytes>,
    
    /// UTF-8 string name.
    pub name: Utf8Bytes,
    
    /// Cumulative size of target object.
    pub tsize: u64,
}

impl PbLink {
    /// Create a new PbNode.
    pub fn new(hash: AnyCid<Bytes>, name: Utf8Bytes, tsize: u64) -> Self {
        Self { hash, name, tsize }
    }

    pub fn unnamed(hash: AnyCid<Bytes>, tsize: u64) -> Self {
        Self::new(hash, Utf8Bytes::new(), tsize)
    }
}

impl PbEncode for PbLink {
    fn pb_size(&self) -> u64 {
        PbField(0, &self.hash).pb_size() +
        PbField(0, &self.name).pb_size() +
        PbField(0, pb::Uint64(self.tsize)).pb_size()
    }

    fn pb_encode(&self, buf: &mut BytesMut) {
        PbField(PbLinkF::Hash, &self.hash).pb_encode(buf);
        PbField(PbLinkF::Name, &self.name).pb_encode(buf);
        PbField(PbLinkF::Tsize, pb::Uint64(self.tsize)).pb_encode(buf);
    }
}
impl PbDecode for PbLink {
    type Output = Canon<Self>;
    type Error = Error;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        // Reference: https://ipld.io/specs/codecs/dag-pb/spec/
        // dag-pb itself is stricter than unixfsv1, most of what would
        // otherwise be non-canon is an error.
        let mut hash = None;
        let mut name = Utf8Bytes::new();
        let mut tsize = 0;
        let mut seen = 0;
        let mut last = 0u8;
        while let Some((fx, tx)) = pb::next_field(buf) {
            try_context(Origin::Node, fx, tx, || {
                let t = tx.try_into().map_err(|_| InnerError::InvalidTag)?;
                // 4. Fields and wire types other than those that appear in the Protobuf schema above are invalid and blocks containing these should be rejected
                let f = fx.try_into().map_err(|_| InnerError::Unknown)?;
                if fx < last {
                    // 1. Fields in the PBLink message must appear in the order as defined by the Protobuf schema
                    return Err(InnerError::OutOfOrder.into());
                }
                if fx == last {
                    // 3. Duplicate entries in the binary form are invalid; blocks with duplicate field values should be rejected
                    return Err(InnerError::Duplicate.into());
                }
                last = fx;
                seen += 1;

                match (f, t) {
                    // Don't need to check seen because the order
                    // check above already catches it.
                    (PbLinkF::Hash, PbType::Length) =>
                        hash = Some(AnyCid::pb_decode(buf)?),
                    (PbLinkF::Name, PbType::Length) =>
                        name = Utf8Bytes::pb_decode(buf)?,
                    (PbLinkF::Tsize, PbType::Varint) =>
                        tsize = Uint64::pb_decode(buf)?,
                    _ => Err(InnerError::Unknown)?,
                }
                Ok(())
            })?;
        }
        // "Even though Hash is optional in the Protobuf encoding, it should not be treated as optional when creating new blocks or decoding existing ones, an omitted Hash should be interpreted as a bad block"
        //
        // Also Kubo encodes empty Name and Tsize, so if any are missing this is
        // non-canonical.
        if let Some(hash) = hash {
            Ok(Canon::new(PbLink {
                hash,
                name,
                tsize,
            }, seen == 3))
        }
        else {
            Err(InnerError::Missing.with_context(
                Origin::Link, PbLinkF::Hash, PbType::Length
            ))
        }
    }
}

/// Fields of PbNode message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(super) enum PbNodeF {
    Links = 2,
    Data = 1,
}

/// An IPFS dag-pb MerkleDAG node
#[derive(Debug, Clone)]
pub struct PbNode<D> {
    /// refs to other objects
    pub links: Vec<PbLink>,

    /// opaque user data
    pub data: Option<D>,
}

impl<D: Sized> PbNode<D> {
    /// Create a new PbNode.
    pub fn new(links: Vec<PbLink>, data: Option<D>) -> Self {
        Self { links, data }
    }
}

impl<D: PbEncode> PbEncode for PbNode<D> {
    fn pb_size(&self) -> u64 {
        let links: u64 = self.links
            .iter()
            .map(|v| PbField::size(v))
            .sum();
        links + PbField::size(&self.data)
    }
    fn pb_encode(&self, buf: &mut BytesMut) {
        for link in self.links.iter() {
            PbField(PbNodeF::Links, link).pb_encode(buf);
        }
        PbField(PbNodeF::Data, &self.data).pb_encode(buf);
    }
}

impl<D: PbDecode<Output=Canon<D>, Error=Error>> PbDecode for PbNode<D> {
    type Output = Canon<Self>;
    type Error = Error;

    /// Read a PbNode from bytes.
    fn pb_decode(buf: &mut Bytes) -> Result<Canon<Self>, Self::Error> {
        let mut node = CanonBuilder::new(PbNode::new(Vec::new(), None));
        let mut last = u8::MAX;
        while let Some((fx, tx)) = pb::next_field(buf) {
            try_context(Origin::Node, fx, tx, || {
                let t = tx.try_into().map_err(|_| InnerError::InvalidTag)?;
                // 4. Fields and wire types other than those that appear in the Protobuf schema above are invalid and blocks containing these should be rejected

                let f = fx.try_into().map_err(|_| InnerError::Unknown)?;
                // Not >= because Links can be duplicated
                if fx > last {
                    // 2. Fields in the PBNode message must be encoded in the order as defined by the Protobuf schema above. Note that this order does not follow the field numbers. The decoder should accept either order, as IPFS data exists in both forms.
                    node.noncanonical();
                }
                last = fx;

                match (f, t) {
                    (PbNodeF::Links, PbType::Length) => {
                        let mut link = Bytes::pb_decode(buf)?;
                        // Link can't be inlined because that would &mut borrow twice.
                        let link = node.taint(PbLink::pb_decode(&mut link)?);
                        node.links.push(link);
                    },
                    (PbNodeF::Data, PbType::Length) => {
                        // 3. Duplicate entries in the binary form are invalid; blocks with duplicate field values should be rejected.
                        if node.data.is_some() {
                            return Err(InnerError::Duplicate.into());
                        }
                        node.data = Some(node.taint(D::pb_decode(buf)?));
                    },
                    _ => return Err(InnerError::WrongType.into()),
                }
                Ok(())
            })?;
        }
        Ok(node.finish())
    }
}