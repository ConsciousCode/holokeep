//! Minimal, strict dag-pb codec: just the `PBNode`/`PBLink` framing, with
//! no interpretation of Data (that's `unixfs`).
//!
//! Encoding is canonical: Links before Data, link fields in order, absent
//! optional fields left out. Decoding enforces the same structure, as the
//! spec requires: no unknown or repeated fields, no fields out of order,
//! and every link Hash a valid CID.
//!
//! <https://ipld.io/specs/codecs/dag-pb/spec/>

use std::borrow::Cow;

use crate::cid::{self, AnyCid, Cid};
use crate::multihash::{DefaultDigest, Inline};
use crate::varint;

/// A dag-pb `PBLink`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbLink<'a> {
    /// Binary CID of the linked block.
    pub hash: Cow<'a, [u8]>,
    pub name: Option<&'a [u8]>,
    /// Cumulative serialized size of the linked DAG.
    pub tsize: Option<u64>,
}

/// A dag-pb `PBNode`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PbNode<'a> {
    pub links: Vec<PbLink<'a>>,
    pub data: Option<&'a [u8]>,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("truncated")]
    Truncated,

    #[error("varint overflow")]
    Overflow,

    #[error("unexpected field {field} with wire type {wire} in {message}")]
    Field { message: &'static str, field: u64, wire: u64 },

    #[error("{0} is repeated or out of order")]
    Order(&'static str),

    #[error("link has no Hash")]
    MissingHash,

    #[error("invalid link Hash")]
    Hash(#[from] cid::DecodeError),

    #[error("invalid UnixFS data: {0}")]
    Unixfs(&'static str),
}

impl From<varint::Error> for DecodeError {
    fn from(value: varint::Error) -> Self {
        match value {
            varint::Error::Truncated => Self::Truncated,
            // Protobuf doesn't require minimal varints
            varint::Error::Overflow | varint::Error::NonMinimal => Self::Overflow,
        }
    }
}

/// A well-typed node which still isn't valid dag-pb.
#[derive(Debug, thiserror::Error)]
pub enum FormError {
    #[error("links must be sorted by Name bytes")]
    Unsorted,
}

impl<'a> PbLink<'a> {
    /// Parse the link's Hash, which decoding has already validated.
    pub fn cid(&self) -> Result<AnyCid<DefaultDigest>, cid::DecodeError> {
        AnyCid::decode(&self.hash)
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_bytes(buf, 1, &self.hash);
        if let Some(name) = self.name {
            put_bytes(buf, 2, name);
        }
        if let Some(tsize) = self.tsize {
            put_uint(buf, 3, tsize);
        }
    }

    fn decode(mut buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut hash = None;
        let mut name = None;
        let mut tsize = None;
        // Fields must appear at most once, in ascending order
        let mut last = 0;
        while !buf.is_empty() {
            let (field, wire) = read_tag(&mut buf)?;
            if field <= last {
                return Err(DecodeError::Order(match field {
                    1 => "Hash",
                    2 => "Name",
                    _ => "Tsize",
                }));
            }
            match (field, wire) {
                (1, LEN) => hash = Some(read_bytes(&mut buf)?),
                (2, LEN) => name = Some(read_bytes(&mut buf)?),
                (3, VARINT) => tsize = Some(varint::read(&mut buf)?),
                (field, wire) => return Err(DecodeError::Field { message: "PBLink", field, wire }),
            }
            last = field;
        }

        let hash = hash.ok_or(DecodeError::MissingHash)?;
        // Room for identity CIDs, which IPIP-0512 caps at 128 bytes
        AnyCid::<Inline<128>>::decode(hash)?;
        Ok(Self { hash: Cow::Borrowed(hash), name, tsize })
    }
}

impl<'a> PbNode<'a> {
    /// Check the rules the types can't express.
    pub fn validate(&self) -> Result<(), FormError> {
        // Absent names sort as empty; equal names keep their order
        if self.links.is_sorted_by_key(|link| link.name.unwrap_or_default()) {
            Ok(())
        }
        else {
            Err(FormError::Unsorted)
        }
    }

    /// Serialize the node canonically. Doesn't `validate` it.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut scratch = Vec::new();
        for link in &self.links {
            scratch.clear();
            link.encode(&mut scratch);
            put_bytes(&mut buf, 2, &scratch);
        }
        if let Some(data) = self.data {
            put_bytes(&mut buf, 1, data);
        }
        buf
    }

    /// Parse a node, borrowing from `buf`.
    pub fn decode(mut buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut node = Self::default();
        while !buf.is_empty() {
            match read_tag(&mut buf)? {
                // Links come before Data, so either after Data is out of order
                _ if node.data.is_some() => return Err(DecodeError::Order("Data")),
                (2, LEN) => node.links.push(PbLink::decode(read_bytes(&mut buf)?)?),
                (1, LEN) => node.data = Some(read_bytes(&mut buf)?),
                (field, wire) => return Err(DecodeError::Field { message: "PBNode", field, wire }),
            }
        }
        Ok(node)
    }
}

//------------------------//
//-[ Protobuf primitives ]-//
//------------------------//

pub const VARINT: u64 = 0;
pub const FIXED64: u64 = 1;
pub const LEN: u64 = 2;
pub const FIXED32: u64 = 5;

fn put_tag(buf: &mut Vec<u8>, field: u64, wire: u64) {
    varint::write(buf, field << 3 | wire);
}

pub fn put_uint(buf: &mut Vec<u8>, field: u64, value: u64) {
    put_tag(buf, field, VARINT);
    varint::write(buf, value);
}

pub fn put_bytes(buf: &mut Vec<u8>, field: u64, value: &[u8]) {
    put_tag(buf, field, LEN);
    varint::write(buf, u64::try_from(value.len()).unwrap_or(u64::MAX));
    buf.extend_from_slice(value);
}

/// Read a (field, wire type) tag.
pub fn read_tag(buf: &mut &[u8]) -> Result<(u64, u64), DecodeError> {
    let tag = varint::read(buf)?;
    Ok((tag >> 3, tag & 7))
}

/// Read a length-delimited value.
pub fn read_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], DecodeError> {
    let len = usize::try_from(varint::read(buf)?).map_err(|_| DecodeError::Truncated)?;
    let (value, rest) = buf.split_at_checked(len).ok_or(DecodeError::Truncated)?;
    *buf = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::{CidRef, Cidv1, Cidv1Spec};

    fn hash() -> Vec<u8> {
        Cidv1Spec::default().hash::<Inline<64>>(b"hello world").to_bytes()
    }

    fn link(name: Option<&[u8]>, tsize: Option<u64>) -> PbLink<'_> {
        PbLink { hash: hash().into(), name, tsize }
    }

    #[test]
    fn empty_node() {
        assert_eq!(PbNode::default().encode(), b"");
        assert_eq!(PbNode::decode(b"").expect("empty"), PbNode::default());
        // Present but empty Data is distinct from absent
        let node = PbNode { data: Some(b""), ..PbNode::default() };
        assert_eq!(node.encode(), [0x0a, 0x00]);
        assert_eq!(PbNode::decode(&[0x0a, 0x00]).expect("empty data"), node);
    }

    #[test]
    fn round_trip_optional_fields() {
        for name in [None, Some(&b""[..]), Some(b"a")] {
            for tsize in [None, Some(0), Some(300)] {
                let node = PbNode { links: vec![link(name, tsize)], data: Some(b"\x08\x01") };
                let bytes = node.encode();
                assert_eq!(PbNode::decode(&bytes).expect("decode"), node, "{name:?} {tsize:?}");
            }
        }
    }

    #[test]
    fn link_cid() {
        let node = PbNode { links: vec![link(None, None)], data: None };
        let bytes = node.encode();
        let decoded = PbNode::decode(&bytes).expect("decode");
        let cid: Cidv1 = decoded.links[0].cid().expect("cid").into();
        assert_eq!(cid.to_string(), "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e");
    }

    #[test]
    fn rejects_bad_structure() {
        let link = PbNode { links: vec![link(Some(b"a"), Some(1))], data: None }.encode();
        let cases: [(&str, Vec<u8>); 6] = [
            ("truncated", link[..link.len() - 1].to_vec()),
            ("unknown field", vec![0x18, 0x01]),
            ("wrong wire type", vec![0x0d, 0, 0, 0, 0]),
            ("links after data", [&[0x0a, 0x00][..], &link].concat()),
            ("repeated data", vec![0x0a, 0x00, 0x0a, 0x00]),
            ("tsize before name", {
                let mut inner = Vec::new();
                put_bytes(&mut inner, 1, &hash());
                put_uint(&mut inner, 3, 1);
                put_bytes(&mut inner, 2, b"a");
                let mut buf = Vec::new();
                put_bytes(&mut buf, 2, &inner);
                buf
            }),
        ];
        for (label, bytes) in cases {
            assert!(PbNode::decode(&bytes).is_err(), "{label}");
        }
    }

    #[test]
    fn validate_sorting() {
        let sorted = PbNode {
            links: vec![link(None, None), link(Some(b"a"), None), link(Some(b"a"), None), link(Some(b"ab"), None), link(Some(b"b"), None)],
            data: None,
        };
        assert!(sorted.validate().is_ok());
        let unsorted = PbNode { links: vec![link(Some(b"b"), None), link(Some(b"a"), None)], data: None };
        assert!(unsorted.validate().is_err());
        // Shorter sorts first
        let unsorted = PbNode { links: vec![link(Some(b"ab"), None), link(Some(b"a"), None)], data: None };
        assert!(unsorted.validate().is_err());
    }
}
