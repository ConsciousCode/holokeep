//! The canonical IPLD data model, which every codec round-trips through.
//!
//! <https://ipld.io/docs/data-model/kinds/>

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use crate::cid::AnyCid;
use crate::multihash::DefaultDigest;

/// A link, preserving its CID version.
pub type Link = AnyCid<DefaultDigest>;

#[derive(Debug, Clone, PartialEq)]
pub enum Ipld {
    Null,
    Bool(bool),
    /// Wide enough for every integer dag-cbor can express, -2^64..2^64.
    Integer(i128),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<Self>),
    Map(BTreeMap<String, Self>),
    Link(Link),
}

impl Serialize for Ipld {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => s.serialize_unit(),
            Self::Bool(b) => s.serialize_bool(*b),
            Self::Integer(i) => match i64::try_from(*i) {
                Ok(i) => s.serialize_i64(i),
                Err(_) => s.serialize_i128(*i),
            },
            Self::Float(f) => s.serialize_f64(*f),
            Self::String(string) => s.serialize_str(string),
            Self::Bytes(bytes) => s.serialize_bytes(bytes),
            Self::List(list) => {
                let mut seq = s.serialize_seq(Some(list.len()))?;
                for item in list {
                    seq.serialize_element(item)?;
                }
                seq.end()
            },
            Self::Map(map) => {
                // Codecs sort keys their own way
                let mut out = s.serialize_map(Some(map.len()))?;
                for (key, value) in map {
                    out.serialize_entry(key, value)?;
                }
                out.end()
            },
            Self::Link(link) => link.serialize(s),
        }
    }
}

struct IpldVisitor;

impl<'de> Visitor<'de> for IpldVisitor {
    type Value = Ipld;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "any IPLD value")
    }

    fn visit_unit<E>(self) -> Result<Ipld, E> { Ok(Ipld::Null) }
    fn visit_none<E>(self) -> Result<Ipld, E> { Ok(Ipld::Null) }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Ipld, D::Error> {
        Ipld::deserialize(d)
    }
    fn visit_bool<E>(self, v: bool) -> Result<Ipld, E> { Ok(Ipld::Bool(v)) }
    fn visit_i64<E>(self, v: i64) -> Result<Ipld, E> { Ok(Ipld::Integer(v.into())) }
    fn visit_u64<E>(self, v: u64) -> Result<Ipld, E> { Ok(Ipld::Integer(v.into())) }
    fn visit_i128<E>(self, v: i128) -> Result<Ipld, E> { Ok(Ipld::Integer(v)) }
    fn visit_f64<E>(self, v: f64) -> Result<Ipld, E> { Ok(Ipld::Float(v)) }
    fn visit_str<E>(self, v: &str) -> Result<Ipld, E> { Ok(Ipld::String(v.into())) }
    fn visit_string<E>(self, v: String) -> Result<Ipld, E> { Ok(Ipld::String(v)) }
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Ipld, E> { Ok(Ipld::Bytes(v.into())) }
    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Ipld, E> { Ok(Ipld::Bytes(v)) }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Ipld, A::Error> {
        let mut list = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
        while let Some(item) = seq.next_element()? {
            list.push(item);
        }
        Ok(Ipld::List(list))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Ipld, A::Error> {
        let mut map = BTreeMap::new();
        while let Some((key, value)) = access.next_entry::<String, Ipld>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(format_args!("duplicate map key {key:?}")));
            }
            map.insert(key, value);
        }
        Ok(Ipld::Map(map))
    }

    /// Links, by the `CID_SERDE_PRIVATE_IDENTIFIER` convention
    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Ipld, D::Error> {
        Link::deserialize(d).map(Ipld::Link)
    }
}

impl<'de> Deserialize<'de> for Ipld {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(IpldVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_dont_bloat_values() {
        // A sha2-256 link inline, so every value isn't paying for the rare
        // long identity digest
        assert!(std::mem::size_of::<Link>() <= 64, "{}", std::mem::size_of::<Link>());
        assert!(std::mem::size_of::<Ipld>() <= 64, "{}", std::mem::size_of::<Ipld>());
    }
}
