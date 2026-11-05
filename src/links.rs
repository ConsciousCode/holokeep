//! The links in a block, read by its codec.

use crate::cid::{DAG_CBOR_CODEC, DAG_JSON_CODEC, DAG_PB_CODEC, GIT_RAW_CODEC, RAW_CODEC};
use crate::model::{Ipld, Link};
use crate::pb::PbNode;
use crate::{dagcbor, dagjson};

/// The CIDv1 codec of `libp2p-key`, which links to nothing.
const LIBP2P_KEY_CODEC: u64 = 0x72;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can't follow links in codec 0x{0:x}")]
    Codec(u64),

    #[error("{0}")]
    Invalid(String),
}

/// Every link in a block, in order.
pub fn links(codec: u64, data: &[u8]) -> Result<Vec<Link>, Error> {
    fn walk(value: Ipld, out: &mut Vec<Link>) {
        match value {
            Ipld::Link(link) => out.push(link),
            Ipld::List(items) => items.into_iter().for_each(|item| walk(item, out)),
            Ipld::Map(map) => map.into_values().for_each(|item| walk(item, out)),
            _ => {},
        }
    }
    let invalid = |e: &dyn std::fmt::Display| Error::Invalid(e.to_string());
    let mut out = Vec::new();
    match codec {
        RAW_CODEC | LIBP2P_KEY_CODEC => {},
        DAG_PB_CODEC => {
            for link in PbNode::decode(data).map_err(|e| invalid(&e))?.links {
                out.push(link.cid().map_err(|e| invalid(&format!("{e:?}")))?);
            }
        },
        DAG_CBOR_CODEC => walk(dagcbor::from_slice(data).map_err(|e| invalid(&e))?, &mut out),
        DAG_JSON_CODEC => walk(dagjson::from_slice(data).map_err(|e| invalid(&e))?, &mut out),
        GIT_RAW_CODEC => out = crate::git::links(data).map_err(|e| invalid(&e))?,
        codec => return Err(Error::Codec(codec)),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_links_in_known_codecs_only() {
        assert!(links(RAW_CODEC, b"anything").expect("raw").is_empty());
        assert_eq!(links(DAG_JSON_CODEC, br#"[{"/":"bafkqaaa"}, {"a": {"/":"bafkqaaa"}}]"#).expect("json").len(), 2);
        assert!(matches!(links(DAG_CBOR_CODEC, b"\xff"), Err(Error::Invalid(_))));
        assert!(matches!(links(0x78, b""), Err(Error::Invalid(_))));
        assert!(matches!(links(0x7b, b""), Err(Error::Codec(0x7b))));
    }
}
