//! Claims: sidecar blocks about their targets, which the README describes.
//! So far only `Group`, which is what a tag is.
//!
//! A claim is dag-cbor with its type inline, under the key `claim`. Its
//! `target` is a set, written as an array sorted by CID bytes, so equal
//! claims are equal blocks.

use std::collections::BTreeMap;

use crate::block::Block;
use crate::cid::{AnyCid, BaseCid, CidRef, Cidv1, Cidv1Spec, DAG_CBOR_CODEC, RAW_CODEC};
use crate::dagcbor;
use crate::model::{Ipld, Link};
use crate::multihash::{Multihash, MultihashFunc};

/// The multihash code of `identity`, whose digest is the content itself.
const IDENTITY: u64 = 0x00;

/// The longest tag name, as much as a `Link` keeps inline. IPIP-0512
/// allows identity digests of up to 128 bytes.
pub const MAX_NAME: usize = 64;

/// "Targets belong to the given group." With an identity CID for `into`,
/// a simple tag: the targets are tagged with its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    into: Link,
}

/// Sort links by their bytes and drop repeats, making them a set.
fn set(links: impl IntoIterator<Item = Link>) -> Vec<Link> {
    let set: BTreeMap<Vec<u8>, Link> = links.into_iter().map(|link| (link.to_bytes(), link)).collect();
    set.into_values().collect()
}

impl Group {
    /// A group of the targets, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>, into: Link) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, into })
    }

    pub fn target(&self) -> &[Link] { &self.target }

    /// What the targets belong to: the schema's `into`.
    pub const fn group(&self) -> &Link { &self.into }

    fn to_ipld(&self) -> Ipld {
        Ipld::Map(BTreeMap::from([
            ("claim".to_owned(), Ipld::String("group".to_owned())),
            ("target".to_owned(), Ipld::List(self.target.iter().cloned().map(Ipld::Link).collect())),
            ("into".to_owned(), Ipld::Link(self.into.clone())),
        ]))
    }

    /// The claim as a dag-cbor block.
    pub fn block(&self) -> Block {
        let data = dagcbor::to_vec(&self.to_ipld()).unwrap_or_default();
        Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), data.into())
    }

    /// The group claim a dag-cbor block's bytes are, if they're exactly
    /// one: canonical, with a set of targets and nothing else.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let Ipld::Map(mut map) = dagcbor::from_slice(data).ok()? else {
            return None;
        };
        if map.remove("claim")? != Ipld::String("group".to_owned()) {
            return None;
        }
        let Ipld::Link(into) = map.remove("into")? else {
            return None;
        };
        let Ipld::List(target) = map.remove("target")? else {
            return None;
        };
        let target = target
            .into_iter()
            .map(|link| match link {
                Ipld::Link(link) => Some(link),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        if !map.is_empty() {
            return None;
        }
        let group = Self::new(target.clone(), into)?;
        // Sorted and distinct already, and canonical dag-cbor
        (group.target == target && dagcbor::to_vec(&group.to_ipld()).ok()? == data).then_some(group)
    }
}

/// The CID of a simple tag: its name, as a raw identity CID.
pub fn tag(name: &str) -> Option<Link> {
    (!name.is_empty() && name.len() <= MAX_NAME).then_some(())?;
    let hash = Multihash::try_wrap(IDENTITY, name.as_bytes()).ok()?;
    Some(AnyCid::V1(Cidv1::new(RAW_CODEC, hash)))
}

/// A simple tag's name, if the CID is one.
pub fn tag_name(cid: &Link) -> Option<&str> {
    (cid.codec() == RAW_CODEC && cid.hashcode() == IDENTITY).then_some(())?;
    std::str::from_utf8(cid.digest_ref()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(data: &[u8]) -> Link {
        AnyCid::V1(Block::hash(Cidv1Spec::default(), data.into()).cid().clone())
    }

    #[test]
    fn tags_are_identity_cids() {
        let music = tag("music").expect("tag");
        assert_eq!(tag_name(&music), Some("music"));
        // As Kubo inlines it: `ipfs add --inline --raw-leaves`
        assert_eq!(music.to_string(), "bafkqablnovzwsyy");
        assert_eq!(tag(""), None);
        assert_eq!(tag(&"x".repeat(MAX_NAME + 1)), None);
        assert_eq!(tag_name(&cid(b"music")), None);
    }

    #[test]
    fn targets_are_a_set() {
        let (a, b) = (cid(b"a"), cid(b"b"));
        let into = tag("t").expect("tag");
        let one = Group::new([b.clone(), a.clone(), b.clone()], into.clone()).expect("group");
        let other = Group::new([a, b], into.clone()).expect("group");
        assert_eq!(one.block(), other.block());
        assert_eq!(one.target().len(), 2);
        assert_eq!(Group::new([], into), None);
    }

    #[test]
    fn parses_only_canonical_groups() {
        let group = Group::new([cid(b"a"), cid(b"b")], tag("t").expect("tag")).expect("group");
        let block = group.block();
        assert_eq!(Group::parse(block.data()), Some(group.clone()));

        let with = |key: &str, value: Ipld| {
            let Ipld::Map(mut map) = group.to_ipld() else { panic!("a group is a map") };
            map.insert(key.to_owned(), value);
            dagcbor::to_vec(&Ipld::Map(map)).expect("encode")
        };
        let links = |links: Vec<Link>| Ipld::List(links.into_iter().map(Ipld::Link).collect());
        for (label, data) in [
            ("unsorted", with("target", links(group.target().iter().rev().cloned().collect()))),
            ("repeated", with("target", links(vec![cid(b"a"), cid(b"a")]))),
            ("empty", with("target", links(vec![]))),
            ("another claim", with("claim", Ipld::String("same".into()))),
            ("an extra key", with("when", Ipld::String("now".into()))),
            ("not a link", with("into", Ipld::String("t".into()))),
        ] {
            assert_eq!(Group::parse(&data), None, "{label}");
        }
    }
}
