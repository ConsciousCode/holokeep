//! Claims: sidecar blocks about their targets, which the README describes.
//!
//! So far `Group`, which is what a tag is, `Keep`, which says to keep its
//! targets, `Set`, which says what an anchor is now, and `Tomb`, which
//! retracts.
//!
//! An anchor is an empty identity, in the manner of Perkeep's permanodes:
//! claims hung on it are its state. It's an identity CID of `{anchor:
//! <16 random bytes>}`, so it's named without being stored anywhere.
//!
//! A claim is dag-cbor with its type inline, under the key `claim`. Its
//! `target` is a set, written as an array sorted by CID bytes, so equal
//! claims are equal blocks.
//!
//! A claim with one target which encodes to no more than an identity
//! digest allows is *dissolved*: its CID is its own bytes, so it's named
//! without being hashed, and a store keeps it as rows without a multihash.
//! Anything bigger is precipitated, an ordinary sha2-256 block.

use std::collections::BTreeMap;

use crate::block::{Block, IDENTITY, IDENTITY_MAX};
use crate::cid::{AnyCid, BaseCid, CidRef, Cidv1, Cidv1Spec, DAG_CBOR_CODEC, RAW_CODEC};
use crate::dagcbor;
use crate::model::{Ipld, Link};
use crate::multihash::{Multihash, MultihashFunc};

/// The longest tag name: IPIP-0512's limit on identity digests.
pub const MAX_NAME: usize = IDENTITY_MAX;

/// "Targets belong to the given group." With an identity CID for `into`,
/// a simple tag: the targets are tagged with its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    into: Link,
}

/// "Mark a block as collectable." Locally a claim it targets is retracted
/// at once; the tomb itself outlives it so the claim isn't brought back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tomb {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
}

/// "Keep the targets, and what they link to", short of what's `beyond`.
///
/// `beyond` is the frontier where its reach stops, for DAGs too large to
/// hold, left out when empty. What's added is kept unless said otherwise;
/// what nothing kept links to is, in time, collectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keep {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    /// Sorted by CID bytes and distinct.
    beyond: Vec<Link>,
    /// Which time the targets are kept, from 0, left out when 0: keeping
    /// them again once a keep's been tombed takes a new claim, since a
    /// tomb is forever.
    n: u64,
}

/// "The targets, anchors, are `value` as of `at`", in seconds since the
/// epoch.
///
/// An anchor is whatever its latest set says that counts, by `at`
/// and then CID bytes, so it's mutable while every claim stays put: what
/// it was is the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    value: Link,
    at: u64,
}

/// Any claim this understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Group(Group),
    Keep(Keep),
    Set(Set),
    Tomb(Tomb),
}

/// Sort links by their bytes and drop repeats, making them a set.
fn set(links: impl IntoIterator<Item = Link>) -> Vec<Link> {
    let set: BTreeMap<Vec<u8>, Link> = links.into_iter().map(|link| (link.to_bytes(), link)).collect();
    set.into_values().collect()
}

fn links(links: &[Link]) -> Ipld {
    Ipld::List(links.iter().cloned().map(Ipld::Link).collect())
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
}

impl Keep {
    /// A keep of the targets, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>) -> Option<Self> {
        Self::bounded(target, [])
    }

    /// A keep of the targets short of a frontier, if there are any.
    pub fn bounded(target: impl IntoIterator<Item = Link>, beyond: impl IntoIterator<Item = Link>) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, beyond: set(beyond), n: 0 })
    }

    /// The same keep, but the `n`th time.
    #[must_use]
    pub const fn again(mut self, n: u64) -> Self {
        self.n = n;
        self
    }

    pub const fn n(&self) -> u64 { self.n }

    pub fn target(&self) -> &[Link] { &self.target }

    /// Where the keep's reach stops: what's linked to but not kept.
    pub fn beyond(&self) -> &[Link] { &self.beyond }
}

impl Set {
    /// A set of the anchors, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>, value: Link, at: u64) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, value, at })
    }

    pub fn target(&self) -> &[Link] { &self.target }

    pub const fn value(&self) -> &Link { &self.value }

    pub const fn at(&self) -> u64 { self.at }
}

impl Tomb {
    /// A tomb for the targets, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target })
    }

    pub fn target(&self) -> &[Link] { &self.target }
}

impl Claim {
    pub fn target(&self) -> &[Link] {
        match self {
            Self::Group(group) => group.target(),
            Self::Keep(keep) => keep.target(),
            Self::Set(set) => set.target(),
            Self::Tomb(tomb) => tomb.target(),
        }
    }

    fn to_ipld(&self) -> Ipld {
        let (kind, mut map) = match self {
            Self::Group(group) => ("group", BTreeMap::from([("into".to_owned(), Ipld::Link(group.into.clone()))])),
            Self::Keep(keep) => {
                let mut map = BTreeMap::new();
                if !keep.beyond.is_empty() {
                    map.insert("beyond".to_owned(), links(&keep.beyond));
                }
                if keep.n > 0 {
                    map.insert("n".to_owned(), Ipld::Integer(keep.n.into()));
                }
                ("keep", map)
            },
            Self::Set(set) => ("set", BTreeMap::from([
                ("value".to_owned(), Ipld::Link(set.value.clone())),
                ("at".to_owned(), Ipld::Integer(set.at.into())),
            ])),
            Self::Tomb(_) => ("tomb", BTreeMap::new()),
        };
        map.insert("claim".to_owned(), Ipld::String(kind.to_owned()));
        map.insert("target".to_owned(), links(self.target()));
        Ipld::Map(map)
    }

    fn encode(&self) -> Vec<u8> {
        dagcbor::to_vec(&self.to_ipld()).unwrap_or_default()
    }

    /// Whether the claim is dissolved: one target, and small enough to be
    /// its own CID. A keep with a frontier never is, so a dissolved keep
    /// is always of all of its target.
    pub fn dissolves(&self) -> bool {
        let bounded = matches!(self, Self::Keep(keep) if !keep.beyond.is_empty());
        !bounded && self.target().len() == 1 && self.encode().len() <= IDENTITY_MAX
    }

    /// The claim as a dag-cbor block: an identity block if it dissolves,
    /// otherwise hashed.
    pub fn block(&self) -> Block {
        let data = self.encode();
        if self.dissolves()
            && let Some(block) = Block::identity(DAG_CBOR_CODEC, data.clone().into())
        {
            return block;
        }
        Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), data.into())
    }

    /// The claim's CID, as `block` would make it.
    pub fn cid(&self) -> Link {
        AnyCid::V1(self.block().cid().clone())
    }

    /// The claim a dag-cbor block's bytes are, if they're exactly one:
    /// canonical, with a set of targets and nothing else.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let Ipld::Map(mut map) = dagcbor::from_slice(data).ok()? else {
            return None;
        };
        let Ipld::String(kind) = map.remove("claim")? else {
            return None;
        };
        let Ipld::List(target) = map.remove("target")? else {
            return None;
        };
        let target = link_list(target)?;
        let claim = match kind.as_str() {
            "group" => {
                let Ipld::Link(into) = map.remove("into")? else {
                    return None;
                };
                Self::Group(Group::new(target.clone(), into)?)
            },
            "keep" => {
                let beyond = match map.remove("beyond") {
                    Some(Ipld::List(beyond)) if !beyond.is_empty() => link_list(beyond)?,
                    Some(_) => return None,
                    None => Vec::new(),
                };
                let n = match map.remove("n") {
                    Some(Ipld::Integer(n)) => u64::try_from(n).ok().filter(|&n| n > 0)?,
                    Some(_) => return None,
                    None => 0,
                };
                Self::Keep(Keep::bounded(target.clone(), beyond)?.again(n))
            },
            "set" => {
                let (Ipld::Link(value), Ipld::Integer(at)) = (map.remove("value")?, map.remove("at")?) else {
                    return None;
                };
                Self::Set(Set::new(target.clone(), value, u64::try_from(at).ok()?)?)
            },
            "tomb" => Self::Tomb(Tomb::new(target.clone())?),
            _ => return None,
        };
        // Nothing else, sorted and distinct already, and canonical dag-cbor
        (map.is_empty() && claim.target() == target && claim.encode() == data).then_some(claim)
    }
}

fn link_list(list: Vec<Ipld>) -> Option<Vec<Link>> {
    list.into_iter()
        .map(|link| match link {
            Ipld::Link(link) => Some(link),
            _ => None,
        })
        .collect()
}

/// A new anchor: an identity CID of 16 random bytes, marked as an anchor.
pub fn anchor() -> std::io::Result<Link> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(std::io::Error::other)?;
    let value = Ipld::Map(BTreeMap::from([("anchor".to_owned(), Ipld::Bytes(nonce.to_vec()))]));
    let data = dagcbor::to_vec(&value).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    Block::identity(DAG_CBOR_CODEC, data.into())
        .map(|block| AnyCid::V1(block.cid().clone()))
        .ok_or_else(|| std::io::Error::other("an anchor too large to be an identity"))
}

/// Whether a CID is an anchor.
pub fn is_anchor(cid: &Link) -> bool {
    if cid.codec() != DAG_CBOR_CODEC || cid.hashcode() != IDENTITY {
        return false;
    }
    matches!(dagcbor::from_slice(cid.digest_ref()), Ok(Ipld::Map(map)) if map.len() == 1 && matches!(map.get("anchor"), Some(Ipld::Bytes(nonce)) if nonce.len() == 16))
}

/// The CID of a simple tag: its name, as a raw identity CID.
pub fn tag(name: &str) -> Option<Link> {
    (!name.is_empty()).then_some(())?;
    Block::identity(RAW_CODEC, name.as_bytes().into()).map(|block| AnyCid::V1(block.cid().clone()))
}

/// A simple tag's name, if the CID is one.
pub fn tag_name(cid: &Link) -> Option<&str> {
    (cid.codec() == RAW_CODEC && cid.hashcode() == IDENTITY).then_some(())?;
    std::str::from_utf8(cid.digest_ref()).ok()
}

/// The claim an identity CID is, if it's a dissolved one.
pub fn dissolved(cid: &Link) -> Option<Claim> {
    (cid.codec() == DAG_CBOR_CODEC && cid.hashcode() == IDENTITY).then_some(())?;
    Claim::parse(cid.digest_ref()).filter(Claim::dissolves)
}

/// A dissolved claim's CID from its bytes.
pub fn dissolved_cid(data: &[u8]) -> Option<Link> {
    let hash = Multihash::try_wrap(IDENTITY, data).ok()?;
    Some(AnyCid::V1(Cidv1::new(DAG_CBOR_CODEC, hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(data: &[u8]) -> Link {
        AnyCid::V1(Block::hash(Cidv1Spec::default(), data.into()).cid().clone())
    }

    fn group(target: &[Link], name: &str) -> Claim {
        Claim::Group(Group::new(target.iter().cloned(), tag(name).expect("tag")).expect("group"))
    }

    #[test]
    fn tags_are_identity_cids() {
        let music = tag("music").expect("tag");
        assert_eq!(tag_name(&music), Some("music"));
        // As Kubo inlines it: `ipfs add --inline --raw-leaves`
        assert_eq!(music.to_string(), "bafkqablnovzwsyy");
        assert_eq!(tag(""), None);
        assert!(tag(&"x".repeat(MAX_NAME)).is_some());
        assert_eq!(tag(&"x".repeat(MAX_NAME + 1)), None);
        assert_eq!(tag_name(&cid(b"music")), None);
    }

    #[test]
    fn targets_are_a_set() {
        let (a, b) = (cid(b"a"), cid(b"b"));
        let one = group(&[b.clone(), a.clone(), b.clone()], "t");
        let other = group(&[a, b], "t");
        assert_eq!(one.block(), other.block());
        assert_eq!(one.target().len(), 2);
        assert_eq!(Group::new([], tag("t").expect("tag")), None);
        assert_eq!(Tomb::new([]), None);
    }

    #[test]
    fn small_claims_dissolve() {
        let single = group(&[cid(b"a")], "music");
        assert!(single.dissolves());
        let block = single.block();
        assert_eq!(block.cid().hashcode(), IDENTITY);
        assert_eq!(dissolved(&single.cid()), Some(single.clone()));
        // A tomb for it still fits, though it holds the whole claim
        let tomb = Claim::Tomb(Tomb::new([single.cid()]).expect("tomb"));
        assert!(tomb.dissolves(), "{} bytes", tomb.encode().len());
        assert_eq!(dissolved(&tomb.cid()), Some(tomb));

        // Two targets, or a name too long to fit, are hashed
        let pair = group(&[cid(b"a"), cid(b"b")], "music");
        assert!(!pair.dissolves());
        assert_eq!(pair.block().cid().hashcode(), 0x12);
        let long = group(&[cid(b"a")], &"x".repeat(100));
        assert!(!long.dissolves());
        assert_eq!(dissolved(&long.cid()), None);
    }

    #[test]
    fn parses_only_canonical_claims() {
        let claim = group(&[cid(b"a"), cid(b"b")], "t");
        assert_eq!(Claim::parse(claim.block().data()), Some(claim.clone()));
        let tomb = Claim::Tomb(Tomb::new([cid(b"a")]).expect("tomb"));
        assert_eq!(Claim::parse(tomb.block().data()), Some(tomb));

        let with = |key: &str, value: Ipld| {
            let Ipld::Map(mut map) = claim.to_ipld() else { panic!("a claim is a map") };
            map.insert(key.to_owned(), value);
            dagcbor::to_vec(&Ipld::Map(map)).expect("encode")
        };
        for (label, data) in [
            ("unsorted", with("target", links(&claim.target().iter().rev().cloned().collect::<Vec<_>>()))),
            ("repeated", with("target", links(&[cid(b"a"), cid(b"a")]))),
            ("empty", with("target", links(&[]))),
            ("unknown claim", with("claim", Ipld::String("same".into()))),
            ("an extra key", with("when", Ipld::String("now".into()))),
            ("not a link", with("into", Ipld::String("t".into()))),
            ("a tomb with into", with("claim", Ipld::String("tomb".into()))),
        ] {
            assert_eq!(Claim::parse(&data), None, "{label}");
        }
    }

    #[test]
    fn keeps_round_trip_and_dissolve() {
        let keep = Claim::Keep(Keep::new([cid(b"b"), cid(b"a"), cid(b"a")]).expect("keep"));
        assert_eq!(keep.target().len(), 2, "a set");
        assert!(!keep.dissolves(), "two targets");
        assert_eq!(Claim::parse(keep.block().data()), Some(keep));
        let one = Claim::Keep(Keep::new([cid(b"a")]).expect("keep"));
        assert!(one.dissolves());
        assert_eq!(dissolved(&one.cid()), Some(one));
        assert!(Keep::new([]).is_none());
    }

    #[test]
    fn frontiers_bound_keeps_and_never_dissolve() {
        let keep = Keep::bounded([cid(b"a")], [cid(b"z"), cid(b"y"), cid(b"z")]).expect("keep");
        assert_eq!(keep.beyond().len(), 2, "a set");
        let bounded = Claim::Keep(keep);
        assert!(!bounded.dissolves(), "a dissolved keep is of everything");
        assert_eq!(bounded.cid().hashcode(), 0x12);
        assert_eq!(Claim::parse(bounded.block().data()), Some(bounded));
        // No frontier is no field, so it's the same claim as an unbounded keep
        assert_eq!(Claim::Keep(Keep::bounded([cid(b"a")], []).expect("keep")).cid(), Claim::Keep(Keep::new([cid(b"a")]).expect("keep")).cid());
        // An empty frontier isn't canonical
        let empty = dagcbor::to_vec(&Ipld::Map(BTreeMap::from([
            ("beyond".to_owned(), Ipld::List(Vec::new())),
            ("claim".to_owned(), Ipld::String("keep".into())),
            ("target".to_owned(), Ipld::List(vec![Ipld::Link(cid(b"a"))])),
        ])))
        .expect("encode");
        assert_eq!(Claim::parse(&empty), None);
    }

    #[test]
    fn sets_round_trip_and_dissolve() {
        let anchor = super::anchor().expect("anchor");
        let set = Claim::Set(Set::new([anchor], cid(b"v"), 1_800_000_000).expect("set"));
        assert!(set.dissolves(), "an anchor and a value fit");
        assert_eq!(dissolved(&set.cid()), Some(set.clone()));
        assert_eq!(Claim::parse(set.block().data()), Some(set));
        assert!(Set::new([], cid(b"v"), 0).is_none());
    }

    #[test]
    fn keeps_again_are_new_claims() {
        let first = Claim::Keep(Keep::new([cid(b"a")]).expect("keep"));
        let again = Claim::Keep(Keep::new([cid(b"a")]).expect("keep").again(1));
        assert_ne!(first.cid(), again.cid());
        assert!(again.dissolves());
        assert_eq!(dissolved(&again.cid()), Some(again));
        assert_eq!(Claim::Keep(Keep::new([cid(b"a")]).expect("keep").again(0)).cid(), first.cid(), "0 is left out");
    }
}
