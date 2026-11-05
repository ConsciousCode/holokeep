//! Letting go of copies the mesh can spare, when space runs short:
//! `/holokeep/trim/1.0.0` and `/holokeep/dropped/1.0.0`.
//!
//! This is collecting surplus, not garbage: nothing is deleted from the
//! mesh, only copies beyond what durability asks for. Which blocks should
//! live at all is for claims to say (keeps and tombs), later.
//!
//! Space is kept between watermarks. When the repo's free space falls
//! below the low one, the node trims until it's back above the high one,
//! and between them it neither trims nor takes copies from others, so it
//! doesn't flap at a threshold. Its offers count only the space above the
//! high mark.
//!
//! A leaf (structure stays, being small and what's queried) whose copies
//! here could go is a candidate when its copies elsewhere, as sighted,
//! would still take `copies` failures to lose. Sightings may be wrong, so
//! before letting go the node asks every connected member what it holds
//! of the candidates, now: an *intent*. Each answers with its copies, a
//! *grant*, and only what's still enough by those answers goes. Two nodes
//! may mean to let go of the same block at once; a member which is itself
//! about to let go of a block refuses an intent for it unless the asker is
//! ranked below it, by the same rendezvous hashing which ranks holders,
//! and if so gives way: the lowest-ranked lets go first, so both never do.
//!
//! What's let go of is told to every member, which forget their sightings
//! of it, and audit it soon if they hold it: while who's connected doesn't
//! change, a node's sightings of the others needn't expire, since anything
//! they let go of they'd have said.

use std::collections::{BTreeMap, HashSet};

use libp2p::request_response::OutboundRequestId;
use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::multihash::Multihash;
use crate::store::{BlockIndex as _, Catalog, Replica, tolerance};

use super::durability::{Sightings, distinct, score};
use super::mesh::Result;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/trim/1.0.0");
pub const DROPPED: StreamProtocol = StreamProtocol::new("/holokeep/dropped/1.0.0");

/// The most blocks in one intent.
const BATCH: usize = 512;

/// Blocks a node means to let go of.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Intent {
    keys: Vec<ByteBuf>,
}

/// An answer to an intent: the copies held here of what it names, and
/// what this node means to let go of first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Grant {
    held: Vec<(ByteBuf, Vec<Replica>)>,
    refused: Vec<ByteBuf>,
}

impl Grant {
    /// Say nothing of holding whichever blocks these are.
    pub fn withhold(&mut self, mut withheld: impl FnMut(&[u8]) -> bool) {
        self.held.retain(|(key, _)| !withheld(key));
    }
}

/// Blocks a node has let go of.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dropped {
    keys: Vec<ByteBuf>,
}

impl Dropped {
    pub fn keys(&self) -> impl Iterator<Item = Multihash> + '_ {
        self.keys.iter().filter_map(|key| <Multihash>::decode(key).ok())
    }
}

/// An acknowledgement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ack {}

/// Whether `a` lets go of a block before `b`: the lower ranked first.
pub fn drops_before(key: &[u8], a: &PeerId, b: &PeerId) -> bool {
    score(key, a, 1.0) < score(key, b, 1.0)
}

/// Where the repo's free space is kept: trimming starts below `low` and
/// stops above `high`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Watermarks {
    pub low: u64,
    pub high: u64,
    trimming: bool,
}

impl Watermarks {
    pub const fn new(low: u64, high: u64) -> Self {
        Self { low, high: if high < low { low } else { high }, trimming: false }
    }

    /// Take in the free space now, and say whether to trim.
    pub const fn update(&mut self, free: u64) -> bool {
        if free < self.low {
            self.trimming = true;
        } else if free >= self.high {
            self.trimming = false;
        }
        self.trimming
    }

    /// Whether it's between trimming down and coming back up.
    pub const fn pressed(&self) -> bool {
        self.trimming
    }

    /// The space others may fill: what's above the high mark.
    pub const fn spare(&self, free: u64) -> u64 {
        free.saturating_sub(self.high)
    }
}

/// What a trim did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Blocks whose copies here looked spare.
    pub considered: usize,
    /// Blocks let go of.
    pub dropped: usize,
    /// Bytes freed.
    pub freed: u64,
}

/// A block this node means to let go of.
#[derive(Debug, Default)]
struct Candidate {
    /// Its copies here on volumes which aren't the repo's own, which stay.
    staying: Vec<Replica>,
    /// Copies members have said they hold, now.
    granted: BTreeMap<PeerId, Vec<Replica>>,
    /// A member lets go of it first.
    refused: bool,
    /// How many failures it should take to lose it, as its nearest keeps
    /// say, or as the trim runs with.
    copies: usize,
}

/// Letting go of what's spare of some blocks.
pub struct Trim {
    candidates: BTreeMap<Vec<u8>, Candidate>,
    awaiting: HashSet<OutboundRequestId>,
    report: Report,
}

impl Trim {
    /// Of these blocks, those whose copies here could go and whose copies
    /// elsewhere, as sighted, would still take `copies` failures to lose.
    /// Returns the trim and the intents to send every peer.
    pub fn start(catalog: &Catalog, sightings: &Sightings, peers: &[PeerId], copies: usize, keys: impl IntoIterator<Item = Multihash>) -> Result<(Self, Vec<Intent>)> {
        let own = catalog.own_labels();
        let mut trim = Self { candidates: BTreeMap::new(), awaiting: HashSet::new(), report: Report::default() };
        for key in keys {
            let bytes = key.to_bytes();
            // Spare to this mesh is only spare here if no other account has
            // it
            if trim.candidates.contains_key(&bytes)
                || !catalog.can_drop(key.as_ref())?
                || !catalog.visible(key.as_ref())?
                || catalog.visible_to_others(key.as_ref())?
            {
                continue;
            }
            let staying: Vec<Replica> = catalog.replicas(key.as_ref())?.into_iter().filter(|replica| !own.contains(&replica.label)).collect();
            let sighted: Vec<Replica> = sightings.of(key.as_ref())?.into_iter().filter(|(peer, _)| peers.contains(peer)).map(|(_, replica)| replica).collect();
            let copies = catalog.copies_wanted(key.as_ref(), copies)?.unwrap_or(copies);
            if tolerance(&distinct(staying.iter().chain(&sighted)), copies) < copies {
                continue;
            }
            trim.candidates.insert(bytes, Candidate { staying, copies, ..Candidate::default() });
        }
        trim.report.considered = trim.candidates.len();
        let keys: Vec<ByteBuf> = trim.candidates.keys().cloned().map(ByteBuf::from).collect();
        let intents = keys.chunks(BATCH).map(|keys| Intent { keys: keys.to_vec() }).collect();
        Ok((trim, intents))
    }

    pub fn sent(&mut self, request: OutboundRequestId) {
        self.awaiting.insert(request);
    }

    pub fn asked(&self, request: OutboundRequestId) -> bool {
        self.awaiting.contains(&request)
    }

    /// Whether this means to let go of a block.
    pub fn means(&self, key: &[u8]) -> bool {
        self.candidates.get(key).is_some_and(|candidate| !candidate.refused)
    }

    /// Give way to a member letting go of a block first.
    pub fn give_way(&mut self, key: &[u8]) {
        if let Some(candidate) = self.candidates.get_mut(key) {
            candidate.refused = true;
        }
    }

    /// Take in a member's grant.
    pub fn granted(&mut self, request: OutboundRequestId, peer: PeerId, grant: Grant) {
        if !self.awaiting.remove(&request) {
            return;
        }
        for (key, replicas) in grant.held {
            if let Some(candidate) = self.candidates.get_mut(key.as_slice()) {
                candidate.granted.insert(peer, replicas);
            }
        }
        for key in grant.refused {
            self.give_way(&key);
        }
    }

    /// A member which didn't answer: its copies aren't counted.
    pub fn failed(&mut self, request: OutboundRequestId) {
        self.awaiting.remove(&request);
    }

    pub fn waiting(&self) -> bool {
        !self.awaiting.is_empty()
    }

    /// Once every member's answered, what can go: blocks still enough
    /// without the copies here, by what members said.
    pub fn decide(&self) -> Vec<Multihash> {
        self.candidates
            .iter()
            .filter(|(_, candidate)| !candidate.refused)
            .filter(|(_, candidate)| tolerance(&distinct(candidate.staying.iter().chain(candidate.granted.values().flatten())), candidate.copies) >= candidate.copies)
            .filter_map(|(key, _)| <Multihash>::decode(key).ok())
            .collect()
    }

    /// Note what was let go of.
    pub const fn dropped(&mut self, blocks: usize, freed: u64) {
        self.report.dropped = self.report.dropped.saturating_add(blocks);
        self.report.freed = self.report.freed.saturating_add(freed);
    }

    pub fn report(&self) -> Report {
        self.report.clone()
    }
}

/// Answer an intent: the copies held here of what it names, refusing
/// what a trim here lets go of first, and giving way where the asker
/// does.
pub fn answer(catalog: &Catalog, me: &PeerId, peer: &PeerId, intent: &Intent, trims: &mut [&mut Trim]) -> Result<Grant> {
    let mut grant = Grant::default();
    for key in &intent.keys {
        let Ok(multihash) = <Multihash>::decode(key) else {
            continue;
        };
        if !catalog.has(multihash.as_ref())? || !catalog.visible(multihash.as_ref())? {
            continue;
        }
        let mine = trims.iter().any(|trim| trim.means(key));
        if mine && !drops_before(key, peer, me) {
            grant.refused.push(key.clone());
            continue;
        }
        for trim in trims.iter_mut() {
            trim.give_way(key);
        }
        grant.held.push((key.clone(), catalog.replicas(multihash.as_ref())?));
    }
    Ok(grant)
}

/// What was let go of, to tell members.
pub fn dropped(keys: &[Multihash]) -> Dropped {
    Dropped { keys: keys.iter().map(|key| ByteBuf::from(key.to_bytes())).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watermarks_keep_space_between_them() {
        let mut marks = Watermarks::new(100, 200);
        assert!(!marks.update(150), "between them, from calm: calm");
        assert!(marks.update(99), "below the low mark: trim");
        assert!(marks.update(150), "between them, trimming: keep trimming");
        assert!(!marks.update(200), "at the high mark: stop");
        assert!(!marks.update(150));
        assert_eq!(marks.spare(250), 50);
        assert_eq!(marks.spare(150), 0);
        assert_eq!(Watermarks::new(300, 200).high, 300, "the high mark's at least the low");
    }

    #[test]
    fn only_leaves_in_the_repos_own_stores_can_be_let_go_of() {
        use crate::block::Block;
        use crate::cid::{CidRef, CidVersion, Cidv1Spec, DAG_CBOR_CODEC};
        use crate::multihash::MultihashFunc;
        let scratch = crate::testutil::Scratch::new("trim-drop");
        let catalog = Catalog::open_repo(scratch.path()).expect("open");
        let small = Block::hash(Cidv1Spec::default(), b"small leaf".as_slice().into());
        // Large enough for the shards
        let large = Block::hash(Cidv1Spec::default(), vec![7u8; 128 << 10].into());
        let data = crate::dagcbor::to_vec(&crate::model::Ipld::List(vec![crate::model::Ipld::Link(small.cid().clone().into())])).expect("encode");
        let structure = Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), data.into());
        for block in [&small, &large, &structure] {
            catalog.put_block(block, CidVersion::V1).expect("put");
        }
        assert_eq!(catalog.store_of(large.cid().multihash()).expect("store").as_deref(), Some("flatfs"));
        assert!(!catalog.can_drop(structure.cid().multihash()).expect("can"), "structure stays");
        assert_eq!(catalog.drop_copies(structure.cid().multihash()).expect("drop"), None);
        assert_eq!(catalog.drop_copies(small.cid().multihash()).expect("drop"), Some(10));
        assert_eq!(catalog.drop_copies(large.cid().multihash()).expect("drop"), Some(128 << 10));
        for leaf in [&small, &large] {
            assert!(!catalog.has(leaf.cid().multihash()).expect("has"));
            assert_eq!(catalog.get_block(&leaf.cid().clone().into()).expect("get"), None);
        }
        // And the shards forget it, so a reopened catalog doesn't find it
        drop(catalog);
        let catalog = Catalog::open_repo(scratch.path()).expect("reopen");
        assert!(!catalog.has(large.cid().multihash()).expect("has"));
    }

    #[test]
    fn the_lowest_ranked_lets_go_first() {
        let (a, b) = (PeerId::random(), PeerId::random());
        for key in 0..32u8 {
            assert_ne!(drops_before(&[key], &a, &b), drops_before(&[key], &b, &a));
        }
    }
}
