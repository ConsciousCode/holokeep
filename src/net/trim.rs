//! Letting go of copies here once they're worth less than the space
//! they take, without the mesh losing anything for it:
//! `/holokeep/trim/1.0.0` and `/holokeep/dropped/1.0.0`.
//!
//! This is collecting surplus, not garbage: nothing is deleted from the
//! mesh, only copies here, or handed to a member they're worth more to.
//! Which blocks should live at all is for claims to say (keeps and
//! tombs).
//!
//! A copy here is worth what it adds to its block's copies, one for each
//! member holding one, weighed as `balance` says, and space costs the odds of this node's being
//! full, the copy included; one worth less than its space is let go of.
//! So there's no line at which trimming starts: as a node fills, the
//! copies past what blocks want go first, then more, but never the last
//! copy of anything.
//!
//! A leaf (structure stays, being small and what's queried) whose copy
//! here is worth less than its space, by the copies elsewhere as
//! sighted, is a candidate. Sightings may be wrong, so before letting go
//! the node asks every connected member what it holds of the candidates,
//! now: an *intent*. Each answers with its copies, a *grant*, and only
//! what's still worth less by those answers goes. Two nodes may mean to
//! let go of the same block at once; a member which is itself about to
//! let go of a block refuses an intent for it unless the asker is ranked
//! below it, by the same rendezvous hashing which ranks holders, and if
//! so gives way: the lowest-ranked lets go first, so both never do.
//!
//! When trimming of itself, a candidate a member would value more than
//! its space costs it is *handed off* rather than dropped: a grant says
//! where its member would keep a block and how full it is, as an
//! advert's answer does, and the block is pushed to the member chosen as
//! an audit chooses, one holding none, and goes once that member's said
//! it kept it, so there are as many copies as before: blocks move to
//! emptier members whole, and a last copy moves rather than going.
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
use crate::balance::{Fill, Scales, Worth};
use crate::store::{BlockIndex as _, Catalog, Offer, Replica};

use super::durability::{Kept, Sightings, choose, holders, offered, score};
use super::mesh::Result;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/trim/1.0.0");
pub const DROPPED: StreamProtocol = StreamProtocol::new("/holokeep/dropped/1.0.0");

/// The most blocks in one intent.
pub const BATCH: usize = 512;

/// About the most block data one trim hands off: it's held in memory to
/// push, and a trim which freed space is followed by another at once.
const HANDING: u64 = 64 << 20;

/// Blocks a node means to let go of.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Intent {
    keys: Vec<ByteBuf>,
    /// Whose blocks these are, as `Want`'s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<ByteBuf>,
}

super::hosts::for_user!(Intent);

/// An answer to an intent: the copies held here of what it names, what
/// this node means to let go of first, and where it would keep a block
/// handed to it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Grant {
    held: Vec<(ByteBuf, Vec<Replica>)>,
    refused: Vec<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offer: Option<Offer>,
}

impl Grant {
    /// Where the member would keep a block, and how full it is.
    pub const fn offer(&self) -> Option<&Offer> {
        self.offer.as_ref()
    }

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

/// Where the repo's space stands: the most to keep here, if there's a
/// most, and what's stored, as last measured and taken in since.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Space {
    pub target: Option<u64>,
    stored: u64,
}

impl Space {
    pub const fn new(target: Option<u64>) -> Self {
        Self { target, stored: 0 }
    }

    /// Take in what's stored here, as measured.
    pub const fn update(&mut self, stored: u64) {
        self.stored = stored;
    }

    /// Note what's been taken in since what's stored was measured.
    pub const fn took(&mut self, bytes: u64) {
        self.stored = self.stored.saturating_add(bytes);
    }

    /// What's stored here, as last measured, and taken in since.
    pub const fn stored(&self) -> u64 {
        self.stored
    }

    /// How full it is, with this much free, if that's known.
    pub fn fill(&self, free: Option<u64>) -> Option<Fill> {
        Fill::of(self.stored, self.target, free)
    }

    /// The space others may fill: what's free, if that's known, and under
    /// the target, if there is one; None if neither.
    pub const fn room(&self, free: Option<u64>) -> Option<u64> {
        let under = match self.target {
            Some(target) => Some(target.saturating_sub(self.stored)),
            None => None,
        };
        match (free, under) {
            (Some(free), Some(under)) => Some(if free < under { free } else { under }),
            (Some(room), None) | (None, Some(room)) => Some(room),
            (None, None) => None,
        }
    }
}

/// What a trim did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Blocks whose copies here might go.
    pub considered: usize,
    /// Blocks let go of.
    pub dropped: usize,
    /// Of those, the blocks handed to a member first.
    pub handed: usize,
    /// Bytes freed.
    pub freed: u64,
}

/// A block this node means to let go of.
#[derive(Debug)]
struct Candidate {
    /// Its copies in the repo's own volumes, which would go.
    mine: Vec<Replica>,
    /// Its copies here on volumes which aren't the repo's own, which stay.
    staying: Vec<Replica>,
    /// Copies members have said they hold, now.
    granted: BTreeMap<PeerId, Vec<Replica>>,
    /// A member lets go of it first.
    refused: bool,
    /// What its copies are worth.
    worth: Worth,
    /// The member it's handed to, and how many copies there were before,
    /// which there must be once that member's kept it.
    to: Option<(PeerId, usize)>,
}

impl Candidate {
    const fn new(mine: Vec<Replica>, staying: Vec<Replica>, worth: Worth) -> Self {
        Self { mine, staying, granted: BTreeMap::new(), refused: false, worth, to: None }
    }

    /// How many copies there are with those here: this node's one, and
    /// members' as they've said.
    fn now(&self) -> usize {
        let here: Vec<Replica> = self.mine.iter().chain(&self.staying).cloned().collect();
        holders(std::iter::once(here.as_slice()).chain(self.granted.values().map(Vec::as_slice)))
    }

    /// How many there would be without them: this node's still, if it
    /// holds one on a volume that stays.
    fn without(&self) -> usize {
        holders(std::iter::once(self.staying.as_slice()).chain(self.granted.values().map(Vec::as_slice)))
    }

    /// Whether the copies here are worth less than their space costs.
    fn goes(&self, cost: f64) -> bool {
        worth_here(self.worth, self.without(), self.now()) < cost
    }

    /// Whether what's left would be `copies` copies.
    fn enough(&self, copies: usize) -> bool {
        self.without() >= copies
    }
}

/// What the copies here are worth, taking a block from `without` copies
/// to `with`: each one more, the copy that makes it so.
fn worth_here(worth: Worth, without: usize, with: usize) -> f64 {
    (without.saturating_add(1)..=with).map(|k| worth.of(k)).sum()
}

/// What a trim hands to each member before letting go of it.
pub type Handing = BTreeMap<PeerId, Vec<Multihash>>;

/// Letting go of copies here of some blocks.
pub struct Trim {
    candidates: BTreeMap<Vec<u8>, Candidate>,
    awaiting: HashSet<OutboundRequestId>,
    /// Whether what a member would value more is handed off to it.
    hand_off: bool,
    /// What space costs here.
    cost: f64,
    /// Where each member which answered would keep a block.
    offers: BTreeMap<PeerId, Offer>,
    /// Pushes of what's handed off, unanswered.
    pushing: HashSet<OutboundRequestId>,
    decided: bool,
    report: Report,
}

impl Trim {
    /// Of these blocks, those whose copies here could go and are worth
    /// less than their space costs here (`scales.cost`), by the copies
    /// elsewhere as sighted; `hand_off`, handing them to members they'd
    /// be worth more to. Returns the trim and the intents to send every
    /// peer.
    pub fn start(catalog: &Catalog, sightings: &Sightings, peers: &[PeerId], scales: Scales, hand_off: bool, keys: impl IntoIterator<Item = Multihash>) -> Result<(Self, Vec<Intent>)> {
        let own = catalog.own_labels();
        let mut trim = Self {
            candidates: BTreeMap::new(),
            awaiting: HashSet::new(),
            hand_off,
            cost: scales.cost,
            offers: BTreeMap::new(),
            pushing: HashSet::new(),
            decided: false,
            report: Report::default(),
        };
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
            let (mine, staying): (Vec<Replica>, Vec<Replica>) = catalog.replicas(key.as_ref())?.into_iter().partition(|replica| own.contains(&replica.label));
            let sighted: Vec<Replica> = sightings.of(key.as_ref())?.into_iter().filter(|(peer, _)| peers.contains(peer)).map(|(_, replica)| replica).collect();
            let worth = scales.worth(catalog.copies_wanted(key.as_ref(), scales.copies)?.unwrap_or(scales.copies));
            // As sightings have it, till members say
            let mut seen = Candidate::new(mine, staying.iter().chain(&sighted).cloned().collect(), worth);
            if seen.goes(scales.cost) && (hand_off || seen.enough(1)) {
                seen.staying = staying;
                trim.candidates.insert(bytes, seen);
            }
        }
        trim.report.considered = trim.candidates.len();
        let keys: Vec<ByteBuf> = trim.candidates.keys().cloned().map(ByteBuf::from).collect();
        let intents = keys.chunks(BATCH).map(|keys| Intent { keys: keys.to_vec(), user: None }).collect();
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
        if let Some(offer) = grant.offer {
            self.offers.insert(peer, offer);
        }
    }

    /// A member which didn't answer: its copies aren't counted.
    pub fn failed(&mut self, request: OutboundRequestId) {
        self.awaiting.remove(&request);
    }

    /// Whether it's waiting on grants, or on members keeping what's handed
    /// to them.
    pub fn waiting(&self) -> bool {
        !self.awaiting.is_empty() || !self.pushing.is_empty()
    }

    pub const fn decided(&self) -> bool {
        self.decided
    }

    /// Once every member's answered, what's to go: of what's still worth
    /// less than its space here by what members said, handing off, what
    /// to hand to whom first, a member it's worth more to whose copy would
    /// make up for those here, about `HANDING` at most; and what can go
    /// now, with another copy left.
    pub fn decide(&mut self, catalog: &Catalog) -> Result<(Vec<Multihash>, Handing)> {
        self.decided = true;
        let (mut now, mut hand) = (Vec::new(), Handing::new());
        let mut sent: BTreeMap<PeerId, u64> = BTreeMap::new();
        let mut handing = 0u64;
        for (key, candidate) in &mut self.candidates {
            let Ok(multihash) = <Multihash>::decode(key) else {
                continue;
            };
            if candidate.refused || !candidate.goes(self.cost) {
                continue;
            }
            // One that holds none makes up for the copy here
            let (before, without) = (candidate.now(), candidate.without());
            if self.hand_off && handing < HANDING && without < before {
                let size = catalog.held_size(multihash.as_ref())?.unwrap_or_default();
                let offers = self.offers.iter().filter(|(peer, _)| !candidate.granted.contains_key(*peer));
                if let Some(to) = choose(key, without, offers, candidate.worth, size, &sent) {
                    let given = sent.entry(to).or_default();
                    *given = given.saturating_add(size);
                    handing = handing.saturating_add(size);
                    candidate.to = Some((to, before));
                    hand.entry(to).or_default().push(multihash);
                    continue;
                }
            }
            if candidate.enough(1) {
                now.push(multihash);
            }
        }
        Ok((now, hand))
    }

    /// A push of what's handed off, sent.
    pub fn sent_push(&mut self, request: OutboundRequestId) {
        self.pushing.insert(request);
    }

    pub fn pushed(&self, request: OutboundRequestId) -> bool {
        self.pushing.contains(&request)
    }

    /// Take in what a member kept of what was handed to it.
    pub fn kept(&mut self, request: OutboundRequestId, peer: PeerId, kept: &Kept) {
        if !self.pushing.remove(&request) {
            return;
        }
        for (key, replicas) in kept.copies() {
            if let Some(candidate) = self.candidates.get_mut(key) {
                candidate.granted.insert(peer, replicas.to_vec());
            }
        }
    }

    /// A push which failed: what it carried stays.
    pub fn push_failed(&mut self, request: OutboundRequestId) {
        self.pushing.remove(&request);
    }

    /// Of what was handed off, what can go now that members have kept it,
    /// unless it's since given way to a member letting go of it first.
    pub fn handed(&self) -> Vec<Multihash> {
        self.candidates
            .iter()
            .filter(|(_, candidate)| !candidate.refused && candidate.to.is_some_and(|(_, before)| candidate.enough(before)))
            .filter_map(|(key, _)| <Multihash>::decode(key).ok())
            .collect()
    }

    /// Note what was let go of, and how much of it was handed off.
    pub const fn dropped(&mut self, blocks: usize, handed: usize, freed: u64) {
        self.report.dropped = self.report.dropped.saturating_add(blocks);
        self.report.handed = self.report.handed.saturating_add(handed);
        self.report.freed = self.report.freed.saturating_add(freed);
    }

    pub fn report(&self) -> Report {
        self.report.clone()
    }
}

/// Answer an intent: the copies held here of what it names, refusing
/// what a trim here lets go of first, and giving way where the asker
/// does; and where this would keep a block handed to it.
pub fn answer(catalog: &Catalog, me: &PeerId, peer: &PeerId, intent: &Intent, trims: &mut [&mut Trim], space: &Space) -> Result<Grant> {
    let mut grant = Grant { offer: Some(offered(catalog, space)?), ..Grant::default() };
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
    fn space_is_under_the_target_and_whats_free() {
        let mut space = Space::new(Some(1000));
        space.update(600);
        assert_eq!(space.room(Some(5000)), Some(400), "what's under the target");
        assert_eq!(space.room(Some(250)), Some(250), "or what's free, if less");
        assert_eq!(space.room(None), Some(400));
        space.took(100);
        assert_eq!(space.room(None), Some(300), "less what's been taken since");
        assert_eq!(space.fill(Some(5)), Some(Fill { stored: 700, capacity: 1000 }));
        let mut untargeted = Space::new(None);
        untargeted.update(100);
        assert_eq!(untargeted.room(Some(50)), Some(50));
        assert_eq!(untargeted.fill(Some(300)), Some(Fill { stored: 100, capacity: 400 }), "what's stored and free together");
        assert_eq!(untargeted.fill(None), None);
    }

    #[test]
    fn copies_here_are_worth_each_failure_they_add() {
        let worth = Worth { n: 2, q: 0.1 };
        assert!(worth_here(worth, 2, 2).abs() < f64::EPSILON, "adding nothing, worth nothing");
        assert!((worth_here(worth, 1, 2) - 1.0).abs() < 1e-12);
        assert!((worth_here(worth, 2, 3) - 0.1).abs() < 1e-12);
        assert!((worth_here(worth, 0, 1) - 10.0).abs() < 1e-9, "the last copy");
        assert!((worth_here(worth, 1, 3) - 1.1).abs() < 1e-12, "two volumes here, each a failure");
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
