//! Letting go of copies here when space runs short, without the mesh
//! being any easier to lose for it: `/holokeep/trim/1.0.0` and
//! `/holokeep/dropped/1.0.0`.
//!
//! This is collecting surplus, not garbage: nothing is deleted from the
//! mesh, only copies here, beyond what durability asks for or handed to a
//! member with room. Which blocks should live at all is for claims to say
//! (keeps and tombs).
//!
//! Space is kept between watermarks. When the repo's free space falls
//! below the low one, the node trims until it's back above the high one,
//! and between them it neither trims nor takes copies from others, so it
//! doesn't flap at a threshold. Its offers count only the space above the
//! high mark. A node may have a target too, the most it means to keep: it
//! trims once what's stored here passes the target until it's a tenth
//! under, and offers only what's under that, so a machine with a small
//! disk, or other uses for it, needn't fill it for the mesh.
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
//! Under pressure, what isn't surplus is a candidate too, and is *handed
//! off*: a grant says where its member would keep a block, as an advert's
//! answer does, and a block whose copies here are needed is pushed to the
//! member whose copy would make up for them, chosen as an audit chooses,
//! and goes once that member's said it kept it. A copy here goes only if
//! what's left takes as many failures to lose as with it, so a block
//! short of its copies may still move, but never gets shorter, and the
//! last copy of anything never goes: what no member has room for stays.
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
use crate::store::{BlockIndex as _, Catalog, Offer, Replica, tolerance};

use super::durability::{Kept, Sightings, choose, distinct, offered, score};
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

/// Where the repo's space is kept.
///
/// Trimming starts when free space falls below `low`, or what's stored
/// here passes `target`, if there is one, and stops once free space is
/// back above `high` and what's stored is back under the target's calm
/// mark.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Watermarks {
    pub low: u64,
    pub high: u64,
    /// The most to keep here, if there's a most.
    pub target: Option<u64>,
    /// What's stored here, as last measured, and taken in since.
    used: u64,
    /// Trimming for free space.
    short: bool,
    /// Trimming for the target.
    over: bool,
}

impl Watermarks {
    pub const fn new(low: u64, high: u64) -> Self {
        Self { low, high: if high < low { low } else { high }, target: None, used: 0, short: false, over: false }
    }

    /// With the most to keep here.
    #[must_use]
    pub const fn with_target(mut self, target: Option<u64>) -> Self {
        self.target = target;
        self
    }

    /// Where trimming for the target stops, and what others may fill up
    /// to: a tenth under it.
    pub const fn calm(&self) -> Option<u64> {
        match self.target {
            Some(target) => Some(target.saturating_sub(target / 10)),
            None => None,
        }
    }

    /// Take in the free space now, if it's known, and what's stored here,
    /// and say whether to trim.
    pub const fn update(&mut self, free: Option<u64>, used: u64) -> bool {
        self.used = used;
        if let Some(free) = free {
            if free < self.low {
                self.short = true;
            } else if free >= self.high {
                self.short = false;
            }
        }
        match (self.target, self.calm()) {
            (Some(target), _) if used > target => self.over = true,
            (Some(_), Some(calm)) if used > calm => {},
            _ => self.over = false,
        }
        self.pressed()
    }

    /// Whether it's between trimming down and coming back up.
    pub const fn pressed(&self) -> bool {
        self.short || self.over
    }

    /// Note what's been taken in since what's stored was measured.
    pub const fn took(&mut self, bytes: u64) {
        self.used = self.used.saturating_add(bytes);
    }

    /// What's stored here, as last measured, and taken in since.
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// The space others may fill: what's above the high mark of free
    /// space, if that's known, and under the calm mark, if there's a
    /// target; None if neither.
    pub const fn room(&self, free: Option<u64>) -> Option<u64> {
        let free = match free {
            Some(free) => Some(free.saturating_sub(self.high)),
            None => None,
        };
        let under = match self.calm() {
            Some(calm) => Some(calm.saturating_sub(self.used)),
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
#[derive(Debug, Default)]
struct Candidate {
    /// Its copies in the repo's own volumes, which would go.
    mine: Vec<Replica>,
    /// Its copies here on volumes which aren't the repo's own, which stay.
    staying: Vec<Replica>,
    /// Copies members have said they hold, now.
    granted: BTreeMap<PeerId, Vec<Replica>>,
    /// A member lets go of it first.
    refused: bool,
    /// How many failures it should take to lose it, as its nearest keeps
    /// say, or as the trim runs with.
    copies: usize,
    /// The member it's handed to, and how many failures it took to lose
    /// it before, which what's left once that member's kept it must too.
    to: Option<(PeerId, usize)>,
}

impl Candidate {
    /// The copies which stay if those here go: on other volumes here, and
    /// members' as they've said.
    fn left(&self) -> Vec<Replica> {
        self.staying.iter().chain(self.granted.values().flatten()).cloned().collect()
    }

    /// How many failures it takes to lose it with the copies here.
    fn now(&self) -> usize {
        tolerance(&distinct(self.left().iter().chain(&self.mine)), self.copies)
    }

    /// Whether the copies here can go without it being any easier to lose,
    /// as far as `copies` counts.
    fn spare(&self) -> bool {
        self.enough(self.now())
    }

    /// Whether what's left would take `failures` to lose.
    fn enough(&self, failures: usize) -> bool {
        tolerance(&distinct(&self.left()), self.copies) >= failures
    }
}

/// What a trim hands to each member before letting go of it.
pub type Handing = BTreeMap<PeerId, Vec<Multihash>>;

/// Letting go of copies here of some blocks.
pub struct Trim {
    candidates: BTreeMap<Vec<u8>, Candidate>,
    awaiting: HashSet<OutboundRequestId>,
    /// Whether what isn't surplus is handed off.
    hand_off: bool,
    /// Where each member which answered would keep a block.
    offers: BTreeMap<PeerId, Offer>,
    /// Pushes of what's handed off, unanswered.
    pushing: HashSet<OutboundRequestId>,
    decided: bool,
    report: Report,
}

impl Trim {
    /// Of these blocks, those whose copies here could go and whose copies
    /// elsewhere, as sighted, would still take `copies` failures to lose;
    /// or, `hand_off`, any whose copies here could go. Returns the trim
    /// and the intents to send every peer.
    pub fn start(catalog: &Catalog, sightings: &Sightings, peers: &[PeerId], copies: usize, hand_off: bool, keys: impl IntoIterator<Item = Multihash>) -> Result<(Self, Vec<Intent>)> {
        let own = catalog.own_labels();
        let mut trim = Self {
            candidates: BTreeMap::new(),
            awaiting: HashSet::new(),
            hand_off,
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
            let copies = catalog.copies_wanted(key.as_ref(), copies)?.unwrap_or(copies);
            if !hand_off && tolerance(&distinct(staying.iter().chain(&sighted)), copies) < copies {
                continue;
            }
            trim.candidates.insert(bytes, Candidate { mine, staying, copies, ..Candidate::default() });
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

    /// Once every member's answered, what can go now, blocks still enough
    /// without the copies here by what members said; and, handing off,
    /// what to hand to whom first, a member whose copy would make up for
    /// those here and with room for it, about `HANDING` at most.
    pub fn decide(&mut self, catalog: &Catalog) -> Result<(Vec<Multihash>, Handing)> {
        self.decided = true;
        let (mut now, mut hand) = (Vec::new(), Handing::new());
        let mut room: BTreeMap<PeerId, Option<u64>> = self.offers.iter().map(|(peer, offer)| (*peer, offer.free)).collect();
        let mut handing = 0u64;
        for (key, candidate) in &mut self.candidates {
            let Ok(multihash) = <Multihash>::decode(key) else {
                continue;
            };
            if candidate.refused {
                continue;
            }
            if candidate.spare() {
                now.push(multihash);
                continue;
            }
            if !self.hand_off || handing >= HANDING {
                continue;
            }
            let size = catalog.held_size(multihash.as_ref())?.unwrap_or_default();
            let left = candidate.left();
            let fits = |peer: &PeerId| room.get(peer).is_some_and(|room| room.is_none_or(|room| room >= size));
            let offers = self.offers.iter().filter(|(peer, _)| fits(peer) && !candidate.granted.contains_key(*peer));
            let Some(to) = choose(key, &left, offers, candidate.copies) else {
                continue;
            };
            // Its copy must make up for those here
            let Some(offer) = self.offers.get(&to) else {
                continue;
            };
            let with = [distinct(&left), vec![offer.risks.clone()]].concat();
            let before = candidate.now();
            if tolerance(&with, candidate.copies) < before {
                continue;
            }
            if let Some(Some(room)) = room.get_mut(&to) {
                *room = room.saturating_sub(size);
            }
            handing = handing.saturating_add(size);
            candidate.to = Some((to, before));
            hand.entry(to).or_default().push(multihash);
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
pub fn answer(catalog: &Catalog, me: &PeerId, peer: &PeerId, intent: &Intent, trims: &mut [&mut Trim], marks: &Watermarks) -> Result<Grant> {
    let mut grant = Grant { offer: Some(offered(catalog, marks)?), ..Grant::default() };
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
        assert!(!marks.update(Some(150), 0), "between them, from calm: calm");
        assert!(marks.update(Some(99), 0), "below the low mark: trim");
        assert!(marks.update(Some(150), 0), "between them, trimming: keep trimming");
        assert!(marks.update(None, 0), "not knowing: as it was");
        assert!(!marks.update(Some(200), 0), "at the high mark: stop");
        assert!(!marks.update(Some(150), 0));
        assert_eq!(marks.room(Some(250)), Some(50));
        assert_eq!(marks.room(Some(150)), Some(0));
        assert_eq!(marks.room(None), None);
        assert_eq!(Watermarks::new(300, 200).high, 300, "the high mark's at least the low");
    }

    #[test]
    fn a_target_keeps_whats_stored_a_tenth_under_it() {
        let mut marks = Watermarks::new(100, 200).with_target(Some(1000));
        assert_eq!(marks.calm(), Some(900));
        assert!(!marks.update(Some(5000), 950), "between calm and the target, from calm: calm");
        assert_eq!(marks.room(Some(5000)), Some(0), "nor taking more");
        assert!(marks.update(Some(5000), 1001), "past the target: trim");
        assert!(marks.update(Some(5000), 950), "above calm, trimming: keep trimming");
        assert!(!marks.update(Some(5000), 900), "at calm: stop");
        assert_eq!(marks.room(Some(5000)), Some(0));
        marks.update(Some(5000), 600);
        assert_eq!(marks.room(Some(5000)), Some(300), "what's under calm");
        assert_eq!(marks.room(Some(450)), Some(250), "or above the high mark, if less");
        assert_eq!(marks.room(None), Some(300));
        marks.took(100);
        assert_eq!(marks.room(None), Some(200), "less what's been taken since");
        assert!(marks.update(Some(50), 600), "short of free space, under the target: trim");
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
