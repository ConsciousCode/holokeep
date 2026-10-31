//! Keeping blocks durable across the mesh: adverts, sightings and
//! recruiting.
//!
//! A node audits what it holds: each block's tolerance, how many risks
//! would have to fail to lose every copy, counting its own volumes' copies
//! and the copies it has *sighted* on other nodes. A block short of the
//! tolerance asked for is advertised to every connected member, with the
//! copies this node holds. Each member answers with the copies it holds
//! of those, which corrects what's sighted, and with its *offer*: what the
//! volume it would keep a block on risks, and how much space is free
//! there.
//!
//! What's still short is sent to a target chosen by rendezvous hashing:
//! of the members whose copy would raise the block's tolerance most, the
//! one whose hash with the block, weighted by its free space, is highest.
//! The same hashing over the holders (unweighted) says which holder does
//! this, so when several hold a block only one advertises it; the others
//! leave it to that one while they believe it holds a copy. A target which
//! doesn't keep what it's sent is passed over for the next.
//!
//! Sightings are kept beside the catalog, never in its `blocks`, which is
//! the truth about this node's own volumes: only for blocks this node
//! holds, and only for so long, by its own clock. One which expires lowers
//! a block's tolerance, so it's advertised again, and the holders' answers
//! sight their copies again or a new one is made: audit and repair are the
//! same loop.
//!
//! Every member answers, so in a small mesh adverts go straight to each;
//! gossip is for when the mesh isn't fully connected.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::request_response::OutboundRequestId;
use libp2p::{PeerId, StreamProtocol};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::Digest as _;

use crate::block::{Block, IDENTITY};
use crate::cid::{BaseCid, Cid, CidRef};
use crate::model::Link;
use crate::multihash::Multihash;
use crate::store::{BlockIndex, Catalog, Db, Key, Offer, Replica, tolerance};

use super::mesh::Result;

pub const ADVERTS: StreamProtocol = StreamProtocol::new("/holokeep/adverts/1.0.0");
pub const PUSH: StreamProtocol = StreamProtocol::new("/holokeep/push/1.0.0");

/// The most blocks in one advert.
const ADVERT_BATCH: usize = 512;

/// About the most block data in one push, which always carries at least
/// one block.
const BUDGET: usize = 4 << 20;

/// How long a copy sighted on another node is believed in.
pub const TTL: Duration = Duration::from_hours(24 * 7);

/// The space assumed free on a volume which doesn't say: a gigabyte.
const UNKNOWN_FREE_MIB: u64 = 1024;

/// Blocks a holder believes short, each with the copies it holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Advert {
    blocks: Vec<(ByteBuf, Vec<Replica>)>,
}

/// An answer to an advert: the copies this node holds of the blocks, and
/// where it would keep one it's sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Haves {
    held: Vec<(ByteBuf, Vec<Replica>)>,
    offer: Option<Offer>,
}

/// Blocks sent to be kept, as (CID, bytes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Push {
    blocks: Vec<(ByteBuf, ByteBuf)>,
}

impl Push {
    /// Pushes of these blocks, each about a few megabytes at most.
    pub fn batches(blocks: impl IntoIterator<Item = Block>) -> Vec<Self> {
        let mut pushes = Vec::new();
        let (mut push, mut size) = (Self::default(), 0usize);
        for block in blocks {
            if !push.blocks.is_empty() && size.saturating_add(block.data().len()) > BUDGET {
                pushes.push(std::mem::take(&mut push));
                size = 0;
            }
            size = size.saturating_add(block.data().len());
            push.blocks.push((ByteBuf::from(block.cid().to_bytes()), ByteBuf::from(block.data().to_vec())));
        }
        if !push.blocks.is_empty() {
            pushes.push(push);
        }
        pushes
    }
}

/// The blocks of a push which were kept, and the copies of each now.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Kept {
    kept: Vec<(ByteBuf, Vec<Replica>)>,
}

impl Kept {
    /// The multihashes of what was kept.
    pub fn keys(&self) -> Vec<Vec<u8>> {
        self.kept.iter().map(|(key, _)| key.to_vec()).collect()
    }

    /// Note the copies a member kept of what was pushed to it outside an
    /// audit, of what this node holds.
    pub fn sight(&self, catalog: &Catalog, sightings: &Sightings, peer: &PeerId) -> Result<()> {
        for (key, replicas) in &self.kept {
            let Ok(key) = decode(key) else {
                continue;
            };
            if key.code() != IDENTITY && catalog.has(key.as_ref())? {
                for replica in replicas {
                    sightings.see(key.as_ref(), peer, replica)?;
                }
            }
        }
        Ok(())
    }
}

fn decode(key: &[u8]) -> std::result::Result<Multihash, crate::multihash::DecodeError> {
    Multihash::decode(key)
}

fn now() -> i64 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// Copies of blocks this node holds, sighted on other nodes.
pub struct Sightings {
    db: Db,
    ttl: Duration,
}

impl Sightings {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "-- Copies of blocks this node holds, as other nodes have said they
             -- hold them, by volume label: believed in for a while after.
             CREATE TABLE IF NOT EXISTS sightings (
                 block INTEGER NOT NULL REFERENCES multihashes (id),
                 label BLOB NOT NULL,
                 peer TEXT NOT NULL,
                 risks TEXT NOT NULL,
                 seen INTEGER NOT NULL,
                 PRIMARY KEY (block, label)
             ) WITHOUT ROWID;",
        )?;
        Ok(Self { db, ttl: TTL })
    }

    /// Believe in sightings for this long instead.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    fn cutoff(&self) -> i64 {
        now().saturating_sub(i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX))
    }

    /// Note that a peer holds a copy of a block.
    pub fn see(&self, key: Key<'_>, peer: &PeerId, replica: &Replica) -> Result<()> {
        let block = self.db.intern(key)?;
        self.db.conn()
            .prepare_cached("INSERT OR REPLACE INTO sightings (block, label, peer, risks, seen) VALUES (?1, ?2, ?3, ?4, ?5)")?
            .execute(params![block, replica.label, peer.to_string(), replica.risks.join("\n"), now()])?;
        Ok(())
    }

    /// Forget a peer's copies of a block: it says it holds none.
    pub fn unsee(&self, key: Key<'_>, peer: &PeerId) -> Result<()> {
        let Some(block) = self.db.lookup(key)? else {
            return Ok(());
        };
        self.db.conn().prepare_cached("DELETE FROM sightings WHERE block = ?1 AND peer = ?2")?.execute(params![block, peer.to_string()])?;
        Ok(())
    }

    /// The copies of a block still believed in, and who holds each.
    pub fn of(&self, key: Key<'_>) -> Result<Vec<(PeerId, Replica)>> {
        let Some(block) = self.db.lookup(key)? else {
            return Ok(Vec::new());
        };
        let mut stmt = self.db.conn().prepare_cached("SELECT peer, label, risks FROM sightings WHERE block = ?1 AND seen >= ?2 ORDER BY label")?;
        let rows = stmt.query_map(params![block, self.cutoff()], |row| Ok((row.get::<_, String>(0)?, row.get(1)?, row.get::<_, String>(2)?)))?;
        let mut sighted = Vec::new();
        for row in rows {
            let (peer, label, risks) = row?;
            if let Ok(peer) = PeerId::from_str(&peer) {
                sighted.push((peer, Replica { label, risks: risks.split('\n').filter(|risk| !risk.is_empty()).map(str::to_owned).collect() }));
            }
        }
        Ok(sighted)
    }

    /// Forget sightings no longer believed in, and those of blocks this
    /// node no longer holds. Returns how many.
    pub fn expire(&self) -> Result<usize> {
        Ok(self.db.conn()
            .prepare_cached("DELETE FROM sightings WHERE seen < ?1 OR block NOT IN (SELECT block FROM blocks)")?
            .execute([self.cutoff()])?)
    }
}

/// A hash of a block and a peer, uniform in (0, 1).
fn draw(key: &[u8], peer: &PeerId) -> f64 {
    let hash = sha2::Sha256::new().chain_update(key).chain_update(peer.to_bytes()).finalize();
    let x = hash.first_chunk::<4>().map_or(0, |bytes| u32::from_be_bytes(*bytes));
    (f64::from(x) + 1.0) / (f64::from(u32::MAX) + 2.0)
}

/// A peer's rendezvous score for a block, weighted: the highest wins, and
/// each peer wins in proportion to its weight.
fn score(key: &[u8], peer: &PeerId, weight: f64) -> f64 {
    -weight / draw(key, peer).ln()
}

/// The holder of a block responsible for it: the same answer from every
/// node which knows the same holders.
pub fn first_holder<'a>(key: &[u8], holders: impl IntoIterator<Item = &'a PeerId>) -> Option<PeerId> {
    holders.into_iter().max_by(|a, b| score(key, a, 1.0).total_cmp(&score(key, b, 1.0))).copied()
}

/// What a volume's free space weighs, in mebibytes.
fn weight(free: Option<u64>) -> f64 {
    let mib = free.map_or(UNKNOWN_FREE_MIB, |free| free >> 20).max(1);
    f64::from(u32::try_from(mib).unwrap_or(u32::MAX))
}

/// The risks of each distinct copy, by label: a volume two nodes share is
/// one copy.
fn distinct<'a>(replicas: impl IntoIterator<Item = &'a Replica>) -> Vec<Vec<String>> {
    let by_label: BTreeMap<&[u8], &Vec<String>> = replicas.into_iter().map(|replica| (replica.label.as_slice(), &replica.risks)).collect();
    by_label.into_values().cloned().collect()
}

/// Where to send a block to raise its tolerance: of the offers whose copy
/// would raise it most, the one with the highest weighted rendezvous score.
pub fn choose<'a>(key: &[u8], held: &[Replica], offers: impl IntoIterator<Item = (&'a PeerId, &'a Offer)>, copies: usize) -> Option<PeerId> {
    let have = distinct(held);
    let now = tolerance(&have, copies);
    let raised: Vec<(PeerId, usize, f64)> = offers
        .into_iter()
        .map(|(peer, offer)| {
            let with = tolerance(&[have.as_slice(), std::slice::from_ref(&offer.risks)].concat(), copies);
            (*peer, with, weight(offer.free))
        })
        .filter(|&(_, with, _)| with > now)
        .collect();
    let best = raised.iter().map(|&(_, with, _)| with).max()?;
    raised
        .into_iter()
        .filter(|&(_, with, _)| with == best)
        .max_by(|(a, _, wa), (b, _, wb)| score(key, a, *wa).total_cmp(&score(key, b, *wb)))
        .map(|(peer, _, _)| peer)
}

/// Answer an advert: the copies held here of what it names, noting the
/// advertiser's copies of those, and where this node would keep a block.
pub fn answer_advert(catalog: &Catalog, sightings: &Sightings, peer: &PeerId, advert: &Advert) -> Result<Haves> {
    let mut held = Vec::new();
    for (key, theirs) in &advert.blocks {
        let Ok(multihash) = decode(key) else {
            continue;
        };
        if multihash.code() == IDENTITY || !catalog.has(multihash.as_ref())? {
            continue;
        }
        for replica in theirs {
            sightings.see(multihash.as_ref(), peer, replica)?;
        }
        held.push((key.clone(), catalog.replicas(multihash.as_ref())?));
    }
    Ok(Haves { held, offer: Some(catalog.offer()?) })
}

/// Keep what's pushed, if there's room and each block matches its CID.
pub fn answer_push(catalog: &Catalog, push: Push) -> Result<Kept> {
    let size = push.blocks.iter().fold(0usize, |size, (_, data)| size.saturating_add(data.len()));
    if catalog.offer()?.free.is_some_and(|free| u64::try_from(size).unwrap_or(u64::MAX) > free) {
        return Ok(Kept::default());
    }
    let mut kept = Vec::new();
    for (cid, data) in push.blocks {
        let Ok(link) = Link::decode(&cid) else {
            continue;
        };
        let Ok(block) = Block::verify(link.clone().into(), data.into_vec().into_boxed_slice()) else {
            continue;
        };
        catalog.put_block(&block, link.version())?;
        kept.push((ByteBuf::from(link.multihash().to_bytes()), catalog.replicas(link.multihash())?));
    }
    Ok(Kept { kept })
}

/// What an audit did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Blocks advertised as short.
    pub advertised: usize,
    /// Copies sent and kept.
    pub copied: usize,
    /// Blocks still short, with no member to raise them.
    pub short: usize,
}

/// A block being audited: who holds copies, and who's been passed over.
#[derive(Debug, Default)]
struct Holding {
    holders: BTreeMap<PeerId, Vec<Replica>>,
    passed: BTreeSet<PeerId>,
    pushing: bool,
}

/// Pushes to send: to whom, what, and the blocks' multihashes.
pub type Pushes = Vec<(PeerId, Push, Vec<Vec<u8>>)>;

/// Auditing what this node holds, and raising what's short.
pub struct Audit {
    me: PeerId,
    copies: usize,
    blocks: BTreeMap<Vec<u8>, Holding>,
    offers: BTreeMap<PeerId, Offer>,
    /// Adverts sent: to whom, and naming what.
    adverts: HashMap<OutboundRequestId, (PeerId, Vec<Vec<u8>>)>,
    /// Pushes sent: to whom, and of what.
    pushes: HashMap<OutboundRequestId, (PeerId, Vec<Vec<u8>>)>,
    /// Rounds of pushes decided.
    rounds: usize,
    report: Report,
}

impl Audit {
    /// Find what this node holds short of `copies` failures to lose, and
    /// is responsible for among the holders it knows of, connected or
    /// itself. Returns the audit and the adverts to send every peer.
    pub fn start(catalog: &Catalog, sightings: &Sightings, me: PeerId, peers: &[PeerId], copies: usize) -> Result<(Self, Vec<Advert>)> {
        sightings.expire()?;
        let mut audit = Self {
            me,
            copies,
            blocks: BTreeMap::new(),
            offers: BTreeMap::new(),
            adverts: HashMap::new(),
            pushes: HashMap::new(),
            rounds: 0,
            report: Report::default(),
        };
        let mut adverts = Vec::new();
        let mut advert = Advert::default();
        for key in catalog.keys()? {
            if key.code() == IDENTITY {
                continue;
            }
            let ours = catalog.replicas(key.as_ref())?;
            let mut holding = Holding::default();
            for (peer, replica) in sightings.of(key.as_ref())? {
                if peers.contains(&peer) {
                    holding.holders.entry(peer).or_default().push(replica);
                }
            }
            let have = distinct(ours.iter().chain(holding.holders.values().flatten()));
            if tolerance(&have, copies) >= copies {
                continue;
            }
            let bytes = key.to_bytes();
            if first_holder(&bytes, holding.holders.keys().chain([&me])) != Some(me) {
                continue;
            }
            holding.holders.insert(me, ours.clone());
            advert.blocks.push((ByteBuf::from(bytes.clone()), ours));
            audit.blocks.insert(bytes, holding);
            if advert.blocks.len() >= ADVERT_BATCH {
                adverts.push(std::mem::take(&mut advert));
            }
        }
        if !advert.blocks.is_empty() {
            adverts.push(advert);
        }
        audit.report.advertised = audit.blocks.len();
        Ok((audit, adverts))
    }

    pub fn sent_advert(&mut self, request: OutboundRequestId, peer: PeerId, advert: &Advert) {
        self.adverts.insert(request, (peer, advert.blocks.iter().map(|(key, _)| key.to_vec()).collect()));
    }

    pub fn sent_push(&mut self, request: OutboundRequestId, peer: PeerId, keys: Vec<Vec<u8>>) {
        self.pushes.insert(request, (peer, keys));
    }

    pub fn asked(&self, request: OutboundRequestId) -> bool {
        self.adverts.contains_key(&request) || self.pushes.contains_key(&request)
    }

    /// Take in a member's answer to an advert: its copies, sighted, and
    /// its offer.
    pub fn haves(&mut self, sightings: &Sightings, request: OutboundRequestId, haves: Haves) -> Result<()> {
        let Some((peer, asked)) = self.adverts.remove(&request) else {
            return Ok(());
        };
        if let Some(offer) = haves.offer {
            self.offers.insert(peer, offer);
        }
        let mut held: BTreeMap<Vec<u8>, Vec<Replica>> = haves.held.into_iter().map(|(key, replicas)| (key.into_vec(), replicas)).collect();
        for key in asked {
            let Ok(multihash) = decode(&key) else {
                continue;
            };
            let Some(holding) = self.blocks.get_mut(&key) else {
                continue;
            };
            if let Some(replicas) = held.remove(&key) {
                for replica in &replicas {
                    sightings.see(multihash.as_ref(), &peer, replica)?;
                }
                holding.holders.insert(peer, replicas);
            } else {
                sightings.unsee(multihash.as_ref(), &peer)?;
                holding.holders.remove(&peer);
            }
        }
        Ok(())
    }

    /// A member which didn't answer an advert: it offers nothing.
    pub fn advert_failed(&mut self, request: OutboundRequestId) {
        self.adverts.remove(&request);
    }

    /// Take in what a member kept of a push, and pass it over for what it
    /// didn't.
    pub fn kept(&mut self, sightings: &Sightings, request: OutboundRequestId, kept: Kept) -> Result<()> {
        let Some((peer, keys)) = self.pushes.remove(&request) else {
            return Ok(());
        };
        let mut kept: BTreeMap<Vec<u8>, Vec<Replica>> = kept.kept.into_iter().map(|(key, replicas)| (key.into_vec(), replicas)).collect();
        for key in keys {
            let Some(holding) = self.blocks.get_mut(&key) else {
                continue;
            };
            holding.pushing = false;
            match kept.remove(&key) {
                Some(replicas) => {
                    if let Ok(multihash) = decode(&key) {
                        for replica in &replicas {
                            sightings.see(multihash.as_ref(), &peer, replica)?;
                        }
                    }
                    holding.holders.insert(peer, replicas);
                    self.report.copied = self.report.copied.saturating_add(1);
                },
                None => {
                    holding.passed.insert(peer);
                },
            }
        }
        Ok(())
    }

    /// A push which got no answer: pass its target over.
    pub fn push_failed(&mut self, request: OutboundRequestId) {
        let Some((peer, keys)) = self.pushes.remove(&request) else {
            return;
        };
        for key in keys {
            if let Some(holding) = self.blocks.get_mut(&key) {
                holding.pushing = false;
                holding.passed.insert(peer);
            }
        }
    }

    /// Whether every advert and push has been answered, or given up on.
    pub fn waiting(&self) -> bool {
        !self.adverts.is_empty() || !self.pushes.is_empty()
    }

    /// Once nothing's awaited, say what to push to whom: each block still
    /// short, to the member chosen for it. None means the audit's done.
    pub fn decide(&mut self, catalog: &Catalog) -> Result<Option<Pushes>> {
        if self.waiting() {
            return Ok(Some(Vec::new()));
        }
        let first = self.rounds == 0;
        self.rounds = self.rounds.saturating_add(1);
        let mut targets: BTreeMap<PeerId, Vec<Vec<u8>>> = BTreeMap::new();
        let mut settled = Vec::new();
        for (key, holding) in &mut self.blocks {
            let held: Vec<Replica> = holding.holders.values().flatten().cloned().collect();
            if tolerance(&distinct(&held), self.copies) >= self.copies {
                settled.push(key.clone());
                continue;
            }
            // A holder learned of only now may be the one responsible; once
            // this node's sent a copy, it sees the block through
            if first && first_holder(key, holding.holders.keys()) != Some(self.me) {
                settled.push(key.clone());
                continue;
            }
            let offers = self.offers.iter().filter(|(peer, _)| !holding.holders.contains_key(peer) && !holding.passed.contains(peer));
            let Some(target) = choose(key, &held, offers, self.copies) else {
                self.report.short = self.report.short.saturating_add(1);
                settled.push(key.clone());
                continue;
            };
            holding.pushing = true;
            targets.entry(target).or_default().push(key.clone());
        }
        for key in settled {
            self.blocks.remove(&key);
        }
        let mut pushes = Vec::new();
        for (peer, keys) in targets {
            let mut push = Push::default();
            let (mut size, mut batch) = (0usize, Vec::new());
            for key in keys {
                let block = decode(&key).ok().map(|multihash| catalog.read_block(multihash.as_ref())).transpose()?.flatten();
                let Some(block) = block else {
                    self.blocks.remove(&key);
                    self.report.short = self.report.short.saturating_add(1);
                    continue;
                };
                if !push.blocks.is_empty() && size.saturating_add(block.data().len()) > BUDGET {
                    pushes.push((peer, std::mem::take(&mut push), std::mem::take(&mut batch)));
                    size = 0;
                }
                size = size.saturating_add(block.data().len());
                push.blocks.push((ByteBuf::from(block.cid().to_bytes()), ByteBuf::from(block.data().to_vec())));
                batch.push(key);
            }
            if !push.blocks.is_empty() {
                pushes.push((peer, push, batch));
            }
        }
        Ok((!pushes.is_empty()).then_some(pushes))
    }

    pub fn report(&self) -> Report {
        self.report.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(risks: &[&str]) -> Offer {
        Offer { risks: risks.iter().map(|&risk| risk.to_owned()).collect(), free: None }
    }

    fn replica(label: u8, risks: &[&str]) -> Replica {
        Replica { label: vec![label], risks: risks.iter().map(|&risk| risk.to_owned()).collect() }
    }

    #[test]
    fn the_target_is_whoever_raises_tolerance_most() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let held = [replica(1, &["volume:1", "disk:x"])];
        // b's volume is on the same disk; a's isn't
        let offers = BTreeMap::from([(a, offer(&["volume:2", "disk:y"])), (b, offer(&["volume:3", "disk:x"]))]);
        for key in 0..32u8 {
            assert_eq!(choose(&[key], &held, &offers, 2), Some(a));
        }
        // Already enough
        assert_eq!(choose(&[0], &[held[0].clone(), replica(2, &["disk:y"])], &offers, 2), None);
    }

    #[test]
    fn a_shared_volume_is_one_copy() {
        let shared = [replica(1, &["volume:1"]), replica(1, &["volume:1"])];
        assert_eq!(tolerance(&distinct(&shared), 2), 1);
    }

    #[test]
    fn targets_spread_by_free_space() {
        let peers: Vec<PeerId> = (0..3).map(|_| PeerId::random()).collect();
        let roomy = |peer: usize| Offer { risks: vec![format!("volume:{peer}")], free: Some(if peer == 0 { 3 << 30 } else { 1 << 30 }) };
        let offers: BTreeMap<PeerId, Offer> = peers.iter().enumerate().map(|(i, peer)| (*peer, roomy(i))).collect();
        let held = [replica(9, &["volume:9"])];
        let mut wins = [0usize; 3];
        for key in 0..3000u16 {
            let target = choose(&key.to_be_bytes(), &held, &offers, 2).expect("target");
            if let Some(win) = peers.iter().position(|peer| *peer == target).and_then(|i| wins.get_mut(i)) {
                *win = win.saturating_add(1);
            }
        }
        // 3:1:1 by free space, give or take
        assert!(wins.iter().all(|&win| win > 300), "{wins:?}");
        assert!(wins[0] > 1500 && wins[0] < 2100, "{wins:?}");
        // Whatever order a node knows the offers in
        assert_eq!(choose(&[7], &held, &offers, 2), choose(&[7], &held, offers.iter().rev(), 2));
    }

    #[test]
    fn one_holder_is_responsible() {
        let holders: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
        let mut firsts = BTreeSet::new();
        for key in 0..64u8 {
            let first = first_holder(&[key], &holders).expect("first");
            assert_eq!(first_holder(&[key], holders.iter().rev()), Some(first), "the order known in doesn't matter");
            firsts.insert(first);
        }
        assert_eq!(firsts.len(), 4, "each is responsible for some");
    }

    #[test]
    fn sightings_expire() {
        let db = Db::memory().expect("db");
        let catalog = Catalog::standard(db.clone()).expect("catalog");
        let block = Block::hash(crate::cid::Cidv1Spec::default(), b"seen".as_slice().into());
        catalog.put_block(&block, crate::cid::CidVersion::V1).expect("put");
        let key = block.cid().multihash();
        let peer = PeerId::random();
        let sightings = Sightings::open(db.clone()).expect("open");
        sightings.see(key, &peer, &replica(1, &["volume:1", "disk:x"])).expect("see");
        assert_eq!(sightings.of(key).expect("of"), [(peer, replica(1, &["volume:1", "disk:x"]))]);
        sightings.unsee(key, &peer).expect("unsee");
        assert!(sightings.of(key).expect("of").is_empty());
        sightings.see(key, &peer, &replica(1, &[])).expect("see");
        let stale = Sightings::open(db).expect("open").with_ttl(Duration::ZERO);
        // Seen this second is still believed for this second; a negative
        // age isn't possible, so look back from a moment on
        std::thread::sleep(Duration::from_millis(1100));
        assert!(stale.of(key).expect("of").is_empty());
        assert_eq!(stale.expire().expect("expire"), 1);
        assert_eq!(sightings.of(key).expect("of"), []);
    }
}
