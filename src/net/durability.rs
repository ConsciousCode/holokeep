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
use rusqlite::{OptionalExtension, params};
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

/// Blocks sent to be kept, as (CID, bytes), and the copies the sender
/// holds of each, so the receiver knows of them without asking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Push {
    blocks: Vec<(ByteBuf, ByteBuf)>,
    #[serde(default)]
    copies: Vec<Vec<Replica>>,
}

impl Push {
    /// Pushes of these blocks, each about a few megabytes at most, with
    /// the copies held here.
    pub fn batches(catalog: &Catalog, blocks: impl IntoIterator<Item = Block>) -> Result<Vec<Self>> {
        let mut pushes = Vec::new();
        let (mut push, mut size) = (Self::default(), 0usize);
        for block in blocks {
            if !push.blocks.is_empty() && size.saturating_add(block.data().len()) > BUDGET {
                pushes.push(std::mem::take(&mut push));
                size = 0;
            }
            size = size.saturating_add(block.data().len());
            push.add(catalog, &block)?;
        }
        if !push.blocks.is_empty() {
            pushes.push(push);
        }
        Ok(pushes)
    }

    fn add(&mut self, catalog: &Catalog, block: &Block) -> Result<()> {
        self.copies.push(catalog.replicas(block.cid().multihash())?);
        self.blocks.push((ByteBuf::from(block.cid().to_bytes()), ByteBuf::from(block.data().to_vec())));
        Ok(())
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
///
/// A sighting expires after a while, unless the peer's been connected
/// since it was made: a member lets the others know what it lets go of,
/// so while it stays connected nothing it said it held has gone unsaid.
/// Expiry is for what a disconnection hides.
pub struct Sightings {
    db: Db,
    ttl: Duration,
    /// Peers connected, and since when.
    live: std::cell::RefCell<HashMap<PeerId, i64>>,
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
             ) WITHOUT ROWID;
             -- Where audits are up to.
             CREATE TABLE IF NOT EXISTS audit_state (
                 name TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );",
        )?;
        Ok(Self { db, ttl: TTL, live: std::cell::RefCell::default() })
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

    /// A peer's connected, as of now.
    pub fn connected(&self, peer: PeerId) {
        self.live.borrow_mut().entry(peer).or_insert_with(now);
    }

    pub fn disconnected(&self, peer: &PeerId) {
        self.live.borrow_mut().remove(peer);
    }

    /// Whether a sighting is still believed in: recent enough, or vouched
    /// for by the peer's having stayed connected since.
    fn believed(&self, peer: &PeerId, seen: i64, cutoff: i64) -> bool {
        seen >= cutoff || self.live.borrow().get(peer).is_some_and(|&since| since <= seen)
    }

    /// Note that a peer holds a copy of a block.
    pub fn see(&self, key: Key<'_>, peer: &PeerId, replica: &Replica) -> Result<()> {
        let block = self.db.intern(key)?;
        self.db.conn()
            .prepare_cached("INSERT OR REPLACE INTO sightings (block, label, peer, risks, seen) VALUES (?1, ?2, ?3, ?4, ?5)")?
            .execute(params![block, replica.label, peer.to_string(), replica.risks.join("\n"), now()])?;
        Ok(())
    }

    /// Forget every sighting of a block: this node no longer holds it.
    pub fn forget(&self, key: Key<'_>) -> Result<()> {
        if let Some(block) = self.db.lookup(key)? {
            self.db.conn().prepare_cached("DELETE FROM sightings WHERE block = ?1")?.execute([block])?;
        }
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

    /// Whether any copy of a block still believed in is past half its
    /// time: due to be sighted again before it's forgotten.
    pub fn stale(&self, key: Key<'_>) -> Result<bool> {
        let Some(block) = self.db.lookup(key)? else {
            return Ok(false);
        };
        let half = i64::try_from(self.ttl.as_secs() / 2).unwrap_or(i64::MAX);
        let due = now().saturating_sub(half);
        let cutoff = self.cutoff();
        let mut stmt = self.db.conn().prepare_cached("SELECT peer, seen FROM sightings WHERE block = ?1 AND seen < ?2")?;
        let rows = stmt.query_map(params![block, due], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (peer, seen) = row?;
            let vouched = PeerId::from_str(&peer).is_ok_and(|peer| self.live.borrow().get(&peer).is_some_and(|&since| since <= seen));
            if seen >= cutoff && !vouched {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Where the trickle's read up to of what's arrived.
    pub fn fresh_cursor(&self) -> Result<i64> {
        Ok(self.db.conn()
            .prepare_cached("SELECT value FROM audit_state WHERE name = 'fresh'")?
            .query_row([], |row| row.get(0))
            .optional()?
            .unwrap_or_default())
    }

    pub fn set_fresh_cursor(&self, cursor: i64) -> Result<()> {
        self.db.conn().prepare_cached("INSERT OR REPLACE INTO audit_state (name, value) VALUES ('fresh', ?1)")?.execute([cursor])?;
        Ok(())
    }

    /// The copies of a block still believed in, and who holds each.
    pub fn of(&self, key: Key<'_>) -> Result<Vec<(PeerId, Replica)>> {
        let Some(block) = self.db.lookup(key)? else {
            return Ok(Vec::new());
        };
        let mut stmt = self.db.conn().prepare_cached("SELECT peer, label, risks, seen FROM sightings WHERE block = ?1 ORDER BY label")?;
        let rows = stmt.query_map([block], |row| Ok((row.get::<_, String>(0)?, row.get(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?)))?;
        let cutoff = self.cutoff();
        let mut sighted = Vec::new();
        for row in rows {
            let (peer, label, risks, seen) = row?;
            if let Ok(peer) = PeerId::from_str(&peer)
                && self.believed(&peer, seen, cutoff)
            {
                sighted.push((peer, Replica { label, risks: risks.split('\n').filter(|risk| !risk.is_empty()).map(str::to_owned).collect() }));
            }
        }
        Ok(sighted)
    }

    /// Forget sightings no longer believed in, and those of blocks this
    /// node no longer holds. Returns how many.
    pub fn expire(&self) -> Result<usize> {
        let conn = self.db.conn();
        let mut forgotten = conn.prepare_cached("DELETE FROM sightings WHERE block NOT IN (SELECT block FROM blocks)")?.execute([])?;
        let cutoff = self.cutoff();
        let old: Vec<(i64, Vec<u8>, String, i64)> = conn
            .prepare_cached("SELECT block, label, peer, seen FROM sightings WHERE seen < ?1")?
            .query_map([cutoff], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut delete = conn.prepare_cached("DELETE FROM sightings WHERE block = ?1 AND label = ?2")?;
        for (block, label, peer, seen) in old {
            if !PeerId::from_str(&peer).is_ok_and(|peer| self.believed(&peer, seen, cutoff)) {
                forgotten = forgotten.saturating_add(delete.execute(params![block, label])?);
            }
        }
        Ok(forgotten)
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
pub(crate) fn score(key: &[u8], peer: &PeerId, weight: f64) -> f64 {
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
pub(crate) fn distinct<'a>(replicas: impl IntoIterator<Item = &'a Replica>) -> Vec<Vec<String>> {
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
pub fn answer_advert(catalog: &Catalog, sightings: &Sightings, peer: &PeerId, advert: &Advert, marks: &super::trim::Watermarks) -> Result<Haves> {
    let mut held = Vec::new();
    for (key, theirs) in &advert.blocks {
        let Ok(multihash) = decode(key) else {
            continue;
        };
        if multihash.code() == IDENTITY || !catalog.has(multihash.as_ref())? || !catalog.visible(multihash.as_ref())? {
            continue;
        }
        for replica in theirs {
            sightings.see(multihash.as_ref(), peer, replica)?;
        }
        held.push((key.clone(), catalog.replicas(multihash.as_ref())?));
    }
    let mut offer = catalog.offer()?;
    offer.free = offer.free.map(|free| marks.spare(free));
    Ok(Haves { held, offer: Some(offer) })
}

/// Keep what's pushed, if there's room and each block matches its CID,
/// noting the sender's copies of what's kept.
pub fn answer_push(catalog: &Catalog, sightings: &Sightings, peer: &PeerId, push: Push, marks: &super::trim::Watermarks) -> Result<Kept> {
    let size = push.blocks.iter().fold(0usize, |size, (_, data)| size.saturating_add(data.len()));
    if catalog.offer()?.free.is_some_and(|free| u64::try_from(size).unwrap_or(u64::MAX) > marks.spare(free)) {
        return Ok(Kept::default());
    }
    let mut kept = Vec::new();
    let mut copies = push.copies.into_iter();
    for (cid, data) in push.blocks {
        let theirs = copies.next().unwrap_or_default();
        let Ok(link) = Link::decode(&cid) else {
            continue;
        };
        let Ok(block) = Block::verify(link.clone().into(), data.into_vec().into_boxed_slice()) else {
            continue;
        };
        catalog.put_block(&block, link.version())?;
        if link.hashcode() != IDENTITY {
            for replica in &theirs {
                sightings.see(link.multihash(), peer, replica)?;
            }
        }
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
    /// Audit these blocks: find those short of `copies` failures to lose,
    /// or whose copies elsewhere are due to be sighted again, and which
    /// this node is responsible for among the holders it knows of,
    /// connected or itself. Returns the audit and the adverts to send
    /// every peer.
    pub fn start(
        catalog: &Catalog,
        sightings: &Sightings,
        me: PeerId,
        peers: &[PeerId],
        copies: usize,
        keys: impl IntoIterator<Item = Multihash>,
    ) -> Result<(Self, Vec<Advert>)> {
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
        for key in keys {
            if key.code() == IDENTITY || audit.blocks.contains_key(&key.to_bytes()) {
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
            if tolerance(&have, copies) >= copies && !sightings.stale(key.as_ref())? {
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
                push.add(catalog, &block)?;
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

/// The interval the trickle keeps when there's nothing to do.
pub const CALM: Duration = Duration::from_mins(1);

/// The interval it keeps when there is.
pub const ALERT: Duration = Duration::from_secs(2);

/// How many files imported in place the trickle looks at each tick, to
/// notice any gone or changed which no watch did.
pub const EXTERNAL: usize = 64;

/// About how often, while calm, each block is sampled: often enough that a
/// sighting is usually refreshed in the second half of its time, before
/// it's forgotten.
const REVISIT: Duration = Duration::from_secs(TTL.as_secs() / 8);

/// The most of what's arrived audited at once.
pub const FRESH: usize = 256;

/// Auditing as a trickle, a few blocks at a time, at a pace that answers
/// to what it finds.
///
/// Copies made means more may be needed, so it hurries, halving its
/// interval down to `ALERT`; nothing to do and it relaxes, back up to
/// `CALM`. A member coming or going alarms it. Blocks no member can raise
/// don't count, or they'd keep it hurrying for nothing.
///
/// Each tick audits what's arrived since the last, so new blocks find
/// copies within seconds, and a sample at random of the rest, sized so
/// that at the calm pace each block comes up about every `REVISIT`.
#[derive(Debug, Clone)]
pub struct Trickle {
    interval: Duration,
}

impl Default for Trickle {
    fn default() -> Self {
        Self { interval: ALERT }
    }
}

impl Trickle {
    /// How many blocks of `blocks` to sample each tick.
    pub fn sample_size(blocks: u64) -> usize {
        let size = blocks.saturating_mul(CALM.as_secs()).div_ceil(REVISIT.as_secs().max(1));
        usize::try_from(size).unwrap_or(usize::MAX).max(1)
    }

    /// Answer what a tick found: whether copies were made, or more has
    /// arrived than one tick audits.
    pub fn observe(&mut self, report: &Report, more: bool) {
        self.interval = if report.copied > 0 || more {
            self.interval.checked_div(2).unwrap_or(ALERT).max(ALERT)
        } else {
            self.interval.saturating_add(self.interval.checked_div(4).unwrap_or_default()).min(CALM)
        };
    }

    /// Something changed which may have left blocks short.
    pub const fn alarm(&mut self) {
        self.interval = ALERT;
    }

    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// How long until the next tick: the interval, give or take a fifth,
    /// so nodes don't fall into step.
    pub fn delay(&self) -> Duration {
        let mut byte = [0u8];
        let _ = getrandom::getrandom(&mut byte);
        // 0.8 to 1.2 of the interval
        let [byte] = byte;
        let fifths = 0.8 + 0.4 * f64::from(byte) / 255.0;
        self.interval.mul_f64(fifths)
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
    fn the_trickle_hurries_when_theres_work_and_relaxes_when_not() {
        let mut trickle = Trickle::default();
        assert_eq!(trickle.interval(), ALERT);
        for _ in 0..30 {
            trickle.observe(&Report::default(), false);
        }
        assert_eq!(trickle.interval(), CALM);
        trickle.observe(&Report { advertised: 3, copied: 0, short: 3 }, false);
        assert_eq!(trickle.interval(), CALM, "what no one can raise is no reason to hurry");
        trickle.observe(&Report { advertised: 3, copied: 1, short: 0 }, false);
        assert_eq!(trickle.interval(), CALM / 2);
        trickle.observe(&Report::default(), true);
        assert_eq!(trickle.interval(), CALM / 4);
        trickle.alarm();
        assert_eq!(trickle.interval(), ALERT);
        let delay = trickle.delay();
        assert!(delay >= ALERT.mul_f64(0.79) && delay <= ALERT.mul_f64(1.21), "{delay:?}");
    }

    #[test]
    fn samples_visit_every_block_about_as_often_as_asked() {
        assert_eq!(Trickle::sample_size(0), 1);
        // A tick a minute, every block about every 21 hours
        assert_eq!(Trickle::sample_size(75_600), 60);
        assert_eq!(Trickle::sample_size(1_000_000), 794);
    }

    fn catalog_of(n: u8) -> (Db, Catalog, Vec<Block>) {
        let db = Db::memory().expect("db");
        let catalog = Catalog::standard(db.clone()).expect("catalog");
        let blocks: Vec<Block> = (0..n).map(|i| Block::hash(crate::cid::Cidv1Spec::default(), vec![i, 0x5a].into())).collect();
        for block in &blocks {
            catalog.put_block(block, crate::cid::CidVersion::V1).expect("put");
        }
        (db, catalog, blocks)
    }

    #[test]
    fn samples_are_of_whats_here() {
        let (_, catalog, blocks) = catalog_of(50);
        assert_eq!(catalog.block_count().expect("count"), 50);
        let sample = catalog.sample(10).expect("sample");
        assert!(sample.len() > 5 && sample.len() <= 10, "{}", sample.len());
        assert!(sample.iter().all(|key| catalog.has(key.as_ref()).expect("has")));
        let all = catalog.sample(1000).expect("sample");
        assert!(all.len() <= 50 && all.len() > 40, "{}", all.len());
        // What's arrived, in order, read on from where it was left
        let (first, at) = catalog.fresh_since(0, 30).expect("fresh");
        let (rest, end) = catalog.fresh_since(at, 30).expect("fresh");
        assert_eq!((first.len(), rest.len()), (30, 20));
        assert!(catalog.fresh_since(end, 30).expect("fresh").0.is_empty());
        let keys: Vec<Vec<u8>> = first.iter().chain(&rest).map(Multihash::to_bytes).collect();
        assert_eq!(keys, blocks.iter().map(|block| block.cid().multihash().to_bytes()).collect::<Vec<_>>());
    }

    #[test]
    fn copies_elsewhere_are_sighted_again_before_theyre_forgotten() {
        let (db, catalog, blocks) = catalog_of(1);
        let key = decode(&blocks.first().expect("block").cid().multihash().to_bytes()).expect("key");
        let me = PeerId::random();
        // A peer this node outranks, so it's the one to refresh
        let peer = std::iter::repeat_with(PeerId::random)
            .find(|peer| first_holder(&key.to_bytes(), [&me, peer]) == Some(me))
            .expect("one soon enough");
        let sightings = Sightings::open(db.clone()).expect("open");
        sightings.see(key.as_ref(), &peer, &replica(1, &["volume:01", "disk:elsewhere"])).expect("see");
        // Enough copies, freshly sighted: nothing to say
        let advertised = |sightings: &Sightings| {
            Audit::start(&catalog, sightings, me, &[peer], 2, [key.clone()]).expect("start").0.report.advertised
        };
        assert_eq!(advertised(&sightings), 0);
        // Four days on, it's due
        db.conn().execute("UPDATE sightings SET seen = seen - 4 * 86400", []).expect("age");
        assert_eq!(advertised(&sightings), 1);
    }

    #[test]
    fn a_peer_connected_since_vouches_for_its_sightings() {
        let (db, _catalog, blocks) = catalog_of(1);
        let key = blocks.first().expect("block").cid().multihash();
        let peer = PeerId::random();
        let sightings = Sightings::open(db).expect("open").with_ttl(Duration::ZERO);
        sightings.connected(peer);
        sightings.see(key, &peer, &replica(1, &["volume:01"])).expect("see");
        std::thread::sleep(Duration::from_millis(1100));
        // Past its time, but the peer's been connected since
        assert_eq!(sightings.of(key).expect("of").len(), 1);
        assert!(!sightings.stale(key).expect("stale"));
        assert_eq!(sightings.expire().expect("expire"), 0);
        sightings.disconnected(&peer);
        assert!(sightings.of(key).expect("of").is_empty());
        assert_eq!(sightings.expire().expect("expire"), 1);
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
