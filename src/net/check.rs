//! Checking which members hold blocks, for `hk block where` and the like.
//!
//! What's sighted is the cache. Asked to, a node asks each connected member
//! about the blocks it has no fresh sighting of from that member, or about
//! every one, with an advert, as an audit does: answering one does nothing
//! but say what's held, and note the asker's copies. What a member says it
//! holds is noted as sighted, and what it says it doesn't, forgotten, of
//! the blocks this node holds, whose sightings it keeps. That a member
//! doesn't hold a block isn't kept, as it may have it again at any time.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;

use libp2p::PeerId;
use libp2p::request_response::OutboundRequestId;
use serde_bytes::ByteBuf;

use super::durability::{ADVERT_BATCH, Advert, Haves, Sightings};
use super::mesh::Result;
use crate::block::IDENTITY;
use crate::health::{Elsewhere, Known};
use crate::multihash::Multihash;
use crate::store::{BlockIndex as _, Catalog, Replica};

/// A check, as the node knows it.
pub type CheckId = u64;

/// Whom a check asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asking {
    /// No one: what's sighted is all.
    No,
    /// Each connected member, of what it's not been sighted with lately.
    Unsighted,
    /// Each connected member, of everything.
    All,
}

impl Asking {
    pub const fn word(self) -> &'static str {
        match self {
            Self::No => "sighted",
            Self::Unsighted => "ask",
            Self::All => "ask-all",
        }
    }
}

impl FromStr for Asking {
    type Err = ();

    fn from_str(word: &str) -> std::result::Result<Self, ()> {
        [Self::No, Self::Unsighted, Self::All].into_iter().find(|asking| asking.word() == word).ok_or(())
    }
}

/// Who holds a block's copies, and when each was seen holding them.
type Holders = BTreeMap<PeerId, (Vec<Replica>, i64)>;

/// Finding who holds some blocks.
#[derive(Debug, Default)]
pub struct Check {
    /// Each block's copies elsewhere, by its multihash: by whom, and seen
    /// when.
    found: BTreeMap<Vec<u8>, Holders>,
    /// Adverts sent: to whom, and naming what.
    asking: HashMap<OutboundRequestId, (PeerId, Vec<Vec<u8>>)>,
    asked: BTreeSet<PeerId>,
    unanswered: BTreeSet<PeerId>,
    /// How many members it could have asked.
    connected: usize,
}

impl Check {
    /// Check these blocks among these members, connected, asking them as
    /// said. Returns the check and the adverts to send whom: each names
    /// the copies here, if they count (`own`), as an audit's do.
    pub fn start(catalog: &Catalog, sightings: &Sightings, own: bool, members: &[PeerId], keys: &[Multihash], asking: Asking) -> Result<(Self, Vec<(PeerId, Advert)>)> {
        let mut check = Self { connected: members.len(), ..Self::default() };
        let mut ask: BTreeMap<PeerId, Vec<(ByteBuf, Vec<Replica>)>> = BTreeMap::new();
        for key in keys {
            let bytes = key.to_bytes();
            if key.code() == IDENTITY || check.found.contains_key(&bytes) {
                continue;
            }
            let mut found = Holders::new();
            for (peer, replica, seen) in sightings.sighted(key.as_ref())? {
                let (replicas, latest) = found.entry(peer).or_insert_with(|| (Vec::new(), seen));
                replicas.push(replica);
                *latest = (*latest).max(seen);
            }
            if asking != Asking::No {
                let ours = if own { catalog.replicas(key.as_ref())? } else { Vec::new() };
                for peer in members {
                    let fresh = found.get(peer).is_some_and(|&(_, seen)| sightings.fresh(peer, seen));
                    if asking == Asking::All || !fresh {
                        ask.entry(*peer).or_default().push((ByteBuf::from(bytes.clone()), ours.clone()));
                    }
                }
            }
            check.found.insert(bytes, found);
        }
        let mut adverts = Vec::new();
        for (peer, blocks) in ask {
            for batch in blocks.chunks(ADVERT_BATCH) {
                adverts.push((peer, Advert::naming(batch.to_vec())));
            }
        }
        Ok((check, adverts))
    }

    pub fn sent(&mut self, request: OutboundRequestId, peer: PeerId, advert: &Advert) {
        self.asking.insert(request, (peer, advert.keys()));
    }

    /// Whether it sent this advert.
    pub fn asked(&self, request: OutboundRequestId) -> bool {
        self.asking.contains_key(&request)
    }

    /// Take in a member's answer: its copies, noted as sighted of what's
    /// held here, and what it doesn't hold, forgotten.
    pub fn answered(&mut self, catalog: &Catalog, sightings: &Sightings, request: OutboundRequestId, haves: Haves) -> Result<()> {
        let Some((peer, asked)) = self.asking.remove(&request) else {
            return Ok(());
        };
        self.asked.insert(peer);
        let now = crate::health::now();
        let mut held: BTreeMap<Vec<u8>, Vec<Replica>> = haves.into_held().into_iter().map(|(key, replicas)| (key.into_vec(), replicas)).collect();
        // Every answer's taken in whether or not it can be noted, as an
        // audit's are: sightings are made again
        let mut noting = Ok(());
        for key in asked {
            let Some(found) = self.found.get_mut(&key) else {
                continue;
            };
            let replicas = held.remove(&key);
            if noting.is_ok()
                && let Ok(multihash) = Multihash::decode(&key)
            {
                noting = note(catalog, sightings, &multihash, &peer, replicas.as_deref());
            }
            match replicas {
                Some(replicas) => {
                    found.insert(peer, (replicas, now));
                },
                None => {
                    found.remove(&peer);
                },
            }
        }
        noting
    }

    /// An advert that got no answer.
    pub fn failed(&mut self, request: OutboundRequestId) {
        if let Some((peer, _)) = self.asking.remove(&request) {
            self.unanswered.insert(peer);
        }
    }

    /// Whether every advert's been answered, or given up on.
    pub fn done(&self) -> bool {
        self.asking.is_empty()
    }

    /// What it found.
    pub fn known(self) -> Known {
        let elsewhere = self
            .found
            .into_iter()
            .map(|(key, found)| {
                let copies = found.into_iter().flat_map(|(peer, (replicas, seen))| replicas.into_iter().map(move |replica| Elsewhere { peer: peer.to_string(), replica, seen })).collect();
                (key, copies)
            })
            .collect();
        let unanswered: BTreeSet<String> = self.unanswered.iter().map(ToString::to_string).collect();
        let asked = self.asked.iter().map(ToString::to_string).filter(|peer| !unanswered.contains(peer)).collect();
        Known { node: true, connected: self.connected, elsewhere, asked, unanswered }
    }
}

/// Note what a member said of a block this node holds: its copies, or
/// that it has none.
fn note(catalog: &Catalog, sightings: &Sightings, key: &Multihash, peer: &PeerId, replicas: Option<&[Replica]>) -> Result<()> {
    if !catalog.has(key.as_ref())? {
        return Ok(());
    }
    match replicas {
        Some(replicas) => {
            for replica in replicas {
                sightings.see(key.as_ref(), peer, replica)?;
            }
        },
        None => sightings.unsee(key.as_ref(), peer)?,
    }
    Ok(())
}

