//! Wanting blocks from other nodes: `/holokeep/blocks/1.0.0`.
//!
//! A want names multihashes; the answer carries those the peer could read,
//! each under the CID it was put with, so the asker learns its codec too,
//! and names those it doesn't have. What it leaves out of both, to keep an
//! answer to a few megabytes, is asked again.
//!
//! A fetch walks a DAG from its root: what's here is read here, for its
//! links (a raw block has none, so it's only looked for, never read), and
//! what isn't is wanted. Each multihash is asked of one connected member
//! at a time, starting from a different one for each block so a large
//! DAG's load is spread; a member without it passes it to the next. One
//! no member has is missing. Every block is verified against its CID
//! before it's kept, whoever sent it.
//!
//! In a small mesh, asking members in turn is enough; Kademlia provider
//! records are for when it isn't.

use std::collections::{BTreeMap, HashMap, HashSet};

use libp2p::PeerId;
use libp2p::request_response::OutboundRequestId;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::block::{Block, IDENTITY};
use crate::cid::{AnyCid, BaseCid, Cid, CidRef, Cidv1, RAW_CODEC};
use crate::model::Link;
use crate::multihash::Multihash;
use crate::store::{BlockIndex, BlockSource, Catalog, Replica};

use super::durability::Sightings;

use super::mesh::Result;

pub const PROTOCOL: libp2p::StreamProtocol = libp2p::StreamProtocol::new("/holokeep/blocks/1.0.0");

/// The most multihashes in one want.
const BATCH: usize = 64;

/// About the most block data in one answer, which always carries at least
/// one block if it can, however large.
const BUDGET: usize = 4 << 20;

/// Blocks wanted, by multihash.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Want {
    want: Vec<ByteBuf>,
    /// Whose these are wanted for, by the user's key CID: omitted by older
    /// builds, for the user the mesh was for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<ByteBuf>,
}

super::hosts::for_user!(Want);

/// An answer to a want: blocks as (CID, bytes), and the multihashes of
/// those the peer doesn't have; and the copies the peer holds of each
/// block, so the asker knows where else it lives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Blocks {
    #[serde(rename = "blocks")]
    found: Vec<(ByteBuf, ByteBuf)>,
    missing: Vec<ByteBuf>,
    #[serde(default)]
    copies: Vec<Vec<Replica>>,
}

impl Blocks {
    /// The multihashes of the blocks it carries.
    pub fn served(&self) -> Vec<Vec<u8>> {
        self.found.iter().filter_map(|(cid, _)| Some(Link::decode(cid).ok()?.multihash().to_bytes())).collect()
    }
}

/// Answer a want from what the catalog can read.
pub fn answer(catalog: &Catalog, want: &Want) -> Blocks {
    let mut answer = Blocks::default();
    let mut size = 0usize;
    for key in &want.want {
        let Ok(multihash) = Multihash::decode(key) else {
            answer.missing.push(key.clone());
            continue;
        };
        // Another account's is as good as not here
        let Ok(Some(data)) = catalog.visible(multihash.as_ref()).and_then(|visible| visible.then(|| catalog.get(multihash.as_ref())).transpose().map(Option::flatten)) else {
            answer.missing.push(key.clone());
            continue;
        };
        if !answer.found.is_empty() && size.saturating_add(data.len()) > BUDGET {
            // Left out, to be asked again
            continue;
        }
        size = size.saturating_add(data.len());
        let cid = catalog.cids(multihash.as_ref()).ok().and_then(|cids| cids.into_iter().next());
        answer.copies.push(catalog.replicas(multihash.as_ref()).unwrap_or_default());
        let cid = cid.unwrap_or_else(|| AnyCid::V1(Cidv1::new(RAW_CODEC, multihash)));
        answer.found.push((ByteBuf::from(cid.to_bytes()), ByteBuf::from(data)));
    }
    answer
}

/// An answer to a want refused, as from an account whose user the asker
/// doesn't host: none of it's here.
pub fn refuse(want: &Want) -> Blocks {
    Blocks { missing: want.want.clone(), ..Blocks::default() }
}

/// A block being wanted: its CID, and how many members have been asked.
type Wanted = (Link, usize);

/// Blocks to ask of one member, by multihash bytes.
type Batch = BTreeMap<Vec<u8>, Wanted>;

/// Fetching the DAG under a root.
pub struct Fetch {
    /// Blocks to look for here first.
    queue: Vec<Link>,
    /// Blocks to ask for, by multihash bytes.
    wanted: Batch,
    /// Wants sent, and what each asked for.
    inflight: HashMap<OutboundRequestId, Batch>,
    seen: HashSet<Vec<u8>>,
    fetched: usize,
    missing: Vec<Link>,
    /// Whether to follow links, fetching whole DAGs, or just the blocks.
    deep: bool,
}

impl Fetch {
    /// Fetch the DAG under a root.
    pub fn new(root: Link) -> Self {
        Self::of(vec![root], true)
    }

    /// Fetch just these blocks, not what they link to: what a reader
    /// needs next, without the rest of a DAG it may never read.
    pub fn blocks(blocks: Vec<Link>) -> Self {
        Self::of(blocks, false)
    }

    fn of(queue: Vec<Link>, deep: bool) -> Self {
        Self { queue, wanted: BTreeMap::new(), inflight: HashMap::new(), seen: HashSet::new(), fetched: 0, missing: Vec::new(), deep }
    }

    /// Look at what's queued here, then say what to ask of whom: batches
    /// of multihashes for members. Each is passed to `sent` once it is.
    pub fn plan(&mut self, catalog: &Catalog, peers: &[PeerId]) -> Result<Vec<(PeerId, Batch)>> {
        while let Some(link) = self.queue.pop() {
            let key = link.multihash().to_bytes();
            if link.hashcode() == IDENTITY || !self.seen.insert(key.clone()) {
                continue;
            }
            if catalog.has(link.multihash())? {
                if link.codec() == RAW_CODEC || !self.deep {
                    continue;
                }
                // Here, unless it's only on a volume that isn't attached
                if let Ok(Some(block)) = catalog.get_block(&link) {
                    self.queue.extend(crate::links::links(link.codec(), block.data()).unwrap_or_default());
                    continue;
                }
            }
            self.wanted.insert(key, (link, 0));
        }
        let mut batches: BTreeMap<PeerId, Batch> = BTreeMap::new();
        for (key, (link, asked)) in std::mem::take(&mut self.wanted) {
            if asked >= peers.len() {
                self.missing.push(link);
                continue;
            }
            // Start from a different member for each block
            let start = key.last().copied().map_or(0, usize::from);
            let Some(&peer) = peers.get(start.saturating_add(asked).checked_rem(peers.len()).unwrap_or_default()) else {
                continue;
            };
            batches.entry(peer).or_default().insert(key, (link, asked));
        }
        let mut plan = Vec::new();
        for (peer, mut batch) in batches {
            while !batch.is_empty() {
                let rest = batch.keys().nth(BATCH).cloned().map(|key| batch.split_off(&key)).unwrap_or_default();
                plan.push((peer, std::mem::replace(&mut batch, rest)));
            }
        }
        Ok(plan)
    }

    /// The want for a batch.
    pub fn want(batch: &Batch) -> Want {
        Want { want: batch.keys().cloned().map(ByteBuf::from).collect(), user: None }
    }

    pub fn sent(&mut self, request: OutboundRequestId, batch: Batch) {
        self.inflight.insert(request, batch);
    }

    pub fn asked(&self, request: OutboundRequestId) -> bool {
        self.inflight.contains_key(&request)
    }

    /// Keep what a member sent, if it's what was asked for and its bytes
    /// match its CID, and queue its links.
    /// The sender's copies of what's kept are sighted.
    pub fn received(&mut self, catalog: &Catalog, sightings: &Sightings, peer: &PeerId, request: OutboundRequestId, answer: Blocks) -> Result<()> {
        let Some(mut asked) = self.inflight.remove(&request) else {
            return Ok(());
        };
        let mut copies = answer.copies.into_iter();
        let mut failed = None;
        for (cid, data) in answer.found {
            let theirs = copies.next().unwrap_or_default();
            let Ok(link) = Link::decode(&cid) else {
                continue;
            };
            let key = link.multihash().to_bytes();
            let Some((_, tried)) = asked.remove(&key) else {
                continue;
            };
            let Ok(block) = Block::verify(link.clone().into(), data.into_vec().into_boxed_slice()) else {
                // Wrong bytes: ask someone else
                self.wanted.insert(key, (link, 1));
                continue;
            };
            // What can't be kept yet is wanted still, as is the rest of the
            // answer, there being no use in waiting for each in turn
            if let Err(e) = catalog.put_block(&block, link.version()) {
                asked.insert(key, (link, tried));
                failed = Some(e.into());
                break;
            }
            if link.hashcode() != IDENTITY {
                for replica in &theirs {
                    if let Err(e) = sightings.see(link.multihash(), peer, replica) {
                        failed = Some(e);
                    }
                }
            }
            self.fetched = self.fetched.saturating_add(1);
            if link.codec() != RAW_CODEC && self.deep {
                self.queue.extend(crate::links::links(link.codec(), block.data()).unwrap_or_default());
            }
        }
        for key in answer.missing {
            if let Some((link, tried)) = asked.remove(key.as_slice()) {
                self.wanted.insert(key.into_vec(), (link, tried.saturating_add(1)));
            }
        }
        // Left out to keep the answer small: the same member again
        self.wanted.extend(asked);
        failed.map_or(Ok(()), Err)
    }

    /// A want which got no answer: ask the next member.
    pub fn failed(&mut self, request: OutboundRequestId) {
        for (key, (link, tried)) in self.inflight.remove(&request).unwrap_or_default() {
            self.wanted.insert(key, (link, tried.saturating_add(1)));
        }
    }

    pub fn done(&self) -> bool {
        self.queue.is_empty() && self.wanted.is_empty() && self.inflight.is_empty()
    }

    /// How many blocks were fetched, and those no member had.
    pub fn outcome(self) -> (usize, Vec<Link>) {
        (self.fetched, self.missing)
    }
}
