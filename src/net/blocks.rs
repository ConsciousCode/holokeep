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
use crate::store::{BlockIndex, BlockSource, Catalog};

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
}

/// An answer to a want: blocks as (CID, bytes), and the multihashes of
/// those the peer doesn't have.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Blocks {
    blocks: Vec<(ByteBuf, ByteBuf)>,
    missing: Vec<ByteBuf>,
}

impl Blocks {
    /// The multihashes of the blocks it carries.
    pub fn served(&self) -> Vec<Vec<u8>> {
        self.blocks.iter().filter_map(|(cid, _)| Some(Link::decode(cid).ok()?.multihash().to_bytes())).collect()
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
        let Ok(Some(data)) = catalog.get(multihash.as_ref()) else {
            answer.missing.push(key.clone());
            continue;
        };
        if !answer.blocks.is_empty() && size.saturating_add(data.len()) > BUDGET {
            // Left out, to be asked again
            continue;
        }
        size = size.saturating_add(data.len());
        let cid = catalog.cids(multihash.as_ref()).ok().and_then(|cids| cids.into_iter().next());
        let cid = cid.unwrap_or_else(|| AnyCid::V1(Cidv1::new(RAW_CODEC, multihash)));
        answer.blocks.push((ByteBuf::from(cid.to_bytes()), ByteBuf::from(data)));
    }
    answer
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
}

impl Fetch {
    pub fn new(root: Link) -> Self {
        Self { queue: vec![root], wanted: BTreeMap::new(), inflight: HashMap::new(), seen: HashSet::new(), fetched: 0, missing: Vec::new() }
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
                if link.codec() == RAW_CODEC {
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
        Want { want: batch.keys().cloned().map(ByteBuf::from).collect() }
    }

    pub fn sent(&mut self, request: OutboundRequestId, batch: Batch) {
        self.inflight.insert(request, batch);
    }

    pub fn asked(&self, request: OutboundRequestId) -> bool {
        self.inflight.contains_key(&request)
    }

    /// Keep what a member sent, if it's what was asked for and its bytes
    /// match its CID, and queue its links.
    pub fn received(&mut self, catalog: &Catalog, request: OutboundRequestId, answer: Blocks) -> Result<()> {
        let Some(mut asked) = self.inflight.remove(&request) else {
            return Ok(());
        };
        for (cid, data) in answer.blocks {
            let Ok(link) = Link::decode(&cid) else {
                continue;
            };
            let key = link.multihash().to_bytes();
            if asked.remove(&key).is_none() {
                continue;
            }
            let Ok(block) = Block::verify(link.clone().into(), data.into_vec().into_boxed_slice()) else {
                // Wrong bytes: ask someone else
                self.wanted.insert(key, (link, 1));
                continue;
            };
            catalog.put_block(&block, link.version())?;
            self.fetched = self.fetched.saturating_add(1);
            if link.codec() != RAW_CODEC {
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
        Ok(())
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
