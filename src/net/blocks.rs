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
//! A whole file's CID, as DASL and `ATproto` name files, is no block anyone
//! can send, files being chunked. A member without such a block that
//! knows what it's the same as, through the UnixFS lens, sends the
//! `same` claims saying so beside its not having it; the asker keeps
//! them, and if they count, fetches the layout they name instead, each
//! block checked as it comes. Whoever reads the whole file checks it
//! against the whole CID once it's read (see `export::cat`).
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
use crate::claim::Claim;
use crate::export::Fetch as _;
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

impl Want {
    /// A want of these blocks, as a thin client asks: at most a batch's
    /// worth, the rest left out.
    pub fn of(blocks: &[Link]) -> Self {
        Self { want: blocks.iter().take(BATCH).map(|cid| ByteBuf::from(cid.multihash().to_bytes())).collect(), user: None }
    }
}

/// An answer to a want: blocks as (CID, bytes), and the multihashes of
/// those the peer doesn't have.
///
/// With them, the copies the peer holds of each block, so the asker knows
/// where else it lives, and the `same` claims saying what whole files it
/// doesn't have as blocks are the same as.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Blocks {
    #[serde(rename = "blocks")]
    found: Vec<(ByteBuf, ByteBuf)>,
    missing: Vec<ByteBuf>,
    #[serde(default)]
    copies: Vec<Vec<Replica>>,
    /// Claims as (CID, bytes): omitted by older builds, and when there are
    /// none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    said: Vec<(ByteBuf, ByteBuf)>,
}

impl Blocks {
    /// The multihashes of the blocks it carries.
    /// What wasn't here to serve, by CIDs of no codec in particular, as
    /// fetching blocks alone needs none: theirs come with them.
    pub fn missing(&self) -> Vec<Link> {
        self.missing.iter().filter_map(|key| Some(AnyCid::V1(Cidv1::new(RAW_CODEC, Multihash::decode(key).ok()?)))).collect()
    }

    /// The blocks it carries, as (CID, bytes), unverified.
    pub fn found(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.found.iter().map(|(cid, data)| (cid.as_slice(), data.as_slice()))
    }

    pub fn served(&self) -> Vec<Vec<u8>> {
        self.found.iter().filter_map(|(cid, _)| Some(Link::decode(cid).ok()?.multihash().to_bytes())).collect()
    }

    /// As served to a guest: the copies held here are no concern of a
    /// machine that doesn't host whose they are.
    #[must_use]
    pub fn without_copies(mut self) -> Self {
        self.copies.clear();
        self
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
            // A whole file's, perhaps, which is said to be the same as a
            // layout of it
            say_same_file(catalog, &AnyCid::V1(Cidv1::new(RAW_CODEC, multihash)), &mut answer.said);
            answer.missing.push(key.clone());
            continue;
        };
        if !answer.found.is_empty() && size.saturating_add(data.len()) > BUDGET {
            // Left out, to be asked again
            continue;
        }
        size = size.saturating_add(data.len());
        super::recent::used(&multihash.to_bytes());
        let cid = catalog.cids(multihash.as_ref()).ok().and_then(|cids| cids.into_iter().next());
        answer.copies.push(catalog.replicas(multihash.as_ref()).unwrap_or_default());
        let cid = cid.unwrap_or_else(|| AnyCid::V1(Cidv1::new(RAW_CODEC, multihash)));
        answer.found.push((ByteBuf::from(cid.to_bytes()), ByteBuf::from(data)));
    }
    answer
}

/// Add to what's said the same claims saying what a whole file's CID is
/// the same as, with their signatures and tombs, and theirs, without
/// which they're not what they say (see `structure::backrefs`).
fn say_same_file(catalog: &Catalog, whole: &Link, said: &mut Vec<(ByteBuf, ByteBuf)>) {
    let Ok(claims) = catalog.saying_same_file(whole) else {
        return;
    };
    if claims.is_empty() {
        return;
    }
    let keys: Vec<Vec<u8>> = claims.iter().map(|claim| claim.cid().multihash().to_bytes()).collect();
    let about = super::structure::backrefs(catalog, keys.iter().map(Vec::as_slice)).unwrap_or_default();
    let about = about.iter().filter_map(|cid| catalog.get_block(cid).ok().flatten());
    for block in claims.into_iter().chain(about) {
        let cid = ByteBuf::from(block.cid().to_bytes());
        if !said.iter().any(|(saying, _)| *saying == cid) {
            said.push((cid, ByteBuf::from(block.data().to_vec())));
        }
    }
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
    /// Whether what was first queued is yet to be looked up as whole
    /// files' CIDs, said to be the same as layouts here.
    roots: bool,
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
        Self { queue, wanted: BTreeMap::new(), inflight: HashMap::new(), seen: HashSet::new(), fetched: 0, missing: Vec::new(), deep, roots: true }
    }

    /// Look at what's queued here, then say what to ask of whom: batches
    /// of multihashes for members. Each is passed to `sent` once it is.
    pub fn plan(&mut self, catalog: &Catalog, peers: &[PeerId]) -> Result<Vec<(PeerId, Batch)>> {
        // A whole file's CID is fetched as a layout of it, if it's said to
        // be the same as one here. Only those first queued may be: what
        // they link to is of a layout already.
        if std::mem::take(&mut self.roots) {
            for link in &mut self.queue {
                if let Some(layout) = catalog.same_file(link)? {
                    *link = layout;
                }
            }
        }
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
        let said = Self::keep_said(catalog, &asked, answer.said).unwrap_or_else(|e| {
            failed = Some(e);
            false
        });
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
                // Not a block, but a whole file's, said to be the same as a
                // layout, which is fetched instead
                if said && let Some(layout) = catalog.same_file(&link)? {
                    self.queue.push(layout);
                    continue;
                }
                self.wanted.insert(key.into_vec(), (link, tried.saturating_add(1)));
            }
        }
        // Left out to keep the answer small: the same member again
        self.wanted.extend(asked);
        failed.map_or(Ok(()), Err)
    }

    /// Keep the `same` claims an answer carries which name, through the
    /// UnixFS lens, what was asked for, and the claims about them, however
    /// deep: their signatures and tombs. Nothing else is. Whether any
    /// were. They're kept whoever signed them, but count only if a key
    /// that counts here did.
    fn keep_said(catalog: &Catalog, asked: &Batch, said: Vec<(ByteBuf, ByteBuf)>) -> Result<bool> {
        let mut claims: Vec<(Link, Block, Claim)> = said.into_iter()
            .filter_map(|(cid, data)| {
                let link = Link::decode(&cid).ok()?;
                let block = Block::verify(link.clone().into(), data.into_vec().into_boxed_slice()).ok()?;
                let claim = Claim::parse(block.data())?;
                Some((link, block, claim))
            })
            .collect();
        let mut kept: HashSet<Vec<u8>> = HashSet::new();
        loop {
            let (keep, rest): (Vec<_>, Vec<_>) = claims.into_iter().partition(|(_, _, claim)| match claim {
                Claim::Same(same) => same.lens() == Some(crate::same::UNIXFS)
                    && same.target().iter().any(|target| asked.contains_key(&target.multihash().to_bytes())),
                claim @ (Claim::Sign(_) | Claim::Tomb(_)) => claim.target().iter().any(|target| kept.contains(&target.multihash().to_bytes())),
                _ => false,
            });
            claims = rest;
            if keep.is_empty() {
                break;
            }
            for (link, block, _) in keep {
                catalog.put_block(&block, link.version())?;
                kept.insert(link.multihash().to_bytes());
            }
        }
        Ok(!kept.is_empty())
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
