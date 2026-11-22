//! Capabilities: sharing by key, from ciphertext no member guards.
//!
//! A DAG is shared by sealing it: every block is encrypted under a node
//! key of its own, derived down the tree from a random read key, so a key
//! opens what's under it and nothing above. A directory entry's key is
//! derived from its directory's and its name, so an edit seals again only
//! the path to it; anything else's, from its parent's and its CID. What's
//! sealed in each block is a sealed node: the plaintext block, whole, and
//! the ciphertext CIDs of its links, which can't be worked out from the
//! block, padded to a size class. Sealing is deterministic: the same DAG
//! under the same read key seals to the same blocks, on any machine.
//!
//! A capability names the sealed root, the plaintext root, and the read
//! key, as `hkcap` and dag-cbor in multibase. This is the first phase of
//! the wiki's Capabilities page: snapshots, a fixed root with no heads.

use std::collections::{BTreeMap, HashMap};

use zeroize::Zeroizing;

use crate::block::{Block, IDENTITY};
use crate::cid::{AnyCid, BaseCid as _, CidRef, DAG_PB_CODEC};
use crate::export::Fetch;
use crate::model::{Ipld, Link};
use crate::pb::PbNode;
use crate::unixfs::{DataBuf, DataType};
use crate::vault::{Sealer, derive};

/// What a capability's text starts with.
pub const PREFIX: &str = "hkcap";

/// The smallest size class, and the largest a power of two: past it,
/// sealed nodes are padded to its multiples.
const SMALLEST: usize = 256;
const PAGE: usize = 4096;

/// A HAMT's fanout, when its shard doesn't say.
const FANOUT: u64 = 256;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] crate::vault::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] crate::store::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("its latest head is older than one read before: what has it may be out of date, or keeping the latest from you")]
    Behind,
}

pub type Result<T> = std::result::Result<T, Error>;

fn invalid(what: impl Into<String>) -> Error {
    Error::Invalid(what.into())
}

/// A 32-byte key, wiped when dropped.
type Key = Zeroizing<[u8; 32]>;

/// The root node's key, from the read key.
fn root_key(read: &[u8; 32]) -> Key {
    derive(read, b"root", b"")
}

/// The key of a directory's entry, by its name.
fn by_name(key: &[u8; 32], name: &[u8]) -> Key {
    derive(key, b"name", name)
}

/// The key of anything else linked to, by its plaintext CID.
fn by_cid(key: &[u8; 32], cid: &Link) -> Key {
    derive(key, b"cid", &cid.to_bytes())
}

/// How long a sealed node of `len` bytes is once padded: to 256 B, 512 B,
/// 1 KiB, 2 KiB, 4 KiB, then each multiple of 4 KiB.
pub const fn padded(len: usize) -> usize {
    if len <= PAGE {
        if len <= SMALLEST { SMALLEST } else { len.next_power_of_two() }
    } else {
        len.div_ceil(PAGE).saturating_mul(PAGE)
    }
}

/// A sealed node: a plaintext block, its links' ciphertext CIDs, and the
/// sealed anchor each mount point among its entries is, as dag-cbor,
/// padded with zeros.
fn encode(block: &[u8], links: &[Link], mounts: &BTreeMap<String, Mount>) -> Result<Vec<u8>> {
    let mut map = BTreeMap::from([("block".to_owned(), Ipld::Bytes(block.to_vec()))]);
    if !links.is_empty() {
        map.insert("links".to_owned(), Ipld::List(links.iter().cloned().map(Ipld::Link).collect()));
    }
    if !mounts.is_empty() {
        let mounts = mounts.iter().map(|(name, mount)| {
            let mount = BTreeMap::from([("read".to_owned(), Ipld::Bytes(mount.read.to_vec())), ("view".to_owned(), Ipld::Link(mount.view.clone()))]);
            (name.clone(), Ipld::Map(mount))
        });
        map.insert("mounts".to_owned(), Ipld::Map(mounts.collect()));
    }
    pad(map)
}

/// The sealed anchor a mount point is, as its parent's sealed node says:
/// its sealed view, and its read key.
#[derive(Clone)]
pub struct Mount {
    pub view: Link,
    read: Key,
    /// The plaintext anchor it's of, as its symlink says, once that's
    /// read: not sealed in `mounts`.
    pub of: Option<Link>,
}

impl Mount {
    /// What reads it.
    pub fn live(&self) -> Live {
        Live::new(self.view.clone(), Zeroizing::new(*self.read))
    }
}

/// How big a mount point's block may be, as its link says: a symlink to
/// `/anchors/<anchor>`. Anything bigger isn't read to see if it's one.
const MOUNT_MAX: u64 = 256;

/// The anchor a block names, if it's a mount point: a UnixFS symlink to
/// `/anchors/<anchor>`.
fn mount_target(data: &[u8]) -> Option<Link> {
    let node = PbNode::decode(data).ok()?;
    let unixfs = DataBuf::decode(node.data?).ok()?;
    if unixfs.data_type != DataType::Symlink || !node.links.is_empty() {
        return None;
    }
    let target = unixfs.data?;
    let anchor: Link = std::str::from_utf8(target.strip_prefix(b"/anchors/")?).ok()?.parse().ok()?;
    crate::claim::is_anchor(&anchor).then_some(anchor)
}

/// A padded dag-cbor map, read: one canonical map, then only zeros, to
/// the size class its length makes it.
fn unpad(bytes: &[u8], what: &str) -> Result<BTreeMap<String, Ipld>> {
    let (value, rest): (Ipld, &[u8]) = crate::dagcbor::from_slice_first(bytes).map_err(|e| invalid(format!("a {what} that isn't one: {e}")))?;
    let len = bytes.len().saturating_sub(rest.len());
    if rest.iter().any(|&byte| byte != 0) || bytes.len() != padded(len) {
        return Err(invalid(format!("a {what} padded wrongly")));
    }
    match value {
        Ipld::Map(map) => Ok(map),
        _ => Err(invalid(format!("a {what} that isn't a map"))),
    }
}

/// A dag-cbor map, padded to its size class.
fn pad(map: BTreeMap<String, Ipld>) -> Result<Vec<u8>> {
    let mut bytes = crate::dagcbor::to_vec(&Ipld::Map(map)).map_err(|e| invalid(format!("encoding: {e}")))?;
    bytes.resize(padded(bytes.len()), 0);
    Ok(bytes)
}

/// What a sealed node says.
struct Opened {
    block: Vec<u8>,
    links: Vec<Link>,
    /// Keys for entries that don't derive theirs, by name.
    keys: BTreeMap<String, Key>,
    /// The sealed anchors mount points among its entries are, by name.
    mounts: BTreeMap<String, Mount>,
}

/// A sealed node, read: one canonical dag-cbor map, then only zeros, to
/// the size class its length makes it.
fn decode(bytes: &[u8]) -> Result<Opened> {
    let mut map = unpad(bytes, "sealed node")?;
    let Some(Ipld::Bytes(block)) = map.remove("block") else {
        return Err(invalid("a sealed node with no block"));
    };
    let links = match map.remove("links") {
        None => Vec::new(),
        Some(Ipld::List(links)) => links.into_iter().map(|link| match link {
            Ipld::Link(link) => Ok(link),
            _ => Err(invalid("a sealed node's link that isn't one")),
        }).collect::<Result<_>>()?,
        Some(_) => return Err(invalid("a sealed node's links that aren't a list")),
    };
    let keys = match map.remove("keys") {
        None => BTreeMap::new(),
        Some(Ipld::Map(keys)) => keys.into_iter().map(|(name, key)| match key {
            Ipld::Bytes(key) => <[u8; 32]>::try_from(key.as_slice()).map(|key| (name, Zeroizing::new(key))).map_err(|_| invalid("a sealed node's key that isn't 32 bytes")),
            _ => Err(invalid("a sealed node's key that isn't bytes")),
        }).collect::<Result<_>>()?,
        Some(_) => return Err(invalid("a sealed node's keys that aren't a map")),
    };
    let mounts = match map.remove("mounts") {
        None => BTreeMap::new(),
        Some(Ipld::Map(mounts)) => mounts.into_iter().map(|(name, mount)| {
            let bad = || invalid("a sealed node's mount point that isn't {view, read}");
            let Ipld::Map(mut mount) = mount else {
                return Err(bad());
            };
            let (Some(Ipld::Link(view)), Some(Ipld::Bytes(read)), true) = (mount.remove("view"), mount.remove("read"), mount.is_empty()) else {
                return Err(bad());
            };
            let read = <[u8; 32]>::try_from(read.as_slice()).map_err(|_| bad())?;
            crate::claim::viewed(&view).ok_or_else(bad)?;
            Ok((name, Mount { view, read: Zeroizing::new(read), of: None }))
        }).collect::<Result<_>>()?,
        Some(_) => return Err(invalid("a sealed node's mount points that aren't a map")),
    };
    if let Some(other) = map.keys().next() {
        return Err(invalid(format!("a sealed node with `{other}` in it")));
    }
    Ok(Opened { block, links, keys, mounts })
}

/// One of a block's links, and how its key's found: the key, the entry
/// name it's by, if it's a directory's entry, and the key of the
/// directory whose HAMT it's a shard of, if it is one.
struct Child {
    cid: Link,
    key: Key,
    entry: Option<Vec<u8>>,
    within: Option<Key>,
    /// Where it is among its parent's links, if that's said by name: an
    /// entry, by its name, or a HAMT's shard, by its index.
    place: Option<Vec<u8>>,
    /// How big what it links to is, all told, if its link says.
    size: Option<u64>,
}

/// The links of a plaintext block, in order, each with its key: by name,
/// for a directory's entries, whether in its node or its HAMT's shards,
/// from the directory's key; by CID for anything else, and for a HAMT's
/// shards, from the directory's key, so an entry's key doesn't change as
/// the HAMT's shape does. `within` is the directory's key, if this block
/// is a HAMT's shard below its root.
fn children(cid: &Link, data: &[u8], key: &[u8; 32], within: Option<&Key>) -> Result<Vec<Child>> {
    let bad = |e: &dyn std::fmt::Display| invalid(format!("{cid}: {e}"));
    if cid.codec() != DAG_PB_CODEC {
        let links = crate::links::links(cid.codec(), data).map_err(|e| bad(&e))?;
        return Ok(links.into_iter().map(|link| Child { key: by_cid(key, &link), cid: link, entry: None, within: None, place: None, size: None }).collect());
    }
    let node = PbNode::decode(data).map_err(|e| bad(&format!("{e:?}")))?;
    let unixfs = node.data.and_then(|data| DataBuf::decode(data).ok());
    let mut out = Vec::with_capacity(node.links.len());
    for link in &node.links {
        let child: Link = link.cid().map_err(|e| bad(&format!("{e:?}")))?;
        let name = link.name.unwrap_or_default();
        let size = link.tsize;
        out.push(match unixfs.as_ref().map(|unixfs| unixfs.data_type) {
            Some(DataType::Directory) => Child { key: by_name(key, name), cid: child, entry: Some(name.to_vec()), within: None, place: Some([b"e", name].concat()), size },
            Some(DataType::HAMTShard) => {
                let dir: &[u8; 32] = within.map_or(key, |within| within);
                let fanout = unixfs.as_ref().and_then(|unixfs| unixfs.fanout).unwrap_or(FANOUT);
                let pad = format!("{:X}", fanout.saturating_sub(1)).len();
                match name.get(pad..) {
                    Some([]) => Child { key: by_cid(dir, &child), cid: child, entry: None, within: Some(Zeroizing::new(*dir)), place: Some([b"s", name].concat()), size },
                    Some(entry) => Child { key: by_name(dir, entry), cid: child, entry: Some(entry.to_vec()), within: None, place: Some([b"e", entry].concat()), size },
                    None => return Err(bad(&"a HAMT's link with too short a name")),
                }
            },
            _ => Child { key: by_cid(key, &child), cid: child, entry: None, within: None, place: None, size },
        });
    }
    Ok(out)
}

/// A DAG, sealed: its root's ciphertext, and every sealed block.
pub struct Sealed {
    pub root: Link,
    pub blocks: Vec<Block>,
}

/// Seal the DAG under `root` with a read key, fetching its blocks from
/// `src`. Identity CIDs aren't sealed, being in their parents already.
pub fn seal(src: &impl Fetch, root: &Link, read: &[u8; 32]) -> Result<Sealed> {
    seal_since(src, root, read, None)
}

/// Seal a DAG as `seal` does, after an earlier one: only what's new.
///
/// `before` is a DAG sealed under the same read key, its plaintext root
/// and sealed root, whose sealed blocks `src` has too: what's the same in both, by plaintext CID and
/// key, isn't sealed again, nor read, and only what's new is returned. The
/// earlier tree's opened along each path that's changed, to find what's
/// the same below it.
pub fn seal_since(src: &impl Fetch, root: &Link, read: &[u8; 32], before: Option<(Link, Link)>) -> Result<Sealed> {
    seal_tree(src, root, read, before, MountKeys::None).map(|(sealed, _)| sealed)
}

/// How mount points are sealed.
///
/// Not at all, as the symlinks they are; as the sealed anchor each
/// anchor's published as, from the capabilities' secret; or as those
/// known, by the plaintext anchor each is of, as a writer knows them from
/// what it read, the rest as symlinks.
#[derive(Clone, Copy)]
pub enum MountKeys<'a> {
    None,
    Secret(&'a [u8; 32]),
    Known(&'a [Mount]),
}

/// Seal a DAG as `seal_since` does, each mount point among a directory's
/// entries as `mounts` says (see `Mount`). Returns the anchors mount
/// points name in what was sealed, which is only what's new.
fn seal_tree(src: &impl Fetch, root: &Link, read: &[u8; 32], before: Option<(Link, Link)>, mounts: MountKeys<'_>) -> Result<(Sealed, Vec<Link>)> {
    let mut sealing = Sealing { src, mounts, mounted: Vec::new(), done: HashMap::new(), blocks: Vec::new() };
    let root = sealing.seal(root, &root_key(read), None, before)?;
    Ok((Sealed { root, blocks: sealing.blocks }, sealing.mounted))
}

struct Sealing<'a, F> {
    src: &'a F,
    mounts: MountKeys<'a>,
    /// The anchors mount points sealed name, each once.
    mounted: Vec<Link>,
    /// What's been sealed, by plaintext CID and key: the same block under
    /// the same key seals the same way, so once.
    done: HashMap<(Vec<u8>, [u8; 32]), Link>,
    blocks: Vec<Block>,
}

impl<F: Fetch> Sealing<'_, F> {
    /// Seal a block and what's under it, under its key, with what was in
    /// its place before, if anything was: its plaintext and sealed CIDs.
    fn seal(&mut self, cid: &Link, key: &Key, within: Option<&Key>, before: Option<(Link, Link)>) -> Result<Link> {
        if cid.hashcode() == IDENTITY {
            return Ok(cid.clone());
        }
        let done = (cid.to_bytes(), **key);
        if let Some(sealed) = self.done.get(&done) {
            return Ok(sealed.clone());
        }
        // Nothing's changed here: it's sealed already
        if let Some((was, sealed)) = &before
            && was == cid
        {
            self.done.insert(done, sealed.clone());
            return Ok(sealed.clone());
        }
        let data = self.src.fetch(cid)?;
        let mut was = match before {
            Some((was, sealed)) => self.opened(&was, &sealed, key, within),
            None => HashMap::new(),
        };
        let mut links = Vec::new();
        let mut mounts = BTreeMap::new();
        for child in children(cid, &data, key, within)? {
            if let Some((name, mount)) = self.mount(&child)? {
                mounts.insert(name, mount);
            }
            let before = child.place.as_ref().and_then(|place| was.remove(place));
            links.push(self.seal(&child.cid, &child.key, child.within.as_ref(), before)?);
        }
        let block = Sealer::new(key).seal(cid, &encode(&data, &links, &mounts)?)?;
        let sealed = AnyCid::V1(block.cid().clone());
        self.blocks.push(block);
        self.done.insert(done, sealed.clone());
        Ok(sealed)
    }

    /// The sealed anchor an entry is, if it's a mount point and mount
    /// points are being sealed: by its name.
    fn mount(&mut self, child: &Child) -> Result<Option<(String, Mount)>> {
        let Some(entry) = &child.entry else {
            return Ok(None);
        };
        if matches!(self.mounts, MountKeys::None) {
            return Ok(None);
        }
        if child.size.is_some_and(|size| size > MOUNT_MAX) || child.cid.codec() != DAG_PB_CODEC || child.cid.hashcode() == IDENTITY {
            return Ok(None);
        }
        let Ok(name) = String::from_utf8(entry.clone()) else {
            return Ok(None);
        };
        let Some(anchor) = mount_target(&self.src.fetch(&child.cid)?) else {
            return Ok(None);
        };
        let mount = match self.mounts {
            MountKeys::Secret(secret) => {
                let published = Published::of(secret, &anchor)?;
                Mount { view: published.view, read: published.read, of: Some(anchor.clone()) }
            },
            MountKeys::Known(known) => match known.iter().find(|mount| mount.of.as_ref() == Some(&anchor)) {
                Some(mount) => mount.clone(),
                None => return Ok(None),
            },
            MountKeys::None => return Ok(None),
        };
        if !self.mounted.contains(&anchor) {
            self.mounted.push(anchor);
        }
        Ok(Some((name, mount)))
    }

    /// What was sealed in a place before, opened: each of its links is
    /// noted as sealed, by plaintext CID and key, and those whose place is
    /// said by name are returned by it, to follow down. Nothing, if it
    /// can't be opened, so what's under it is sealed again.
    fn opened(&mut self, plain: &Link, sealed: &Link, key: &Key, within: Option<&Key>) -> HashMap<Vec<u8>, (Link, Link)> {
        let mut places = HashMap::new();
        let Ok(bytes) = self.src.fetch(sealed) else {
            return places;
        };
        let Ok(node) = Sealer::new(key).open(plain, &bytes).map_err(Error::from).and_then(|opened| decode(&opened)) else {
            return places;
        };
        let Ok(children) = children(plain, &node.block, key, within) else {
            return places;
        };
        if children.len() != node.links.len() || !node.keys.is_empty() {
            return places;
        }
        for (child, sealed) in children.into_iter().zip(node.links) {
            self.done.insert((child.cid.to_bytes(), *child.key), sealed.clone());
            if let Some(place) = child.place {
                places.insert(place, (child.cid, sealed));
            }
        }
        places
    }
}

/// Where sealed blocks are read from, each asked for with its block
/// access token.
///
/// A holder outside the reader's meshes wants proof of it (see
/// `crate::net::door`). Anything blocks can be fetched from is one,
/// heeding no tokens.
pub trait Source {
    /// Sealed blocks, by CID, each with its token: their bytes, in order.
    fn sealed(&self, wanted: &[(Link, [u8; 32])]) -> Result<Vec<Vec<u8>>>;
}

impl<F: Fetch> Source for F {
    fn sealed(&self, wanted: &[(Link, [u8; 32])]) -> Result<Vec<Vec<u8>>> {
        self.prefetch(&wanted.iter().map(|(cid, _)| cid.clone()).collect::<Vec<_>>());
        wanted.iter().map(|(cid, _)| Ok(self.fetch(cid)?)).collect()
    }
}

/// A sealed node's block access token, from its key and plaintext CID.
fn node_bat(key: &[u8; 32], plain: &Link) -> [u8; 32] {
    *derive(key, b"bat", &plain.to_bytes())
}

/// Unseal the DAG a capability names, fetching sealed blocks from `src`.
///
/// Returns every plaintext block, root first, each checked against its
/// CID. Identity CIDs are left out, being in their parents. Each level's
/// blocks are asked for at once.
pub fn unseal(src: &impl Source, cap: &Snapshot) -> Result<Vec<Block>> {
    unseal_mounts(src, cap).map(|(blocks, _)| blocks)
}

/// The sealed anchors mount points are, each by its path, `/`-separated.
type MountsAt = Vec<(String, Mount)>;

/// Unseal a DAG as `unseal` does, returning too the sealed anchor each
/// mount point in it is, by its path from the root, `/`-separated.
fn unseal_mounts(src: &impl Source, cap: &Snapshot) -> Result<(Vec<Block>, MountsAt)> {
    let mut out = Vec::new();
    let mut mounts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut level = vec![(cap.plain.clone(), cap.root.clone(), root_key(&cap.read), None::<Key>, String::new())];
    while !level.is_empty() {
        level.retain(|(plain, _, key, ..)| plain.hashcode() != IDENTITY && seen.insert((plain.to_bytes(), **key)));
        let wanted: Vec<(Link, [u8; 32])> = level.iter().map(|(plain, sealed, key, ..)| (sealed.clone(), node_bat(key, plain))).collect();
        let fetched = src.sealed(&wanted)?;
        let mut next = Vec::new();
        for ((plain, _, key, within, path), bytes) in level.into_iter().zip(fetched) {
            let mut opened = decode(&Sealer::new(&key).open(&plain, &bytes)?)?;
            let block = Block::verify(plain.clone().into(), std::mem::take(&mut opened.block).into_boxed_slice()).map_err(|_| invalid(format!("{plain} unsealed to other bytes")))?;
            let children = children(&plain, block.data(), &key, within.as_ref())?;
            if children.len() != opened.links.len() {
                return Err(invalid(format!("{plain}'s sealed node has {} links for its {}", opened.links.len(), children.len())));
            }
            for (child, sealed) in children.into_iter().zip(std::mem::take(&mut opened.links)) {
                let entry = child.entry.as_deref().and_then(|entry| std::str::from_utf8(entry).ok());
                let path = match entry {
                    Some(entry) if path.is_empty() => entry.to_owned(),
                    Some(entry) => format!("{path}/{entry}"),
                    None => path.clone(),
                };
                if let Some(mount) = entry.and_then(|entry| opened.mounts.remove(entry)) {
                    mounts.push((path.clone(), mount, child.cid.clone()));
                }
                // A key that doesn't derive, kept from an earlier read key
                let kept = entry.and_then(|entry| opened.keys.get(entry));
                let key = kept.map_or(child.key, |kept| Zeroizing::new(**kept));
                next.push((child.cid, sealed, key, child.within, path));
            }
            if let Some(name) = opened.mounts.keys().next() {
                return Err(invalid(format!("{plain}'s sealed node has a mount point {name} for no entry of it")));
            }
            out.push(block);
        }
        level = next;
    }
    // Which plaintext anchor each is, as its symlink, unsealed, says
    let mounts = mounts.into_iter().map(|(path, mut mount, cid)| {
        mount.of = out.iter().find(|block| AnyCid::V1(block.cid().clone()) == cid).and_then(|block| mount_target(block.data()));
        (path, mount)
    }).collect();
    Ok((out, mounts))
}

/// Sealed blocks held in memory, by CID, to unseal from: a CAR's.
#[derive(Default)]
pub struct Held(HashMap<Vec<u8>, Vec<u8>>);

impl Held {
    /// Every block of a CAR, each checked against its CID.
    pub fn from_car(reader: impl std::io::Read + 'static) -> Result<Self> {
        let mut held = Self::default();
        held.add_car(reader)?;
        Ok(held)
    }

    /// Every block of another CAR too, each checked against its CID.
    pub fn add_car(&mut self, reader: impl std::io::Read + 'static) -> Result<()> {
        let mut car = crate::car::CarReader::new(reader)?;
        while let Some((block, _)) = car.next_block()? {
            self.0.insert(AnyCid::V1(block.cid().clone()).to_bytes(), block.into_data().into_vec());
        }
        Ok(())
    }

    pub fn insert(&mut self, block: Block) {
        self.0.insert(AnyCid::V1(block.cid().clone()).to_bytes(), block.into_data().into_vec());
    }

    /// Every block held, as blocks.
    pub fn blocks(&self) -> impl Iterator<Item = Block> + '_ {
        self.0.iter().filter_map(|(cid, data)| {
            let link: Link = crate::cid::Cid::decode(cid).ok()?;
            Block::verify(link.into(), data.clone().into_boxed_slice()).ok()
        })
    }

    /// Every block held, as claims among them might be.
    pub fn all(&self) -> impl Iterator<Item = &[u8]> {
        self.0.values().map(Vec::as_slice)
    }
}

/// The claims a catalog holds of a sealed anchor, to judge which count.
///
/// They're its sets, the grants on it, and what signs each, as blocks.
/// Its first grant isn't among them: a reader makes it (see `genesis`).
pub fn claims_about(catalog: &crate::store::Catalog, view: &Link) -> Result<Vec<(Link, Vec<u8>)>> {
    use crate::store::RefIndex as _;
    let (anchor, _) = crate::claim::viewed(view).ok_or_else(|| invalid("not a sealed view"))?;
    let mut out = Vec::new();
    let mut found = Vec::new();
    for key in catalog.backrefs(anchor.multihash())? {
        found.extend(catalog.cid_of(key.as_ref())?);
    }
    // A hashed block's link to an identity CID, as an anchor's is, isn't
    // indexed as a reference, so grants are found as grants
    if let Some(claims) = catalog.claims() {
        found.extend(claims.grants()?.into_iter().filter(|(_, grant, _)| grant.on() == Some(&anchor)).map(|(cid, ..)| cid));
    }
    found.sort_by_key(CidRef::to_bytes);
    found.dedup();
    for claim in found {
        let Some(block) = catalog.get_block(&claim)? else {
            continue;
        };
        match crate::claim::Claim::parse(block.data()) {
            Some(crate::claim::Claim::Set(_)) => {},
            Some(crate::claim::Claim::Grant(grant)) if grant.on() == Some(&anchor) => {},
            _ => continue,
        }
        for sign in catalog.backrefs(claim.multihash())? {
            if let Some(cid) = catalog.cid_of(sign.as_ref())?
                && let Some(sign) = catalog.get_block(&cid)?
                && matches!(crate::claim::Claim::parse(sign.data()), Some(crate::claim::Claim::Sign(_)))
            {
                out.push((cid, sign.into_data().into_vec()));
            }
        }
        out.push((claim, block.into_data().into_vec()));
    }
    Ok(out)
}

impl Fetch for Held {
    fn fetch(&self, cid: &Link) -> std::io::Result<Vec<u8>> {
        self.0.get(&cid.to_bytes()).cloned().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("{cid} isn't here")))
    }
}

/// A plaintext anchor, as it's published sealed.
///
/// It's a sealed anchor of its own, whose owner key `K` alone signs what
/// counts in its view, and the read key its heads and tree are sealed
/// with. Each is derived from the
/// user's capabilities' secret and the anchor's nonce, so nothing need be
/// kept, and no one without the secret can tell whose a sealed anchor is,
/// or which plaintext anchor.
pub struct Published {
    /// The sealed anchor, and its owner's view of it, which is what
    /// counts.
    pub anchor: Link,
    pub view: Link,
    /// The plaintext anchor it's of.
    pub of: Link,
    owner: crate::keys::Key,
    read: Key,
    /// What its manifests seal which plaintext anchor it is with.
    manifest: Key,
}

impl Published {
    pub fn of(secret: &[u8; 32], anchor: &Link) -> Result<Self> {
        let nonce = crate::claim::anchor_nonce(anchor).ok_or_else(|| invalid(format!("{anchor} isn't an anchor: only an anchor's owner publishes it")))?;
        let owner = crate::keys::Key::from_seed(&derive(secret, b"owner", &nonce));
        let sealed: [u8; 16] = derive(secret, b"nonce", &nonce).first_chunk::<16>().copied().unwrap_or_default();
        let sealed = crate::claim::anchor_of(sealed)?;
        let view = crate::claim::view(&sealed, &owner.id()).ok_or_else(|| invalid("a sealed anchor with no view"))?;
        Ok(Self { anchor: sealed, view, of: anchor.clone(), owner, read: derive(secret, b"read", &nonce), manifest: derive(secret, b"manifest", b"") })
    }

    /// What writes it, as a writer whose key's seed is given, for an
    /// owner's view (see `add_writer`).
    pub fn write_capability(&self, writer: Key, owner: Option<Link>) -> Capability {
        Capability::Write(Write::new(Live::new(self.view.clone(), Zeroizing::new(*self.read)), writer, self.of.clone(), owner))
    }

    /// What reads it.
    pub fn capability(&self) -> Capability {
        Capability::Live(Live::new(self.view.clone(), Zeroizing::new(*self.read)))
    }
}

/// The key a sealed anchor's heads are sealed with, from its read key.
fn head_key(read: &[u8; 32]) -> Key {
    derive(read, b"head", b"")
}

/// The block access token of every head of a sealed anchor, from its read
/// key: what a reader proves it knows to be told of its heads, or given
/// one.
pub fn head_bat(read: &[u8; 32]) -> [u8; 32] {
    *derive(&head_key(read), b"bat", b"")
}

/// What a head block says.
///
/// That's the plaintext root, the sealed root, the plaintext sets of the
/// anchor it's of, by CID, as its owner's machines say, and for a head a
/// writer of a capability made, the plaintext set it carries, and that
/// writer's sign of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadBlock {
    pub plain: Link,
    pub root: Link,
    pub sets: Vec<Link>,
    pub set: Option<Vec<u8>>,
    pub sign: Option<Vec<u8>>,
}

impl HeadBlock {
    pub const fn new(plain: Link, root: Link) -> Self {
        Self { plain, root, sets: Vec::new(), set: None, sign: None }
    }
}

/// A head block, padded and sealed under the head key alone, so the same
/// head seals the same way.
fn seal_head(read: &[u8; 32], head: &HeadBlock) -> Result<Block> {
    let mut map = BTreeMap::from([("plain".to_owned(), Ipld::Link(head.plain.clone())), ("root".to_owned(), Ipld::Link(head.root.clone()))]);
    if !head.sets.is_empty() {
        let mut sets = head.sets.clone();
        sets.sort_by_key(CidRef::to_bytes);
        sets.dedup();
        map.insert("sets".to_owned(), Ipld::List(sets.into_iter().map(Ipld::Link).collect()));
    }
    if let (Some(set), Some(sign)) = (&head.set, &head.sign) {
        map.insert("set".to_owned(), Ipld::Bytes(set.clone()));
        map.insert("sign".to_owned(), Ipld::Bytes(sign.clone()));
    }
    Ok(crate::vault::seal_bytes(&head_key(read), &pad(map)?)?)
}

/// A head block, opened.
fn open_head(read: &[u8; 32], sealed: &[u8]) -> Result<HeadBlock> {
    let bad = || invalid("a head that isn't one");
    let mut map = unpad(&crate::vault::open_bytes(&head_key(read), sealed)?, "head")?;
    let (Some(Ipld::Link(plain)), Some(Ipld::Link(root))) = (map.remove("plain"), map.remove("root")) else {
        return Err(bad());
    };
    let sets = match map.remove("sets") {
        None => Vec::new(),
        Some(Ipld::List(sets)) => sets.into_iter().map(|set| match set {
            Ipld::Link(set) => Ok(set),
            _ => Err(bad()),
        }).collect::<Result<_>>()?,
        Some(_) => return Err(bad()),
    };
    let (set, sign) = match (map.remove("set"), map.remove("sign")) {
        (None, None) => (None, None),
        (Some(Ipld::Bytes(set)), Some(Ipld::Bytes(sign))) => (Some(set), Some(sign)),
        _ => return Err(bad()),
    };
    if !map.is_empty() {
        return Err(bad());
    }
    Ok(HeadBlock { plain, root, sets, set, sign })
}

/// The first of a sealed view's grants: its owner key, given everything,
/// by itself. The same for every key, so a reader makes it, needing no
/// sign: the view naming the key is what it rests on.
fn genesis(owner: &Link) -> Result<crate::claim::Claim> {
    crate::claim::Grant::new([owner.clone()], None, ["/".to_owned()], [], [], []).map(crate::claim::Claim::Grant).ok_or_else(|| invalid("no first grant"))
}

/// A sealed view's grants, worked out on their own, with its owner key
/// as founder of a mesh of one, every other key a visitor of it (see
/// `crate::grants`): who may write it, and, write taken away, which sets
/// still count.
struct Judge {
    owner: Link,
    anchor: Link,
    state: Option<crate::grants::State>,
    /// Sets that stand of writers write's been taken from, by CID bytes,
    /// and the sets before them among those judged.
    stood: std::collections::HashSet<Vec<u8>>,
}

impl Judge {
    /// Work out the grants on a sealed anchor among claims, each with the
    /// keys whose signs of it verify; `sets` are the sets judged, by CID
    /// bytes, to follow what stands back by `prev`.
    fn of(owner: &Link, anchor: &Link, grants: Vec<(Link, crate::claim::Grant, Vec<Link>)>, sets: &BTreeMap<Vec<u8>, crate::claim::Set>) -> Result<Self> {
        let first = genesis(owner)?;
        let crate::claim::Claim::Grant(first_grant) = &first else {
            return Err(invalid("no first grant"));
        };
        let mut signed = vec![crate::grants::Signed { cid: first.cid(), grant: first_grant.clone(), by: vec![owner.clone()] }];
        signed.extend(grants.into_iter().filter(|(_, grant, _)| grant.on() == Some(anchor)).map(|(cid, grant, by)| crate::grants::Signed { cid, grant, by }));
        let state = crate::grants::State::new(&first.cid(), signed);
        let mut stood = std::collections::HashSet::new();
        let mut pending: Vec<Vec<u8>> = state.iter().flat_map(crate::grants::State::shares).filter(|share| share.owner == *owner && share.anchor == *anchor).flat_map(|share| share.stands).map(|set| set.to_bytes()).collect();
        while let Some(set) = pending.pop() {
            if stood.insert(set.clone()) {
                pending.extend(sets.get(&set).and_then(crate::claim::Set::prev).unwrap_or_default().iter().map(CidRef::to_bytes));
            }
        }
        Ok(Self { owner: owner.clone(), anchor: anchor.clone(), state, stood })
    }

    /// Whether a set, by CID bytes, signed by a key, counts: the owner
    /// key's, a writer's while it may write, or one that stands.
    fn counts(&self, set: &[u8], by: &Link) -> bool {
        *by == self.owner || self.stood.contains(set) || self.state.as_ref().is_some_and(|state| state.holds_on(&self.owner, &self.anchor, by, crate::grants::WRITE))
    }
}

/// The claims judged of a sealed view: its sets, each with the signs that
/// verify, and its grants, each with the keys that sign it.
#[derive(Default)]
struct Gathered<'a> {
    sets: BTreeMap<Vec<u8>, (crate::claim::Set, &'a [u8])>,
    signs: HashMap<Vec<u8>, Vec<(Link, &'a [u8])>>,
    grants: Vec<(Link, crate::claim::Grant)>,
}

impl<'a> Gathered<'a> {
    fn add(&mut self, anchor: &Link, data: &'a [u8]) -> Option<Vec<u8>> {
        match crate::claim::Claim::parse(data)? {
            crate::claim::Claim::Set(set) if set.target().contains(anchor) && set.owner().is_none() => {
                let cid = crate::claim::Claim::Set(set.clone()).cid().to_bytes();
                self.sets.insert(cid.clone(), (set, data));
                Some(cid)
            },
            crate::claim::Claim::Sign(sign) if sign.verify() => {
                for signed in sign.signs() {
                    self.signs.entry(signed.to_bytes()).or_default().push((sign.by().clone(), data));
                }
                None
            },
            grant @ crate::claim::Claim::Grant(_) => {
                let cid = grant.cid();
                if let crate::claim::Claim::Grant(grant) = grant
                    && grant.on() == Some(anchor)
                {
                    self.grants.push((cid, grant));
                }
                None
            },
            _ => None,
        }
    }

    /// The grants with who signs each.
    fn signed_grants(&self) -> Vec<(Link, crate::claim::Grant, Vec<Link>)> {
        self.grants.iter().map(|(cid, grant)| {
            let by = self.signs.get(&cid.to_bytes()).map(|signs| signs.iter().map(|(by, _)| by.clone()).collect()).unwrap_or_default();
            (cid.clone(), grant.clone(), by)
        }).collect()
    }
}

/// What a sealed anchor's manifests say they are.
const MANIFEST: &str = "holokeep-cap-1";

/// The most blocks one manifest names; more take parts.
const ENTRIES: usize = 1024;

/// A vault's capabilities' secret, which every sealed anchor's keys are
/// derived from.
pub fn secret(vault: &crate::vault::Vault) -> Key {
    vault.derive_secret(b"capabilities")
}

/// What a manifest says: which sealed view it's of, the blocks it names,
/// its parts, the manifest before it, and, sealed, which plaintext anchor
/// it's of. Parts say only their blocks.
struct Manifest {
    view: Option<Link>,
    blocks: Vec<Link>,
    parts: Vec<Link>,
    next: Option<Link>,
    sealed: Option<Vec<u8>>,
}

impl Manifest {
    /// As a dag-cbor block, its links plain, so a holder keeps all of it
    /// from one keep without reading any of it.
    fn block(&self) -> Result<Block> {
        let links = |links: &[Link]| Ipld::List(links.iter().cloned().map(Ipld::Link).collect());
        let mut map = BTreeMap::from([("manifest".to_owned(), Ipld::String(MANIFEST.to_owned())), ("blocks".to_owned(), links(&self.blocks))]);
        if let Some(view) = &self.view {
            map.insert("view".to_owned(), Ipld::Link(view.clone()));
        }
        if !self.parts.is_empty() {
            map.insert("parts".to_owned(), links(&self.parts));
        }
        if let Some(next) = &self.next {
            map.insert("next".to_owned(), Ipld::Link(next.clone()));
        }
        if let Some(sealed) = &self.sealed {
            map.insert("sealed".to_owned(), Ipld::Bytes(sealed.clone()));
        }
        let bytes = crate::dagcbor::to_vec(&Ipld::Map(map)).map_err(|e| invalid(format!("encoding a manifest: {e}")))?;
        Ok(Block::hash(crate::cid::Cidv1Spec::new(crate::cid::DAG_CBOR_CODEC, crate::multihash::MultihashFunc::Sha2_256), bytes.into()))
    }

    fn parse(data: &[u8]) -> Option<Self> {
        let Ok(Ipld::Map(mut map)) = crate::dagcbor::from_slice(data) else {
            return None;
        };
        if map.remove("manifest") != Some(Ipld::String(MANIFEST.to_owned())) {
            return None;
        }
        let links = |value: Option<Ipld>| -> Option<Vec<Link>> {
            match value {
                None => Some(Vec::new()),
                Some(Ipld::List(list)) => list.into_iter().map(|link| match link {
                    Ipld::Link(link) => Some(link),
                    _ => None,
                }).collect(),
                Some(_) => None,
            }
        };
        let link = |value: Option<Ipld>| -> Option<Option<Link>> {
            match value {
                None => Some(None),
                Some(Ipld::Link(link)) => Some(Some(link)),
                Some(_) => None,
            }
        };
        let sealed = match map.remove("sealed") {
            None => None,
            Some(Ipld::Bytes(sealed)) => Some(sealed),
            Some(_) => return None,
        };
        Some(Self { view: link(map.remove("view"))?, blocks: links(map.remove("blocks"))?, parts: links(map.remove("parts"))?, next: link(map.remove("next"))?, sealed })
    }
}

/// Act as the vault, then as whoever the catalog acted for before.
fn as_vault<T>(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault, f: impl FnOnce(&mut crate::store::Catalog) -> Result<T>) -> Result<T> {
    let owner = (catalog.uid(), catalog.signer().cloned().ok_or_else(|| invalid("this repo has no key to sign with"))?);
    catalog.act_for(vault.uid(), vault.key().clone())?;
    let done = f(catalog);
    catalog.act_for(owner.0, owner.1)?;
    done
}

fn block_here(catalog: &crate::store::Catalog, cid: &Link) -> Result<Block> {
    catalog.get_block(cid)?.ok_or_else(|| invalid(format!("{cid} isn't here")))
}

/// The vault's manifests of sealed anchors it keeps, each with what it
/// is.
fn kept_manifests(catalog: &crate::store::Catalog) -> Result<Vec<(Link, Manifest)>> {
    let keeps = catalog.claims().map(crate::store::ClaimStore::keeps).transpose()?.unwrap_or_default();
    Ok(keeps.into_iter().filter_map(|cid| {
        let block = catalog.get_block(&cid).ok()??;
        Manifest::parse(block.data()).map(|manifest| (cid, manifest))
    }).collect())
}

/// A head of a sealed view among claims: its set's CID bytes, the set,
/// and the set's and its counting sign's bytes.
type Judged<'a> = (Vec<u8>, crate::claim::Set, &'a [u8], &'a [u8]);

/// The heads of a sealed view among the claims gathered, latest first, by
/// `at`, then CID: the sets that count, signed by a key that may write it
/// (see `Judge`), or `trusted`, which no other replaces.
fn heads_among<'a>(gathered: &Gathered<'a>, owner: &Link, anchor: &Link, trusted: &std::collections::HashSet<Vec<u8>>) -> Result<Vec<Judged<'a>>> {
    let counting = counting_among(gathered, owner, anchor, trusted)?;
    let replaced: std::collections::HashSet<Vec<u8>> = counting.iter().flat_map(|(_, set, ..)| set.prev().unwrap_or_default().iter().map(CidRef::to_bytes)).collect();
    let mut heads: Vec<Judged<'a>> = counting.into_iter().filter(|(cid, ..)| !replaced.contains(cid)).collect();
    heads.sort_by(|(a, x, ..), (b, y, ..)| y.at().cmp(&x.at()).then_with(|| b.cmp(a)));
    Ok(heads)
}

/// The sets of a sealed view among the claims gathered that count, as
/// `heads_among` judges them, replaced or not.
fn counting_among<'a>(gathered: &Gathered<'a>, owner: &Link, anchor: &Link, trusted: &std::collections::HashSet<Vec<u8>>) -> Result<Vec<Judged<'a>>> {
    let sets: BTreeMap<Vec<u8>, crate::claim::Set> = gathered.sets.iter().map(|(cid, (set, _))| (cid.clone(), set.clone())).collect();
    let judge = Judge::of(owner, anchor, gathered.signed_grants(), &sets)?;
    Ok(gathered.sets.iter().filter_map(|(cid, (set, data))| {
        let signs = gathered.signs.get(cid)?;
        let sign = signs.iter().find(|(by, _)| judge.counts(cid, by)).or_else(|| signs.first().filter(|_| trusted.contains(cid)))?;
        Some((cid.clone(), set.clone(), *data, sign.1))
    }).collect())
}

/// Whether a set of a sealed view, with a sign of it, is one a writer may
/// make, as the claims a catalog holds of the view judge it.
///
/// The set must be of the sealed anchor, for no other view, and the sign,
/// verifying, by its owner key or a key it's let write. False if the
/// catalog holds nothing of the view, as a holder that isn't one.
pub fn may_write(catalog: &crate::store::Catalog, view: &Link, set: &[u8], sign: &[u8]) -> Result<bool> {
    let (anchor, owner) = crate::claim::viewed(view).ok_or_else(|| invalid("not a sealed view"))?;
    let claims = claims_about(catalog, view)?;
    if claims.is_empty() {
        return Ok(false);
    }
    let mut gathered = Gathered::default();
    for (_, data) in &claims {
        gathered.add(&anchor, data);
    }
    let Some(cid) = gathered.add(&anchor, set) else {
        return Ok(false);
    };
    gathered.add(&anchor, sign);
    let sets: BTreeMap<Vec<u8>, crate::claim::Set> = gathered.sets.iter().map(|(cid, (set, _))| (cid.clone(), set.clone())).collect();
    let judge = Judge::of(&owner, &anchor, gathered.signed_grants(), &sets)?;
    Ok(gathered.signs.get(&cid).is_some_and(|signs| signs.iter().any(|(by, data)| *data == sign && judge.counts(&cid, by))))
}

/// What a writer's head took in carried: the plaintext anchor, and the
/// plaintext set, now here.
pub struct Taken {
    pub anchor: Link,
    pub set: Link,
}

/// Take in what capabilities' writers wrote of the anchors the vault
/// publishes, as the catalog holds it.
///
/// Each set that counts in a sealed view whose head carries a plaintext
/// set (see `write`) of the anchor it's published from, signed by its
/// writer, and that isn't here yet, is unsealed into the catalog, as the
/// account it acts for, with that set and its sign. The set counts in the
/// owner's view if the mesh's grants let its writer write the anchor, as
/// a visitor (see `crate::grants`). If it doesn't, the owner sets the
/// anchor to its value, after it and what it's after: the owner key's
/// grants let it write, and they're the owner's. Merging what it forks
/// is the anchor's, as for any fork. What's taken in is published again
/// with the rest.
pub fn take_in(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault) -> Result<Vec<Taken>> {
    let secret = secret(vault);
    let mut taken = Vec::new();
    for (anchor, _) in published(catalog, vault)? {
        let published = Published::of(&secret, &anchor)?;
        let claims = claims_about(catalog, &published.view)?;
        let mut gathered = Gathered::default();
        for (_, data) in &claims {
            gathered.add(&published.anchor, data);
        }
        for (_, set, ..) in counting_among(&gathered, &published.owner.id(), &published.anchor, &std::collections::HashSet::new())? {
            let Some(block) = catalog.get_block(set.value())? else {
                continue;
            };
            let Ok(head) = open_head(&published.read, block.data()) else {
                continue;
            };
            let (Some(inner), Some(sign)) = (head.set, head.sign) else {
                continue;
            };
            let (Some(crate::claim::Claim::Set(said)), Some(crate::claim::Claim::Sign(signed))) = (crate::claim::Claim::parse(&inner), crate::claim::Claim::parse(&sign)) else {
                continue;
            };
            let inner_cid = crate::claim::Claim::Set(said.clone()).cid();
            // Of the anchor it's published from, its value the head's, and signed
            if said.target() != std::slice::from_ref(&anchor) || *said.value() != head.plain || !signed.verify() || !signed.signs().contains(&inner_cid) {
                continue;
            }
            if catalog.claims().map(|claims| claims.signed_by(&inner_cid, signed.by())).transpose()?.unwrap_or(false) {
                continue;
            }
            // Not all here yet, as while it's still arriving: next time
            let blocks = match unseal(catalog, &Snapshot::new(head.root.clone(), head.plain.clone(), Zeroizing::new(*published.read))) {
                Ok(blocks) => blocks,
                Err(Error::Store(e)) if e.is_busy() => return Err(Error::Store(e)),
                Err(e) => {
                    eprintln!("what a writer wrote of {anchor} can't be taken in yet: {e}");
                    continue;
                },
            };
            let prev: Vec<Link> = said.prev().unwrap_or_default().iter().cloned().chain([inner_cid.clone()]).collect();
            let value = said.value().clone();
            catalog.batch(|catalog| {
                for block in &blocks {
                    catalog.put_block(block, crate::cid::CidVersion::V1)?;
                }
                catalog.put_block(&crate::claim::Claim::Set(said).block(), crate::cid::CidVersion::V1)?;
                catalog.put_block(&crate::claim::Claim::Sign(signed).block(), crate::cid::CidVersion::V1)?;
                // Not counting as a visitor's, as without the mesh's grant, it's
                // set as the owner's, after it: the owner key's grants let it write
                if !catalog.sets_of(&anchor)?.iter().any(|(set, ..)| *set == inner_cid) {
                    catalog.set_anchor_wrote(&anchor, &value, prev, &[])?;
                }
                Ok::<_, Error>(())
            })?;
            taken.push(Taken { anchor: anchor.clone(), set: inner_cid });
        }
    }
    Ok(taken)
}

/// A sealed anchor's heads as a catalog holds them: every head's set, to
/// name as `prev`; the latest's head block, opened; and the latest head
/// the owner's machines made, carrying no writer's set, whose blocks the
/// vault keeps, to seal after.
struct Head {
    sets: Vec<Link>,
    block: HeadBlock,
    ours: Option<HeadBlock>,
}

fn last_head(catalog: &crate::store::Catalog, published: &Published) -> Result<Option<Head>> {
    let claims = claims_about(catalog, &published.view)?;
    let mut gathered = Gathered::default();
    for (_, data) in &claims {
        gathered.add(&published.anchor, data);
    }
    let owner = published.owner.id();
    let none = std::collections::HashSet::new();
    let heads = heads_among(&gathered, &owner, &published.anchor, &none)?;
    let Some((_, latest, ..)) = heads.first() else {
        return Ok(None);
    };
    let block = open_head(&published.read, block_here(catalog, latest.value())?.data())?;
    let sets = heads.iter().filter_map(|(cid, ..)| crate::cid::Cid::decode(cid).ok()).collect();
    let mut counting = counting_among(&gathered, &owner, &published.anchor, &none)?;
    counting.sort_by(|(a, x, ..), (b, y, ..)| y.at().cmp(&x.at()).then_with(|| b.cmp(a)));
    let ours = counting.iter().find_map(|(_, set, ..)| {
        let head = open_head(&published.read, catalog.get_block(set.value()).ok()??.data()).ok()?;
        head.set.is_none().then_some(head)
    });
    Ok(Some(Head { sets, block, ours }))
}

/// The key a machine of the owner's writes a sealed anchor with: derived
/// from the capabilities' secret, the anchor's nonce and the machine's
/// device key, so each machine's signs are one chain of its own.
fn writer_key(secret: &[u8; 32], nonce: &[u8; 16], device: Option<&Link>) -> crate::keys::Key {
    let mut data = nonce.to_vec();
    data.extend(device.map(CidRef::to_bytes).unwrap_or_default());
    crate::keys::Key::from_seed(&derive(secret, b"writer", &data))
}

/// The claims giving a key write on a sealed anchor, signed by its owner
/// key, if it can't write already: its first grant, if that isn't held,
/// then the grant, each with the owner key's sign. Put in the catalog;
/// returns their CIDs, to go in the manifest.
fn grant_write(catalog: &crate::store::Catalog, published: &Published, writer: &Link) -> Result<Vec<Link>> {
    let claims = claims_about(catalog, &published.view)?;
    let mut gathered = Gathered::default();
    for (_, data) in &claims {
        gathered.add(&published.anchor, data);
    }
    let owner = published.owner.id();
    let judge = Judge::of(&owner, &published.anchor, gathered.signed_grants(), &BTreeMap::new())?;
    if judge.state.as_ref().is_some_and(|state| state.holds_on(&owner, &published.anchor, writer, crate::grants::WRITE)) {
        return Ok(Vec::new());
    }
    let first = genesis(&owner)?;
    let prev = judge.state.as_ref().map_or_else(|| vec![first.cid()], crate::grants::State::heads);
    let grant = crate::claim::Grant::new([writer.clone()], Some(published.anchor.clone()), [crate::grants::WRITE.to_owned()], [], [], prev).ok_or_else(|| invalid("no grant"))?;
    let grant = crate::claim::Claim::Grant(grant);
    let mut out = Vec::new();
    for claim in [&first, &grant] {
        if catalog.get_block(&claim.cid())?.is_some() && claim.cid() == first.cid() {
            continue;
        }
        catalog.put_block(&claim.block(), crate::cid::CidVersion::V1)?;
        out.push(claim.cid());
        out.extend(catalog.sign_with_key(&published.owner, [claim.cid()])?);
    }
    Ok(out)
}

/// What publishing made: the set now the sealed anchor's latest, the
/// manifest the vault keeps of everything published of it, and whether
/// either's new.
pub struct Publication {
    pub set: Link,
    pub manifest: Link,
    pub fresh: bool,
    /// The anchors mount points name in what was sealed of it anew.
    pub mounted: Vec<Link>,
}

/// Publish what an anchor is now, `value`, as its sealed anchor's head.
///
/// What's changed since the last head is sealed, and a head naming it set
/// in the sealed view after every head there is, signed by this machine's
/// writer key, which the owner key gives write first if it's to. All of it
/// is the vault's, which keeps a manifest of it, linking the manifest
/// before by `next`, in place of keeping that, so whatever holds the vault
/// holds every head published. Nothing new is made if the last head's
/// already of it.
pub fn publish(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault, published: &Published, value: &Link) -> Result<Publication> {
    let secret = secret(vault);
    let last = last_head(catalog, published)?;
    let ours = last.as_ref().and_then(|head| head.ours.as_ref()).map(|ours| (ours.plain.clone(), ours.root.clone()));
    let (sealed, mounted) = seal_tree(catalog, value, &published.read, ours, MountKeys::Secret(&secret))?;
    let previous = as_vault(catalog, vault, |catalog| Ok(kept_manifests(catalog)?.into_iter().find(|(_, manifest)| manifest.view.as_ref() == Some(&published.view)).map(|(cid, _)| cid)))?;
    let mut sets: Vec<Link> = catalog.anchor_heads(&published.of)?.into_iter().map(|(set, ..)| set).collect();
    sets.sort_by_key(CidRef::to_bytes);
    // Nothing new: one head, of this, saying it's of the sets there are
    if let (Some(last), Some(previous)) = (&last, &previous)
        && last.block.plain == *value
        && last.block.sets == sets
        && last.sets.len() == 1
    {
        let set = last.sets.first().cloned().unwrap_or_else(|| value.clone());
        return Ok(Publication { set, manifest: previous.clone(), fresh: false, mounted });
    }
    let mut block = HeadBlock::new(value.clone(), sealed.root.clone());
    block.sets = sets;
    let head = seal_head(&published.read, &block)?;
    let head_cid = AnyCid::V1(head.cid().clone());
    let nonce = crate::claim::anchor_nonce(&published.of).ok_or_else(|| invalid("not an anchor"))?;
    let writer = writer_key(&secret, &nonce, catalog.signer().map(crate::keys::Key::id).as_ref());
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    let after = last.map(|head| head.sets).unwrap_or_default();
    let set = crate::claim::Claim::Set(crate::claim::Set::new([published.anchor.clone()], head_cid, at).ok_or_else(|| invalid("a set of nothing"))?.after(Some(after)));
    as_vault(catalog, vault, |catalog| catalog.batch(|catalog| {
        let mut entries = grant_write(catalog, published, &writer.id())?;
        for block in sealed.blocks.iter().chain([&head, &set.block()]) {
            catalog.put_block(block, crate::cid::CidVersion::V1)?;
            entries.push(AnyCid::V1(block.cid().clone()));
        }
        entries.push(catalog.sign_with_key(&writer, [set.cid()])?.ok_or_else(|| invalid("the head's signed already"))?);
        let manifest = keep_entries(catalog, published, previous.as_ref(), entries)?;
        Ok(Publication { set: set.cid(), manifest, fresh: true, mounted })
    }))
}

/// Keep what's new of a sealed anchor, `entries`, as the vault: a manifest
/// naming them, in parts if there are many, after the manifest it keeps,
/// `previous`, which it keeps in that one's place. Returns the manifest.
fn keep_entries(catalog: &crate::store::Catalog, published: &Published, previous: Option<&Link>, entries: Vec<Link>) -> Result<Link> {
    let of = crate::dagcbor::to_vec(&Ipld::Map(BTreeMap::from([("anchor".to_owned(), Ipld::Link(published.of.clone()))]))).map_err(|e| invalid(format!("{e}")))?;
    let of = crate::vault::seal_bytes(&published.manifest, &of)?.into_data().into_vec();
    let mut top = Manifest { view: Some(published.view.clone()), blocks: Vec::new(), parts: Vec::new(), next: previous.cloned(), sealed: Some(of) };
    if entries.len() <= ENTRIES {
        top.blocks = entries;
    } else {
        for chunk in entries.chunks(ENTRIES) {
            let part = Manifest { view: None, blocks: chunk.to_vec(), parts: Vec::new(), next: None, sealed: None }.block()?;
            catalog.put_block(&part, crate::cid::CidVersion::V1)?;
            top.parts.push(AnyCid::V1(part.cid().clone()));
        }
    }
    let top = top.block()?;
    catalog.put_block(&top, crate::cid::CidVersion::V1)?;
    let manifest = AnyCid::V1(top.cid().clone());
    catalog.keep(&manifest)?;
    if let Some(previous) = previous {
        catalog.unkeep(previous)?;
    }
    Ok(manifest)
}

/// Let a new writer write a published anchor.
///
/// It's a fresh writer key, which its owner key gives `/anchor/write` on
/// the sealed anchor, kept by the vault with what's published of it.
/// Returns the writer key's seed, for a capability (see
/// `Published::write_capability`).
pub fn add_writer(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault, published: &Published) -> Result<Key> {
    let seed = fresh_key()?;
    let writer = crate::keys::Key::from_seed(&seed);
    as_vault(catalog, vault, |catalog| catalog.batch(|catalog| {
        let previous = kept_manifests(catalog)?.into_iter().find(|(_, manifest)| manifest.view.as_ref() == Some(&published.view)).map(|(cid, _)| cid);
        let previous = previous.ok_or_else(|| invalid(format!("{} isn't published: publish it before letting anyone write it", published.of)))?;
        let entries = grant_write(catalog, published, &writer.id())?;
        keep_entries(catalog, published, Some(&previous), entries)?;
        Ok(())
    }))?;
    Ok(seed)
}

/// A head a capability's writer made: its sealed tree and head block,
/// its set, and the writer's sign of that.
pub struct Written {
    pub blocks: Vec<Block>,
    pub set: Block,
    pub sign: Block,
}

impl Written {
    /// Its set's CID.
    pub fn set_cid(&self) -> Link {
        AnyCid::V1(self.set.cid().clone())
    }

    /// Every block of it.
    pub fn all(&self) -> Vec<Block> {
        self.blocks.iter().chain([&self.set, &self.sign]).cloned().collect()
    }
}

/// Write a sealed anchor with a write capability: `value`, a plaintext
/// tree the catalog has, after the head read, `base`.
///
/// The tree's sealed whole, which seals what's unchanged as it was, every
/// mount point it read sealed as it was. The head carries a plaintext set
/// of the plaintext anchor, for the capability's owner's view, after the
/// plaintext sets the head read was of, signed by the writer key: what the
/// owner's machines count in the plaintext (see `crate::grants`, on
/// visitors). The head's set in the sealed view is after the head read,
/// signed by the writer key too. The writer's signs are kept in the
/// catalog, as its chain; the plaintext set isn't.
pub fn write(catalog: &mut crate::store::Catalog, cap: &Write, base: &Base, value: &Link) -> Result<Written> {
    let (anchor, _) = crate::claim::viewed(&cap.live.view).ok_or_else(|| invalid("not a sealed view"))?;
    let (sealed, _) = seal_tree(catalog, value, &cap.live.read, None, MountKeys::Known(&base.mounts))?;
    let writer = cap.writer();
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    let mut prev = base.block.sets.clone();
    if let Some(set) = base.block.set.as_deref().and_then(crate::claim::Claim::parse) {
        prev.push(set.cid());
    }
    let inner = crate::claim::Set::new([cap.of.clone()], value.clone(), at).ok_or_else(|| invalid("a set of nothing"))?.after(Some(prev)).for_view(cap.owner.clone());
    let inner = crate::claim::Claim::Set(inner);
    let inner_sign = catalog.sign_with_key(&writer, [inner.cid()])?.ok_or_else(|| invalid("the set's signed already"))?;
    let mut block = HeadBlock::new(value.clone(), sealed.root.clone());
    block.set = Some(inner.block().into_data().into_vec());
    block.sign = Some(block_here(catalog, &inner_sign)?.into_data().into_vec());
    let head = seal_head(&cap.live.read, &block)?;
    let set = crate::claim::Set::new([anchor], AnyCid::V1(head.cid().clone()), at).ok_or_else(|| invalid("a set of nothing"))?.after(Some(vec![base.set.clone()]));
    let set = crate::claim::Claim::Set(set);
    catalog.put_block(&set.block(), crate::cid::CidVersion::V1)?;
    let sign = catalog.sign_with_key(&writer, [set.cid()])?.ok_or_else(|| invalid("the head's signed already"))?;
    let mut blocks = sealed.blocks;
    blocks.push(head);
    Ok(Written { blocks, set: set.block(), sign: block_here(catalog, &sign)? })
}

/// Publish what an anchor is now, and what's mounted in it.
///
/// It's published as `publish` does, then each anchor a mount point names
/// in what's new of it, as it is, and so on down, each once: so a reader
/// of it reads what's mounted in it too. A mounted
/// anchor that's nothing yet isn't published. Returns each anchor
/// published and its publication, the anchor asked for first.
pub fn publish_mounted(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault, anchor: &Link, value: &Link) -> Result<Vec<(Link, Publication)>> {
    let secret = secret(vault);
    let mut done = Vec::new();
    let mut seen = std::collections::HashSet::from([anchor.to_bytes()]);
    let mut queue = std::collections::VecDeque::from([(anchor.clone(), value.clone())]);
    while let Some((anchor, value)) = queue.pop_front() {
        let publication = publish(catalog, vault, &Published::of(&secret, &anchor)?, &value)?;
        for mounted in &publication.mounted {
            if seen.insert(mounted.to_bytes())
                && let Some(value) = catalog.anchor_value(mounted)?
            {
                queue.push_back((mounted.clone(), value));
            }
        }
        done.push((anchor, publication));
    }
    Ok(done)
}

/// The anchors the vault keeps published, each with its manifest.
pub fn published(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault) -> Result<Vec<(Link, Link)>> {
    let key = derive(&secret(vault), b"manifest", b"");
    let manifests = as_vault(catalog, vault, |catalog| kept_manifests(catalog))?;
    Ok(manifests.into_iter().filter_map(|(cid, manifest)| {
        let of = crate::vault::open_bytes(&key, &manifest.sealed?).ok()?;
        let Ok(Ipld::Map(mut map)) = crate::dagcbor::from_slice(&of) else {
            return None;
        };
        match map.remove("anchor") {
            Some(Ipld::Link(anchor)) => Some((anchor, cid)),
            _ => None,
        }
    }).collect())
}

/// Stop keeping a sealed anchor published.
///
/// The vault lets go of its manifest, so what's only its is collected in time, wherever it's held.
/// Whoever has its capability reads its last head till then. Whether it
/// was.
pub fn unpublish(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault, published: &Published) -> Result<bool> {
    as_vault(catalog, vault, |catalog| {
        let mut was = false;
        for (cid, manifest) in kept_manifests(catalog)? {
            if manifest.view.as_ref() == Some(&published.view) {
                catalog.unkeep(&cid)?;
                was = true;
            }
        }
        Ok(was)
    })
}

/// Every block a manifest names, its parts and the manifests before it
/// too, and the manifests themselves: everything published of a sealed
/// anchor, as a reader from nothing needs it.
pub fn published_blocks(catalog: &crate::store::Catalog, manifest: &Link) -> Result<Vec<Block>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut manifests = vec![manifest.clone()];
    while let Some(cid) = manifests.pop() {
        if !seen.insert(cid.to_bytes()) {
            continue;
        }
        let block = block_here(catalog, &cid)?;
        let said = Manifest::parse(block.data()).ok_or_else(|| invalid(format!("{cid} isn't a manifest")))?;
        out.push(block);
        for link in said.blocks {
            if seen.insert(link.to_bytes()) {
                out.push(block_here(catalog, &link)?);
            }
        }
        manifests.extend(said.parts);
        manifests.extend(said.next);
    }
    Ok(out)
}

/// Read a sealed anchor from what's held, as its latest head.
///
/// Of the sets of its sealed anchor signed by the owner key its view
/// names, or a writer it let write, the latest of those no other replaces
/// is unsealed. Returns its
/// plaintext root, and every block of it, root first.
pub fn read_live<'a>(src: &impl Source, claims: impl IntoIterator<Item = &'a [u8]>, live: &Live) -> Result<(Link, Vec<Block>)> {
    read_live_after(src, claims, &[], live).map(|read| (read.plain, read.blocks))
}

/// A sealed anchor as read: its plaintext root, every block of it, root
/// first, and the head read, as its set and the owner key's sign of it,
/// for a reader to remember (see `Remembered`).
pub struct Read {
    pub plain: Link,
    pub blocks: Vec<Block>,
    pub head: Vec<Vec<u8>>,
    /// What a writer writes after: the head read, as its set, and its head
    /// block, opened.
    pub set: Link,
    pub block: HeadBlock,
}

/// Read a sealed anchor from what's held, as its latest head, judging it
/// beside the head read before, `remembered`.
///
/// What's held can't forge a head, but it can keep the latest back,
/// offering an older one as if it were. The head read before is judged
/// with what's offered, so an older head never replaces it: if it's still
/// the latest, and isn't offered, what's held is behind it, and it's an
/// error, `Error::Behind`, as it may be read elsewhere.
pub fn read_live_after<'a>(src: &impl Source, claims: impl IntoIterator<Item = &'a [u8]>, remembered: &'a [Vec<u8>], live: &Live) -> Result<Read> {
    read_one(src, claims, remembered, live).map(|(read, _)| read)
}

/// Read a sealed anchor as `read_live_after` does, returning too the
/// sealed anchor each mount point in it is, by its path.
fn read_one<'a>(src: &impl Source, claims: impl IntoIterator<Item = &'a [u8]>, remembered: &'a [Vec<u8>], live: &Live) -> Result<(Read, MountsAt)> {
    let (anchor, owner) = crate::claim::viewed(&live.view).ok_or_else(|| invalid("not a sealed view"))?;
    let mut gathered = Gathered::default();
    let mut offered = std::collections::HashSet::new();
    for data in claims {
        offered.extend(gathered.add(&anchor, data));
    }
    // What was read before counts as it did: it was judged then
    let mut trusted = std::collections::HashSet::new();
    for data in remembered {
        trusted.extend(gathered.add(&anchor, data));
    }
    let heads = heads_among(&gathered, &owner, &anchor, &trusted)?;
    let (cid, head, data, sign) = heads.into_iter().next().ok_or_else(|| invalid("no head of the sealed anchor that its owner key, or a writer it let write, signed"))?;
    if !offered.contains(&cid) {
        return Err(Error::Behind);
    }
    let fetched = src.sealed(&[(head.value().clone(), head_bat(&live.read))])?;
    let block = open_head(&live.read, fetched.first().ok_or_else(|| invalid("no head"))?)?;
    let (plain, root) = (block.plain.clone(), block.root.clone());
    let set = crate::cid::Cid::decode(&cid).map_err(|_| invalid("a head's set with no CID"))?;
    let (blocks, mounts) = unseal_mounts(src, &Snapshot::new(root, plain.clone(), Zeroizing::new(*live.read)))?;
    Ok((Read { plain, blocks, head: vec![data.to_vec(), sign.to_vec()], set, block }, mounts))
}

/// The head a reader last read of a sealed anchor.
///
/// It's kept in the reader's repo, per account, by sealed view: so what's
/// offered later is judged beside it, and a head older than it is noticed
/// (see `read_live_after`).
///
/// It's the reader's alone, unshared and unsigned by it: a file, a
/// dag-cbor list of the set and its sign, under `heads/<uid>/<view>`.
pub struct Remembered {
    path: std::path::PathBuf,
}

impl Remembered {
    pub fn of(repo: &std::path::Path, uid: u32, view: &Link) -> Self {
        Self { path: repo.join("heads").join(uid.to_string()).join(view.to_string()) }
    }

    /// What's remembered: nothing, if nothing's been read.
    pub fn claims(&self) -> Result<Vec<Vec<u8>>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let Ok(Ipld::List(list)) = crate::dagcbor::from_slice(&bytes) else {
            return Err(invalid(format!("{}: not a remembered head", self.path.display())));
        };
        list.into_iter().map(|item| match item {
            Ipld::Bytes(data) => Ok(data),
            _ => Err(invalid(format!("{}: not a remembered head", self.path.display()))),
        }).collect()
    }

    /// Remember a head read, in place of what was: written aside and
    /// renamed, so it's one or the other.
    pub fn remember(&self, head: &[Vec<u8>]) -> Result<()> {
        let dir = self.path.parent().ok_or_else(|| invalid("nowhere to remember"))?;
        std::fs::create_dir_all(dir)?;
        let bytes = crate::dagcbor::to_vec(&Ipld::List(head.iter().cloned().map(Ipld::Bytes).collect())).map_err(|e| invalid(format!("{e}")))?;
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|e| e.error)?;
        Ok(())
    }
}

/// Where a sealed anchor's heads are found: the claims about its sealed
/// view, as blocks, to judge which count.
pub trait Heads {
    fn heads_of(&self, live: &Live) -> Result<Vec<Vec<u8>>>;
}

impl Heads for Held {
    fn heads_of(&self, _: &Live) -> Result<Vec<Vec<u8>>> {
        Ok(self.0.values().cloned().collect())
    }
}

impl Heads for crate::store::Catalog {
    fn heads_of(&self, live: &Live) -> Result<Vec<Vec<u8>>> {
        Ok(claims_about(self, &live.view)?.into_iter().map(|(_, data)| data).collect())
    }
}

/// A mount point read, or not: its path from the root of what mounts it,
/// `/`-separated, the sealed view it is, and what it was read as, or why
/// it wasn't.
pub struct Mounted {
    pub path: String,
    pub view: Link,
    pub read: std::result::Result<Link, String>,
}

/// A sealed anchor read, and every anchor mounted in it: the plaintext
/// root, every block read, the head read of each sealed view, to
/// remember, and each mount point.
pub struct Reading {
    pub plain: Link,
    pub blocks: Vec<Block>,
    pub heads: Vec<(Link, Vec<Vec<u8>>)>,
    pub mounts: Vec<Mounted>,
    /// What a writer of the anchor asked for writes after, if it's a
    /// sealed anchor's (see `write`).
    pub base: Option<Base>,
}

/// What a writer writes after: the head it read, as its set, its head
/// block, and the mount points in its tree, each with the plaintext
/// anchor it's of.
pub struct Base {
    pub set: Link,
    pub block: HeadBlock,
    pub mounts: Vec<Mount>,
}

/// Read a sealed anchor at its latest head, judged beside the head
/// `remembered` says was read before of each view (see
/// `read_live_after`), and each anchor mounted in it, and so on down,
/// each view once.
///
/// What's mounted is read from the same place. One that can't be read,
/// or is behind, is said so in `mounts`, and the rest read: only the
/// anchor asked for must be.
pub fn read(src: &(impl Source + Heads), live: &Live, remembered: &dyn Fn(&Link) -> Vec<Vec<u8>>) -> Result<Reading> {
    let claims = src.heads_of(live)?;
    let (top, mounts) = read_one(src, claims.iter().map(Vec::as_slice), &remembered(&live.view), live)?;
    let base = Base { set: top.set, block: top.block, mounts: mounts.iter().map(|(_, mount)| mount.clone()).collect() };
    let mut reading = Reading { plain: top.plain, blocks: top.blocks, heads: vec![(live.view.clone(), top.head)], mounts: Vec::new(), base: Some(base) };
    let mut seen = std::collections::HashSet::from([live.view.to_bytes()]);
    let mut queue: std::collections::VecDeque<(String, Mount)> = mounts.into();
    while let Some((path, mount)) = queue.pop_front() {
        if !seen.insert(mount.view.to_bytes()) {
            continue;
        }
        let live = mount.live();
        let read = src.heads_of(&live).and_then(|claims| read_one(src, claims.iter().map(Vec::as_slice), &remembered(&live.view), &live));
        let read = match read {
            Ok((read, below)) => {
                queue.extend(below.into_iter().map(|(below, mount)| (format!("{path}/{below}"), mount)));
                reading.blocks.extend(read.blocks);
                reading.heads.push((live.view.clone(), read.head));
                Ok(read.plain)
            },
            Err(e) => Err(e.to_string()),
        };
        reading.mounts.push(Mounted { path, view: live.view, read });
    }
    Ok(reading)
}

/// A fresh read key, random.
pub fn fresh_key() -> Result<Key> {
    let mut read = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(read.as_mut()).map_err(std::io::Error::other)?;
    Ok(read)
}

/// What lets whoever holds it read a sealed DAG, fixed: its sealed root,
/// its plaintext root, which each block's key and nonce are derived with,
/// and the read key.
pub struct Snapshot {
    pub root: Link,
    pub plain: Link,
    read: Key,
}

impl Snapshot {
    pub const fn new(root: Link, plain: Link, read: Key) -> Self {
        Self { root, plain, read }
    }

    pub const fn read(&self) -> &Key {
        &self.read
    }
}

/// What lets whoever holds it read a sealed anchor, as it is whenever
/// it's read: its sealed view, which names its owner key, and its read key.
#[derive(Clone)]
pub struct Live {
    pub view: Link,
    read: Key,
    /// Where some holders' doors are, as multiaddrs ending in their peer
    /// IDs (see `crate::net::door`), if it says.
    pub at: Vec<String>,
}

impl Live {
    pub const fn new(view: Link, read: Key) -> Self {
        Self { view, read, at: Vec::new() }
    }

    /// The same, saying where holders' doors are.
    #[must_use]
    pub fn at(mut self, at: Vec<String>) -> Self {
        self.at = at;
        self
    }

    pub const fn read(&self) -> &Key {
        &self.read
    }
}

/// What reads a sealed anchor, as a capability's map.
fn live_map(live: &Live) -> BTreeMap<String, Ipld> {
    let mut map = BTreeMap::from([("read".to_owned(), Ipld::Bytes(live.read.to_vec())), ("view".to_owned(), Ipld::Link(live.view.clone()))]);
    if !live.at.is_empty() {
        map.insert("at".to_owned(), Ipld::List(live.at.iter().cloned().map(Ipld::String).collect()));
    }
    map
}

/// A capability, as it's written: `hkcap`, then dag-cbor in multibase
/// base32, of `{plain, read, root}` for a snapshot or `{read, view}` for
/// a sealed anchor.
pub enum Capability {
    Snapshot(Snapshot),
    Live(Live),
    Write(Write),
}

/// What lets whoever holds it write a sealed anchor, and read it.
///
/// It's what reads it, the seed of a writer key its owner key's let
/// write, the plaintext anchor it's of, and the user whose view of that
/// the sets it carries are for, if it's said.
pub struct Write {
    pub live: Live,
    writer: Key,
    pub of: Link,
    pub owner: Option<Link>,
}

impl Write {
    pub const fn new(live: Live, writer: Key, of: Link, owner: Option<Link>) -> Self {
        Self { live, writer, of, owner }
    }

    /// The writer key's seed.
    pub fn seed(&self) -> Key {
        Zeroizing::new(*self.writer)
    }

    /// The writer key.
    pub fn writer(&self) -> crate::keys::Key {
        crate::keys::Key::from_seed(&self.writer)
    }
}

impl Capability {
    /// What reads a sealed anchor, if it's of one.
    pub const fn live(&self) -> Option<&Live> {
        match self {
            Self::Live(live) | Self::Write(Write { live, .. }) => Some(live),
            Self::Snapshot(_) => None,
        }
    }
}

impl Capability {
    pub fn encode(&self) -> String {
        let map = match self {
            Self::Snapshot(snapshot) => BTreeMap::from([
                ("plain".to_owned(), Ipld::Link(snapshot.plain.clone())),
                ("read".to_owned(), Ipld::Bytes(snapshot.read.to_vec())),
                ("root".to_owned(), Ipld::Link(snapshot.root.clone())),
            ]),
            Self::Live(live) => live_map(live),
            Self::Write(write) => {
                let mut map = live_map(&write.live);
                map.insert("write".to_owned(), Ipld::Bytes(write.writer.to_vec()));
                map.insert("of".to_owned(), Ipld::Link(write.of.clone()));
                if let Some(owner) = &write.owner {
                    map.insert("for".to_owned(), Ipld::Link(owner.clone()));
                }
                map
            },
        };
        let bytes = Zeroizing::new(crate::dagcbor::to_vec(&Ipld::Map(map)).unwrap_or_default());
        format!("{PREFIX}{}", multibase::encode(multibase::Base::Base32Lower, bytes.as_slice()))
    }

    pub fn decode(text: &str) -> Result<Self> {
        let not = || invalid("not a capability");
        let text = text.trim().strip_prefix(PREFIX).ok_or_else(not)?;
        let (_, bytes) = multibase::decode(text).map_err(|_| not())?;
        let bytes = Zeroizing::new(bytes);
        let Ok(Ipld::Map(mut map)) = crate::dagcbor::from_slice(&bytes) else {
            return Err(not());
        };
        let Some(Ipld::Bytes(read)) = map.remove("read") else {
            return Err(invalid("a capability with no read key"));
        };
        let read = Zeroizing::new(<[u8; 32]>::try_from(read.as_slice()).map_err(|_| invalid("a capability's read key isn't 32 bytes"))?);
        let at = match map.remove("at") {
            None => Vec::new(),
            Some(Ipld::List(at)) => at.into_iter().map(|addr| match addr {
                Ipld::String(addr) => Ok(addr),
                _ => Err(invalid("a capability's door that isn't a multiaddr")),
            }).collect::<Result<_>>()?,
            Some(_) => return Err(invalid("a capability's doors that aren't a list")),
        };
        let capability = match (map.remove("view"), map.remove("root"), map.remove("plain")) {
            (Some(Ipld::Link(view)), None, None) if crate::claim::viewed(&view).is_some() => match (map.remove("write"), map.remove("of"), map.remove("for")) {
                (None, None, None) => Self::Live(Live { view, read, at }),
                (Some(Ipld::Bytes(writer)), Some(Ipld::Link(of)), owner) => {
                    let writer = Zeroizing::new(<[u8; 32]>::try_from(writer.as_slice()).map_err(|_| invalid("a capability's writer key isn't 32 bytes"))?);
                    let owner = match owner {
                        None => None,
                        Some(Ipld::Link(owner)) => Some(owner),
                        Some(_) => return Err(invalid("a capability's owner that isn't a key")),
                    };
                    crate::claim::is_anchor(&of).then_some(()).ok_or_else(|| invalid("a capability's plaintext anchor that isn't one"))?;
                    Self::Write(Write { live: Live { view, read, at }, writer, of, owner })
                },
                _ => return Err(invalid("a capability that writes, with no writer key or plaintext anchor")),
            },
            (None, Some(Ipld::Link(root)), Some(Ipld::Link(plain))) => Self::Snapshot(Snapshot { root, plain, read }),
            _ => return Err(invalid("a capability naming neither a sealed view nor a sealed root and its plaintext")),
        };
        if let Some(other) = map.keys().next() {
            return Err(invalid(format!("a capability with `{other}` in it, which this doesn't read yet")));
        }
        Ok(capability)
    }
}

#[cfg(test)]
mod tests;
