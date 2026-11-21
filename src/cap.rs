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

/// A sealed node: a plaintext block and its links' ciphertext CIDs, as
/// dag-cbor, padded with zeros.
fn encode(block: &[u8], links: &[Link]) -> Result<Vec<u8>> {
    let mut map = BTreeMap::from([("block".to_owned(), Ipld::Bytes(block.to_vec()))]);
    if !links.is_empty() {
        map.insert("links".to_owned(), Ipld::List(links.iter().cloned().map(Ipld::Link).collect()));
    }
    pad(map)
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
    if map.contains_key("mounts") {
        return Err(invalid("a sealed node with mount points, which aren't read yet"));
    }
    if let Some(other) = map.keys().next() {
        return Err(invalid(format!("a sealed node with `{other}` in it")));
    }
    Ok(Opened { block, links, keys })
}

/// One of a block's links, and how its key's found: the key, the entry
/// name it's by, if it's a directory's entry, and the key of the
/// directory whose HAMT it's a shard of, if it is one.
struct Child {
    cid: Link,
    key: Key,
    entry: Option<Vec<u8>>,
    within: Option<Key>,
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
        return Ok(links.into_iter().map(|link| Child { key: by_cid(key, &link), cid: link, entry: None, within: None }).collect());
    }
    let node = PbNode::decode(data).map_err(|e| bad(&format!("{e:?}")))?;
    let unixfs = node.data.and_then(|data| DataBuf::decode(data).ok());
    let mut out = Vec::with_capacity(node.links.len());
    for link in &node.links {
        let child: Link = link.cid().map_err(|e| bad(&format!("{e:?}")))?;
        let name = link.name.unwrap_or_default();
        out.push(match unixfs.as_ref().map(|unixfs| unixfs.data_type) {
            Some(DataType::Directory) => Child { key: by_name(key, name), cid: child, entry: Some(name.to_vec()), within: None },
            Some(DataType::HAMTShard) => {
                let dir: &[u8; 32] = within.map_or(key, |within| within);
                let fanout = unixfs.as_ref().and_then(|unixfs| unixfs.fanout).unwrap_or(FANOUT);
                let pad = format!("{:X}", fanout.saturating_sub(1)).len();
                match name.get(pad..) {
                    Some([]) => Child { key: by_cid(dir, &child), cid: child, entry: None, within: Some(Zeroizing::new(*dir)) },
                    Some(entry) => Child { key: by_name(dir, entry), cid: child, entry: Some(entry.to_vec()), within: None },
                    None => return Err(bad(&"a HAMT's link with too short a name")),
                }
            },
            _ => Child { key: by_cid(key, &child), cid: child, entry: None, within: None },
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
    let mut sealing = Sealing { src, done: HashMap::new(), blocks: Vec::new() };
    let root = sealing.seal(root, &root_key(read), None)?;
    Ok(Sealed { root, blocks: sealing.blocks })
}

struct Sealing<'a, F> {
    src: &'a F,
    /// What's been sealed, by plaintext CID and key: the same block under
    /// the same key seals the same way, so once.
    done: HashMap<(Vec<u8>, [u8; 32]), Link>,
    blocks: Vec<Block>,
}

impl<F: Fetch> Sealing<'_, F> {
    fn seal(&mut self, cid: &Link, key: &Key, within: Option<&Key>) -> Result<Link> {
        if cid.hashcode() == IDENTITY {
            return Ok(cid.clone());
        }
        let done = (cid.to_bytes(), **key);
        if let Some(sealed) = self.done.get(&done) {
            return Ok(sealed.clone());
        }
        let data = self.src.fetch(cid)?;
        let mut links = Vec::new();
        for child in children(cid, &data, key, within)? {
            links.push(self.seal(&child.cid, &child.key, child.within.as_ref())?);
        }
        let block = Sealer::new(key).seal(cid, &encode(&data, &links)?)?;
        let sealed = AnyCid::V1(block.cid().clone());
        self.blocks.push(block);
        self.done.insert(done, sealed.clone());
        Ok(sealed)
    }
}

/// Unseal the DAG a capability names, fetching sealed blocks from
/// `src`: every plaintext block, root first, each checked against its
/// CID. Identity CIDs are left out, being in their parents.
pub fn unseal(src: &impl Fetch, cap: &Snapshot) -> Result<Vec<Block>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![(cap.plain.clone(), cap.root.clone(), root_key(&cap.read), None::<Key>)];
    while let Some((plain, sealed, key, within)) = stack.pop() {
        if plain.hashcode() == IDENTITY || !seen.insert((plain.to_bytes(), *key)) {
            continue;
        }
        let bytes = src.fetch(&sealed)?;
        let opened = decode(&Sealer::new(&key).open(&plain, &bytes)?)?;
        let block = Block::verify(plain.clone().into(), opened.block.into_boxed_slice()).map_err(|_| invalid(format!("{plain} unsealed to other bytes")))?;
        let children = children(&plain, block.data(), &key, within.as_ref())?;
        if children.len() != opened.links.len() {
            return Err(invalid(format!("{plain}'s sealed node has {} links for its {}", opened.links.len(), children.len())));
        }
        for (child, sealed) in children.into_iter().zip(opened.links).rev() {
            // A key that doesn't derive, kept from an earlier read key
            let kept = child.entry.as_deref().and_then(|entry| std::str::from_utf8(entry).ok()).and_then(|entry| opened.keys.get(entry));
            let key = kept.map_or(child.key, |kept| Zeroizing::new(**kept));
            stack.push((child.cid, sealed, key, child.within));
        }
        out.push(block);
    }
    Ok(out)
}

/// Sealed blocks held in memory, by CID, to unseal from: a CAR's.
#[derive(Default)]
pub struct Held(HashMap<Vec<u8>, Vec<u8>>);

impl Held {
    /// Every block of a CAR, each checked against its CID.
    pub fn from_car(reader: impl std::io::Read + 'static) -> Result<Self> {
        let mut car = crate::car::CarReader::new(reader)?;
        let mut held = Self::default();
        while let Some((block, _)) = car.next_block()? {
            held.0.insert(AnyCid::V1(block.cid().clone()).to_bytes(), block.into_data().into_vec());
        }
        Ok(held)
    }

    pub fn insert(&mut self, block: Block) {
        self.0.insert(AnyCid::V1(block.cid().clone()).to_bytes(), block.into_data().into_vec());
    }
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
    owner: crate::keys::Key,
    read: Key,
}

impl Published {
    pub fn of(secret: &[u8; 32], anchor: &Link) -> Result<Self> {
        let nonce = crate::claim::anchor_nonce(anchor).ok_or_else(|| invalid(format!("{anchor} isn't an anchor: only an anchor's owner publishes it")))?;
        let owner = crate::keys::Key::from_seed(&derive(secret, b"owner", &nonce));
        let sealed: [u8; 16] = derive(secret, b"nonce", &nonce).first_chunk::<16>().copied().unwrap_or_default();
        let sealed = crate::claim::anchor_of(sealed)?;
        let view = crate::claim::view(&sealed, &owner.id()).ok_or_else(|| invalid("a sealed anchor with no view"))?;
        Ok(Self { anchor: sealed, view, owner, read: derive(secret, b"read", &nonce) })
    }

    /// What reads it.
    pub fn capability(&self) -> Capability {
        Capability::Live(Live { view: self.view.clone(), read: Zeroizing::new(*self.read) })
    }
}

/// The key a sealed anchor's heads are sealed with, from its read key.
fn head_key(read: &[u8; 32]) -> Key {
    derive(read, b"head", b"")
}

/// A head block: what the sealed anchor's value is, its plaintext root,
/// which its root block's key and nonce are derived with, and its sealed
/// root, padded and sealed under the head key.
fn seal_head(read: &[u8; 32], plain: &Link, root: &Link) -> Result<Block> {
    let body = pad(BTreeMap::from([("plain".to_owned(), Ipld::Link(plain.clone())), ("root".to_owned(), Ipld::Link(root.clone()))]))?;
    Ok(crate::vault::seal_bytes(&head_key(read), &body)?)
}

/// What a head block says: the plaintext root and the sealed root.
fn open_head(read: &[u8; 32], sealed: &[u8]) -> Result<(Link, Link)> {
    let mut map = unpad(&crate::vault::open_bytes(&head_key(read), sealed)?, "head")?;
    match (map.remove("plain"), map.remove("root"), map.is_empty()) {
        (Some(Ipld::Link(plain)), Some(Ipld::Link(root)), true) => Ok((plain, root)),
        _ => Err(invalid("a head that isn't one")),
    }
}

/// What publishing made: the set now the sealed anchor's latest, and every
/// block a reader needs, sealed blocks, the head, the set and its sign.
pub struct Publication {
    pub set: Link,
    pub blocks: Vec<Block>,
}

/// Publish what an anchor is now, `value`, as its sealed anchor's head.
///
/// Its tree's sealed, and a head naming it set in the sealed view after
/// the last head, signed by its owner key, in the catalog. Nothing new is
/// set if the last head's already of it.
pub fn publish(catalog: &mut crate::store::Catalog, published: &Published, value: &Link) -> Result<Publication> {
    let sealed = seal(catalog, value, &published.read)?;
    let head = seal_head(&published.read, value, &sealed.root)?;
    let head_cid = AnyCid::V1(head.cid().clone());
    let claim_block = |catalog: &crate::store::Catalog, cid: &Link| -> Result<Block> {
        catalog.get_block(cid)?.ok_or_else(|| invalid(format!("{cid} isn't here")))
    };
    // The owner key signs heads alone, one after another: its last sign
    // is of the last head
    let last_sign = catalog.claims().map(|claims| claims.head(&published.owner.id())).transpose()?.flatten();
    let last = match &last_sign {
        Some(sign) => match crate::claim::Claim::parse(claim_block(catalog, sign)?.data()) {
            Some(crate::claim::Claim::Sign(sign)) => sign.signs().to_vec(),
            _ => return Err(invalid("the owner key's last sign isn't one")),
        },
        None => Vec::new(),
    };
    for set in &last {
        if let Some(crate::claim::Claim::Set(was)) = crate::claim::Claim::parse(claim_block(catalog, set)?.data())
            && *was.value() == head_cid
        {
            let mut blocks = sealed.blocks;
            blocks.extend([head, claim_block(catalog, set)?]);
            blocks.extend(last_sign.iter().map(|sign| claim_block(catalog, sign)).collect::<Result<Vec<_>>>()?);
            return Ok(Publication { set: set.clone(), blocks });
        }
    }
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    let set = crate::claim::Set::new([published.anchor.clone()], head_cid, at).ok_or_else(|| invalid("a set of nothing"))?.after(Some(last));
    let set = crate::claim::Claim::Set(set);
    catalog.put_block(&set.block(), crate::cid::CidVersion::V1)?;
    let sign = catalog.sign_with_key(&published.owner, [set.cid()])?.ok_or_else(|| invalid("the head's signed already"))?;
    let mut blocks = sealed.blocks;
    blocks.extend([head, set.block(), claim_block(catalog, &sign)?]);
    Ok(Publication { set: set.cid(), blocks })
}

/// Read a sealed anchor from what's held, as its latest head.
///
/// Of the sets of its sealed anchor signed by the owner key its view
/// names, the latest of those no other replaces is unsealed. Returns its
/// plaintext root, and every block of it, root first.
pub fn read_live(src: &Held, live: &Live) -> Result<(Link, Vec<Block>)> {
    let (anchor, owner) = crate::claim::viewed(&live.view).ok_or_else(|| invalid("not a sealed view"))?;
    let mut sets = BTreeMap::new();
    let mut signed = std::collections::HashSet::new();
    for data in src.0.values() {
        match crate::claim::Claim::parse(data) {
            Some(crate::claim::Claim::Set(set)) if set.target().contains(&anchor) && set.owner().is_none() => {
                let cid = crate::claim::Claim::Set(set.clone()).cid();
                sets.insert(cid.to_bytes(), (cid, set));
            },
            Some(crate::claim::Claim::Sign(sign)) if *sign.by() == owner && sign.verify() => {
                signed.extend(sign.signs().iter().map(CidRef::to_bytes));
            },
            _ => {},
        }
    }
    sets.retain(|cid, _| signed.contains(cid));
    let replaced: std::collections::HashSet<Vec<u8>> = sets.values().flat_map(|(_, set)| set.prev().unwrap_or_default().iter().map(CidRef::to_bytes)).collect();
    let (_, head) = sets
        .into_iter()
        .filter(|(cid, _)| !replaced.contains(cid))
        .max_by(|(a, (_, x)), (b, (_, y))| x.at().cmp(&y.at()).then_with(|| a.cmp(b)))
        .map(|(_, head)| head)
        .ok_or_else(|| invalid("no head of the sealed anchor its owner signed"))?;
    let (plain, root) = open_head(&live.read, &src.fetch(head.value())?)?;
    let blocks = unseal(src, &Snapshot::new(root, plain.clone(), Zeroizing::new(*live.read)))?;
    Ok((plain, blocks))
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
pub struct Live {
    pub view: Link,
    read: Key,
}

impl Live {
    pub const fn new(view: Link, read: Key) -> Self {
        Self { view, read }
    }

    pub const fn read(&self) -> &Key {
        &self.read
    }
}

/// A capability, as it's written: `hkcap`, then dag-cbor in multibase
/// base32, of `{plain, read, root}` for a snapshot or `{read, view}` for
/// a sealed anchor.
pub enum Capability {
    Snapshot(Snapshot),
    Live(Live),
}

impl Capability {
    pub fn encode(&self) -> String {
        let map = match self {
            Self::Snapshot(snapshot) => BTreeMap::from([
                ("plain".to_owned(), Ipld::Link(snapshot.plain.clone())),
                ("read".to_owned(), Ipld::Bytes(snapshot.read.to_vec())),
                ("root".to_owned(), Ipld::Link(snapshot.root.clone())),
            ]),
            Self::Live(live) => BTreeMap::from([
                ("read".to_owned(), Ipld::Bytes(live.read.to_vec())),
                ("view".to_owned(), Ipld::Link(live.view.clone())),
            ]),
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
        let capability = match (map.remove("view"), map.remove("root"), map.remove("plain")) {
            (Some(Ipld::Link(view)), None, None) if crate::claim::viewed(&view).is_some() => Self::Live(Live { view, read }),
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
