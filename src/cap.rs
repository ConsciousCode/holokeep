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
    /// Where it is among its parent's links, if that's said by name: an
    /// entry, by its name, or a HAMT's shard, by its index.
    place: Option<Vec<u8>>,
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
        return Ok(links.into_iter().map(|link| Child { key: by_cid(key, &link), cid: link, entry: None, within: None, place: None }).collect());
    }
    let node = PbNode::decode(data).map_err(|e| bad(&format!("{e:?}")))?;
    let unixfs = node.data.and_then(|data| DataBuf::decode(data).ok());
    let mut out = Vec::with_capacity(node.links.len());
    for link in &node.links {
        let child: Link = link.cid().map_err(|e| bad(&format!("{e:?}")))?;
        let name = link.name.unwrap_or_default();
        out.push(match unixfs.as_ref().map(|unixfs| unixfs.data_type) {
            Some(DataType::Directory) => Child { key: by_name(key, name), cid: child, entry: Some(name.to_vec()), within: None, place: Some([b"e", name].concat()) },
            Some(DataType::HAMTShard) => {
                let dir: &[u8; 32] = within.map_or(key, |within| within);
                let fanout = unixfs.as_ref().and_then(|unixfs| unixfs.fanout).unwrap_or(FANOUT);
                let pad = format!("{:X}", fanout.saturating_sub(1)).len();
                match name.get(pad..) {
                    Some([]) => Child { key: by_cid(dir, &child), cid: child, entry: None, within: Some(Zeroizing::new(*dir)), place: Some([b"s", name].concat()) },
                    Some(entry) => Child { key: by_name(dir, entry), cid: child, entry: Some(entry.to_vec()), within: None, place: Some([b"e", entry].concat()) },
                    None => return Err(bad(&"a HAMT's link with too short a name")),
                }
            },
            _ => Child { key: by_cid(key, &child), cid: child, entry: None, within: None, place: None },
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
    let mut sealing = Sealing { src, done: HashMap::new(), blocks: Vec::new() };
    let root = sealing.seal(root, &root_key(read), None, before)?;
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
        for child in children(cid, &data, key, within)? {
            let before = child.place.as_ref().and_then(|place| was.remove(place));
            links.push(self.seal(&child.cid, &child.key, child.within.as_ref(), before)?);
        }
        let block = Sealer::new(key).seal(cid, &encode(&data, &links)?)?;
        let sealed = AnyCid::V1(block.cid().clone());
        self.blocks.push(block);
        self.done.insert(done, sealed.clone());
        Ok(sealed)
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
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut level = vec![(cap.plain.clone(), cap.root.clone(), root_key(&cap.read), None::<Key>)];
    while !level.is_empty() {
        level.retain(|(plain, _, key, _)| plain.hashcode() != IDENTITY && seen.insert((plain.to_bytes(), **key)));
        let wanted: Vec<(Link, [u8; 32])> = level.iter().map(|(plain, sealed, key, _)| (sealed.clone(), node_bat(key, plain))).collect();
        let fetched = src.sealed(&wanted)?;
        let mut next = Vec::new();
        for ((plain, _, key, within), bytes) in level.into_iter().zip(fetched) {
            let opened = decode(&Sealer::new(&key).open(&plain, &bytes)?)?;
            let block = Block::verify(plain.clone().into(), opened.block.into_boxed_slice()).map_err(|_| invalid(format!("{plain} unsealed to other bytes")))?;
            let children = children(&plain, block.data(), &key, within.as_ref())?;
            if children.len() != opened.links.len() {
                return Err(invalid(format!("{plain}'s sealed node has {} links for its {}", opened.links.len(), children.len())));
            }
            for (child, sealed) in children.into_iter().zip(opened.links) {
                // A key that doesn't derive, kept from an earlier read key
                let kept = child.entry.as_deref().and_then(|entry| std::str::from_utf8(entry).ok()).and_then(|entry| opened.keys.get(entry));
                let key = kept.map_or(child.key, |kept| Zeroizing::new(**kept));
                next.push((child.cid, sealed, key, child.within));
            }
            out.push(block);
        }
        level = next;
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

    /// Every block held, as claims among them might be.
    pub fn all(&self) -> impl Iterator<Item = &[u8]> {
        self.0.values().map(Vec::as_slice)
    }
}

/// The claims a catalog holds of a sealed anchor, its view's anchor: its
/// sets, and what signs them, as blocks, to judge which count.
pub fn claims_about(catalog: &crate::store::Catalog, view: &Link) -> Result<Vec<(Link, Vec<u8>)>> {
    use crate::store::RefIndex as _;
    let (anchor, _) = crate::claim::viewed(view).ok_or_else(|| invalid("not a sealed view"))?;
    let mut out = Vec::new();
    for key in catalog.backrefs(anchor.multihash())? {
        let Some(set) = catalog.cid_of(key.as_ref())? else {
            continue;
        };
        let Some(block) = catalog.get_block(&set)? else {
            continue;
        };
        if !matches!(crate::claim::Claim::parse(block.data()), Some(crate::claim::Claim::Set(_))) {
            continue;
        }
        for sign in catalog.backrefs(set.multihash())? {
            if let Some(cid) = catalog.cid_of(sign.as_ref())?
                && let Some(sign) = catalog.get_block(&cid)?
                && matches!(crate::claim::Claim::parse(sign.data()), Some(crate::claim::Claim::Sign(_)))
            {
                out.push((cid, sign.into_data().into_vec()));
            }
        }
        out.push((set, block.into_data().into_vec()));
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

/// A sealed anchor's latest head, as its owner key's last sign says: the
/// set, its head block, and the head's plaintext and sealed roots.
struct Head {
    set: Link,
    block: Link,
    plain: Link,
    root: Link,
}

fn last_head(catalog: &crate::store::Catalog, published: &Published) -> Result<Option<Head>> {
    let Some(sign) = catalog.claims().map(|claims| claims.head(&published.owner.id())).transpose()?.flatten() else {
        return Ok(None);
    };
    let Some(crate::claim::Claim::Sign(sign)) = crate::claim::Claim::parse(block_here(catalog, &sign)?.data()) else {
        return Err(invalid("the owner key's last sign isn't one"));
    };
    let Some(set) = sign.signs().first().cloned() else {
        return Ok(None);
    };
    let Some(crate::claim::Claim::Set(said)) = crate::claim::Claim::parse(block_here(catalog, &set)?.data()) else {
        return Err(invalid("the owner key signed something other than a head"));
    };
    let (plain, root) = open_head(&published.read, block_here(catalog, said.value())?.data())?;
    Ok(Some(Head { set, block: said.value().clone(), plain, root }))
}

/// What publishing made: the set now the sealed anchor's latest, the
/// manifest the vault keeps of everything published of it, and whether
/// either's new.
pub struct Publication {
    pub set: Link,
    pub manifest: Link,
    pub fresh: bool,
}

/// Publish what an anchor is now, `value`, as its sealed anchor's head.
///
/// What's changed since the last head is sealed, and a head naming it set
/// in the sealed view after the last, signed by its owner key. All of it
/// is the vault's, which keeps a manifest of it, linking the manifest
/// before by `next`, in place of keeping that, so whatever holds the vault
/// holds every head published. Nothing new is made if the last head's
/// already of it.
pub fn publish(catalog: &mut crate::store::Catalog, vault: &crate::vault::Vault, published: &Published, value: &Link) -> Result<Publication> {
    let last = last_head(catalog, published)?;
    let sealed = seal_since(catalog, value, &published.read, last.as_ref().map(|head| (head.plain.clone(), head.root.clone())))?;
    let head = seal_head(&published.read, value, &sealed.root)?;
    let head_cid = AnyCid::V1(head.cid().clone());
    let previous = as_vault(catalog, vault, |catalog| Ok(kept_manifests(catalog)?.into_iter().find(|(_, manifest)| manifest.view.as_ref() == Some(&published.view)).map(|(cid, _)| cid)))?;
    if let (Some(last), Some(previous)) = (&last, &previous)
        && last.block == head_cid
    {
        return Ok(Publication { set: last.set.clone(), manifest: previous.clone(), fresh: false });
    }
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    let after = last.map(|head| vec![head.set]).unwrap_or_default();
    let set = crate::claim::Claim::Set(crate::claim::Set::new([published.anchor.clone()], head_cid, at).ok_or_else(|| invalid("a set of nothing"))?.after(Some(after)));
    let of = crate::dagcbor::to_vec(&Ipld::Map(BTreeMap::from([("anchor".to_owned(), Ipld::Link(published.of.clone()))]))).map_err(|e| invalid(format!("{e}")))?;
    let of = crate::vault::seal_bytes(&published.manifest, &of)?.into_data().into_vec();
    as_vault(catalog, vault, |catalog| catalog.batch(|catalog| {
        let mut entries = Vec::with_capacity(sealed.blocks.len().saturating_add(3));
        for block in sealed.blocks.iter().chain([&head, &set.block()]) {
            catalog.put_block(block, crate::cid::CidVersion::V1)?;
            entries.push(AnyCid::V1(block.cid().clone()));
        }
        entries.push(catalog.sign_with_key(&published.owner, [set.cid()])?.ok_or_else(|| invalid("the head's signed already"))?);
        let mut top = Manifest { view: Some(published.view.clone()), blocks: Vec::new(), parts: Vec::new(), next: previous.clone(), sealed: Some(of) };
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
        if let Some(previous) = &previous {
            catalog.unkeep(previous)?;
        }
        Ok(Publication { set: set.cid(), manifest, fresh: true })
    }))
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
/// names, the latest of those no other replaces is unsealed. Returns its
/// plaintext root, and every block of it, root first.
pub fn read_live<'a>(src: &impl Source, claims: impl IntoIterator<Item = &'a [u8]>, live: &Live) -> Result<(Link, Vec<Block>)> {
    let (anchor, owner) = crate::claim::viewed(&live.view).ok_or_else(|| invalid("not a sealed view"))?;
    let mut sets = BTreeMap::new();
    let mut signed = std::collections::HashSet::new();
    for data in claims {
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
    let fetched = src.sealed(&[(head.value().clone(), head_bat(&live.read))])?;
    let (plain, root) = open_head(&live.read, fetched.first().ok_or_else(|| invalid("no head"))?)?;
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
            Self::Live(live) => {
                let mut map = BTreeMap::from([
                    ("read".to_owned(), Ipld::Bytes(live.read.to_vec())),
                    ("view".to_owned(), Ipld::Link(live.view.clone())),
                ]);
                if !live.at.is_empty() {
                    map.insert("at".to_owned(), Ipld::List(live.at.iter().cloned().map(Ipld::String).collect()));
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
            (Some(Ipld::Link(view)), None, None) if crate::claim::viewed(&view).is_some() => Self::Live(Live { view, read, at }),
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
