//! Vaults: what a user keeps with friends, encrypted.
//!
//! Each of the host's accounts has a vault, an internal account of its own
//! with a key to sign with and a secret. Protecting a DAG encrypts each of
//! its blocks with keys derived from the secret and the block's CID, so
//! the same block encrypts the same way every time within one vault, and
//! no way anyone else can predict: pushing again is idempotent, a vault's
//! own duplicates are kept once, and nobody can confirm a vault holds a
//! file they know. The ciphertext, and a manifest of it, are the vault
//! account's, which keeps the manifest; a vault in a protected mesh hears
//! of, holds and serves that and nothing else, so no private claim goes
//! there, and holders keep what the vault keeps as they keep anything.
//!
//! An encrypted block is raw: 8 fixed bytes, a dag-cbor list of one block
//! access token (BAT), then the ciphertext, as Peergos lays them out. The
//! BAT is derived from the secret too. Nothing checks BATs yet; they're in
//! the format from the start so sharing a block with someone outside the
//! vault's meshes needn't encrypt it again.
//!
//! A manifest is dag-cbor whose links, the ciphertext and any further
//! manifests, are plain, so a holder can keep all of it from one keep, and
//! whose `sealed` bytes say, encrypted, which plaintext CID each
//! ciphertext is, and for the first, the root. A holder learns how many
//! blocks there are and how big, and nothing of what they say or how they
//! link.

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::block::{Block, IDENTITY};
use crate::cid::{AnyCid, BaseCid as _, Cid as _, CidRef as _, CidVersion, Cidv1Spec, DAG_CBOR_CODEC, RAW_CODEC};
use crate::model::{Ipld, Link};
use crate::multihash::MultihashFunc;
use crate::store::Catalog;

/// What an encrypted block starts with.
pub const MAGIC: [u8; 8] = *b"hkbats\x00\x01";
/// A dag-cbor list of one 32-byte string: the BATs.
const BATS: [u8; 3] = [0x81, 0x58, 0x20];
/// The magic, then the BATs.
const HEADER: usize = 43;
/// What a manifest says it is.
const FORMAT: &str = "holokeep-vault-1";
/// The most ciphertexts one manifest names; more take a manifest of
/// manifests.
const ENTRIES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] crate::store::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The uid of an account's vault: internal, past any of the host's.
pub const fn vault_of(uid: u32) -> u32 {
    0x8000_0000 | (uid & 0x3FFF_FFFF)
}

/// One of the host's accounts' vault: its account, key and secret.
pub struct Vault {
    uid: u32,
    key: crate::keys::Key,
    secret: Zeroizing<[u8; 32]>,
}

/// What a manifest says: each plaintext CID and its ciphertext's, the
/// manifests it continues in, and for the first, the root.
struct Manifest {
    entries: Vec<(Link, Link)>,
    next: Vec<Link>,
    root: Option<Link>,
}

fn invalid(what: impl Into<String>) -> Error {
    Error::Invalid(what.into())
}

/// HMAC-SHA256.
fn hmac(key: &[u8; 32], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for ((inner, outer), byte) in inner_pad.iter_mut().zip(outer_pad.iter_mut()).zip(key) {
        *inner ^= byte;
        *outer ^= byte;
    }
    let inner = Sha256::new().chain_update(inner_pad).chain_update(message).finalize();
    let outer = Sha256::new().chain_update(outer_pad).chain_update(inner).finalize();
    Zeroizing::new(<[u8; 32]>::try_from(outer.as_slice()).unwrap_or_default())
}

fn cipher(key: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|e| invalid(e.to_string()))
}

fn nonce_of(bytes: &[u8]) -> Result<[u8; 24]> {
    bytes.get(..24).and_then(|nonce| nonce.try_into().ok()).ok_or_else(|| invalid("a nonce too short"))
}

fn cbor(value: &Ipld) -> Result<Vec<u8>> {
    crate::dagcbor::to_vec(value).map_err(|e| invalid(format!("{e:?}")))
}

fn links(links: &[Link]) -> Ipld {
    Ipld::List(links.iter().cloned().map(Ipld::Link).collect())
}

/// A secret in a file readable only by its owner, made there if there's
/// none yet.
fn load_or_make_secret(path: &Path) -> io::Result<Zeroizing<[u8; 32]>> {
    match std::fs::read(path) {
        Ok(bytes) => bytes.as_slice().try_into().map(Zeroizing::new).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{}: not a vault's secret", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut secret = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(secret.as_mut()).map_err(io::Error::other)?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
            file.write_all(secret.as_ref())?;
            file.sync_all()?;
            Ok(secret)
        },
        Err(e) => Err(e),
    }
}

impl Vault {
    /// The vault of one of the host's accounts, by uid, made the first
    /// time it's asked for.
    pub fn open(repo: &Path, owner: u32) -> Result<Self> {
        let uid = vault_of(owner);
        let key = crate::keys::account_key(repo, uid)?;
        let secret = load_or_make_secret(&repo.join("accounts").join(format!("{uid}.secret")))?;
        Ok(Self { uid, key, secret })
    }

    /// The vault's account.
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The key it signs with, which holders take as its user.
    pub const fn key(&self) -> &crate::keys::Key {
        &self.key
    }

    fn derive(&self, label: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
        hmac(&self.secret, &[label, &[0], data].concat())
    }

    /// A block, encrypted: its ciphertext as a raw block.
    pub fn seal(&self, plain: &Link, data: &[u8]) -> Result<Block> {
        let name = plain.to_bytes();
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(&BATS);
        header.extend_from_slice(self.derive(b"bat", &name).as_ref());
        let nonce = nonce_of(self.derive(b"nonce", &name).as_ref())?;
        let ciphertext = cipher(&self.derive(b"key", &name))?
            .encrypt(&nonce.into(), Payload { msg: data, aad: &header })
            .map_err(|_| invalid("encrypting failed"))?;
        Ok(Block::hash(Cidv1Spec::new(RAW_CODEC, MultihashFunc::Sha2_256), [header, ciphertext].concat().into()))
    }

    /// A block back from its ciphertext, checked against its CID.
    pub fn unseal(&self, plain: &Link, sealed: &[u8]) -> Result<Block> {
        let (Some(header), Some(ciphertext)) = (sealed.get(..HEADER), sealed.get(HEADER..)) else {
            return Err(invalid("not an encrypted block"));
        };
        if header.get(..MAGIC.len()) != Some(&MAGIC[..]) || header.get(MAGIC.len()..MAGIC.len().saturating_add(BATS.len())) != Some(&BATS[..]) {
            return Err(invalid("not an encrypted block"));
        }
        let name = plain.to_bytes();
        let nonce = nonce_of(self.derive(b"nonce", &name).as_ref())?;
        let data = cipher(&self.derive(b"key", &name))?
            .decrypt(&nonce.into(), Payload { msg: ciphertext, aad: header })
            .map_err(|_| invalid(format!("{plain} doesn't decrypt with this vault's secret")))?;
        Block::verify(plain.clone().into(), data.into_boxed_slice()).map_err(|_| invalid(format!("{plain} decrypted to other bytes")))
    }

    /// A manifest of ciphertexts, continuing in others, and for the
    /// first, saying the root.
    fn manifest(&self, entries: &[(Link, Link)], next: &[Link], root: Option<&Link>) -> Result<Block> {
        let mut said = BTreeMap::from([("plain".to_owned(), Ipld::List(entries.iter().map(|(plain, _)| Ipld::Bytes(plain.to_bytes())).collect()))]);
        if let Some(root) = root {
            said.insert("root".to_owned(), Ipld::Bytes(root.to_bytes()));
        }
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
        let ciphertext = cipher(&self.derive(b"manifest", b""))?
            .encrypt(&nonce.into(), Payload { msg: &cbor(&Ipld::Map(said))?, aad: FORMAT.as_bytes() })
            .map_err(|_| invalid("encrypting failed"))?;
        let sealed = [&nonce[..], &ciphertext].concat();
        let ciphers: Vec<Link> = entries.iter().map(|(_, cipher)| cipher.clone()).collect();
        let mut map = BTreeMap::from([
            ("bats".to_owned(), Ipld::List(vec![Ipld::Bytes(self.derive(b"bat", &sealed).to_vec())])),
            ("blocks".to_owned(), links(&ciphers)),
            ("manifest".to_owned(), Ipld::String(FORMAT.to_owned())),
            ("sealed".to_owned(), Ipld::Bytes(sealed)),
        ]);
        if !next.is_empty() {
            map.insert("next".to_owned(), links(next));
        }
        Ok(Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), cbor(&Ipld::Map(map))?.into()))
    }

    /// What a manifest says, if it's this vault's.
    fn read(&self, data: &[u8]) -> Result<Manifest> {
        let Ok(Ipld::Map(mut map)) = crate::dagcbor::from_slice(data) else {
            return Err(invalid("not a manifest"));
        };
        if map.remove("manifest") != Some(Ipld::String(FORMAT.to_owned())) {
            return Err(invalid("not a manifest"));
        }
        let link_list = |value: Option<Ipld>| -> Result<Vec<Link>> {
            match value {
                None => Ok(Vec::new()),
                Some(Ipld::List(list)) => list.into_iter().map(|link| match link {
                    Ipld::Link(link) => Ok(link),
                    _ => Err(invalid("a manifest's link isn't one")),
                }).collect(),
                Some(_) => Err(invalid("a manifest's links aren't a list")),
            }
        };
        let (ciphers, next) = (link_list(map.remove("blocks"))?, link_list(map.remove("next"))?);
        let Some(Ipld::Bytes(sealed)) = map.remove("sealed") else {
            return Err(invalid("a manifest with nothing sealed"));
        };
        let nonce = nonce_of(&sealed)?;
        let said = cipher(&self.derive(b"manifest", b""))?
            .decrypt(&nonce.into(), Payload { msg: sealed.get(24..).unwrap_or_default(), aad: FORMAT.as_bytes() })
            .map_err(|_| invalid("a manifest that isn't this vault's"))?;
        let Ok(Ipld::Map(mut said)) = crate::dagcbor::from_slice(&said) else {
            return Err(invalid("a manifest sealing nonsense"));
        };
        let cid = |bytes: Ipld| match bytes {
            Ipld::Bytes(bytes) => Link::decode(&bytes).map_err(|_| invalid("a manifest naming no CID")),
            _ => Err(invalid("a manifest naming no CID")),
        };
        let plain: Vec<Link> = match said.remove("plain") {
            Some(Ipld::List(list)) => list.into_iter().map(cid).collect::<Result<_>>()?,
            _ => return Err(invalid("a manifest naming nothing")),
        };
        if plain.len() != ciphers.len() {
            return Err(invalid("a manifest naming more or fewer than it links"));
        }
        let root = said.remove("root").map(cid).transpose()?;
        Ok(Manifest { entries: plain.into_iter().zip(ciphers).collect(), next, root })
    }
}

/// The vault's key and secret, sealed with the user's passphrase.
const SEALED: &str = "vault";

/// Whether the vault of the account the catalog acts for keeps itself,
/// sealed, so holders keep it too.
pub fn is_sealed(catalog: &mut Catalog, repo: &Path) -> Result<bool> {
    let vault = Vault::open(repo, catalog.uid())?;
    Ok(vault_keeps(catalog, &vault)?.iter().any(|cid| {
        matches!(catalog.get_block(cid), Ok(Some(block)) if crate::keys::Sealed::parse(block.data()).is_some_and(|sealed| sealed.what() == Some(SEALED) && *sealed.key() == vault.key.id()))
    }))
}

/// What a vault keeps.
fn vault_keeps(catalog: &mut Catalog, vault: &Vault) -> Result<Vec<Link>> {
    let owner = (catalog.uid(), catalog.signer().cloned().ok_or_else(|| invalid("this repo has no key to sign with"))?);
    catalog.act_for(vault.uid, vault.key.clone())?;
    let keeps = catalog.claims().map(crate::store::ClaimStore::keeps).transpose();
    catalog.act_for(owner.0, owner.1)?;
    Ok(keeps?.unwrap_or_default())
}

/// Have the vault keep itself sealed with the user's passphrase, and the
/// user's root key as it's sealed in its mesh.
///
/// So a friend holding the vault holds what it takes to recover all of it
/// with the passphrase alone. Nothing, if the vault does already. Returns
/// whether it didn't.
pub fn seal(catalog: &mut Catalog, repo: &Path, passphrase: &[u8], cost: crate::keys::Cost) -> Result<bool> {
    if is_sealed(catalog, repo)? {
        return Ok(false);
    }
    let owner = (catalog.uid(), catalog.signer().cloned().ok_or_else(|| invalid("this repo has no key to sign with"))?);
    let vault = Vault::open(repo, owner.0)?;
    let sealed = crate::keys::Sealed::seal_with(&vault.key, Some(SEALED), vault.secret.as_ref(), passphrase, cost)?.block();
    let mut blocks = vec![sealed];
    for (cid, _) in catalog.seals()? {
        blocks.extend(catalog.get_block(&cid)?);
    }
    catalog.act_for(vault.uid, vault.key)?;
    let kept = catalog.batch(|catalog| {
        for block in &blocks {
            catalog.put_block(block, CidVersion::V1)?;
            catalog.keep(&AnyCid::V1(block.cid().clone()))?;
        }
        Ok::<_, Error>(())
    });
    catalog.act_for(owner.0, owner.1)?;
    kept.map(|()| true)
}

/// What sealed blocks give back with the passphrase: a vault, and the
/// user's root key, if it was among them.
pub struct Recovered {
    pub vault: Vault,
    pub root: Option<crate::keys::Key>,
}

/// Recover an account's vault from sealed blocks a friend holding it kept,
/// with the user's passphrase.
///
/// Its key and secret are here again, and the user's root key is given
/// back, if it was sealed too. Refuses if the account has a vault here
/// already.
pub fn recover(repo: &Path, owner: u32, sealed: &[Vec<u8>], passphrase: &[u8]) -> Result<Recovered> {
    let uid = vault_of(owner);
    let (key_path, secret_path) = (repo.join("accounts").join(format!("{uid}.key")), repo.join("accounts").join(format!("{uid}.secret")));
    if key_path.exists() || secret_path.exists() {
        return Err(invalid("this account has a vault here already"));
    }
    let parsed: Vec<crate::keys::Sealed> = sealed.iter().filter_map(|data| crate::keys::Sealed::parse(data)).collect();
    let (key, secret) = parsed.iter()
        .filter(|sealed| sealed.what() == Some(SEALED))
        .find_map(|sealed| sealed.open_with(passphrase))
        .ok_or_else(|| invalid("nothing sealed opens with that passphrase"))?;
    let secret: [u8; 32] = secret.as_slice().try_into().map_err(|_| invalid("a vault sealed without its secret"))?;
    let root = parsed.iter().filter(|sealed| sealed.what().is_none()).find_map(|sealed| sealed.open(passphrase));
    std::fs::create_dir_all(repo.join("accounts"))?;
    key.save(&key_path)?;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&secret_path)?;
    file.write_all(&secret)?;
    file.sync_all()?;
    Ok(Recovered { vault: Vault::open(repo, owner)?, root })
}

/// The block access token in a block of a vault's, if it has one: an
/// encrypted block's, after its magic, or a manifest's.
pub fn bat(data: &[u8]) -> Option<[u8; 32]> {
    if data.starts_with(&MAGIC) {
        let start = MAGIC.len().saturating_add(BATS.len());
        return data.get(start..HEADER)?.try_into().ok();
    }
    let Ipld::Map(mut map) = crate::dagcbor::from_slice(data).ok()? else {
        return None;
    };
    match map.remove("bats") {
        Some(Ipld::List(bats)) => match bats.into_iter().next() {
            Some(Ipld::Bytes(bat)) => bat.as_slice().try_into().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// How long a proof of knowing a block's token stands.
pub const PROOF_LIFE: u64 = 300;

/// Proof of knowing a block's token, to ask for it: an HMAC of its CID,
/// the asker's peer ID and the time, keyed by the token, so it's good
/// only for that block, that asker and a few minutes.
pub fn prove(bat: &[u8; 32], cid: &Link, asker: &[u8], at: u64) -> [u8; 32] {
    let message = [cid.to_bytes().as_slice(), &[0], asker, &[0], &at.to_be_bytes()].concat();
    *hmac(bat, &message)
}

/// Whether a proof is of knowing a block's token, by this asker, recently.
pub fn check(data: &[u8], cid: &Link, asker: &[u8], at: u64, proof: &[u8; 32], now: u64) -> bool {
    let Some(bat) = bat(data) else {
        return false;
    };
    if now.abs_diff(at) > PROOF_LIFE {
        return false;
    }
    // In constant time, so timing says nothing of how near a guess was
    prove(&bat, cid, asker, at).iter().zip(proof).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

/// Protect a DAG, all of which must be here, in the vault of the account
/// the catalog acts for: encrypt it, as the vault's, and keep a manifest
/// of it. Returns the manifest's CID.
pub fn protect(catalog: &mut Catalog, repo: &Path, root: &Link) -> Result<Link> {
    let owner = (catalog.uid(), catalog.signer().cloned().ok_or_else(|| invalid("this repo has no key to sign with"))?);
    let vault = Vault::open(repo, owner.0)?;
    let mut sealed = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![root.clone()];
    while let Some(link) = stack.pop() {
        if link.hashcode() == IDENTITY || !seen.insert(link.multihash().to_bytes()) {
            continue;
        }
        let block = catalog.get_block(&link)?
            .filter(|_| catalog.visible(link.multihash()).unwrap_or(false))
            .ok_or_else(|| invalid(format!("{link} isn't here: all of what's protected must be")))?;
        stack.extend(crate::links::links(link.codec(), block.data()).unwrap_or_default());
        sealed.push((link.clone(), vault.seal(&link, block.data())?));
    }
    catalog.act_for(vault.uid, vault.key.clone())?;
    let protected = catalog.batch(|catalog| {
        let mut entries = Vec::new();
        for (plain, block) in &sealed {
            catalog.put_block(block, CidVersion::V1)?;
            entries.push((plain.clone(), AnyCid::V1(block.cid().clone())));
        }
        let manifest = if entries.len() <= ENTRIES {
            vault.manifest(&entries, &[], Some(root))?
        } else {
            let mut leaves = Vec::new();
            for chunk in entries.chunks(ENTRIES) {
                let leaf = vault.manifest(chunk, &[], None)?;
                catalog.put_block(&leaf, CidVersion::V1)?;
                leaves.push(AnyCid::V1(leaf.cid().clone()));
            }
            vault.manifest(&[], &leaves, Some(root))?
        };
        catalog.put_block(&manifest, CidVersion::V1)?;
        let cid = AnyCid::V1(manifest.cid().clone());
        catalog.keep(&cid)?;
        Ok::<_, Error>(cid)
    });
    catalog.act_for(owner.0, owner.1)?;
    protected
}

/// Bring a protected DAG back from its manifest and ciphertext, all of
/// which must be here, into the repo of the account the catalog acts for,
/// and keep it. Returns its root, and how many blocks it is.
pub fn restore(catalog: &mut Catalog, repo: &Path, manifest: &Link) -> Result<(Link, usize)> {
    let vault = Vault::open(repo, catalog.uid())?;
    let missing = |cid: &Link| invalid(format!("{cid} isn't here: fetch it through the vault's mesh first"));
    let mut pending = vec![manifest.clone()];
    let mut entries = Vec::new();
    let mut root = None;
    while let Some(cid) = pending.pop() {
        let block = catalog.get_block(&cid)?.ok_or_else(|| missing(&cid))?;
        let read = vault.read(block.data())?;
        root = root.or(read.root);
        entries.extend(read.entries);
        pending.extend(read.next);
    }
    let root = root.ok_or_else(|| invalid("a manifest naming no root"))?;
    catalog.batch(|catalog| {
        for (plain, sealed) in &entries {
            let data = catalog.get_block(sealed)?.ok_or_else(|| missing(sealed))?;
            catalog.put_block(&vault.unseal(plain, data.data())?, plain.version())?;
        }
        catalog.keep(&root)?;
        Ok((root, entries.len()))
    })
}

/// What the vault of the account the catalog acts for keeps: each
/// manifest, and the root it protects.
pub fn list(catalog: &mut Catalog, repo: &Path) -> Result<Vec<(Link, Link)>> {
    let owner = (catalog.uid(), catalog.signer().cloned().ok_or_else(|| invalid("this repo has no key to sign with"))?);
    let vault = Vault::open(repo, owner.0)?;
    catalog.act_for(vault.uid, vault.key.clone())?;
    let keeps = catalog.claims().map(crate::store::ClaimStore::keeps).transpose();
    catalog.act_for(owner.0, owner.1)?;
    let mut found = Vec::new();
    for manifest in keeps?.unwrap_or_default() {
        if let Some(block) = catalog.get_block(&manifest)?
            && let Ok(read) = vault.read(block.data())
            && let Some(root) = read.root
        {
            found.push((manifest, root));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::BlockIndex as _;
    use crate::testutil::Scratch;

    fn raw(data: &[u8]) -> Block {
        Block::hash(Cidv1Spec::default(), data.into())
    }

    #[test]
    fn blocks_seal_the_same_way_in_one_vault_and_open_only_there() {
        let scratch = Scratch::new("vault-seal");
        let vault = Vault::open(scratch.path(), 1000).expect("vault");
        let other = Vault::open(scratch.path(), 1001).expect("vault");
        let block = raw(b"secret");
        let plain = AnyCid::V1(block.cid().clone());
        let sealed = vault.seal(&plain, block.data()).expect("seal");
        assert_eq!(sealed.cid(), vault.seal(&plain, block.data()).expect("seal").cid(), "idempotent");
        assert_ne!(sealed.cid(), other.seal(&plain, block.data()).expect("seal").cid(), "unpredictable elsewhere");
        assert!(sealed.data().starts_with(&MAGIC));
        assert!(!sealed.data().windows(6).any(|window| window == b"secret"));
        assert_eq!(vault.unseal(&plain, sealed.data()).expect("unseal").data(), block.data());
        assert!(other.unseal(&plain, sealed.data()).is_err());
        // A tampered BAT is a tampered block
        let mut tampered = sealed.data().to_vec();
        if let Some(byte) = tampered.get_mut(20) {
            *byte ^= 1;
        }
        assert!(vault.unseal(&plain, &tampered).is_err());
        // The secret stays
        let again = Vault::open(scratch.path(), 1000).expect("vault");
        assert_eq!(again.seal(&plain, block.data()).expect("seal").cid(), sealed.cid());
        assert_eq!(again.key().id(), vault.key().id());
    }

    #[test]
    fn a_protected_dag_comes_back_from_its_manifest() {
        let scratch = Scratch::new("vault-dag");
        let mut repo = Catalog::open_repo(scratch.path()).expect("open");
        let leaves: Vec<Block> = (0..ENTRIES.saturating_add(5)).map(|n| raw(format!("leaf {n}").as_bytes())).collect();
        let list = Ipld::List(leaves.iter().map(|leaf| Ipld::Link(AnyCid::V1(leaf.cid().clone()))).collect());
        let root = Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), cbor(&list).expect("cbor").into());
        for block in leaves.iter().chain([&root]) {
            repo.put_block(block, CidVersion::V1).expect("put");
        }
        let root_cid = AnyCid::V1(root.cid().clone());
        let manifest = protect(&mut repo, scratch.path(), &root_cid).expect("protect");
        assert_eq!(list_of(&mut repo, &scratch), [(manifest.clone(), root_cid.clone())]);
        // The manifest and ciphertext are the vault's, not the owner's
        assert!(!repo.visible(manifest.multihash()).expect("visible"));
        assert!(repo.kept_under(manifest.multihash()).expect("kept"));

        // Lost here, and back
        let fresh = Scratch::new("vault-dag-fresh");
        let mut other = Catalog::open_repo(fresh.path()).expect("open");
        std::fs::create_dir_all(fresh.path().join("accounts")).expect("dir");
        let uid = vault_of(repo.uid());
        for name in [format!("{uid}.key"), format!("{uid}.secret")] {
            std::fs::copy(scratch.path().join("accounts").join(&name), fresh.path().join("accounts").join(&name)).expect("copy");
        }
        // Only the vault's blocks travel
        for key in repo.keys().expect("keys") {
            let cid = repo.cid_of(key.as_ref()).expect("cid").expect("cid");
            let block = repo.get_block(&cid).expect("get").expect("block");
            if block.data().starts_with(&MAGIC) || cid.codec() == DAG_CBOR_CODEC && cid != root_cid {
                other.put_block(&block, CidVersion::V1).expect("put");
            }
        }
        assert!(other.get_block(&root_cid).expect("get").is_none());
        let (back, count) = restore(&mut other, fresh.path(), &manifest).expect("restore");
        assert_eq!((back, count), (root_cid.clone(), leaves.len().saturating_add(1)));
        assert_eq!(other.get_block(&root_cid).expect("get").map(|block| block.data().to_vec()), Some(root.data().to_vec()));
        assert!(other.visible(root_cid.multihash()).expect("visible"));
    }

    #[test]
    fn a_vault_and_its_user_come_back_from_what_a_friend_holds_and_the_passphrase() {
        use crate::keys::Cost;
        let scratch = Scratch::new("vault-recover");
        let mut repo = Catalog::open_repo(scratch.path()).expect("open");
        let root = repo.found_user(b"pass", Cost::NONE).expect("user");
        let block = raw(b"precious");
        repo.put_block(&block, CidVersion::V1).expect("put");
        let plain = AnyCid::V1(block.cid().clone());
        let manifest = protect(&mut repo, scratch.path(), &plain).expect("protect");
        assert!(!is_sealed(&mut repo, scratch.path()).expect("sealed"));
        assert!(seal(&mut repo, scratch.path(), b"pass", Cost::NONE).expect("seal"));
        assert!(!seal(&mut repo, scratch.path(), b"pass", Cost::NONE).expect("seal"), "once");
        // What the vault keeps, as a holder would: the manifest, and the
        // sealed vault and root
        let vault = Vault::open(scratch.path(), repo.uid()).expect("vault");
        let kept = vault_keeps(&mut repo, &vault).expect("keeps");
        assert_eq!(kept.len(), 3);
        let sealed: Vec<Vec<u8>> = kept.iter()
            .filter_map(|cid| repo.get_block(cid).expect("get"))
            .filter(|block| crate::keys::Sealed::parse(block.data()).is_some())
            .map(|block| block.data().to_vec())
            .collect();
        assert_eq!(sealed.len(), 2);

        // Everything here is lost but that, and the ciphertext
        let fresh = Scratch::new("vault-recover-fresh");
        assert!(recover(fresh.path(), repo.uid(), &sealed, b"wrong").is_err());
        let recovered = recover(fresh.path(), repo.uid(), &sealed, b"pass").expect("recover");
        assert_eq!(recovered.vault.key().id(), vault.key().id());
        assert_eq!(recovered.root.map(|root| root.id()), Some(root.id()));
        assert!(recover(fresh.path(), repo.uid(), &sealed, b"pass").is_err(), "a vault's here already");
        let mut other = Catalog::open_repo(fresh.path()).expect("open");
        for cid in std::iter::once(manifest.clone()).chain(kept) {
            let data = repo.get_block(&cid).expect("get").expect("block");
            other.put_block(&data, CidVersion::V1).expect("put");
            for link in crate::links::links(cid.codec(), data.data()).unwrap_or_default() {
                if let Some(block) = repo.get_block(&link).expect("get") {
                    other.put_block(&block, CidVersion::V1).expect("put");
                }
            }
        }
        assert_eq!(restore(&mut other, fresh.path(), &manifest).expect("restore").0, plain);
    }

    #[test]
    fn proofs_of_a_token_are_for_one_block_one_asker_and_a_few_minutes() {
        let scratch = Scratch::new("vault-bat");
        let vault = Vault::open(scratch.path(), 1000).expect("vault");
        let block = raw(b"shared");
        let plain = AnyCid::V1(block.cid().clone());
        let sealed = vault.seal(&plain, block.data()).expect("seal");
        let cid = AnyCid::V1(sealed.cid().clone());
        let bat = bat(sealed.data()).expect("bat");
        let proof = prove(&bat, &cid, b"asker", 1000);
        assert!(check(sealed.data(), &cid, b"asker", 1000, &proof, 1100));
        assert!(!check(sealed.data(), &cid, b"another", 1000, &proof, 1100));
        assert!(!check(sealed.data(), &cid, b"asker", 1000, &proof, 1000 + PROOF_LIFE + 1));
        assert!(!check(sealed.data(), &plain, b"asker", 1000, &proof, 1100));
        assert!(!check(sealed.data(), &cid, b"asker", 1000, &prove(&[0; 32], &cid, b"asker", 1000), 1100));
        assert!(!check(block.data(), &cid, b"asker", 1000, &proof, 1100), "no token, no proof");
        // A manifest has one too
        let manifest = vault.manifest(&[(plain, cid)], &[], None).expect("manifest");
        assert!(super::bat(manifest.data()).is_some());
    }

    fn list_of(repo: &mut Catalog, scratch: &Scratch) -> Vec<(Link, Link)> {
        list(repo, scratch.path()).expect("list")
    }
}
