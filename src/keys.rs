//! Keys: who may say what.
//!
//! A user is a root key, which signs nothing but certificates: a `device`
//! claim, signed by the root, says a node's key acts for the user, and a
//! tomb of it, signed by the root, says it no longer does. Devices sign
//! everything else. A key is named by a CID, as libp2p names peers: an
//! identity multihash of its public key, protobuf-encoded, under the
//! `libp2p-key` codec, so a node's key and its peer ID are one.
//!
//! A node's secret is kept as libp2p keeps it, a protobuf-encoded ed25519
//! keypair, readable only by its owner. The user's root key is kept on no
//! machine: it's sealed with the user's passphrase, as a block the mesh
//! keeps like any other (see `Sealed`), and opened only to certify or
//! revoke a device. A device that's stolen has no more of the root than
//! anyone else.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

use crate::block::{Block, IDENTITY};
use crate::cid::{AnyCid, BaseCid, CidRef, Cidv1, Cidv1Spec, DAG_CBOR_CODEC, LIBP2P_KEY_CODEC};
use crate::model::{Ipld, Link};
use crate::multihash::{Multihash, MultihashFunc};

/// This node's key, as libp2p keeps it.
pub const NODE_KEY: &str = "node.key";
/// Where a user's root key was kept, unsealed, before it was sealed.
pub const USER_KEY: &str = "user.key";

/// A public key's protobuf encoding: type ed25519, then 32 bytes.
const PUBLIC_PREFIX: [u8; 4] = [0x08, 0x01, 0x12, 0x20];
/// A keypair's: type ed25519, then the secret and public halves.
const SECRET_PREFIX: [u8; 4] = [0x08, 0x01, 0x12, 0x40];

/// A key which can sign.
#[derive(Clone)]
pub struct Key(SigningKey);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.id())
    }
}

impl Key {
    /// A new random key.
    pub fn generate() -> io::Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(io::Error::other)?;
        Ok(Self(SigningKey::from_bytes(&secret)))
    }

    /// The key as libp2p encodes a keypair.
    pub fn to_protobuf(&self) -> Vec<u8> {
        [&SECRET_PREFIX[..], &self.0.to_keypair_bytes()].concat()
    }

    /// A key libp2p encoded, if it's an ed25519 keypair.
    pub fn from_protobuf(bytes: &[u8]) -> Option<Self> {
        let pair: &[u8; 64] = bytes.strip_prefix(&SECRET_PREFIX)?.try_into().ok()?;
        SigningKey::from_keypair_bytes(pair).ok().map(Self)
    }

    /// The key's name.
    pub fn id(&self) -> Link {
        id_of(&self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).to_bytes().to_vec()
    }

    /// The key in a file, made there if there's none yet.
    pub fn load_or_make(path: &Path) -> io::Result<Self> {
        if let Some(key) = Self::load(path)? {
            return Ok(key);
        }
        let key = Self::generate()?;
        key.save(path)?;
        Ok(key)
    }

    /// The key in a file, if there is one.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        match fs::read(path) {
            Ok(bytes) => Self::from_protobuf(&bytes)
                .map(Some)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{}: not an ed25519 key", path.display()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Keep the key in a file readable only by its owner, replacing what's
    /// there.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let temp = path.with_extension("new");
        let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temp)?;
        file.write_all(&self.to_protobuf())?;
        file.sync_all()?;
        fs::rename(&temp, path)
    }
}

/// The key a repo signs with for one of the host's accounts: the node's
/// own for its owner, otherwise one of the account's own in `accounts/`,
/// made the first time it's needed.
pub fn account_key(repo: &Path, uid: u32) -> io::Result<Key> {
    if uid == rustix::process::getuid().as_raw() {
        return Key::load_or_make(&repo.join(NODE_KEY));
    }
    Key::load_or_make(&repo.join("accounts").join(format!("{uid}.key")))
}

/// A public key's name.
fn id_of(key: &VerifyingKey) -> Link {
    let encoded = [&PUBLIC_PREFIX[..], key.as_bytes()].concat();
    // 36 bytes, more than fit inline
    let hash = Multihash::new(IDENTITY, crate::multihash::Spill::Heap(encoded.into()));
    AnyCid::V1(Cidv1::new(LIBP2P_KEY_CODEC, hash))
}

/// The public key a name is, if it's one.
fn public(id: &Link) -> Option<VerifyingKey> {
    (id.codec() == LIBP2P_KEY_CODEC && id.hashcode() == IDENTITY).then_some(())?;
    let bytes: &[u8; 32] = id.digest_ref().strip_prefix(&PUBLIC_PREFIX)?.try_into().ok()?;
    VerifyingKey::from_bytes(bytes).ok()
}

/// A key's name as a libp2p peer ID: its multihash, in base58.
pub fn peer_id(id: &Link) -> String {
    let encoded = multibase::encode(multibase::Base::Base58Btc, id.multihash().to_bytes());
    encoded.strip_prefix('z').map_or_else(|| encoded.clone(), str::to_owned)
}

/// The key a peer ID names, if it's an ed25519 key's.
pub fn from_peer_id(peer: &str) -> Option<Link> {
    let (_, multihash) = multibase::decode(format!("z{peer}")).ok()?;
    Some(Multihash::<Vec<u8>>::decode(&multihash).ok()?)
        .map(|hash| AnyCid::V1(Cidv1::new(LIBP2P_KEY_CODEC, Multihash::new(hash.code(), crate::multihash::Spill::Heap(hash.into_digest().into())))))
        .filter(is_key)
}

/// Whether a CID names a key.
pub fn is_key(id: &Link) -> bool {
    public(id).is_some()
}

/// Whether `signature` is the named key's of `message`.
pub fn verify(id: &Link, message: &[u8], signature: &[u8]) -> bool {
    let (Some(key), Ok(signature)) = (public(id), Signature::from_slice(signature)) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// How costly a passphrase is to guess at: argon2id's memory, in KiB,
/// its passes, and its lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    pub memory: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Cost {
    /// RFC 9106's second recommendation: 64 MiB, three passes, four lanes.
    pub const RECOMMENDED: Self = Self { memory: 64 * 1024, passes: 3, lanes: 4 };
    /// As cheap as argon2id goes, for tests: no protection at all.
    pub const NONE: Self = Self { memory: 8, passes: 1, lanes: 1 };
}

/// A key sealed with a passphrase: a block anyone may hold, which only
/// someone with the passphrase can open. The key's name is bound to it,
/// so it opens only as the key it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    key: Link,
    cost: Cost,
    salt: Vec<u8>,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

const KDF: &str = "argon2id";
const CIPHER: &str = "xchacha20poly1305";

/// A passphrase stretched into a key to seal with.
fn stretch(passphrase: &[u8], salt: &[u8], cost: Cost) -> Option<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(cost.memory, cost.passes, cost.lanes, Some(32)).ok()?;
    let mut key = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .ok()?;
    Some(key)
}

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

impl Sealed {
    /// Seal a key with a passphrase, at a cost to anyone guessing it.
    pub fn seal(key: &Key, passphrase: &[u8], cost: Cost) -> io::Result<Self> {
        let salt = random::<16>()?.to_vec();
        let nonce = random::<24>()?;
        let secret = stretch(passphrase, &salt, cost).ok_or_else(|| io::Error::other("argon2id won't take that cost"))?;
        let cipher = XChaCha20Poly1305::new_from_slice(secret.as_ref()).map_err(io::Error::other)?;
        let id = key.id();
        let plain = Zeroizing::new(key.to_protobuf());
        let ciphertext = cipher
            .encrypt(&nonce.into(), Payload { msg: &plain, aad: &id.to_bytes() })
            .map_err(|_| io::Error::other("sealing failed"))?;
        Ok(Self { key: id, cost, salt, nonce, ciphertext })
    }

    /// The key, if the passphrase is the one it was sealed with.
    pub fn open(&self, passphrase: &[u8]) -> Option<Key> {
        let secret = stretch(passphrase, &self.salt, self.cost)?;
        let cipher = XChaCha20Poly1305::new_from_slice(secret.as_ref()).ok()?;
        let plain = Zeroizing::new(cipher.decrypt(&self.nonce.into(), Payload { msg: &self.ciphertext, aad: &self.key.to_bytes() }).ok()?);
        Key::from_protobuf(&plain).filter(|key| key.id() == self.key)
    }

    /// Which key it is.
    pub const fn key(&self) -> &Link {
        &self.key
    }

    fn to_ipld(&self) -> Ipld {
        Ipld::Map(BTreeMap::from([
            ("cipher".to_owned(), Ipld::String(CIPHER.to_owned())),
            ("kdf".to_owned(), Ipld::String(KDF.to_owned())),
            ("key".to_owned(), Ipld::Link(self.key.clone())),
            ("lanes".to_owned(), Ipld::Integer(self.cost.lanes.into())),
            ("memory".to_owned(), Ipld::Integer(self.cost.memory.into())),
            ("nonce".to_owned(), Ipld::Bytes(self.nonce.to_vec())),
            ("passes".to_owned(), Ipld::Integer(self.cost.passes.into())),
            ("salt".to_owned(), Ipld::Bytes(self.salt.clone())),
            ("sealed".to_owned(), Ipld::Bytes(self.ciphertext.clone())),
        ]))
    }

    /// The sealed key as a dag-cbor block.
    pub fn block(&self) -> Block {
        let data = crate::dagcbor::to_vec(&self.to_ipld()).unwrap_or_default();
        Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), data.into())
    }

    /// The sealed key a dag-cbor block is, if it's one.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let Ipld::Map(mut map) = crate::dagcbor::from_slice(data).ok()? else {
            return None;
        };
        let mut take = |name: &str| map.remove(name);
        let integer = |value: Option<Ipld>| match value {
            Some(Ipld::Integer(n)) => u32::try_from(n).ok(),
            _ => None,
        };
        let bytes = |value: Option<Ipld>| match value {
            Some(Ipld::Bytes(bytes)) => Some(bytes),
            _ => None,
        };
        let (Some(Ipld::String(kdf)), Some(Ipld::String(cipher)), Some(Ipld::Link(key))) = (take("kdf"), take("cipher"), take("key")) else {
            return None;
        };
        (kdf == KDF && cipher == CIPHER && is_key(&key)).then_some(())?;
        let cost = Cost { memory: integer(take("memory"))?, passes: integer(take("passes"))?, lanes: integer(take("lanes"))? };
        let (salt, nonce, ciphertext) = (bytes(take("salt"))?, bytes(take("nonce"))?, bytes(take("sealed"))?);
        let sealed = Self { key, cost, salt, nonce: nonce.as_slice().try_into().ok()?, ciphertext };
        map.is_empty().then_some(sealed)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn signatures_check_out_only_for_their_key_and_message() {
        let key = Key::generate().unwrap();
        let other = Key::generate().unwrap();
        let signature = key.sign(b"keep this");
        assert!(verify(&key.id(), b"keep this", &signature));
        assert!(!verify(&key.id(), b"keep that", &signature));
        assert!(!verify(&other.id(), b"keep this", &signature));
        assert!(!verify(&key.id(), b"keep this", &signature[1..]));
    }

    #[test]
    fn keys_round_trip_through_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(NODE_KEY);
        assert!(Key::load(&path).unwrap().is_none());
        let key = Key::load_or_make(&path).unwrap();
        assert_eq!(Key::load_or_make(&path).unwrap().id(), key.id());
        assert!(is_key(&key.id()));
        assert!(!is_key(&crate::claim::tag("not a key").unwrap()));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn a_sealed_key_opens_only_with_its_passphrase() {
        let key = Key::generate().unwrap();
        let sealed = Sealed::seal(&key, b"correct horse", Cost::NONE).unwrap();
        let block = sealed.block();
        let parsed = Sealed::parse(block.data()).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(parsed.open(b"correct horse").map(|key| key.id()), Some(key.id()));
        assert!(parsed.open(b"battery staple").is_none());
        // Bound to the key it says it is
        let other = Key::generate().unwrap();
        let swapped = Sealed { key: other.id(), ..sealed };
        assert!(swapped.open(b"correct horse").is_none());
        assert!(Sealed::parse(crate::claim::Claim::Tomb(crate::claim::Tomb::new([key.id()]).unwrap()).block().data()).is_none());
    }

    #[cfg(feature = "net")]
    #[test]
    fn keys_are_libp2p_keys() {
        let key = Key::generate().unwrap();
        let pair = libp2p::identity::Keypair::from_protobuf_encoding(&key.to_protobuf()).unwrap();
        assert_eq!(pair.public().to_peer_id().to_bytes(), key.id().multihash().to_bytes());
        let peer = pair.public().to_peer_id().to_string();
        assert_eq!(peer_id(&key.id()), peer);
        assert_eq!(from_peer_id(&peer), Some(key.id()));
        assert_eq!(from_peer_id("not a peer"), None);
        let back = Key::from_protobuf(&pair.to_protobuf_encoding().unwrap()).unwrap();
        assert_eq!(back.id(), key.id());
    }
}
