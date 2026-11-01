//! Keys: who may say what.
//!
//! A user is a root key, which signs nothing but certificates: a `device`
//! claim, signed by the root, says a node's key acts for the user, and a
//! tomb of it, signed by the root, says it no longer does. Devices sign
//! everything else. A key is named by a CID, as libp2p names peers: an
//! identity multihash of its public key, protobuf-encoded, under the
//! `libp2p-key` codec, so a node's key and its peer ID are one.
//!
//! Secrets are kept as libp2p keeps them, a protobuf-encoded ed25519
//! keypair, readable only by their owner.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::cid::{AnyCid, BaseCid, CidRef, Cidv1, LIBP2P_KEY_CODEC};
use crate::block::IDENTITY;
use crate::model::Link;
use crate::multihash::Multihash;

/// This node's key, as libp2p keeps it.
pub const NODE_KEY: &str = "node.key";
/// The user's root key, on whichever machine keeps it.
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

    #[cfg(feature = "net")]
    #[test]
    fn keys_are_libp2p_keys() {
        let key = Key::generate().unwrap();
        let pair = libp2p::identity::Keypair::from_protobuf_encoding(&key.to_protobuf()).unwrap();
        assert_eq!(pair.public().to_peer_id().to_bytes(), key.id().multihash().to_bytes());
        let back = Key::from_protobuf(&pair.to_protobuf_encoding().unwrap()).unwrap();
        assert_eq!(back.id(), key.id());
    }
}
