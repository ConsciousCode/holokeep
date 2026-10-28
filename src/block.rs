//! Block type representing raw data with a CID.
//! Preserves the invariant that the cid exactly matches the data.
//! Where blocks are kept is the `store` module.

use crate::cid::{BaseCid, CidRef, Cid, Cidv1, Cidv1Spec};
use crate::multihash::{DefaultDigest, DigestBuf, Multihash, MultihashDigest, MultihashFunc, SizeError};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError<D: DigestBuf> {
    /// Could not convert a hash code to a known hash codec
    #[error("could not convert hash code 0x{0:x} to a hash codec")]
    UnknownHash(u64),

    /// Error wrapping the digest in the given type
    #[error("wrapping digest")]
    Wrap(#[from] SizeError),

    /// Digests didn't match
    #[error("digest mismatch; expected {0}, got {1}")]
    Mismatch(Multihash<D>, Multihash<D>),
}

/// A block of data with an associated CID.
///
/// Blocks are the fundamental unit of storage in IPFS.
/// Each block contains raw data and a CID (Content Identifier)
/// that is derived from the hash of the data.
/// 
/// This maintains the invariant that the cid corresponds to the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block<D: DigestBuf=DefaultDigest> {
    /// The content identifier for this block
    cid: Cidv1<D>,
    /// The raw data
    data: Box<[u8]>,
}

impl<D: DigestBuf> Block<D> {
    /// Create a new block using the given cid spec and data. Takes ownership.
    pub fn hash(spec: Cidv1Spec, data: Box<[u8]>) -> Self {
        Self { cid: spec.hash(&data), data }
    }

    /// Verify that a CID matches data, returning a new block.
    pub fn verify(cid: Cidv1<D>, data: Box<[u8]>) -> Result<Self, VerifyError<D>> {
        let hashcode = cid.hashcode();
        let spec: MultihashFunc = hashcode
            .try_into()
            .map_err(|_| VerifyError::UnknownHash(hashcode))?;
        let digest: Multihash<D> = spec.digest(&data)?;
        if digest == cid.multihash() {
            Ok(Self { cid, data })
        }
        else {
            Err(VerifyError::Mismatch(cid.into_multihash(), digest))
        }
    }

    /// Get the CID of this block
    pub const fn cid(&self) -> &Cidv1<D> { &self.cid }

    /// Get the raw data of this block
    pub fn data(&self) -> &[u8] { &self.data }

    /// Get the length of this block's data
    pub const fn len(&self) -> usize { self.data.len() }

    /// Consume the block and return its data
    pub fn into_data(self) -> Box<[u8]> { self.data }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multihash::Inline;
    use crate::multihash::MultihashFunc;
    use crate::cid::RAW_CODEC;

    #[test]
    fn test_block_new_raw() {
        let spec = Cidv1Spec::new(RAW_CODEC, MultihashFunc::Sha2_256);
        let data = Vec::from(&b"hello world"[..]).into_boxed_slice();
        let block: Block<[u8; 32]> = Block::hash(spec, data.clone());

        assert_eq!(block.data(), &data[..]);
        assert_eq!(block.len(), 11);
        assert_eq!(
            block.cid().to_string(),
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
        );
        assert_eq!(block.into_data(), data);
    }

    fn hello() -> Block {
        Block::hash(Cidv1Spec::default(), b"hello world"[..].into())
    }

    #[test]
    fn verify_matching() {
        let block = hello();
        let verified = Block::verify(block.cid().clone(), block.data().into()).expect("matches");
        assert_eq!(verified, block);

        // Any supported hash function, not just the default
        let spec = Cidv1Spec::new(RAW_CODEC, MultihashFunc::Sha3_512);
        let block: Block = Block::hash(spec, b"hello world"[..].into());
        assert!(Block::verify(block.cid().clone(), block.data().into()).is_ok());
    }

    #[test]
    fn verify_mismatch() {
        let block = hello();
        let err = Block::verify(block.cid().clone(), b"hello there"[..].into())
            .expect_err("different data");
        let VerifyError::Mismatch(expected, got) = err else { panic!("{err:?}") };
        assert_eq!(expected, block.cid().multihash());
        assert_ne!(expected, got);
    }

    #[test]
    fn verify_unknown_hash() {
        let digest = Inline::<64>::decode(&[0; 16]).expect("fits");
        let cid = Cidv1::new(RAW_CODEC, Multihash::new(0xd5, digest));
        let err = Block::verify(cid, Box::default()).expect_err("md5 unsupported");
        assert!(matches!(err, VerifyError::UnknownHash(0xd5)));
    }
}
