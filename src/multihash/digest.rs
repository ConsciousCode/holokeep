//! Code for managing multihash digests.

//use bytes::{Buf, Bytes};

use super::SizeError;

/// Trait for implementing multihash digest backings which support
/// construction, allowing one to create them by reading provided data.
pub trait DigestBuf: AsRef<[u8]> + Sized {
    // IPIP-0512 establishes a 128 byte limit for identity hashes for unixfsv1

    /// The maximum length this backing supports for early varint digest size
    /// rejection.
    const MAX_LEN: usize = 128;

    /// Create a digest by reading it from a buffer.
    fn decode(buf: &[u8]) -> Result<Self, SizeError>;
}

/// Only valid for digests exactly S bytes long.
impl<const S: usize> DigestBuf for [u8; S] {
    const MAX_LEN: usize = S;

    fn decode(digest: &[u8]) -> Result<Self, SizeError> {
        let len = digest.len();
        if len == S {
            let mut tmp = [0u8; S];
            tmp[..len].copy_from_slice(digest);
            Ok(tmp)
        }
        else {
            Err(SizeError::Mismatch)?
        }
    }
}

/*
impl DigestBuf for Bytes {
    fn from_slice(digest: &[u8]) -> Result<Self, SizeError> {
        Ok(Bytes::copy_from_slice(digest))
    }

    fn decode(mut buf: &[u8]) -> Result<Self, DecodeError> {
        let available = buf.remaining();
        if available < buf.len() {
            Err(DecodeError::Truncated)
        }
        else {
            Ok(buf.copy_to_bytes(buf.len()))
        }
    }
}
*/

impl DigestBuf for Box<[u8]> {
    fn decode(buf: &[u8]) -> Result<Self, SizeError> {
        Ok(buf.into())
    }
}

impl DigestBuf for Vec<u8> {
    fn decode(buf: &[u8]) -> Result<Self, SizeError> {
        Ok(buf.into())
    }
}

/// Store the digest inline with the multihash using a maximum size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Inline<const S: usize> {
    len: u8,
    digest: [u8; S],
}
impl<const S: usize> AsRef<[u8]> for Inline<S> {
    fn as_ref(&self) -> &[u8] {
        self.digest.get(..usize::from(self.len)).unwrap_or(&self.digest)
    }
}
impl<const S: usize> DigestBuf for Inline<S> {
    const MAX_LEN: usize = S;

    fn decode(digest: &[u8]) -> Result<Self, SizeError> {
        let len = digest.len();
        if len > S {
            Err(SizeError::Overflow)
        }
        else {
            Ok(Self {
                len: u8::try_from(len).map_err(|_| SizeError::Overflow)?,
                digest: {
                    let mut tmp = [0u8; S];
                    tmp[..len].copy_from_slice(digest);
                    tmp
                }
            })
        }
    }
}
/// A digest kept inline up to `S` bytes, and on the heap beyond, so the
/// common case (32-byte digests) never allocates while identity digests can
/// still be as long as IPIP-0512 allows. A digest is only ever on the heap
/// when it's longer than `S`, but equality, ordering and hashing go by the
/// bytes regardless.
#[derive(Clone, Debug)]
pub enum Spill<const S: usize> {
    Inline(Inline<S>),
    Heap(Box<[u8]>),
}

impl<const S: usize> AsRef<[u8]> for Spill<S> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Inline(digest) => digest.as_ref(),
            Self::Heap(digest) => digest,
        }
    }
}

impl<const S: usize> DigestBuf for Spill<S> {
    fn decode(digest: &[u8]) -> Result<Self, SizeError> {
        if digest.len() > Self::MAX_LEN {
            Err(SizeError::Overflow)
        }
        else if digest.len() > S {
            Ok(Self::Heap(digest.into()))
        }
        else {
            Inline::decode(digest).map(Self::Inline)
        }
    }
}

impl<const S: usize> PartialEq for Spill<S> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl<const S: usize> Eq for Spill<S> {}

impl<const S: usize> PartialOrd for Spill<S> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<const S: usize> Ord for Spill<S> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl<const S: usize> std::hash::Hash for Spill<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

/// The digest CIDs keep by default: sha2-256 and its kin inline.
pub type DefaultDigest = Spill<32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spills_only_past_its_inline_size() {
        let short = Spill::<32>::decode(&[7; 32]).expect("short");
        let long = Spill::<32>::decode(&[7; 33]).expect("long");
        assert!(matches!(short, Spill::Inline(_)));
        assert!(matches!(long, Spill::Heap(_)));
        assert_eq!(long.as_ref(), &[7; 33]);
        assert!(Spill::<32>::decode(&[7; 128]).is_ok());
        assert!(Spill::<32>::decode(&[7; 129]).is_err());
        // By the bytes, wherever they're kept
        assert_eq!(Spill::<32>::Heap(vec![7; 32].into()), short);
        assert!(std::mem::size_of::<Spill<32>>() <= 40);
    }
}
