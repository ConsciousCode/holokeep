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
        &self.digest[..self.len as usize]
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
                len: len as u8,
                digest: {
                    let mut tmp = [0u8; S];
                    tmp[..len].copy_from_slice(digest);
                    tmp
                }
            })
        }
    }
}