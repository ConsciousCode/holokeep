use std::cmp::Ordering;
use core::hash::{Hash, Hasher};

use crate::varint;

mod digest;
mod codec;
pub use digest::{DigestBuf, Inline};
pub use codec::{MultihashCodec, MultihashDigest, MultihashFunc};

#[derive(Debug, thiserror::Error)]
pub enum SizeError {
    /// The digest is too big to be read into the backing.
    #[error("digest size overflow")]
    Overflow,

    /// Error used by sized array backing for when the size doesn't
    /// exactly match.
    #[error("incorrect fixed digest size")]
    Mismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// There were not enough bytes to read the multihash.
    #[error("truncated bytes")]
    Truncated,

    /// Error while parsing.
    #[error("parsing")]
    Parse,

    /// Error while building a multihash from a digest.
    #[error("size of a digest")]
    Size(#[from] SizeError),
}

impl From<varint::Error> for DecodeError {
    fn from(value: varint::Error) -> Self {
        match value {
            varint::Error::Truncated => Self::Truncated,
            varint::Error::Overflow => Self::Parse,
        }
    }
}

/// An IPLD multihash, encoding the digest along with the hash function used
/// to generate it.
#[derive(Clone, Debug)]
pub struct Multihash<D: ?Sized=Inline<64>> {
    /// The code of the Multihash.
    code: u64,
    /// The digest.
    digest: D,
}

impl<D: Sized> Multihash<D> {
    /// Build a new multihash given its digest.
    pub fn new(code: u64, digest: D) -> Self {
        Self { code, digest }
    }
    
    /// Consume the multihash and return its digest.
    pub fn into_digest(self) -> D { self.digest }
}

impl<D: ?Sized> Multihash<D> {
    /// Returns the code of the multihash
    pub const fn code(&self) -> u64 { self.code }

    /// Borrow the inner digest.
    pub const fn digest(&self) -> &D { &self.digest }
}

impl<D: AsRef<[u8]>> Multihash<D> {
    /// Returns the size of the digest.
    pub fn len(&self) -> usize { self.digest.as_ref().len() }

    /// Borrow the multihash.
    pub fn as_ref(&self) -> Multihash<&[u8]> {
        Multihash { code: self.code, digest: self.digest.as_ref() }
    }

    /// Get the digest as a slice.
    pub fn digest_ref(&self) -> &[u8] { self.digest.as_ref() }

    /// Returns the number of bytes needed to encode this multihash.
    pub fn size(&self) -> usize {
        let len = self.len();
        varint::size(self.code()) +
        varint::size(len as u64) +
        len
    }

    /// Writes a multihash to a byte stream, returning the written size.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        varint::write(buf, self.code());
        varint::write(buf, self.len() as u64);
        buf.extend(self.digest().as_ref());
    }

    /// Returns the bytes of a multihash.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        self.encode(&mut bytes);
        bytes
    }
}

impl<'a> Multihash<&'a [u8]> {
    /// Wrap a digest slice into a multihash.
    pub fn wrap(code: u64, digest: &'a [u8]) -> Self {
        Self { code, digest }
    }
}

impl<D: DigestBuf> Multihash<D> {
    /// Try to copy the digest into a multihash.
    pub fn try_wrap(code: u64, digest: &[u8]) -> Result<Self, SizeError> {
        Ok(Self { code, digest: D::decode(digest)? })
    }

    /// Reads a multihash from a byte stream that contains a full multihash (code, size and the digest)
    pub fn decode(mut buf: &[u8]) -> Result<Self, DecodeError> {
        let code = varint::read(&mut buf)?;
        let len  = varint::read(&mut buf)? as usize;
        if len > D::MAX_LEN {
            Err(SizeError::Overflow.into())
        }
        else {
            Ok(Self { code, digest: D::decode(buf)? })
        }
    }
}

impl<D: Hash> Hash for Multihash<D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.code.hash(state);
        self.digest.hash(state);
    }
}

impl<A: AsRef<[u8]>, B: AsRef<[u8]>> PartialEq<Multihash<B>> for Multihash<A> {
    fn eq(&self, other: &Multihash<B>) -> bool {
        self.code() == other.code() && self.digest_ref() == other.digest_ref()
    }
}
impl<D: AsRef<[u8]>> Eq for Multihash<D> {}

impl<A: PartialOrd<B> + AsRef<[u8]>, B: PartialOrd<A> + AsRef<[u8]>> PartialOrd<Multihash<B>> for Multihash<A> {
    fn partial_cmp(&self, other: &Multihash<B>) -> Option<Ordering> {
        match self.code.partial_cmp(&other.code)? {
            Ordering::Equal => self.digest().partial_cmp(other.digest()),
            ord => Some(ord),
        }
    }
}
impl<D: Ord + AsRef<[u8]>> Ord for Multihash<D> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.code()
            .cmp(&other.code)
            .then_with(|| self.digest().cmp(other.digest()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_macro::hex;

    #[test]
    fn empty_multihash() {
        let mh1: Multihash<[u8; 32]> = MultihashFunc::Sha2_256
            .digest(b"")
            .expect("sha2-256 wrap");
        let mh2: Multihash<[u8; 32]> = MultihashFunc::Sha2_256.wrap(hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert_eq!(mh1, mh2);
    }

    //#[test]
    //fn encoding
}