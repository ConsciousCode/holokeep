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
            varint::Error::Overflow | varint::Error::NonMinimal => Self::Parse,
        }
    }
}

/// An IPLD multihash, encoding the digest along with the hash function used
/// to generate it.
#[derive(Clone, Copy, Debug)]
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
        let code = varint::read_minimal(&mut buf)?;
        let len = usize::try_from(varint::read_minimal(&mut buf)?)
            .map_err(|_| SizeError::Overflow)?;
        if len > D::MAX_LEN {
            return Err(SizeError::Overflow.into());
        }
        match buf.len().cmp(&len) {
            Ordering::Less => Err(DecodeError::Truncated),
            Ordering::Greater => Err(DecodeError::Parse),
            Ordering::Equal => Ok(Self { code, digest: D::decode(buf)? }),
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

    /// Check a function's digest of "abc" against an independent
    /// implementation (Python's hashlib and mmh3).
    fn check<const N: usize>(func: MultihashFunc, input: &[u8], expected: [u8; N]) {
        let mh: Multihash<[u8; N]> = func.digest(input).expect(func.name());
        assert_eq!(mh.code(), u64::from(func));
        assert_eq!(*mh.digest(), expected, "{}", func.name());
        assert_eq!(func.size(), N, "{}", func.name());
        assert_eq!(MultihashFunc::try_from(func.name()).ok(), Some(func));
        assert_eq!(MultihashFunc::try_from(func.code()).ok(), Some(func));
    }

    #[test]
    fn digest_vectors() {
        use MultihashFunc::*;
        check(Sha1, b"abc", hex!("a9993e364706816aba3e25717850c26c9cd0d89d"));
        check(Sha2_224, b"abc", hex!("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
        check(Sha2_256, b"abc", hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        check(Sha2_384, b"abc", hex!("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
        check(Sha2_512, b"abc", hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
        check(Sha2_512_224, b"abc", hex!("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"));
        check(Sha2_512_256, b"abc", hex!("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"));
        check(Sha3_224, b"abc", hex!("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"));
        check(Sha3_256, b"abc", hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
        check(Sha3_384, b"abc", hex!("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"));
        check(Sha3_512, b"abc", hex!("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
        check(Blake2b_256, b"abc", hex!("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"));
        // sha2-256 with the top two bits cleared
        check(Sha2_256_trunc254_padded, b"abc", hex!("3a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        // h1 of murmur3-x64-128, big-endian, as Go's murmur3.Sum64
        check(Murmur3_x64_64, b"", hex!("0000000000000000"));
        check(Murmur3_x64_64, b"hello", hex!("cbd8a7b341bd9b02"));
        check(Murmur3_x64_64, b"entry-1.txt", hex!("dde36f58fc157797"));
    }

    #[test]
    fn unknown_functions() {
        assert!(MultihashFunc::try_from("md5").is_err());
        assert!(MultihashFunc::try_from(0xd5u64).is_err());
    }

    fn empty_sha256() -> Vec<u8> {
        let mut bytes = vec![0x12, 0x20];
        bytes.extend(hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        bytes
    }

    #[test]
    fn encode() {
        let mh: Multihash<[u8; 32]> = MultihashFunc::Sha2_256.digest(b"").expect("digest");
        assert_eq!(mh.to_bytes(), empty_sha256());
        assert_eq!(mh.size(), 34);
        assert_eq!(mh.len(), 32);

        // Codes above 127 take a multi-byte varint
        let mh: Multihash<[u8; 32]> = MultihashFunc::Blake2b_256.digest(b"").expect("digest");
        let bytes = mh.to_bytes();
        assert_eq!(bytes[..4], [0xa0, 0xe4, 0x02, 0x20]);
        assert_eq!(bytes.len(), mh.size());
    }

    #[test]
    fn decode_backings() {
        let bytes = empty_sha256();
        let array: Multihash<[u8; 32]> = Multihash::decode(&bytes).expect("array");
        let inline: Multihash = Multihash::decode(&bytes).expect("inline");
        let vec: Multihash<Vec<u8>> = Multihash::decode(&bytes).expect("vec");
        let boxed: Multihash<Box<[u8]>> = Multihash::decode(&bytes).expect("box");

        assert_eq!(array.code(), 0x12);
        assert_eq!(array, inline);
        assert_eq!(inline, vec);
        assert_eq!(vec, boxed);
        assert_eq!(boxed.as_ref(), Multihash::wrap(0x12, &bytes[2..]));
        assert_eq!(inline.to_bytes(), bytes);
    }

    #[test]
    fn decode_errors() {
        let bytes = empty_sha256();
        let decode = Multihash::<Vec<u8>>::decode;

        assert!(matches!(decode(&[]), Err(DecodeError::Truncated)));
        assert!(matches!(decode(&bytes[..1]), Err(DecodeError::Truncated)));
        assert!(matches!(decode(&bytes[..33]), Err(DecodeError::Truncated)));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(decode(&trailing), Err(DecodeError::Parse)));

        // Too big for the backing is caught from the length alone
        assert!(matches!(
            Multihash::<Inline<16>>::decode(&bytes),
            Err(DecodeError::Size(SizeError::Overflow))
        ));
        assert!(matches!(
            Multihash::<[u8; 20]>::decode(&bytes),
            Err(DecodeError::Size(SizeError::Overflow))
        ));
        // Fixed arrays need exactly their size
        assert!(matches!(
            Multihash::<[u8; 64]>::decode(&bytes),
            Err(DecodeError::Size(SizeError::Mismatch))
        ));
    }

    #[test]
    fn try_wrap() {
        let digest = [7u8; 32];
        let mh = Multihash::<Inline<64>>::try_wrap(0x12, &digest).expect("fits");
        assert_eq!(mh.digest_ref(), digest);
        assert!(Multihash::<Inline<16>>::try_wrap(0x12, &digest).is_err());
        assert!(Multihash::<[u8; 31]>::try_wrap(0x12, &digest).is_err());
    }

    #[test]
    fn ordering() {
        let a = Multihash::new(0x12, [0u8; 2]);
        let b = Multihash::new(0x12, [1u8; 2]);
        let c = Multihash::new(0x13, [0u8; 2]);
        // Code first, then digest
        assert!(a < b);
        assert!(b < c);
        assert_ne!(a, c);
    }
}