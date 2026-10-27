use std::io;
use core::hash::Hash;

use digest::Digest;
use murmur3::murmur3_x64_128;
use num_enum::{TryFromPrimitive, IntoPrimitive};

use super::{Multihash, DigestBuf, SizeError};

pub trait MultihashCodec:
    TryFrom<u64> +
    Into<u64> +
    Send +
    Sync +
    Unpin +
    Copy +
    Eq +
    std::fmt::Debug +
    'static
{
    /// Get the hash function code.
    fn code(&self) -> u64 {
        (*self).into()
    }
}

/// A multihash codetable which can be used to generate multihashes.
pub trait MultihashDigest: MultihashCodec {
    /// Create a multihash using this hash function.
    fn digest<D: DigestBuf>(&self, input: &[u8]) -> Result<Multihash<D>, SizeError>;

    /// Wrap an existing digest with this hash function.
    fn wrap<D: AsRef<[u8]>>(&self, digest: D) -> Multihash<D> {
        Multihash::new(self.code(), digest)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("name not supported by this codetable")]
pub struct UnsupportedName;

fn sha2_256_trunc254_padded(src: &[u8]) -> [u8; 32] {
    let mut digest = sha2::Sha256::digest(src);
    let digest = digest
        .as_mut_array()
        .expect("sha2-256-trunc254-padded");
    digest[0] &= 0b0011_1111;
    *digest
}

fn murmur3_x64_64(src: &[u8]) -> [u8; 8] {
    let digest = murmur3_x64_128(&mut io::Cursor::new(src), 0)
        .expect("no error for io::Cursor Read");
    // The crate returns (h2 << 64) | h1, but murmur3-x64-64 is h1 alone
    // (what Go's murmur3.Sum64 returns), big-endian
    let mut buf = [0u8; _];
    buf.copy_from_slice(&digest.to_be_bytes()[8..]);
    buf
}

// Utility macro for building a code table.
macro_rules! build_codec_enum {
    {$( $name:ident => ($str:expr, $code:expr, $size:expr, $digest:expr), )*} => {
        /// Hash function multicodec code.
        #[allow(non_camel_case_types)]
        #[derive(PartialEq, Eq, Copy, Clone, Debug, Hash, TryFromPrimitive, IntoPrimitive)]
        #[repr(u64)]
        pub enum MultihashFunc { $( $name = $code, )* }

        impl MultihashFunc {
            const fn size_name(&self) -> (usize, &'static str) {
                match self { $( Self::$name => ($size, $str), )* }
            }
        }

        impl<'a> TryFrom<&'a str> for MultihashFunc {
            type Error = UnsupportedName;
            fn try_from(name: &'a str) -> Result<Self, Self::Error> {
                match name {
                    $( $str => Ok(Self::$name), )*
                    _ => Err(UnsupportedName),
                }
            }
        }

        impl MultihashDigest for MultihashFunc {
            fn digest<D: DigestBuf>(&self, input: &[u8]) -> Result<Multihash<D>, SizeError> {
                match self {
                    $( Self::$name => Ok(Multihash::new(
                        self.code(),
                        D::decode(($digest)(input).as_slice())?
                    )), )*
                }
            }
        }
    }
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    // uses digest 0.10.3, we have 0.11.3
    use blake2::{
        Blake2b,
        digest::Digest,
        digest::consts::U32,
    };
    type Blake2b256 = Blake2b<U32>;
    Blake2b256::digest(input).into()
}

// https://github.com/multiformats/multicodec/blob/master/table.csv
// All permanent multihash entries
build_codec_enum!(
    Sha1 => ("sha1", 0x11, 20, sha1::Sha1::digest),
    
    Sha2_224 => ("sha2-224", 0x1013, 28, sha2::Sha224::digest),
    Sha2_256 => ("sha2-256", 0x12, 32, sha2::Sha256::digest),
    Sha2_256_trunc254_padded => ("sha2-256-trunc254-padded", 0x1012, 32, sha2_256_trunc254_padded),
    Sha2_384 => ("sha2-384", 0x20, 48, sha2::Sha384::digest),
    Sha2_512 => ("sha2-512", 0x13, 64, sha2::Sha512::digest),
    Sha2_512_224 => ("sha2-512-224", 0x1014, 28, sha2::Sha512_224::digest),
    Sha2_512_256 => ("sha2-512-256", 0x1015, 32, sha2::Sha512_256::digest),

    Sha3_224 => ("sha3-224", 0x17, 28, sha3::Sha3_224::digest),
    Sha3_256 => ("sha3-256", 0x16, 32, sha3::Sha3_256::digest),
    Sha3_384 => ("sha3-384", 0x15, 48, sha3::Sha3_384::digest),
    Sha3_512 => ("sha3-512", 0x14, 64, sha3::Sha3_512::digest),

    Murmur3_x64_64 => ("murmur3-x64-64", 0x22, 8, murmur3_x64_64),
    Blake2b_256 => ("blake2b-256", 0xb220, 32, blake2b_256),
    // Poseidon_bls12_381_a2_fc1 => (0xb401, ), // FileCoin sealed proof, not generally H(bytes) -> digest, input is over elements
);

impl MultihashCodec for MultihashFunc {}

impl MultihashFunc {
    /// Get the size of the digest. Identity is variable so it returns None.
    pub const fn size(&self) -> usize { self.size_name().0 }

    /// Get the name of the hash function.
    pub const fn name(&self) -> &'static str { self.size_name().1 }
}

impl Into<&'static str> for MultihashFunc {
    fn into(self) -> &'static str { self.name() }
}