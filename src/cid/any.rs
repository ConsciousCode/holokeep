//! Implementations supporting concrete CIDs which preserve their version.
//! This is particularly helpful for code paths which require round-tripping
//! the link or for version-specific serialization.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use digest::Digest;
use serde::{ser, de};
use serde_bytes;

use crate::multihash::{DigestBuf, Multihash, MultihashDigest, MultihashFunc};

use super::{v0, CidVersion, BaseCid, CidRef, Cid, Cidv0, Cidv1, Cidv1Spec, DecodeError, FromStrError, RAW_CODEC, CID_SERDE_PRIVATE_IDENTIFIER};

#[derive(Debug, Clone)]
pub enum AnyCid<D> {
    V0(Cidv0<D>),
    V1(Cidv1<D>),
}

macro_rules! cid_call {
    ($self:ident . $method:ident ( $($rest:expr),* ) ) => {
        match $self {
            AnyCid::V0(cid) => cid.$method($($rest),*),
            AnyCid::V1(cid) => cid.$method($($rest),*),
        }
    };
}

// Utility method to cut down on DRY dispatching to the wrapped CID structs.
macro_rules! cid_dispatch {
    ($(
        $(#[$attr:meta])*
        $vis:vis fn $method:ident (
            &self $(, $arg:ident : $type:ty )*
        ) $(-> $ret:ty)? ;
    )*) => {$(
        $(#[$attr])*
        $vis fn $method(&self $(, $arg : $type )*) $(-> $ret)* {
            cid_call!(self.$method($($arg),*))
        }
    )*}
}

//--------------------//
//-[ Inherent impls ]-//
//--------------------//

impl<D: AsRef<[u8]>> AnyCid<D> {
    /// Get an `AnyCid` borrowing the digest.
    pub fn as_ref(&self) -> AnyCid<&[u8]> {
        match self {
            Self::V0(v) => AnyCid::V0(v.as_ref()),
            Self::V1(v) => AnyCid::V1(v.as_ref()),
        }
    }
}

//---------------//
//-[ Cid impls ]-//
//---------------//

impl<D> BaseCid for AnyCid<D> {
    cid_dispatch! {
        fn version(&self) -> CidVersion;
        fn codec(&self) -> u64;
        fn hashcode(&self) -> u64;
    }
}

impl<D: AsRef<[u8]>> CidRef for AnyCid<D> {
    cid_dispatch! {
        fn digest_ref(&self) -> &[u8];
        fn multihash(&self) -> Multihash<&[u8]>;
        fn to_bytes(&self) -> Vec<u8>;
        fn size(&self) -> usize;
        fn encode(&self, buf: &mut Vec<u8>);
    }
}

impl<D: DigestBuf> Cid<D> for AnyCid<D> {
    fn digest(&self) -> &D {
        cid_call!(self.digest())
    }
    
    fn into_digest(self) -> D {
        cid_call!(self.into_digest())
    }

    fn into_multihash(self) -> Multihash<D> {
        cid_call!(self.into_multihash())
    }

    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        const HASH_CODE: u8 = v0::HASH_BYTE;

        // Peek first byte to branch between V0 (0x12) and V1 (0x01)
        match buf.first() {
            Some(&HASH_CODE) => Ok(Self::V0(Cidv0::decode(buf)?)),
            Some(0x01) => Ok(Self::V1(Cidv1::decode(buf)?)),
            Some(_) => Err(DecodeError::Version),
            None => Err(DecodeError::Truncated),
        }
    }
}

//-----------------//
//-[ Trait impls ]-//
//-----------------//

/// Cidv0 -> `AnyCid`
impl<D> From<Cidv0<D>> for AnyCid<D> {
    fn from(cid: Cidv0<D>) -> Self {
        Self::V0(cid)
    }
}

/// Cidv1 -> `AnyCid`
impl<D> From<Cidv1<D>> for AnyCid<D> {
    fn from(cid: Cidv1<D>) -> Self {
        Self::V1(cid)
    }
}

/// `AnyCid` -> Cidv0
impl<D: DigestBuf> TryFrom<AnyCid<D>> for Cidv0<D> {
    type Error = DecodeError;

    fn try_from(value: AnyCid<D>) -> Result<Self, Self::Error> {
        match value {
            AnyCid::V0(c) => Ok(c),
            AnyCid::V1(c) => c
                .try_into()
                .map_err(|_| DecodeError::Version),
        }
    }
}

impl<D: DigestBuf> From<AnyCid<D>> for Cidv1<D> {
    fn from(value: AnyCid<D>) -> Self {
        cid_call!(value.into())
    }
}

/// str -> `AnyCid`
impl<D: DigestBuf> FromStr for AnyCid<D> {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // CIDv0 strings are always raw base58btc without multibase prefixes (Qm...)
        if s.starts_with("Qm") && s.len() == 46 {
            return Ok(Self::V0(s.parse()?));
        }

        // Anything else is a multibase CIDv1. The spec forbids multibase
        // CIDv0, which Cidv1::decode rejects by its version byte.
        let (_, raw) = multibase::decode(s)?;
        Ok(Self::V1(Cidv1::decode(&raw)?))
    }
}

/// `AnyCid` -> String
impl<D: AsRef<[u8]>> fmt::Display for AnyCid<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cid_call!(self.fmt(f))
    }
}

impl<A: AsRef<[u8]>, B: AsRef<[u8]>> PartialEq<AnyCid<B>> for AnyCid<A> {
    fn eq(&self, other: &AnyCid<B>) -> bool {
        self.codec() == other.codec() && self.multihash() == other.multihash()
    }
}
impl<D: AsRef<[u8]>> Eq for AnyCid<D> {}

//---------------//
//-[ Utilities ]-//
//---------------//

/// A utility struct reifying the specification to build a CID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidSpec<H: MultihashDigest=MultihashFunc> {
    V0,
    V1(Cidv1Spec<H>),
}

impl<H: MultihashDigest> CidSpec<H> {
    /// Create a new CID specification.
    pub fn new(version: CidVersion, codec: u64, hashcode: H) -> Option<Self> {
        const HASH_CODE: u64 = v0::HASH_CODE;
        match (version, codec, hashcode.code()) {
            (CidVersion::V0, v0::CODEC, HASH_CODE) => Some(Self::V0),
            (CidVersion::V0, ..) => None,
            (CidVersion::V1, codec, _) => Some(
                Self::V1(Cidv1Spec::new(codec, hashcode))
            ),
        }
    }

    /// Create a CID from the spec and data.
    ///
    /// # Panics
    ///
    /// If `D` can't hold the digest, which is a choice of types rather than
    /// of data: the largest the codetable makes is 64 bytes.
    #[allow(clippy::expect_used)]
    pub fn hash<D: DigestBuf>(&self, data: &[u8]) -> AnyCid<D> {
        match self {
            Self::V0 => AnyCid::V0(Cidv0::new(
                D::decode(&sha2::Sha256::digest(data))
                    .expect("CIDv0 digest backing big enough")
            )),
            Self::V1(spec) => AnyCid::V1(spec.hash(data)),
        }
    }

    /// Get the CID's version.
    pub const fn version(&self) -> CidVersion {
        match self {
            Self::V0 => CidVersion::V0,
            Self::V1(..) => CidVersion::V1,
        }
    }

    /// Get the CID's codec.
    pub const fn codec(&self) -> u64 {
        match self {
            Self::V0 => v0::CODEC,
            Self::V1(spec, ..) => spec.codec(),
        }
    }

    /// Get the CID's hash code.
    pub fn hashcode(&self) -> u64 {
        match self {
            Self::V0 => v0::HASH_CODE,
            Self::V1(spec) => spec.hashcode(),
        }
    }
}

impl Default for CidSpec<MultihashFunc> {
    fn default() -> Self {
        Self::V1(Cidv1Spec::new(RAW_CODEC, MultihashFunc::Sha2_256))
    }
}

//-----------//
//-[ Serde ]-//
//-----------//

pub struct AnyCidVisitor<D>(PhantomData<D>);

impl<'de, D: DigestBuf> de::Visitor<'de> for AnyCidVisitor<D> {
    type Value = AnyCid<D>;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "a valid CID in bytes")
    }

    /// IPLD codecs wrap CIDs in a newtype named `CID_SERDE_PRIVATE_IDENTIFIER`
    /// whose contents are the binary CID.
    fn visit_newtype_struct<De: de::Deserializer<'de>>(self, d: De) -> Result<Self::Value, De::Error> {
        d.deserialize_bytes(self)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where E: de::Error
    {
        AnyCid::decode(value)
            .map_err(|err| E::custom(
                format!("Failed to deserialize CID: {err}")
            ))
    }

    /// Some Serde data formats interpret a byte stream as a sequence of bytes (e.g. `serde_json`).
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        AnyCid::decode(&bytes)
            .map_err(|err| de::Error::custom(
                format!("Failed to deserialize CID: {err}")
            ))
    }
}

impl<D: AsRef<[u8]>> ser::Serialize for AnyCid<D> {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            serde_bytes::Bytes::new(&self.to_bytes())
        )
    }
}

impl<'de, D: DigestBuf> de::Deserialize<'de> for AnyCid<D> {
    fn deserialize<De: de::Deserializer<'de>>(d: De) -> Result<Self, De::Error> {
        d.deserialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            AnyCidVisitor(PhantomData)
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::DAG_PB_CODEC;
    use crate::multihash::Inline;

    const EMPTY_DIR: &[u8] = &[0x0a, 0x02, 0x08, 0x01];
    const EMPTY_DIR_V0: &str = "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn";
    const EMPTY_DIR_V1: &str = "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354";
    const HELLO: &str = "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e";

    type Any = AnyCid<Inline<64>>;

    #[test]
    fn parse_keeps_version() {
        let v0: Any = EMPTY_DIR_V0.parse().expect("v0");
        let v1: Any = EMPTY_DIR_V1.parse().expect("v1");
        assert_eq!(v0.version(), CidVersion::V0);
        assert_eq!(v1.version(), CidVersion::V1);
        assert_eq!(v0.to_string(), EMPTY_DIR_V0);
        assert_eq!(v1.to_string(), EMPTY_DIR_V1);
        assert_eq!(v0.size(), 34);
        assert_eq!(v1.size(), 36);
        // The spec forbids multibase-encoding CIDv0
        assert!(format!("z{EMPTY_DIR_V0}").parse::<Any>().is_err());
    }

    #[test]
    fn decode_keeps_version() {
        for s in [EMPTY_DIR_V0, EMPTY_DIR_V1, HELLO] {
            let cid: Any = s.parse().expect(s);
            let back = Any::decode(&cid.to_bytes()).expect(s);
            assert_eq!(back.version(), cid.version(), "{s}");
            assert_eq!(back.to_string(), s);
        }
        assert!(matches!(Any::decode(&[]), Err(DecodeError::Truncated)));
        assert!(matches!(Any::decode(&[0x02, 0x55]), Err(DecodeError::Version)));
    }

    #[test]
    fn equality_is_by_content() {
        let v0: Any = EMPTY_DIR_V0.parse().expect("v0");
        let v1: Any = EMPTY_DIR_V1.parse().expect("v1");
        let hello: Any = HELLO.parse().expect("hello");
        assert_eq!(v0, v1);
        assert_ne!(v1, hello);
        // Same codec, different digest
        let other = CidSpec::<MultihashFunc>::V0.hash::<Inline<64>>(b"other");
        assert_ne!(v0, other);
    }

    #[test]
    fn conversions() {
        let v1: Any = EMPTY_DIR_V1.parse().expect("v1");
        assert_eq!(Cidv0::try_from(v1.clone()).expect("downgrade").to_string(), EMPTY_DIR_V0);
        assert_eq!(Cidv1::from(v1).to_string(), EMPTY_DIR_V1);

        let v0: Any = EMPTY_DIR_V0.parse().expect("v0");
        assert_eq!(Cidv1::from(v0).to_string(), EMPTY_DIR_V1);

        let hello: Any = HELLO.parse().expect("hello");
        assert!(matches!(Cidv0::try_from(hello), Err(DecodeError::Version)));
    }

    #[test]
    fn spec() {
        use MultihashFunc::{Sha2_256, Sha2_512};
        assert_eq!(CidSpec::new(CidVersion::V0, DAG_PB_CODEC, Sha2_256), Some(CidSpec::V0));
        assert_eq!(CidSpec::new(CidVersion::V0, RAW_CODEC, Sha2_256), None);
        assert_eq!(CidSpec::new(CidVersion::V0, DAG_PB_CODEC, Sha2_512), None);
        assert_eq!(
            CidSpec::new(CidVersion::V1, RAW_CODEC, Sha2_256),
            Some(CidSpec::default())
        );

        assert_eq!(CidSpec::<MultihashFunc>::V0.hash::<Inline<64>>(EMPTY_DIR).to_string(), EMPTY_DIR_V0);
        assert_eq!(CidSpec::default().hash::<Inline<64>>(b"hello world").to_string(), HELLO);
        assert_eq!(CidSpec::<MultihashFunc>::V0.codec(), DAG_PB_CODEC);
        assert_eq!(CidSpec::<MultihashFunc>::V0.hashcode(), 0x12);
        assert_eq!(CidSpec::default().version(), CidVersion::V1);
    }
}
