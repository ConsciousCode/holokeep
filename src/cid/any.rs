//! Implementations supporting concrete CIDs which preserve their version.
//! This is particularly helpful for code paths which require round-tripping
//! the link or for version-specific serialization.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use digest::Digest;
use multibase::Base;
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
    /// Get an AnyCid borrowing the digest.
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

    fn decode(mut buf: &[u8]) -> Result<Self, DecodeError> {
        const HASH_CODE: u8 = v0::HASH_CODEC as u8;

        // Peek first byte to branch between V0 (0x12) and V1 (0x01)
        match buf.split_off_first() {
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

/// Cidv0 -> AnyCid
impl<D> From<Cidv0<D>> for AnyCid<D> {
    fn from(cid: Cidv0<D>) -> Self {
        Self::V0(cid)
    }
}

/// Cidv1 -> AnyCid
impl<D> From<Cidv1<D>> for AnyCid<D> {
    fn from(cid: Cidv1<D>) -> Self {
        Self::V1(cid)
    }
}

/// AnyCid -> Cidv0
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

/// str -> AnyCid
impl<D: DigestBuf> FromStr for AnyCid<D> {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // CIDv0 strings are always raw base58btc without multibase prefixes (Qm...)
        if s.starts_with("Qm") && s.len() == 46 {
            let (_, raw) = multibase::decode(format!("z{s}"))?;
            let cid = Cidv0::decode(&raw)?;
            return Ok(Self::V0(cid));
        }

        // Multibase encoded CIDs
        let (base, raw) = multibase::decode(s)?;
        if base == Base::Base58Btc && raw.len() == 34 {
            Ok(Self::V0(Cidv0::decode(&raw)?))
        }
        else {
            Ok(Self::V1(Cidv1::decode(&raw)?))
        }
    }
}

/// AnyCid -> String
impl<D: AsRef<[u8]>> fmt::Display for AnyCid<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        cid_call!(self.fmt(f))
    }
}

impl<A: AsRef<[u8]>, B: AsRef<[u8]>> PartialEq<AnyCid<B>> for AnyCid<A> {
    fn eq(&self, other: &AnyCid<B>) -> bool {
        self.codec() == other.codec() && self.multihash() == self.multihash()
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
        const HASH_CODE: u64 = v0::HASH_CODEC as u64;
        match (version, codec, hashcode.code()) {
            (CidVersion::V0, v0::CODEC, HASH_CODE) => Some(Self::V0),
            (CidVersion::V0, ..) => None,
            (CidVersion::V1, codec, _) => Some(
                Self::V1(Cidv1Spec::new(codec, hashcode))
            ),
        }
    }

    /// Create a CID from the spec and data.
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
    pub fn version(&self) -> CidVersion {
        match self {
            Self::V0 => CidVersion::V0,
            Self::V1(..) => CidVersion::V1,
        }
    }

    /// Get the CID's codec.
    pub fn codec(&self) -> u64 {
        match self {
            Self::V0 => v0::CODEC,
            Self::V1(spec, ..) => spec.codec(),
        }
    }

    /// Get the CID's hash code.
    pub fn hashcode(&self) -> u64 {
        match self {
            Self::V0 => v0::HASH_CODEC as u64,
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