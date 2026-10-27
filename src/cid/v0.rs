//! CIDv0-specific implementations.

use std::borrow::Cow;
use std::marker::PhantomData;
use std::str::FromStr;
use std::fmt;

use multibase::Base;
use serde::{ser, de};
use serde_bytes;

use crate::cid::BaseCid;
use crate::multihash::{DigestBuf, Multihash, MultihashFunc};
use crate::varint;

use super::{CidVersion, CidRef, Cid, Cidv1, DecodeError, FromStrError, DAG_PB_CODEC, CID_SERDE_PRIVATE_IDENTIFIER};

pub const CODEC: u64 = DAG_PB_CODEC;
pub const HASH_CODEC: MultihashFunc = MultihashFunc::Sha2_256;

/// A concrete CIDv0 implemenetation.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Cidv0<D=[u8; 32]> {
    digest: D,
}

//--------------------//
//-[ Inherent impls ]-//
//--------------------//

impl<D: Sized> Cidv0<D> {
    pub fn new(digest: D) -> Self {
        Self { digest }
    }
}

impl<D: AsRef<[u8]>> Cidv0<D> {
    pub fn as_ref(&self) -> Cidv0<&[u8]> {
        Cidv0::new(self.digest.as_ref())
    }
}

//---------------//
//-[ Cid impls ]-//
//---------------//

impl<D> BaseCid for Cidv0<D> {
    fn version(&self) -> CidVersion { CidVersion::V0 }
    fn codec(&self) -> u64 { CODEC }
    fn hashcode(&self) -> u64 { HASH_CODEC as u64 }
}

impl<D: AsRef<[u8]>> CidRef for Cidv0<D> {
    fn digest_ref(&self) -> &[u8] {
        self.digest.as_ref()
    }

    fn size(&self) -> usize { 34 }

    fn multihash(&self) -> Multihash<&[u8]> {
        Multihash::wrap(self.hashcode(), self.digest.as_ref())
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        // CIDv0 is just a bare sha2-256 multihash
        buf.push(HASH_CODEC as u8);
        varint::write(buf, HASH_CODEC.size() as u64);
        buf.extend(self.digest.as_ref());
    }
}

impl<D: DigestBuf> Cid<D> for Cidv0<D> {
    fn digest(&self) -> &D { &self.digest }

    fn into_digest(self) -> D { self.digest }
    
    fn into_multihash(self) -> Multihash<D> {
        Multihash::new(self.hashcode(), self.into_digest())
    }

    fn decode(mut buf: &[u8]) -> Result<Self, DecodeError> {
        const CIDV0_HASH_U8: u8 = HASH_CODEC as u8;
        match buf.split_off_first() {
            Some(&CIDV0_HASH_U8) if varint::read(&mut buf)? == 32 =>
                Ok(Self { digest: D::decode(buf)? }),
            Some(&CIDV0_HASH_U8) => Err(DecodeError::Parse),
            Some(_) => Err(DecodeError::Version),
            None => Err(DecodeError::Truncated),
        }
    }
}

//-----------------//
//-[ Trait impls ]-//
//-----------------//

/// Cidv0 -> Multihash
impl<D: DigestBuf> From<Cidv0<D>> for Multihash<D> {
    fn from(value: Cidv0<D>) -> Self {
        Multihash::new(value.hashcode(), value.digest)
    }
}

/// Cidv0 -> Cidv1
impl<D: DigestBuf> From<Cidv0<D>> for Cidv1<D> {
    fn from(value: Cidv0<D>) -> Self {
        Cidv1::new(
            value.codec(),
            Multihash::new(value.hashcode(), value.digest)
        )
    }
}

/// str -> Cidv0
impl<D: DigestBuf> FromStr for Cidv0<D> {
    type Err = FromStrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (base, raw) = multibase::decode(s)?;

        if base == multibase::Base::Base58Btc {
            Ok(Self::decode(&raw)?)
        }
        else {
            Err(DecodeError::Version.into())
        }
    }
}

/// Cidv0 -> String
impl<D: AsRef<[u8]>> fmt::Display for Cidv0<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Base::Base58Btc.encode(self.to_bytes()))
    }
}

//-----------//
//-[ Serde ]-//
//-----------//

// DigestBuf //

struct DigestBufVisitor<D>(PhantomData<D>);

impl<'de, D: DigestBuf> de::Visitor<'de> for DigestBufVisitor<D> {
    type Value = Cidv0<D>;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "a valid CIDv0 in bytes")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where E: de::Error
    {
        Self::Value::decode(value)
            .map_err(|err| E::custom(
                format!("Failed to deserialize CIDv0: {err}")
            ))
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where E: de::Error
    {
        self.visit_bytes(v)
    }

    /// Some Serde data formats interpret a byte stream as a sequence of bytes (e.g. `serde_json`).
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where A: de::SeqAccess<'de>
    {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Self::Value::decode(&bytes)
            .map_err(|err| de::Error::custom(
                format!("Failed to deserialize CIDv0: {err}")
            ))
    }
}

impl<D: AsRef<[u8]>> ser::Serialize for Cidv0<D> {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            serde_bytes::Bytes::new(&self.to_bytes())
        )
    }
}

impl<'de, D: DigestBuf> de::Deserialize<'de> for Cidv0<D> {
    fn deserialize<De: de::Deserializer<'de>>(d: De) -> Result<Self, De::Error> {
        d.deserialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            DigestBufVisitor(PhantomData)
        )
    }
}

// Borrowed [u8] //

struct BorrowedVisitor;

impl<'de> de::Visitor<'de> for BorrowedVisitor {
    type Value = Cidv0<&'de [u8]>;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "a valid CIDv0 in bytes")
    }

    fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
    where E: de::Error
    {
        Ok(Self::Value::new(value))
    }
}

impl<'de> de::Deserialize<'de> for Cidv0<&'de [u8]> {
    fn deserialize<De: de::Deserializer<'de>>(d: De) -> Result<Self, De::Error> {
        d.deserialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            BorrowedVisitor,
        )
    }
}

// Cow //

struct CowVisitor;

impl<'de> de::Visitor<'de> for CowVisitor {
    type Value = Cidv0<Cow<'de, [u8]>>;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "a valid CIDv0 in bytes")
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where E: de::Error,
    {
        Ok(Self::Value::new(Cow::Borrowed(v)))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where E: de::Error,
    {
        Ok(Self::Value::new(Cow::Owned(v)))
    }

    /// Some Serde data formats interpret a byte stream as a sequence of bytes (e.g. `serde_json`).
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where A: de::SeqAccess<'de>,
    {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(Self::Value::new(Cow::Owned(bytes)))
    }
}

impl<'de> de::Deserialize<'de> for Cidv0<Cow<'de, [u8]>> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where D: de::Deserializer<'de>
    {
        d.deserialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            CowVisitor
        )
    }
}