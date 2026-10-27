//! CIDv1-specific implementations.

use std::marker::PhantomData;
use std::str::FromStr;
use std::fmt;

use multibase::Base;
use serde::{ser, de};
use serde_bytes;

use crate::cid::BaseCid;
use crate::multihash::{DigestBuf, Inline, Multihash, MultihashDigest, MultihashFunc};
use crate::varint;

use super::{v0, DecodeError, CidVersion, CidRef, Cid, Cidv0, FromStrError, RAW_CODEC, DAG_PB_CODEC, CID_SERDE_PRIVATE_IDENTIFIER};

/// A concrete IPLD CIDv1 implementation.
#[derive(Clone, Debug)]
pub struct Cidv1<D=Inline<64>> {
    codec: u64,
    hash: Multihash<D>,
}

type X = Box<Cidv1<[u8]>>;

//--------------------//
//-[ Inherent impls ]-//
//--------------------//

impl<D> Cidv1<D> {
    /// Create a new CIDv1 from a codec and multihash.
    pub fn new(codec: u64, hash: Multihash<D>) -> Self {
        Self { codec, hash }
    }
}

impl<D: AsRef<[u8]>> Cidv1<D> {
    pub fn as_ref(&self) -> Cidv1<&[u8]> {
        Cidv1::wrap(self.codec(), self.hash.as_ref())
    }
}

//---------------//
//-[ Cid impls ]-//
//---------------//

impl<D> BaseCid for Cidv1<D> {
    fn version(&self) -> CidVersion { CidVersion::V1 }
    fn codec(&self) -> u64 { self.codec }
    fn hashcode(&self) -> u64 { self.hash.code() }
}

impl<D: AsRef<[u8]>> CidRef for Cidv1<D> {
    fn digest_ref(&self) -> &[u8] { self.hash.digest_ref() }
    fn size(&self) -> usize { varint::size(self.codec) + self.hash.size() }
    fn multihash(&self) -> Multihash<&[u8]> { self.hash.as_ref() }

    /// Write the CID to an arbitrary buffer.
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(1);
        varint::write(buf, self.codec());
        self.hash.encode(buf);
    }
}

impl<'a> Cidv1<&'a [u8]> {
    pub fn wrap(codec: u64, hash: Multihash<&'a [u8]>) -> Self {
        Self { codec, hash }
    }
}

impl<D: DigestBuf> Cid<D> for Cidv1<D> {
    fn digest(&self) -> &D { self.hash.digest() }
    fn into_multihash(self) -> Multihash<D> { self.hash }
    fn into_digest(self) -> D { self.hash.into_digest() }

    fn decode(mut bytes: &[u8]) -> Result<Cidv1<D>, DecodeError> {
        match bytes.split_off_first() {
            Some(&0x01) => {
                let codec = varint::read(&mut bytes)?;
                let hash = Multihash::decode(&mut bytes)?;
                Ok(Self { codec, hash })
            },
            Some(_) => Err(DecodeError::Truncated),
            None => Err(DecodeError::Version),
        }
    }
}

//-----------------//
//-[ Trait impls ]-//
//-----------------//

impl<D: AsRef<[u8]>> fmt::Display for Cidv1<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&multibase::encode(Base::Base32Lower, self.to_bytes()))
    }
}

impl<D: AsRef<[u8]>> From<Cidv1<D>> for Multihash<D> {
    fn from(value: Cidv1<D>) -> Self { value.hash }
}

impl<D: DigestBuf> FromStr for Cidv1<D> {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match multibase::decode(s)? {
            (Base::Base58Btc, raw) if raw.len() == 34 => {
                Ok(Self {
                    codec: DAG_PB_CODEC,
                    hash: Multihash::decode(&mut raw.as_slice())
                        .map_err(DecodeError::from)?
                })
            },
            (_, raw) => Ok(Self::decode(&raw)?),
        }
    }
}

impl<D: DigestBuf> TryFrom<Cidv1<D>> for Cidv0<D> {
    type Error = Cidv1<D>;

    fn try_from(value: Cidv1<D>) -> Result<Self, Self::Error> {
        if value.codec() == DAG_PB_CODEC && value.hashcode() == v0::HASH_CODEC as u64 {
            Ok(Cidv0::new(value.hash.into_digest()))
        }
        else {
            Err(value)
        }
    }
}

impl<A: AsRef<[u8]>, B: AsRef<[u8]>> PartialEq<Cidv1<B>> for Cidv1<A> {
    fn eq(&self, other: &Cidv1<B>) -> bool {
        self.codec == other.codec && self.multihash() == other.multihash()
    }
}
impl<D: AsRef<[u8]>> Eq for Cidv1<D> {}

//---------------//
//-[ Utilities ]-//
//---------------//

/// A utility struct reifying the specification to build a CIDv1.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Cidv1Spec<H: MultihashDigest=MultihashFunc> {
    codec: u64,
    hash: H
}

impl<H: MultihashDigest> Cidv1Spec<H> {
    pub fn new(codec: u64, hash: H) -> Self {
        Self { codec, hash }
    }

    pub fn from_cid<D: AsRef<[u8]>>(cid: &Cidv1<D>) -> Option<Self> {
        Some(Self {
            codec: cid.codec(),
            hash: cid.hashcode().try_into().ok()?
        })
    }

    pub fn version(&self) -> CidVersion { CidVersion::V1 }
    pub fn codec(&self) -> u64 { self.codec }
    pub fn hashcode(&self) -> u64 { self.hash.code() }

    pub fn hash<D: DigestBuf>(&self, data: &[u8]) -> Cidv1<D> {
        Cidv1::new(self.codec,
            self.hash.digest(data)
                .expect("CIDv1 digest backing big enough")
        )
    }
}

impl Default for Cidv1Spec<MultihashFunc> {
    fn default() -> Self {
        Self::new(RAW_CODEC, MultihashFunc::Sha2_256)
    }
}

//-----------//
//-[ Serde ]-//
//-----------//

// DigestBuf //

struct DigestBufVisitor<D>(PhantomData<D>);

impl<'de, D: DigestBuf> de::Visitor<'de> for DigestBufVisitor<D> {
    type Value = Cidv1<D>;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "a valid CIDv1 in bytes")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where E: de::Error
    {
        Self::Value::decode(value)
            .map_err(|err| E::custom(
                format!("Failed to deserialize CIDv1: {err}")
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
                format!("Failed to deserialize CIDv1: {err}")
            ))
    }
}

impl<D: AsRef<[u8]>> ser::Serialize for Cidv1<D> {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            serde_bytes::Bytes::new(&self.to_bytes())
        )
    }
}

impl<'de, D: DigestBuf> de::Deserialize<'de> for Cidv1<D> {
    fn deserialize<De: de::Deserializer<'de>>(d: De) -> Result<Self, De::Error> {
        d.deserialize_newtype_struct(
            CID_SERDE_PRIVATE_IDENTIFIER,
            DigestBufVisitor(PhantomData)
        )
    }
}
