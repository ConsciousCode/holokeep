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

use super::{v0, AnyCid, DecodeError, CidVersion, CidRef, Cid, Cidv0, FromStrError, RAW_CODEC, DAG_PB_CODEC, CID_SERDE_PRIVATE_IDENTIFIER};

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
    fn size(&self) -> usize { 1 + varint::size(self.codec) + self.hash.size() }
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
            Some(_) => Err(DecodeError::Version),
            None => Err(DecodeError::Truncated),
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
        // Accepts CIDv0 strings too, upgrading them
        Ok(s.parse::<AnyCid<D>>()?.into())
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

    /// IPLD codecs wrap CIDs in a newtype named CID_SERDE_PRIVATE_IDENTIFIER
    /// whose contents are the binary CID.
    fn visit_newtype_struct<De: de::Deserializer<'de>>(self, d: De) -> Result<Self::Value, De::Error> {
        d.deserialize_bytes(self)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::{Deserialize, value::{BytesDeserializer, Error as ValueError}};

    // `printf 'hello world' | ipfs add -n` and `ipfs cid format -b ...`
    const HELLO: &str = "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e";
    const HELLO_BASES: [&str; 3] = [
        "k2cwued9o1pvrt3q271rrqbo49x30tbxwpoeaq75z14e5ui2rzygpbe1",
        "zb2rhj7crUKTQYRGCRATFaQ6YFLTde2YzdqbbhAASkL9uRDXn",
        "BAFKREIFZJUT3TE2NHYEKKLSS27NH3K72YSCO7Y32KOAO5EEI66WOF36N5E",
    ];
    // An empty UnixFS directory, as CIDv0 and CIDv1
    const EMPTY_DIR_V0: &str = "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn";
    const EMPTY_DIR_V1: &str = "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354";

    fn hello() -> Cidv1 {
        Cidv1Spec::default().hash(b"hello world")
    }

    #[test]
    fn display_and_parse() {
        let cid = hello();
        assert_eq!(cid.to_string(), HELLO);
        for s in [HELLO].iter().chain(&HELLO_BASES) {
            assert_eq!(s.parse::<Cidv1>().expect(s), cid, "{s}");
        }
        assert!("not a cid".parse::<Cidv1>().is_err());
    }

    #[test]
    fn bytes_round_trip() {
        let cid = hello();
        let bytes = cid.to_bytes();
        assert_eq!(bytes.len(), cid.size());
        assert_eq!(bytes.len(), 36);
        assert_eq!(bytes[..4], [0x01, 0x55, 0x12, 0x20]);
        assert_eq!(Cidv1::<Inline<64>>::decode(&bytes).expect("decode"), cid);
        assert_eq!(Cidv1::<[u8; 32]>::decode(&bytes).expect("decode"), cid);
    }

    #[test]
    fn decode_errors() {
        let bytes = hello().to_bytes();
        let decode = Cidv1::<Vec<u8>>::decode;
        assert!(matches!(decode(&[]), Err(DecodeError::Truncated)));
        assert!(matches!(decode(&bytes[..bytes.len() - 1]), Err(DecodeError::Truncated)));
        // A CIDv0 is a bare multihash, not a CIDv1
        assert!(matches!(decode(&bytes[2..]), Err(DecodeError::Version)));
        let mut v2 = bytes.clone();
        v2[0] = 0x02;
        assert!(matches!(decode(&v2), Err(DecodeError::Version)));
    }

    #[test]
    fn parse_v0_upgrades() {
        let cid: Cidv1 = EMPTY_DIR_V0.parse().expect("CIDv0 string");
        assert_eq!(cid.codec(), DAG_PB_CODEC);
        assert_eq!(cid.to_string(), EMPTY_DIR_V1);
    }

    #[test]
    fn downgrade_to_v0() {
        let dir: Cidv1<[u8; 32]> = EMPTY_DIR_V1.parse().expect("parse");
        let v0: Cidv0 = dir.try_into().expect("dag-pb sha2-256 is CIDv0");
        assert_eq!(v0.to_string(), EMPTY_DIR_V0);

        // Raw codec has no CIDv0 form
        let raw: Cidv1<[u8; 32]> = HELLO.parse().expect("parse");
        let back = Cidv0::try_from(raw).expect_err("raw isn't CIDv0");
        assert_eq!(back.to_string(), HELLO);
    }

    #[test]
    fn equality() {
        let inline = hello();
        let array: Cidv1<[u8; 32]> = Cidv1Spec::default().hash(b"hello world");
        assert_eq!(inline, array);
        assert_eq!(inline.as_ref(), array);

        let other_codec: Cidv1 = Cidv1Spec::new(DAG_PB_CODEC, MultihashFunc::Sha2_256).hash(b"hello world");
        assert_ne!(inline, other_codec);
        assert_ne!(inline, Cidv1Spec::default().hash::<Inline<64>>(b"hello"));
    }

    #[test]
    fn spec() {
        let cid = hello();
        let spec = Cidv1Spec::from_cid(&cid).expect("known hash");
        assert_eq!(spec, Cidv1Spec::default());
        assert_eq!(spec.version(), CidVersion::V1);
        assert_eq!(spec.codec(), RAW_CODEC);
        assert_eq!(spec.hashcode(), 0x12);

        let unknown = Cidv1::new(RAW_CODEC, Multihash::new(0xd5, Inline::<64>::decode(&[0; 16]).expect("fits")));
        assert_eq!(Cidv1Spec::<MultihashFunc>::from_cid(&unknown), None);
    }

    #[test]
    fn serde_bytes() {
        let bytes = hello().to_bytes();
        let de = BytesDeserializer::<ValueError>::new(&bytes);
        assert_eq!(Cidv1::<Inline<64>>::deserialize(de).expect("deserialize"), hello());

        let de = BytesDeserializer::<ValueError>::new(&bytes[1..]);
        assert!(Cidv1::<Inline<64>>::deserialize(de).is_err());
    }
}
