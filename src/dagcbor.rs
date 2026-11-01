//! dag-cbor serde implementation.
//! 
//! CBOR (Concise Binary Object Representation) is a self-describing TLV data
//! serialization format. DAG-CBOR is a strict subset of CBOR for use in IPLD
//! interoperation.
//! 
//! All CBOR values begin with an "initial byte" which is composed of a
//! "major type" (MSB 3 bits) and "additional information" (LSB 5 bits). All
//! values have a "count field" which is either short or long. For AI 0..=23
//! the AI is the short count and 24..=27 the AI is (1, 2, 4, 8) the number of
//! bytes in the long count. A count of 31 is reserved for streaming
//! representations which end with the break marker.
//! 
//! Major types:
//! - 0 positive integer using the count.
//! - 1 negative integer using the count (-count - 1).
//!   - AI 28+ is reserved for positive and negative.
//! - 2 bytes, count is the length followed by unstructured bytes.
//! - 3 string, count is the length followed by utf-8 bytes.
//! - 4 array, count is the number of elements followed by that many elements.
//! - 5 map, count is the number of entries followed by that many key-value pairs.
//! - 6 tag, count is the tag's value.
//! - 7 special/float
//!   - 0..=19 reserved
//!   - 20..=23 are false, true, null, undefined
//!   - 24 is a 1-byte extension
//!   - 25..=27 are f16, f32, and f64
//!   - 28..=30 reserved
//!   - 31 break marker
//! 
//! DAG-CBOR has the following additional requirements:
//! - Map entries are sorted by key (length then value). This corresponds to a bytewise sort of the CBOR encoding.
//! - Indefinite-length containers are forbidden.
//! - Undefined is forbidden.
//! - Only finite floats are allowed.
//! - Floats are always encoded as f64.
//! - -0.0 must not appear, it must be encoded as 0.0.
//! - Map keys must be strings.
//! - Integer encoding and length must always be as short as possible.
//! - Only tag 42 (CID) is valid.

use num_enum::IntoPrimitive;

use crate::canon::Canon;
use crate::serde::{self as harness, Error};

mod ser;
mod de;

pub use de::Deserializer;
pub use ser::Serializer;

pub const CID_TAG: u8 = 42;

/// Encode a value as DAG-CBOR.
pub fn to_vec<T: ?Sized + serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    Ok(harness::serialize(Serializer::new(), value)?.into_bytes())
}

/// Decode a whole DAG-CBOR block.
pub fn from_slice<'de, T: serde::Deserialize<'de>>(input: &'de [u8]) -> Result<T, Error> {
    harness::deserialize(Deserializer::new(input))
}

/// Decode a whole DAG-CBOR block, noting whether it was canonical. Strict
/// errors are still errors, this only covers forms which decode to the
/// same data but wouldn't re-encode to the same bytes.
pub fn from_slice_canon<'de, T: serde::Deserialize<'de>>(input: &'de [u8]) -> Result<Canon<T>, Error> {
    harness::deserialize_canon(Deserializer::new(input))
}

#[derive(Copy, Clone)]
enum Size {
    Count1,
    Count2,
    Count4,
    Count8,
    Inline(u8),
}

impl Size {
    /// Construct a size from the tag which signals it.
    const fn from_tag(tag: u8) -> Option<Self> {
        Some(match ai_field(tag) {
            inl @ ..marker::COUNT1 => Self::Inline(inl),
            marker::COUNT1 => Self::Count1,
            marker::COUNT2 => Self::Count2,
            marker::COUNT4 => Self::Count4,
            marker::COUNT8 => Self::Count8,
            _ => return None
        })
    }

    /// Construct a size from the payload it would signal.
    const fn from_payload(payload: u64) -> Self {
        if payload < 24 {
            let [.., low] = payload.to_be_bytes();
            Self::Inline(low)
        }
        else {
            match payload.bit_width() {
                0..=8 => Self::Count1,
                9..=16 => Self::Count2,
                17..=32 => Self::Count4,
                _ => Self::Count8,
            }
        }
    }

    const fn extra_size(self) -> usize {
        match self {
            Self::Count1 => 1,
            Self::Count2 => 2,
            Self::Count4 => 4,
            Self::Count8 => 8,
            Self::Inline(_) => 0,
        }
    }

    const fn to_ai(self) -> u8 {
        match self {
            Self::Count1 => marker::COUNT1,
            Self::Count2 => marker::COUNT2,
            Self::Count4 => marker::COUNT4,
            Self::Count8 => marker::COUNT8,
            Self::Inline(sz) => sz,
        }
    }
}

/// CBOR major type
#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoPrimitive)]
#[repr(u8)]
pub enum Major {
    Positive = 0,
    Negative = 1,
    Bytes = 2,
    String = 3,
    Array = 4,
    Map = 5,
    Tag = 6,
    Simple = 7,
}

impl Major {
    /// Extract the major type from a byte.
    const fn from_byte(byte: u8) -> Self {
        match byte>>5 {
            0 => Self::Positive,
            1 => Self::Negative,
            2 => Self::Bytes,
            3 => Self::String,
            4 => Self::Array,
            5 => Self::Map,
            6 => Self::Tag,
            // 7, all that's left of three bits
            _ => Self::Simple,
        }
    }

    /// Get the initial byte with this major type and the provided additional
    /// information field.
    // `From` isn't const yet, and a fieldless repr(u8) enum's discriminant
    // is exactly its byte
    #[allow(clippy::as_conversions)]
    const fn initial(self, ai: u8) -> u8 {
        (self as u8)<<5 | ai
    }

    /// Get the initial byte to begin an indefinite length container.
    const fn start(self) -> u8 { self.initial(marker::START) }
}

/// Markers needed to parse sub types.
/// The `START` marker can be combined with major types 2, 3, 4 and 5.
/// The other values are full bytes representing the major type 7 sub-types.
pub mod marker {
    use super::Major;
    
    pub const START: u8 = 31;
    pub const FALSE: u8 = Major::Simple.initial(20);
    pub const TRUE: u8 = Major::Simple.initial(21);
    pub const NULL: u8 = Major::Simple.initial(22);
    pub const UNDEFINED: u8 = Major::Simple.initial(23);
    
    pub const COUNT1: u8 = 24;
    pub const COUNT2: u8 = 25;
    pub const COUNT4: u8 = 26;
    pub const COUNT8: u8 = 27;

    // Simple value 24 is reserved but defined to be a 1-byte extension.
    pub const EXT: u8 = Major::Simple.initial(COUNT1);
    pub const F16: u8 = Major::Simple.initial(COUNT2);
    pub const F32: u8 = Major::Simple.initial(COUNT4);
    pub const F64: u8 = Major::Simple.initial(COUNT8);
    pub const BREAK: u8 = Major::Simple.initial(START);
}

/// Get the additional information field.
const fn ai_field(byte: u8) -> u8 { byte & marker::START }
#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_bytes::ByteBuf;

    use super::*;
    use crate::cid::{CidRef, Cidv0, Cidv1, Cidv1Spec};
    use crate::model::Ipld;

    fn hex(s: &str) -> Vec<u8> {
        multibase::decode(format!("f{s}")).expect("hex").1
    }

    #[test]
    fn links_with_long_digests() {
        use crate::model::Link;
        use crate::multihash::{DigestBuf, Multihash};
        // Up to IPIP-0512's 128 bytes, spilling past what's kept inline
        for len in [0, 32, 33, 64, 65, 128] {
            let digest = crate::multihash::DefaultDigest::decode(&vec![0xab; len]).expect("digest");
            let link: Link = crate::cid::AnyCid::V1(Cidv1::new(0x55, Multihash::new(0x00, digest)));
            let value = Ipld::List(vec![Ipld::Link(link)]);
            let bytes = to_vec(&value).expect("encode");
            assert_eq!(from_slice::<Ipld>(&bytes).expect("decode"), value, "{len}");
        }
    }

    #[test]
    fn limits_nesting() {
        use crate::serde::MAX_DEPTH;
        #[derive(Deserialize)]
        struct Empty {}
        let nested = |list: u8, depth: usize| [vec![list; depth], vec![0xf6]].concat();
        // Lists, and maps keyed by ""
        for (list, label) in [(0x81, "lists"), (0xa1, "maps")] {
            let unit = if list == 0x81 { vec![list] } else { vec![list, 0x60] };
            let block = |depth: usize| [unit.repeat(depth), vec![0xf6]].concat();
            assert!(from_slice::<Ipld>(&block(MAX_DEPTH)).is_ok(), "{label}");
            assert!(from_slice::<Ipld>(&block(MAX_DEPTH + 1)).is_err(), "{label}");
        }
        // Ignored values are limited too
        let ignored = [&[0xa1, 0x61, b'x'][..], &nested(0x81, 100_000)].concat();
        assert!(from_slice::<Empty>(&ignored).is_err());
        // Far past the limit, where the stack would have overflowed
        assert!(from_slice::<Ipld>(&nested(0x81, 100_000)).is_err());
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Variant {
        Unit,
        Newtype(u8),
        Tuple(u8, bool),
        Struct { x: i8 },
    }

    /// Fields deliberately declared out of DAG-CBOR order.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Thing {
        zzz: u32,
        a: String,
        link: Cidv1,
        v0: Cidv0,
        bytes: ByteBuf,
        none: Option<i8>,
        some: Option<i8>,
        list: Vec<i64>,
        variants: Vec<Variant>,
        big: i128,
    }

    fn thing() -> Thing {
        Thing {
            zzz: 70000,
            a: "hello".into(),
            link: Cidv1Spec::default().hash(b"hello world"),
            v0: "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn".parse().expect("v0"),
            bytes: ByteBuf::from(vec![1, 2, 3]),
            none: None,
            some: Some(-5),
            list: vec![i64::MIN, -1, 0, 23, 24, 255, 256, i64::MAX],
            variants: vec![Variant::Unit, Variant::Newtype(1), Variant::Tuple(2, true), Variant::Struct { x: -3 }],
            big: -(1 << 64),
        }
    }

    #[test]
    fn typed_round_trip() {
        let bytes = to_vec(&thing()).expect("encode");
        let decoded = from_slice_canon::<Thing>(&bytes).expect("decode");
        assert!(decoded.is_canon());
        assert_eq!(decoded.into_inner(), thing());

        // Through the data model too, and back to the same bytes
        let ipld: Ipld = from_slice(&bytes).expect("as ipld");
        assert_eq!(to_vec(&ipld).expect("re-encode"), bytes);
    }

    #[test]
    fn struct_keys_sorted_length_first() {
        #[derive(Serialize)]
        struct S { bb: u8, a: u8 }
        assert_eq!(to_vec(&S { bb: 1, a: 2 }).expect("encode"), hex("a261610262626201"));
    }

    #[test]
    fn encodings() {
        let cases: [(Ipld, &str); 9] = [
            (Ipld::Null, "f6"),
            (Ipld::Bool(true), "f5"),
            (Ipld::Integer(24), "1818"),
            (Ipld::Integer(-1), "20"),
            (Ipld::Integer(u64::MAX.into()), "1bffffffffffffffff"),
            (Ipld::Integer(-(1 << 64)), "3bffffffffffffffff"),
            // Floats are always 64 bit
            (Ipld::Float(1.5), "fb3ff8000000000000"),
            (Ipld::Bytes(vec![0xa1]), "41a1"),
            (Ipld::String("a".into()), "6161"),
        ];
        for (value, expected) in cases {
            assert_eq!(to_vec(&value).expect("encode"), hex(expected), "{value:?}");
            assert_eq!(from_slice::<Ipld>(&hex(expected)).expect("decode"), value);
        }

        // Tag 42, bytes with a 0x00 prefix, then the binary CID
        let link: Cidv1 = Cidv1Spec::default().hash(b"hello world");
        let bytes = to_vec(&link).expect("encode");
        assert_eq!(bytes[..4], [0xd8, 0x2a, 0x58, 0x25]);
        assert_eq!(bytes[4], 0x00);
        assert_eq!(bytes[5..], link.to_bytes());
        assert_eq!(from_slice::<Cidv1>(&bytes).expect("decode"), link);
    }

    #[test]
    fn noncanonical_forms_decode() {
        for (label, input, value) in [
            ("f32", "fa3fc00000", Ipld::Float(1.5)),
            ("f16", "f93e00", Ipld::Float(1.5)),
            ("long int", "1801", Ipld::Integer(1)),
            ("long length", "780161", Ipld::String("a".into())),
            ("unsorted keys", "a262626201616102", from_slice::<Ipld>(&hex("a261610262626201")).expect("map")),
        ] {
            let decoded = from_slice_canon::<Ipld>(&hex(input)).expect(label);
            assert!(!decoded.is_canon(), "{label} should be non-canonical");
            assert_eq!(decoded.into_inner(), value, "{label}");
        }
    }

    #[test]
    fn strict_errors() {
        for (label, input) in [
            ("empty", ""),
            ("trailing bytes", "0101"),
            ("truncated string", "6261"),
            ("undefined", "f7"),
            ("indefinite list", "9fff"),
            ("indefinite string", "7f6161ff"),
            ("non-CID tag", "c101"),
            ("NaN", "fb7ff8000000000000"),
            ("infinity", "f97c00"),
            ("CID without 0x00 prefix", "d82a4101"),
            ("non-string key", "a10102"),
            ("duplicate key", "a2616101616102"),
            ("invalid utf-8", "61ff"),
        ] {
            assert!(from_slice::<Ipld>(&hex(input)).is_err(), "{label} should fail");
        }
        assert!(to_vec(&f64::NAN).is_err());
        assert!(to_vec(&f64::INFINITY).is_err());
    }

    #[test]
    fn typed_errors() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code, reason = "only deserialized")]
        struct Pair(u8, u8);
        // Too many and too few tuple elements
        assert!(from_slice::<Pair>(&hex("83010203")).is_err());
        assert!(from_slice::<Pair>(&hex("8101")).is_err());
        // Out of range
        assert!(from_slice::<u8>(&hex("190100")).is_err());
        // An enum map must have exactly one entry
        assert!(from_slice::<Variant>(&hex("a0")).is_err());
        // A link where a CID isn't
        assert!(from_slice::<Cidv1>(&hex("4100")).is_err());
    }
}
