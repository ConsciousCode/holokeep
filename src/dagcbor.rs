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

mod ser;
mod de;

pub const CID_TAG: u8 = 42;

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
            Self::Inline(payload as u8)
        }
        else {
            match payload.bit_width() {
                ..=8 => Self::Count1,
                ..=16 => Self::Count2,
                ..=32 => Self::Count4,
                _ => Self::Count8,
            }
        }
    }

    const fn extra_size(&self) -> usize {
        match self {
            Self::Count1 => 1,
            Self::Count2 => 2,
            Self::Count4 => 4,
            Self::Count8 => 8,
            Self::Inline(_) => 0,
        }
    }

    const fn to_ai(&self) -> u8 {
        match self {
            Self::Count1 => marker::COUNT1,
            Self::Count2 => marker::COUNT2,
            Self::Count4 => marker::COUNT4,
            Self::Count8 => marker::COUNT8,
            Self::Inline(sz) => *sz,
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
            7 => Self::Simple,
            _ => unreachable!() // upper 3 bits in [0, 7]
        }
    }

    /// Get the initial byte with this major type and the provided additional
    /// information field.
    const fn initial(self, ai: u8) -> u8 {
        (self as u8)<<5 | ai
    }

    /// Get the initial byte to begin an indefinite length container.
    const fn start(&self) -> u8 { self.initial(marker::START) }
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