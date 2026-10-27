//! Primitives for reading/writing protobuf. This means one less dependency,
//! but the primary reason it's implemented here is because it guarantees
//! determinism. Kubo's canonical serialization has weird quirks, and any
//! minor differences result in totally different hashes.

use std::{borrow::Borrow, ops::Deref, str::Utf8Error};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::varint;

use super::error::{PrimitiveError, Utf8BytesError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(super) enum PbType {
    /// Variable-length integer using leb128.
    Varint = 0,
    /// Fixed 64-bit integer (also for used for floats etc). Sign is a matter
    /// of bit casting.
    Fixed64 = 1,
    /// A length-prefixed value, used by Bytes, String, and submessages.
    Length = 2,
    //Sgroup = 3, Start of group, deprecated since 2008 and unused by dag-pb.
    //Egroup = 4, End of group
    /// Fixed 32-bit integer, sign is bit-cast.
    Fixed32 = 5,
}

/// Retrieve the next protobuf field, returning None for end of interation.
/// Yields (field id, value)
pub(super) fn next_field(buf: &mut Bytes) -> Option<(u8, u8)> {
    // Iteration ends if this fails
    let ft = match buf.try_get_u8() {
        Ok(ft) => ft,
        Err(_) => return None,
    };
    Some((ft>>3, ft & 7))
}

/// A value writable to a protobuf stream.
pub(super) trait PbEncode {
    /// The tag used to serialize the value. Defaults to PB_LEN because
    /// that covers all non-primitive values.
    const PB_TAG: PbType = PbType::Length;
    
    /// Get the size of the serialized value.
    fn pb_size(&self) -> u64;

    /// Write the value to bytes.
    fn pb_encode(&self, buf: &mut BytesMut);
}

/// A value readable from a protobuf stream.
pub(super) trait PbDecode {
    type Output;
    type Error;

    /// Read a value from bytes.
    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error>;
}

// Utility impl for references.
impl<T: PbEncode> PbEncode for &T {
    const PB_TAG: PbType = T::PB_TAG;
    fn pb_size(&self) -> u64 { T::pb_size(self) }
    fn pb_encode(&self, buf: &mut BytesMut) { T::pb_encode(self, buf) }
}

// Utility impl for optional fields. You can't read an optional field.
impl<T: PbEncode> PbEncode for Option<T> {
    const PB_TAG: PbType = T::PB_TAG;

    fn pb_size(&self) -> u64 {
        self.as_ref().map(T::pb_size).unwrap_or(0)
    }

    fn pb_encode(&self, buf: &mut BytesMut) {
        if let Some(v) = self {
            v.pb_encode(buf)
        }
    }
}

impl PbEncode for Bytes {
    fn pb_size(&self) -> u64 {
        self.len() as u64
    }

    fn pb_encode(&self, buf: &mut BytesMut) {
        varint::write(buf, self.len() as u64);
        buf.put_slice(self);
    }
}
impl PbDecode for Bytes {
    type Output = Self;
    type Error = PrimitiveError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self, Self::Error> {
        let len = varint::read(buf)? as usize;
        let available = buf.remaining();
        if available > len {
            Ok(buf.split_to(len))
        }
        else {
            Err(PrimitiveError::Truncated)
        }
    }
}

/// Wrapper for Bytes expected to be UTF-8 in dag-pb.
#[derive(Debug, Clone)]
pub(super) struct Utf8Bytes(Bytes);
impl Utf8Bytes {
    /// Create an empty UTF8Bytes object. Empty bytes are trivially valid UTF-8.
    pub fn new() -> Self {
        Self(Bytes::new())
    }

    /// Attempt to wrap a Bytes object and interpret it as UTF-8.
    pub fn wrap(bytes: Bytes) -> Result<Self, Utf8Error> {
        str::from_utf8(&bytes)?;
        Ok(Self(bytes))
    }

    /// Get 
    pub fn as_str(&self) -> &str {
        // Safe because `wrap` validates and `Bytes` is immutable.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Utf8Bytes {
    type Target = str;
    
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Borrow<str> for Utf8Bytes {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl Borrow<Bytes> for Utf8Bytes {
    fn borrow(&self) -> &Bytes {
        &self.0
    }
}

impl PbEncode for Utf8Bytes {
    fn pb_size(&self) -> u64 {
        self.0.pb_size()
    }

    fn pb_encode(&self, buf: &mut BytesMut) {
        self.0.pb_encode(buf);
    }
}
impl PbDecode for Utf8Bytes {
    type Output = Self;
    type Error = Utf8BytesError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self, Self::Error> {
        Ok(Utf8Bytes::wrap(Bytes::pb_decode(buf)?)?)
    }
}

/// A variable-length unsigned integer in protobuf. dag-pb does not use
/// signed varint.
#[derive(Copy, Clone)]
pub(super) struct Int64(pub i64);

impl PbEncode for Int64 {
    const PB_TAG: PbType = PbType::Varint;

    fn pb_size(&self) -> u64 { varint::size(self.0 as u64) as u64 }
    fn pb_encode(&self, buf: &mut BytesMut) {
        varint::write(buf, self.0 as u64)
    }
}
impl PbDecode for Int64 {
    type Output = i64;
    type Error = PrimitiveError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        Ok(varint::read(buf)? as i64)
    }
}

/// A variable-length unsigned integer in protobuf. dag-pb does not use
/// signed varint.
#[derive(Copy, Clone)]
pub(super) struct Uint64(pub u64);

impl PbEncode for Uint64 {
    const PB_TAG: PbType = PbType::Varint;

    fn pb_size(&self) -> u64 { varint::size(self.0) as u64 }
    fn pb_encode(&self, buf: &mut BytesMut) { varint::write(buf, self.0) }
}
impl PbDecode for Uint64 {
    type Output = u64;
    type Error = PrimitiveError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        Ok(varint::read(buf)?)
    }
}

impl PbEncode for i64 {
    const PB_TAG: PbType = PbType::Fixed64;

    fn pb_size(&self) -> u64 { 8 }
    fn pb_encode(&self, buf: &mut BytesMut) { buf.put_i64_le(*self) }
}
impl PbDecode for i64 {
    type Output = i64;
    type Error = PrimitiveError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        Ok(buf.try_get_i64_le()?)
    }
}
impl PbEncode for u64 {
    const PB_TAG: PbType = PbType::Fixed64;

    fn pb_size(&self) -> u64 { 8 }
    fn pb_encode(&self, buf: &mut BytesMut) { buf.put_u64_le(*self) }
}
impl PbDecode for u64 {
    type Output = u64;
    type Error = PrimitiveError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        Ok(buf.try_get_u64_le()?)
    }
}

impl PbEncode for i32 {
    const PB_TAG: PbType = PbType::Fixed32;

    fn pb_size(&self) -> u64 { 4 }
    fn pb_encode(&self, buf: &mut BytesMut) { buf.put_i32_le(*self) }
}
impl PbDecode for i32 {
    type Output = Self;
    type Error = PrimitiveError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self, Self::Error> {
        Ok(buf.try_get_i32_le()?)
    }
}
impl PbEncode for u32 {
    const PB_TAG: PbType = PbType::Fixed32;

    fn pb_size(&self) -> u64 { 4 }
    fn pb_encode(&self, buf: &mut BytesMut) { buf.put_u32_le(*self) }
}
impl PbDecode for u32 {
    type Output = Self;
    type Error = PrimitiveError;

    fn pb_decode(buf: &mut Bytes) -> Result<Self, Self::Error> {
        Ok(buf.try_get_u32_le()?)
    }
}

pub(super) struct PbField<F, V: PbEncode>(pub F, pub V);

/// Weird hack: this makes Field::size(value) possible without requiring
/// the actual field enum which size doesn't depend on. Technically size
/// *does* depend on the field because the tag is itself a varint, but as
/// an optimization we assume that there are less than ~31 fields which
/// would require actual varint encoding. None of IPLD does, so.
impl<V: PbEncode> PbField<(), V> {
    pub fn size(value: V) -> u64 { 1 + value.pb_size() }
}
impl<F: Into<u8> + Copy, V: PbEncode> PbEncode for PbField<F, V> {
    fn pb_size(&self) -> u64 {
        1 + // Tag
        if V::PB_TAG == PbType::Length {
            let len = self.1.pb_size();
            varint::size(len) as u64 + len
        }
        else {
            0
        } + // Size varint for length value
        PbField::size(&self.1) as u64 // Body of the value
    }
    fn pb_encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.0.into()<<3 | u8::from(V::PB_TAG));
        self.1.pb_encode(buf);
    }
}

// No PbRead impl for PbField because you can't read a field generically.