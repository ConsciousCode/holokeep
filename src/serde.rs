//! Traits for dramatically simplifying the boilerplate needed to implement
//! serde serializers and deserializers within the IPLD data model.

use std::borrow::Cow;

use crate::canon::Canon;

mod ser;
mod de;

pub use ser::Serializer;
pub use de::Deserializer;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);
impl serde::ser::Error for Error {
    fn custom<T>(msg: T) -> Self where T: std::fmt::Display {
        Self(msg.to_string())
    }
}
impl serde::de::Error for Error {
    fn custom<T>(msg: T) -> Self where T: std::fmt::Display {
        Self(msg.to_string())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Kind { Null, Bool, Int, Float, String, Bytes, List, Map, Link }

/// Type-erased IPLD value.
pub enum Any<'de> {
    Null,
    Bool(bool),
    Integer(i128),
    Float(f64),
    String(Cow<'de, str>),
    Bytes(Cow<'de, [u8]>),
    List(Vec<Any<'de>>),
    Map(Vec<(Cow<'de, str>, Any<'de>)>),
    Link(Cow<'de, [u8]>),
}

/// Trait to serialize a list.
/// 
/// begin -> serialize {element, end}
/// element -> serialize {element, end}
pub trait ListEncoder<E: Encoder>: Sized {
    /// Begin list serialization. This should leave the ListEncoder in a state
    /// ready to serialize an element.
    fn begin(enc: &mut E, size: Option<usize>) -> Result<Self, Error>;

    /// Called before every element is written.
    fn element(&mut self, enc: &mut E) -> Result<(), Error>;

    /// End the encoding.
    fn end(self, enc: &mut E) -> Result<(), Error>;
}

pub trait MapEncoder<E: Encoder>: Sized {
    /// Begin map serialization. This should leave the MapEncoder in a state
    /// ready to serialize an element.
    fn begin(enc: &mut E, size: Option<usize>) -> Result<Self, Error>;

    /// Serialize a key - note that it is always a string.
    fn key(&mut self, enc: &mut E, key: &str) -> Result<(), Error>;

    /// End the encoding.
    fn end(self, enc: &mut E) -> Result<(), Error>;
}

pub trait Encoder: Sized {
    type ListEncoder: ListEncoder<Self>;
    type MapEncoder: MapEncoder<Self>;

    fn encode_null(&mut self) -> Result<(), Error>;
    fn encode_bool(&mut self, value: bool) -> Result<(), Error>;
    fn encode_int(&mut self, value: i128) -> Result<(), Error>;
    fn encode_float(&mut self, value: f64) -> Result<(), Error>;
    fn encode_string(&mut self, value: &str) -> Result<(), Error>;
    fn encode_bytes(&mut self, value: &[u8]) -> Result<(), Error>;
    fn encode_link(&mut self, value: &[u8]) -> Result<(), Error>;
}

pub trait SizeHint: Sized {
    /// If the format supports size hints, return it.
    fn size_hint(&self) -> Option<usize>;
}

pub trait ListDecoder<'de, D: Decoder<'de>>: SizeHint {
    /// Begin list parsing by constructing the list decoder.
    fn begin(dec: &mut D) -> Result<Self, Error>;

    /// Get whether the list has a next element. The serde harness will
    /// manage the expected size, so a format with no break marker can
    /// simply return true.
    fn has_next(&self, dec: &mut D) -> Result<bool, Error>;

    /// Hint that the decoder expects the end of the list.
    fn end(&mut self, dec: &mut D) -> Result<(), Error>;
}

pub trait MapDecoder<'de, D: Decoder<'de>>: SizeHint {
    /// Begin map parsing by constructing the map decoder.
    fn begin(dec: &mut D) -> Result<Self, Error>;

    /// Attempt to get the next map key, or else None. This should leave the
    /// decoder in a state ready to decode the next map item. The serde
    /// harness will manage the expected size, so you can assume that a key
    /// is expected.
    fn key(&mut self, dec: &mut D) -> Result<Option<Cow<'de, str>>, Error>;

    /// Hint that the decoder expects the end of the list.
    fn end(&mut self, dec: &mut D) -> Result<(), Error>;
}

/// Decoder abstracts serde Deserializer so the logic for IPLD codecs can be
/// consolidated.
/// 
/// List has this flow in pseudocode:
/// list_begin()
/// if list_has_next() {
///     deserialize()
///     while(list_has_next()) {
///         list_item()
///         deserialize()
///     }
/// }
/// list_end()
/// 
/// Map has this flow in pseudocode:
/// map_begin()
/// if map_has_next_entry() {
///     map_key()
///     deserialize()
///     while(map_has_next_entry()) {
///         map_item()
///         map_key()
///         deserialize()
///     }
/// }
/// map_end()
/// 
/// This multi-stage flow for container types ensures that reasonable codecs
/// can be serviced.
pub trait Decoder<'de>: Sized {
    type ListDecoder: ListDecoder<'de, Self>;
    type MapDecoder: MapDecoder<'de, Self>;

    /// Peek ahead in the stream for what kind of value is next.
    fn peek_kind(&mut self) -> Result<Kind, Error>;

    /// Skip the next value.
    fn skip(&mut self) -> Result<(), Error>;

    /// Is the format human readable?
    fn is_human_readable() -> bool;

    /// Called after the top-level value, to reject trailing input.
    fn finish(&mut self) -> Result<(), Error>;

    /// Whether everything decoded so far was in canonical form, ie would
    /// re-encode to the same bytes.
    fn is_canon(&self) -> bool;

    /// Decode any value without any expected type.
    fn decode_any(&mut self) -> Result<Any<'de>, Error> {
        Ok(match self.peek_kind()? {
            Kind::Null => {
                self.decode_null()?;
                Any::Null
            },
            Kind::Bool => Any::Bool(self.decode_bool()?),
            Kind::Int => Any::Integer(self.decode_int()?),
            Kind::Float => Any::Float(self.decode_float()?),
            Kind::String => Any::String(self.decode_string()?),
            Kind::Bytes => Any::Bytes(self.decode_bytes()?),
            Kind::Link => Any::Link(self.decode_link()?),
            Kind::List => {
                let mut dec = Self::ListDecoder::begin(self)?;
                // Counted formats leave it to the size hint to stop
                let mut remain = dec.size_hint();
                let mut ls = Vec::with_capacity(remain.unwrap_or(0));
                while remain != Some(0) && dec.has_next(self)? {
                    ls.push(self.decode_any()?);
                    remain = remain.map(|r| r - 1);
                }
                dec.end(self)?;
                Any::List(ls)
            },
            Kind::Map => {
                let mut dec = Self::MapDecoder::begin(self)?;
                let mut remain = dec.size_hint();
                let mut map = Vec::with_capacity(remain.unwrap_or(0));
                while remain != Some(0) && let Some(key) = dec.key(self)? {
                    map.push((key, self.decode_any()?));
                    remain = remain.map(|r| r - 1);
                }
                dec.end(self)?;
                Any::Map(map)
            }
        })
    }

    /// Decode a value expecting a null.
    fn decode_null(&mut self) -> Result<(), Error>;

    /// Decode a value expecting a bool.
    fn decode_bool(&mut self) -> Result<bool, Error>;

    /// Decode a value expecting an integer.
    fn decode_int(&mut self) -> Result<i128, Error>;

    /// Decode a value expecting a float.
    fn decode_float(&mut self) -> Result<f64, Error>;

    /// Decode a value expecting a string.
    fn decode_string(&mut self) -> Result<Cow<'de, str>, Error>;

    /// Decode a value expecting a bytes.
    fn decode_bytes(&mut self) -> Result<Cow<'de, [u8]>, Error>;

    /// Decode a value expecting a link.
    fn decode_link(&mut self) -> Result<Cow<'de, [u8]>, Error>;
}

/// Deserialize a whole input.
pub fn deserialize<'de, D, T>(dec: D) -> Result<T, Error>
    where
        D: Decoder<'de>,
        T: serde::Deserialize<'de>,
{
    deserialize_canon(dec).map(Canon::into_inner)
}

/// Deserialize a whole input, noting whether it was canonical.
pub fn deserialize_canon<'de, D, T>(dec: D) -> Result<Canon<T>, Error>
    where
        D: Decoder<'de>,
        T: serde::Deserialize<'de>,
{
    let mut de = de::Deserializer::new(dec);
    let value = serde::Deserialize::deserialize(&mut de)?;
    let mut dec = de.into_inner();
    dec.finish()?;
    Ok(Canon::new(value, dec.is_canon()))
}

/// Serialize a value, returning the encoder to collect its output from.
pub fn serialize<E, T>(enc: E, value: &T) -> Result<E, Error>
    where
        E: Encoder,
        T: ?Sized + serde::Serialize,
{
    let mut ser = ser::Serializer::new(enc);
    value.serialize(&mut ser)?;
    Ok(ser.into_inner())
}