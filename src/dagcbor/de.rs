use std::borrow::Cow;

use serde::de::{ Error as _, Unexpected };

use crate::{dagcbor::Size, serde::{Decoder, Error, Kind, ListDecoder, MapDecoder, SizeHint}};

use super::{Major, marker, CID_TAG};

/// Get the name of the type corresponding to the tag.
const fn tag_name(byte: u8) -> &'static str {
    match Major::from_byte(byte) {
        Major::Positive => "uint",
        Major::Negative => "sint",
        Major::Bytes => "bytes",
        Major::String => "string",
        Major::Array => "array",
        Major::Map => "map",
        Major::Tag => "link",
        Major::Simple => match byte {
            marker::NULL => "null",
            marker::UNDEFINED => "undefined",
            marker::TRUE => "true",
            marker::FALSE => "false",
            marker::F16 => "f16",
            marker::F32 => "f32",
            marker::F64 => "f64",
            marker::BREAK => "break",
            _ => "<garbage>"
        }
    }
}

/// CBOR deserializer implementing Decode
pub struct Deserializer<'de> {
    /// Input not yet consumed; its first byte is the next head.
    cursor: &'de [u8],
    canon: bool,
}

impl<'de> Deserializer<'de> {
    pub const fn new(input: &'de [u8]) -> Self {
        Self { cursor: input, canon: true }
    }

    /// Mark the parsed value as noncanonical.
    const fn noncanonical(&mut self) { self.canon = false; }

    fn eof() -> Error { Error::custom("eof") }

    /// Peek at the next byte without consuming it.
    fn peek(&self) -> Result<u8, Error> {
        self.cursor.first().copied().ok_or_else(Self::eof)
    }

    /// Consume the next byte.
    fn advance(&mut self) -> Result<u8, Error> {
        self.cursor.split_off_first().copied().ok_or_else(Self::eof)
    }

    fn get_chunk<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        match self.cursor.split_first_chunk() {
            Some((&chunk, cursor)) => {
                self.cursor = cursor;
                Ok(chunk)
            },
            None => Err(Self::eof())
        }
    }

    fn get_slice(&mut self, n: usize) -> Result<&'de [u8], Error> {
        match self.cursor.split_at_checked(n) {
            Some((left, right)) => {
                self.cursor = right;
                Ok(left)
            }
            None => Err(Self::eof())
        }
    }

    fn check_minimal<T>(&mut self, min: T, count: T) -> u64
        where T: Copy + Ord + Into<u64>
    {
        if count < min {
            self.noncanonical();
        }
        count.into()
    }

    /// Consume a head, returning its count field without checking the major.
    fn decode_count(&mut self) -> Result<u64, Error> {
        Ok(match Size::from_tag(self.advance()?) {
            Some(Size::Inline(sz)) => sz.into(),
            Some(Size::Count1) => {
                let count = u8::from_be_bytes(self.get_chunk()?);
                self.check_minimal(24, count)
            },
            Some(Size::Count2) => {
                let count = u16::from_be_bytes(self.get_chunk()?);
                self.check_minimal(1<<8, count)
            },
            Some(Size::Count4) => {
                let count = u32::from_be_bytes(self.get_chunk()?);
                self.check_minimal(1<<16, count)
            },
            Some(Size::Count8) => {
                let count = u64::from_be_bytes(self.get_chunk()?);
                self.check_minimal(1<<32, count)
            },
            None => return Err(Error::invalid_value(
                Unexpected::Other("<garbage>"),
                &"additional information"
            )),
        })
    }

    /// Decode a CBOR count expecting a given major field.
    fn decode_head(&mut self, major: Major) -> Result<u64, Error> {
        let byte = self.peek()?;
        if Major::from_byte(byte) != major {
            return Err(Error::custom(format_args!(
                "invalid type: {}, expected {major:?}", tag_name(byte)
            )));
        }
        self.decode_count()
    }

    /// Decode the length of a definite-length value. DAG-CBOR forbids the
    /// indefinite-length forms.
    fn decode_len(&mut self, major: Major) -> Result<usize, Error> {
        if self.peek()? == major.start() {
            return Err(Error::custom(format_args!("indefinite-length {major:?}")));
        }
        self.decode_head(major)?
            .try_into()
            .map_err(|_| Error::custom("usize overflow"))
    }

    /// A string or bytes payload.
    fn decode_payload(&mut self, major: Major) -> Result<&'de [u8], Error> {
        let len = self.decode_len(major)?;
        self.get_slice(len)
    }
}

impl<'de> Decoder<'de> for Deserializer<'de> {
    type ListDecoder = Container<'de>;
    type MapDecoder = Container<'de>;

    fn peek_kind(&mut self) -> Result<Kind, Error> {
        let byte = self.peek()?;
        Ok(match Major::from_byte(byte) {
            Major::Positive | Major::Negative => Kind::Int,
            Major::Bytes => Kind::Bytes,
            Major::String => Kind::String,
            Major::Array => Kind::List,
            Major::Map => Kind::Map,
            Major::Tag => Kind::Link,
            Major::Simple => match byte {
                marker::NULL => Kind::Null,
                marker::TRUE | marker::FALSE => Kind::Bool,
                marker::F16 | marker::F32 | marker::F64 => Kind::Float,
                byte => return Err(Error::custom(format_args!(
                    "invalid type: {}", tag_name(byte)
                ))),
            }
        })
    }

    fn skip(&mut self) -> Result<(), Error> {
        match self.peek_kind()? {
            Kind::Null => self.decode_null(),
            Kind::Bool => self.decode_bool().map(drop),
            Kind::Int => self.decode_int().map(drop),
            Kind::Float => self.decode_float().map(drop),
            Kind::String => self.decode_string().map(drop),
            Kind::Bytes => self.decode_bytes().map(drop),
            Kind::Link => self.decode_link().map(drop),
            Kind::List => {
                for _ in 0..self.decode_len(Major::Array)? {
                    Decoder::skip(self)?;
                }
                Ok(())
            },
            Kind::Map => {
                for _ in 0..self.decode_len(Major::Map)? {
                    Decoder::skip(self)?;
                    Decoder::skip(self)?;
                }
                Ok(())
            },
        }
    }

    fn is_human_readable() -> bool { false }

    fn finish(&mut self) -> Result<(), Error> {
        if self.cursor.is_empty() {
            Ok(())
        }
        else {
            Err(Error::custom(format_args!("{} trailing bytes", self.cursor.len())))
        }
    }

    fn is_canon(&self) -> bool { self.canon }

    fn decode_null(&mut self) -> Result<(), Error> {
        match self.advance()? {
            marker::NULL => Ok(()),
            byte => Err(Error::custom(format_args!(
                "invalid type: {}, expected null", tag_name(byte)
            ))),
        }
    }

    fn decode_bool(&mut self) -> Result<bool, Error> {
        match self.advance()? {
            marker::TRUE => Ok(true),
            marker::FALSE => Ok(false),
            byte => Err(Error::custom(format_args!(
                "invalid type: {}, expected bool", tag_name(byte)
            ))),
        }
    }

    fn decode_int(&mut self) -> Result<i128, Error> {
        let byte = self.peek()?;
        Ok(match Major::from_byte(byte) {
            Major::Positive => self.decode_count()?.into(),
            Major::Negative => !i128::from(self.decode_count()?), // -1 - count
            _ => return Err(Error::custom(format_args!(
                "invalid type: {}, expected int", tag_name(byte)
            ))),
        })
    }

    fn decode_float(&mut self) -> Result<f64, Error> {
        let value = match self.advance()? {
            // DAG-CBOR floats are always 64 bit
            marker::F16 => {
                self.noncanonical();
                let bits = u16::from_be_bytes(self.get_chunk()?);
                let sign = if bits & 0x8000 == 0 { 1.0 } else { -1.0 };
                let frac = f64::from(bits & 0x3ff);
                sign * match (bits >> 10) & 0x1f {
                    // Subnormal sign * (frac / 2^10) * 2^-14
                    0 => frac * 2.0f64.powi(-24),
                    // Non-finite
                    0x1f => if frac == 0.0 { f64::INFINITY } else { f64::NAN },
                    exp => // Ordinary float
                        (1.0 + frac / 1024.0)
                        * 2.0f64.powi(i32::from(exp).wrapping_sub(15)),
                }
            },
            marker::F32 => {
                self.noncanonical();
                f32::from_be_bytes(self.get_chunk()?).into()
            },
            marker::F64 => f64::from_be_bytes(self.get_chunk()?),
            byte => return Err(Error::custom(format_args!(
                "invalid type: {}, expected float", tag_name(byte)
            ))),
        };
        if value == 0.0 && value.is_sign_negative() {
            // Negative zero is encoded as zero
            self.noncanonical();
            Ok(0.0)
        }
        else if value.is_finite() {
            Ok(value)
        }
        else {
            Err(Error::custom("DAG-CBOR forbids NaN and infinities"))
        }
    }

    fn decode_string(&mut self) -> Result<Cow<'de, str>, Error> {
        str::from_utf8(self.decode_payload(Major::String)?)
            .map_or_else(|_| Err(Error::custom("utf-8 parsing")), |s| Ok(Cow::Borrowed(s)))
    }

    fn decode_bytes(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        Ok(Cow::Borrowed(self.decode_payload(Major::Bytes)?))
    }

    fn decode_link(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        let tag = self.decode_head(Major::Tag)?;
        if tag != u64::from(CID_TAG) {
            return Err(Error::invalid_value(
                Unexpected::Other("non-link tag"), &"tag 42 (CID)"
            ));
        }
        // Binary CIDs are prefixed with the identity multibase, 0x00
        match self.decode_payload(Major::Bytes)?.split_first() {
            Some((0, cid)) => Ok(Cow::Borrowed(cid)),
            _ => Err(Error::custom("CID missing its 0x00 multibase prefix")),
        }
    }
}

// CBOR doesn't need separate structs for list/map.
pub struct Container<'de> {
    size: usize,
    /// The previous map key, to check they're sorted and unique.
    last: Option<Cow<'de, str>>,
}

impl SizeHint for Container<'_> {
    fn size_hint(&self) -> Option<usize> {
        Some(self.size)
    }
}

impl<'de> ListDecoder<'de, Deserializer<'de>> for Container<'de> {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        Ok(Self { size: dec.decode_len(Major::Array)?, last: None })
    }

    fn has_next(&self, _: &mut Deserializer<'de>) -> Result<bool, Error> {
        // If the harness expects a value, we can always read more. DAG-CBOR
        // forbids the break marker/indefinite-length containers.
        Ok(true)
    }

    fn end(&mut self, _: &mut Deserializer<'de>) -> Result<(), Error> {
        Ok(())
    }
}

impl<'de> MapDecoder<'de, Deserializer<'de>> for Container<'de> {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        Ok(Self { size: dec.decode_len(Major::Map)?, last: None })
    }

    fn key(&mut self, dec: &mut Deserializer<'de>)
        -> Result<Option<Cow<'de, str>>, Error>
    {
        let key = dec.decode_string()?;
        // Keys sort by length, then bytewise
        let order = |k: &str| (k.len(), k.as_bytes().to_vec());
        if let Some(last) = &self.last {
            match order(last).cmp(&order(&key)) {
                std::cmp::Ordering::Less => (),
                std::cmp::Ordering::Equal => return Err(Error::custom(format_args!(
                    "duplicate map key {key:?}"
                ))),
                std::cmp::Ordering::Greater => dec.noncanonical(),
            }
        }
        self.last = Some(key.clone());
        Ok(Some(key))
    }

    fn end(&mut self, _dec: &mut Deserializer<'de>) -> Result<(), Error> {
        Ok(())
    }
}
