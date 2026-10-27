use std::borrow::Cow;

use serde::de::{ Error as _, Unexpected };

use crate::{dagcbor::Size, serde::{Decoder, Error, Kind, ListDecoder, MapDecoder, SizeHint}};

use super::{Major, marker, CID_TAG};

/// Get the name of the type corresponding to the tag.
fn tag_name(byte: u8) -> &'static str {
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
    cursor: &'de [u8],
    peek: u8,
    canon: bool,
}

impl<'de> Deserializer<'de> {
    pub fn new(peek: u8, cursor: &'de [u8]) -> Option<Self> {
        Some(Deserializer {
            cursor,
            peek,
            canon: true,
        })
    }

    /// Mark the parsed value as noncanonical.
    fn noncanonical(&mut self) { self.canon = false; }

    /// Peek at the next byte without advancing the cursor.
    fn peek(&self) -> u8 { self.peek }

    /// Advance the cursor by 1.
    fn advance(&mut self) -> Result<u8, Error> {
        match self.cursor.split_off_first() {
            Some(&p) => Ok(std::mem::replace(&mut self.peek, p)),
            None => Err(Error::custom("eof"))
        }
    }
    
    fn get_chunk<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        match self.cursor.split_first_chunk() {
            Some((&chunk, cursor)) => {
                self.cursor = cursor;
                Ok(chunk)
            },
            None => Err(Error::custom("eof"))
        }
    }
    fn get_slice(&mut self, n: usize) -> Result<&'de [u8], Error> {
        match self.cursor.split_at_checked(n) {
            Some((left, right)) => {
                self.cursor = right;
                Ok(left)
            }
            None => Err(Error::custom("eof"))
        }
    }

    fn check_minimal<T>(&mut self, min: T, count: T) -> u64
        where T: Ord + Into<u64>
    {
        if count < min {
            self.noncanonical();
        }
        count.into()
    }

    /// Decode the count field as an integer without checking the major.
    fn decode_count(&mut self) -> Result<u64, Error> {
        Ok(match Size::from_tag(self.advance()?) {
            Some(Size::Inline(sz)) => sz as u64,
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
        }.try_into().expect("fits target"))
    }

    /// Decode a CBOR count expecting a given major field.
    fn decode_head(&mut self, major: Major) -> Result<u64, Error> {
        let byte = self.peek();
        if Major::from_byte(byte) != major {
            return Err(Error::custom(format_args!(
                "invalid type: {}, expected {major:?}", tag_name(byte)
            )));
        }
        self.decode_count()
    }

    /// Decode a CBOR len, an Option<count>
    fn decode_len(&mut self, major: Major) -> Result<Option<usize>, Error> {
        if self.peek() == major.start() {
            self.advance();
            Ok(None)
        }
        else {
            match self.decode_count()?.try_into() {
                Ok(len) => Ok(Some(len)),
                Err(_) => Err(Error::custom("usize overflow")),
            }
        }
    }

    fn skip(&mut self, count: usize) -> Result<(), Error> {
        Ok(match self.cursor.split_at_checked(count) {
            Some(([.., peek], right)) => {
                self.cursor = right;
                self.peek = *peek;
            },
            Some(([], _)) => (), // skip 0
            None => return Err(Error::custom("eof")),
        })
    }

    fn is_break(&mut self) -> bool {
        if self.peek() == marker::BREAK {
            self.advance();
            true
        }
        else {
            false
        }
    }
}

impl<'de> Decoder<'de> for Deserializer<'de> {
    type ListDecoder = Container;
    type MapDecoder = Container;

    fn peek_kind(&mut self) -> Result<Kind, Error> {
        let byte = self.peek();
        Ok(match Major::from_byte(byte) {
            Major::Positive | Major::Negative => Kind::Int,
            Major::Bytes => Kind::Bytes,
            Major::String => Kind::String,
            Major::Array => Kind::List,
            Major::Map => Kind::Map,
            Major::Tag => Kind::Link,
            Major::Simple => match byte {
                marker::NULL | marker::UNDEFINED => Kind::Null,
                marker::TRUE | marker::FALSE => Kind::Bool,
                marker::F16 | marker::F32 | marker::F64 => Kind::Float,
                _ => return Err(Error::custom("unknown kind"))
            }
        })
    }

    fn skip(&mut self) -> Result<(), Error> {
        let byte = self.peek();
        match Major::from_byte(byte) {
            // Atomic
            Major::Positive | Major::Negative =>
                self.skip(Size::from_tag(byte)
                    .ok_or_else(|| Error::custom(format_args!(
                        "got <garbage {byte:x}> during ignored-any"
                    )))?.extra_size()),
            Major::Tag => {
                // Consume tags until we find an actual value
                let _tag: u64 = self.decode_head(Major::Tag)?;
                Decoder::skip(self)
            },
            Major::Simple => {
                self.skip(match byte {
                    marker::FALSE | marker::TRUE | marker::NULL => 0,
                    marker::F16 => 2,
                    marker::F32 => 4,
                    marker::F64 => 8,
                    byte => return Err(Error::custom(format_args!(
                        "got <garbage {byte:x}> during ignored-any"
                    )))
                })
            },

            // Definite length Bytes, String, Array, Map
            major if let Some(len) = self.decode_len(major)? =>
                Ok(match major {
                    Major::Bytes | Major::String => self.skip(len)?,
                    Major::Array => for _ in 0..len {
                        Decoder::skip(self)?;
                    },
                    Major::Map => for _ in 0..len {
                        Decoder::skip(self)?;
                        Decoder::skip(self)?;
                    },
                    _ => unreachable!("major types exhausted"),
                }),
            
            major => Err(Error::custom(format_args!(
                "indefinite-length {major:?}"
            ))),
        }
    }

    fn is_human_readable() -> bool { false }

    fn decode_null(&mut self) -> Result<(), Error> {
        match self.peek() {
            marker::NULL => Ok(()),
            _ => Err(Error::invalid_type(
                Unexpected::Option, &"null"
            )),
        }
    }

    fn decode_bool(&mut self) -> Result<bool, Error> {
        match self.peek() {
            marker::TRUE => Ok(true),
            marker::FALSE => Ok(false),
            byte => Err(Error::custom(format_args!(
                "invalid type: {}, expected bool", tag_name(byte)
            ))),
        }
    }

    fn decode_int(&mut self) -> Result<i128, Error> {
        let byte = self.peek();
        Ok(match Major::from_byte(byte) {
            Major::Positive => {
                let count: u64 = self.decode_count()?;
                count as i128
            },
            Major::Negative => {
                let count: u64 = self.decode_count()?;
                let count = count as i128;
                -count - 1
            },
            _ => return Err(Error::custom(format_args!(
                "invalid type: {}, expected int", tag_name(byte)
            ))),
        })
    }

    fn decode_float(&mut self) -> Result<f64, Error> {
        Ok(match self.peek() {
            marker::F16 => {
                self.advance();
                self.noncanonical();
                let data = i16::from_be_bytes(self.get_chunk()?);
                let sign = data.signum() as f64;
                let frac = data & 0x3ff;
                sign * match (data >> 10) & 0x1f {
                    // Subnormal sign * (frac / 2^10) * 2^-14
                    0 => (frac as f64) * 2.0f64.powi(-24),
                    // Non-finite
                    0x1f => if frac == 0 { f64::INFINITY } else { f64::NAN },
                    exp => // Ordinary float
                        (1.0 + frac as f64 / 1024.0)
                        * 2.0f64.powi(exp as i32 - 15),
                }
            },
            marker::F32 => {
                self.advance();
                self.noncanonical();
                f32::from_be_bytes(self.get_chunk()?) as f64
            },
            marker::F64 => {
                self.advance();
                f64::from_be_bytes(self.get_chunk()?)
            },
            byte => return Err(Error::custom(format_args!(
                "invalid type: {}, expected float", tag_name(byte)
            ))),
        })
    }

    fn decode_string(&mut self) -> Result<Cow<'de, str>, Error> {
        if let Some(len) = self.decode_len(Major::String)? {
            if let Some(chunk) = self.cursor.get(..len) {
                match str::from_utf8(chunk) {
                    Ok(s) => Ok(Cow::Borrowed(s)),
                    Err(_) => Err(Error::custom("utf-8 parsing")),
                }
            }
            else {
                Err(Error::custom("eof while parsing string"))
            }
        }
        else {
            Err(Error::custom("indefinite-length string"))
        }
    }

    fn decode_bytes(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        if let Some(len) = self.decode_len(Major::Bytes)? {
            match self.cursor.get(..len) {
                Some(bs) => Ok(Cow::Borrowed(bs)),
                None => Err(Error::custom("eof while parsing bytes")),
            }
        }
        else {
            Err(Error::invalid_value(
                Unexpected::Other("indefinite-length bytes"),
                &"bytes",
            ))
        }
    }

    fn decode_link(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        let tag = self.decode_head(Major::Tag)?;
        if tag == CID_TAG as u64 {
            self.decode_bytes()
        }
        else {
            Err(Error::invalid_value(
                Unexpected::Other("non-link tag"), &"link"
            ))
        }
    }
}

// CBOR doesn't need separate structs for list/map.
pub struct Container {
    size: usize,
}

impl SizeHint for Container {
    fn size_hint(&self) -> Option<usize> {
        Some(self.size)
    }
}

impl<'de> ListDecoder<'de, Deserializer<'de>> for Container {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        match dec.decode_len(Major::Array)? {
            Some(size) => Ok(Self { size }),
            None => Err(Error::custom("indefinite-length array"))
        }
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

impl<'de> MapDecoder<'de, Deserializer<'de>> for Container {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        match dec.decode_len(Major::Map)? {
            Some(size) => Ok(Self { size }),
            None => Err(Error::custom("indefinite-length map"))
        }
    }

    fn key(&mut self, dec: &mut Deserializer<'de>)
        -> Result<Option<Cow<'de, str>>, Error>
    {
        Ok(Some(dec.decode_string()?))
    }

    fn end(&mut self, _dec: &mut Deserializer<'de>) -> Result<(), Error> {
        Ok(())
    }
}
