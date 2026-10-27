use std::{borrow::Cow, fmt::Display};

use serde::de::{Error as _};
use nonempty::NonEmpty;

use crate::{dagpb::proto::{DagPb, DataType, FieldType, RawUnixfsv1, Unixfsv1}, serde::{Decoder, Error, Kind, ListDecoder, MapDecoder, SizeHint}, varint};

use super::proto::{TypeId, FieldId, Field, Msg};

fn split_tag(tag: u8) -> (TypeId, FieldId) {
    (TypeId::new(tag), FieldId::new(tag))
}

pub struct Deserializer<'de> {
    /// Stack of message frames
    stack: NonEmpty<&'de [u8]>,
    /// Current message.
    msg: Msg,
    /// Index into the repeated field, or -1 
    index: Option<u32>,
}
impl<'de> Deserializer<'de> {
    fn new(buffer: &'de [u8]) -> Self {
        Self {
            stack: NonEmpty::new(buffer),
            msg: Msg::Init,
            index: None,
        }
    }

    fn buffer(&self) -> &'de [u8] { self.stack.last() }
    
    fn buffer_mut(&mut self) -> &mut &'de [u8] {
        self.stack.last_mut()
    }

    fn msg(&self) -> Msg { self.msg }

    /// Peek the next field without checking if the field's type is correct.
    fn field(&mut self, tag: u8) -> Result<Field, Error> {
        let (t, f) = split_tag(tag);
        let field = self.msg().field(f)
            .ok_or_else(|| self.error(format_args!(
                "unknown field `{:?}`", f
            )))?;
        let t = t.try_into()?;
        if field.field_type() != t {
            Err(self.error_in(field, format_args!(
                "invalid type: {t:?}, expected {:?} (int)", field.field_type()
            )))
        }
        else {
            Ok(field)
        }
    }

    /// Peek at the next field converting EOF to an error.
    fn peek_field(&mut self) -> Result<Field, Error> {
        let tag = self.peek().ok_or_else(|| self.eof())?;
        self.field(tag)
    }

    /// Retrieve the next field, advancing the cursor.
    fn next_field(&mut self) -> Result<Field, Error> {
        let tag = self.advance()?;
        self.field(tag)
    }

    fn peek(&self) -> Option<u8> {
        self.buffer().get(0).copied()
    }

    /// Advance the cursor by 1.
    fn advance(&mut self) -> Result<u8, Error> {
        self.buffer_mut()
            .split_off_first()
            .ok_or_else(|| self.eof())
            .copied()
    }
    
    /// Get a known number of bytes and advance the cursor.
    fn get_chunk<const N: usize>(&mut self) -> Result<&[u8; N], Error> {
        let buf = self.buffer_mut();
        match buf.split_first_chunk() {
            Some((chunk, cursor)) => {
                *buf = cursor;
                Ok(chunk)
            },
            None => Err(self.eof())
        }
    }

    /// Get a slice with n bytes and advance the cursor.
    fn get_slice(&mut self, n: usize) -> Result<&'de [u8], Error> {
        match self.buffer_mut().split_off(..n) {
            Some(slice) => Ok(slice),
            None => Err(self.eof()),
        }
    }

    /// Read an leb128 varint (most common in protobuf).
    fn read_int(&mut self, field: Field) -> Result<u64, Error> {
        varint::read(self.buffer_mut())
            .map_err(|e| match e {
                varint::Error::Truncated => self.error_in(field, "eof"),
                varint::Error::Overflow =>
                    self.error_in(field, "varint overflow"),
            })
    }

    /// Read a bytes-like given its field.
    fn read_len_field(&mut self, field: Field) -> Result<&'de [u8], Error> {
        match field.field_type() {
            FieldType::Length => {
                let len = self.read_int(field)?
                    .try_into()
                    .map_err(|_| self.error_in(field, "length too big"))?;
                Ok(self.get_slice(len)?)
            },
            _ => Err(self.error_in(field, format_args!(
                "invalid type: {:?}, expected Length", field.field_type()
            )))
        }
    }

    /// Enter a message frame.
    fn enter_msg(&mut self, msg: Msg, buffer: &'de [u8]) {
        self.msg = msg;
        self.stack.push(buffer)
    }

    /// Exit a message frame.
    fn exit_msg(&mut self) {
        let _buf = self.stack.pop();
        self.msg = self.msg().parent();
    }

    fn eof(&self) -> Error {
        self.error("eof")
    }

    /// Error between fields.
    fn error<T: Display>(&self, msg: T) -> Error {
        let path = self.msg.path();
        match self.index {
            Some(idx) => Error::custom(format_args!("{path}[{idx}]: {msg}")),
            None => Error::custom(format_args!("{path}: {msg}")),
        }
    }

    /// Error while parsing a field.
    fn error_in<T: Display>(&self, field: Field, msg: T) -> Error {
        let (path, field) = (self.msg.path(), field.name());
        match (self.msg, self.index) {
            (_, None) => Error::custom(format_args!("{path}.{field}: {msg}")),
            (Msg::Data, Some(idx)) => Error::custom(format_args!(
                "{path}.{field}[{idx}]: {msg}"
            )),
            (_, Some(idx)) => Error::custom(format_args!(
                "{path}[{idx}].{field}: {msg}"
            )),
        }
    }
}

impl<'de> Decoder<'de> for Deserializer<'de> {
    type ListDecoder = Repeated;
    type MapDecoder = Message;

    fn peek_kind(&mut self) -> Result<Kind, Error> {
        Ok(match self.msg() {
            // Need to treat the outermost message specially because it
            // doesn't have a tag or length.
            Msg::Init => Kind::Map,
            _ => self.peek_field()?.kind(),
        })
    }

    fn skip(&mut self) -> Result<(), Error> {
        if self.buffer().len() == 0 {
            return Err(self.eof())
        }

        Ok(if self.msg() == Msg::Init {
            // Asking to skip the entire object.
            self.buffer_mut().split_off(0..);
        }
        else {
            let field = self.next_field()?;
            match field.field_type() {
                FieldType::Varint => { self.read_int(field)?; },
                FieldType::Fixed64 => { self.get_slice(8)?; },
                FieldType::Length => {
                    let len = self.read_int(field)?
                        .try_into()
                        .map_err(|_| self.error_in(field, "length too big"))?;
                    self.get_slice(len)?;
                },
                FieldType::Fixed32 => { self.get_slice(4)?; },
            }
        })
    }

    fn is_human_readable() -> bool { false }

    fn decode_int(&mut self) -> Result<i128, Error> {
        let field = self.next_field()?;
        let n = match field.field_type() {
            FieldType::Fixed32 => {
                u32::from_le_bytes(*self.get_chunk()?) as i128
            },
            FieldType::Fixed64 => {
                u64::from_le_bytes(*self.get_chunk()?) as i128
            },
            FieldType::Varint => {
                let i = self.read_int(field)?;
                // This is the only signed field
                if field == Field::Seconds {
                    i as i64 as i128
                }
                else {
                    i as i128
                }
            },
            FieldType::Length => return Err(Error::custom(format_args!(
                "invalid type: Length, expected int"
            ))),
        };
        Ok(n)
    }

    fn decode_string(&mut self) -> Result<Cow<'de, str>, Error> {
        let field = self.next_field()?;
        let s = str::from_utf8(self.read_len_field(field)?)
            .map_err(|_| self.error_in(field, "invalid utf-8"))?;

        Ok(Cow::Borrowed(s))
    }
    
    fn decode_bytes(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        let field = self.next_field()?;
        self.read_len_field(field)
            .map(Cow::Borrowed)
    }
    
    fn decode_link(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        self.decode_bytes()
    }

    fn decode_null(&mut self) -> Result<(), Error> {
        Err(self.error("null not valid in dag-pb"))
    }

    fn decode_bool(&mut self) -> Result<bool, Error> {
        Err(self.error("bool not valid in dag-pb"))
    }

    fn decode_float(&mut self) -> Result<f64, Error> {
        Err(self.error("float not valid in dag-pb"))
    }
}

struct Repeated {
    /// Field being repeated.
    field: Field,
}
impl SizeHint for Repeated  {
    fn size_hint(&self) -> Option<usize> { None }
}

impl<'de> ListDecoder<'de, Deserializer<'de>> for Repeated {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        Ok(Self { field: dec.peek_field()? })
    }

    fn has_next(&self, dec: &mut Deserializer<'de>) -> Result<bool, Error> {
        match dec.index.as_mut() {
            Some(idx) => *idx += 1,
            None => dec.index = Some(0),
        }

        // Expect more elements until either the field differs or the outer
        // message is exhausted (peek == None).
        Ok(match dec.peek() {
            Some(tag) => self.field == dec.field(tag)?,
            None => false
        })
    }

    fn end(&mut self, dec: &mut Deserializer<'de>) -> Result<(), Error> {
        dec.index = None;
        Ok(())
    }
}

struct Message;
impl SizeHint for Message {
    fn size_hint(&self) -> Option<usize> { None }
}
impl<'de> MapDecoder<'de, Deserializer<'de>> for Message {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        // Messages in protobuf are technically just byte strings.
        let field = dec.next_field()?;
        let msg = field
            .contains_msg()
            .ok_or_else(|| dec.error("cannot decode as map"))?;
        let buffer = dec.read_len_field(field)?;
        dec.enter_msg(msg, buffer);
        Ok(Self)
    }

    fn key(&mut self, dec: &mut Deserializer<'de>)
        -> Result<Option<Cow<'de, str>>, Error>
    {
        Ok(match dec.peek() {
            Some(tag) => Some(Cow::Borrowed(dec.field(tag)?.name())),
            None => None
        })
    }

    fn end(&mut self, dec: &mut Deserializer<'de>) -> Result<(), Error> {
        dec.exit_msg();
        Ok(())
    }
}

pub fn deserialize<'de>(buffer: &'de [u8])
    -> Result<DagPb<Unixfsv1<'de>>, Error>
{
    let dec = Deserializer::new(buffer);
    let node: DagPb<'_, RawUnixfsv1> = crate::serde::deserialize(dec)?;
    let data = node.data;

    // Post-parsing validation
    if node.links.len() != data.blocksizes.as_ref().map_or(0, Vec::len) {
        return Err(Error::custom(
            "lengths of Links[] and Data.blocksizes[] don't match"
        ))
    }
    
    match data.data_type {
        DataType::File => for link in node.links.iter() {
            if link.name != "" {
                return Err(Error::custom(format_args!(
                    "file has non-empty link name `{}`", link.name
                )))
            }
        },
        DataType::Directory => for link in node.links.iter() {
            match link.name {
                name @ ("" | "." | "..") =>
                    return Err(Error::custom(format_args!(
                        "forbidden filename `{name}`"
                    ))),
                _ => continue,
            }
        },
        _ => ()
    }
    Ok(DagPb {
        data: data.try_into()?,
        links: node.links,
    })
}