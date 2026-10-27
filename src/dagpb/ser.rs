use std::fmt::Display;

use nonempty::NonEmpty;
use serde::ser::{Error as _};

use super::proto::{Field};

use crate::{dagpb::proto::{FieldType, Msg}, serde::{Encoder, Error, ListEncoder, MapEncoder}, varint};

pub struct Serializer {
    /// Stack of message prefixes.
    stack: NonEmpty<Vec<u8>>,
    /// Message the serializer is currently in.
    msg: Msg,
    /// Field currently being serialized.
    field: Option<Field>,
    /// Index of the repeate field we're inside.
    index: Option<u32>,
}
impl Serializer {
    pub fn new() -> Self {
        Serializer {
            stack: NonEmpty::new(Vec::new()),
            msg: Msg::Init,
            field: None,
            index: None,
        }
    }

    fn buffer_mut(&mut self) -> &mut Vec<u8> {
        self.stack.last_mut()
    }

    fn write_u8(&mut self, value: u8) {
        self.buffer_mut().push(value)
    }

    fn write_u32(&mut self, value: u32) {
        self.buffer_mut().extend_from_slice(&value.to_be_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.buffer_mut().extend_from_slice(&value.to_be_bytes());
    }

    fn write_slice(&mut self, slice: &[u8]) {
        self.buffer_mut().extend_from_slice(slice);
    }

    /// Encode a varint
    fn write_int(&mut self, value: u64) {
        varint::write(self.buffer_mut(), value)
    }

    /// Write a value which is length-delimited.
    fn write_len(&mut self, value: &[u8]) -> Result<(), Error> {
        let field = self.write_field()?;
        if field.field_type() != FieldType::Length {
            Err(self.error_in(field, "not a length field"))
        }
        else {
            self.write_int(value.len()
                .try_into()
                .map_err(|_| self.error_in(field, "too long"))?
            );
            Ok(self.write_slice(value))
        }
    }

    /// Signal that we are entering a field.
    fn enter_field(&mut self, field: Field) {
        self.field = Some(field)
    }

    /// Expect that we are already inside a field.
    fn expect_field(&mut self) -> Result<Field, Error> {
        self.field
            .take()
            .ok_or_else(|| self.error("missing field"))
    }

    /// Try to enter a message, returning the field we just entered.
    fn enter_message(&mut self) -> Result<Field, Error> {
        let field = self.expect_field()?;
        self.stack.push(Vec::new());
        self.msg = field.contains_msg()
            .ok_or_else(|| self.error_in(field, "not a message"))?;
        Ok(field)
    }

    /// Exit a message with the field that contained it.
    fn exit_message(&mut self, field: Field) {
        let data = self.stack.pop().unwrap();
        self.msg = self.msg.parent();
        self.enter_field(field);
        self.write_len(&data);
    }

    /// Write the field tag, returning the field for validation.
    fn write_field(&mut self) -> Result<Field, Error> {
        let field = self.expect_field()?;
        self.write_u8(field.tag());
        Ok(field)
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

impl Encoder for Serializer {
    type ListEncoder = Repeated;
    type MapEncoder = Message;

    fn encode_null(&mut self) -> Result<(), Error> {
        self.expect_field()?;
        // Needs to be a no-op for optional fields.
        Ok(())
    }

    fn encode_int(&mut self, value: i128) -> Result<(), Error> {
        let field = self.write_field()?;
        Ok(match field.field_type() {
            FieldType::Fixed64 => self.write_u64(value as u64),
            FieldType::Varint => self.write_int(value as u64),
            FieldType::Fixed32 => self.write_u32(value as u32),
            FieldType::Length => return Err(
                self.error_in(field, "not an int")
            ),
        })
    }

    fn encode_string(&mut self, value: &str) -> Result<(), Error> {
        self.write_len(value.as_bytes())
    }

    fn encode_bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        self.write_len(value)
    }

    fn encode_link(&mut self, value: &[u8]) -> Result<(), Error> {
        self.write_len(value)
    }

    fn encode_bool(&mut self, _value: bool) -> Result<(), Error> {
        Err(self.error("bool not valid in dag-pb"))
    }

    fn encode_float(&mut self, _value: f64) -> Result<(), Error> {
        Err(self.error("float not valid in dag-pb"))
    }
}

struct Repeated {
    /// The field of this collection.
    field: Field,
}

impl ListEncoder<Serializer> for Repeated {
    fn begin(enc: &mut Serializer, _size: Option<usize>)
        -> Result<Self, Error>
    {
        Ok(Self {
            field: enc.expect_field()?,
        })
    }

    fn element(&mut self, enc: &mut Serializer) -> Result<(), Error> {
        Ok(enc.enter_field(self.field))
    }

    fn end(self, _enc: &mut Serializer) -> Result<(), Error> {
        // Lists don't need to end anything
        Ok(())
    }
}

struct Message {
    /// The field that contains this message.
    field: Field,
}

impl MapEncoder<Serializer> for Message {
    fn begin(enc: &mut Serializer, _size: Option<usize>) -> Result<Self, Error> {
        Ok(Self {
            field: enc.enter_message()?,
        })
    }

    fn key(&mut self, enc: &mut Serializer, key: &str) -> Result<(), Error> {
        Ok(enc.enter_field(match (enc.msg, key) {
            (Msg::Node, "Data") => Field::Data,
            (Msg::Node, "Links") => Field::Links,
            
            (Msg::Link, "Hash") => Field::Hash,
            (Msg::Link, "Name") => Field::Name,
            (Msg::Link, "Tsize") => Field::Tsize,

            (Msg::Data, "Type") => Field::Type,
            (Msg::Data, "Data") => Field::UData,
            (Msg::Data, "filesize") => Field::Filesize,
            (Msg::Data, "blocksizes") => Field::Blocksizes,
            (Msg::Data, "hashType") => Field::HashType,
            (Msg::Data, "fanout") => Field::Fanout,
            (Msg::Data, "mode") => Field::Mode,
            (Msg::Data, "mtime") => Field::Mtime,

            (Msg::UnixTime, "Seconds") => Field::Seconds,
            (Msg::UnixTime, "FractionalNanoseconds") =>
                Field::FractionalNanoseconds,
            
            (_, key) => return Err(enc.error(format_args!(
                "unknown key `{key}`"
            )))
        }))
    }

    fn end(self, enc: &mut Serializer) -> Result<(), Error> {
        Ok(enc.exit_message(self.field))
    }
}