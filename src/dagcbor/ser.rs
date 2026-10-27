use serde::ser::{Error as _};

use super::{CID_TAG, Major, marker};

use crate::{dagcbor::Size, serde::{Encoder, Error, ListEncoder, MapEncoder}};

/// Encode a length as an array.
fn encode_len(major: Major, v: u64) -> (usize, [u8; 9]) {
    let mut buf = [0u8; 9];
    let size = Size::from_payload(v);
    buf[0] = major.initial(size.to_ai());
    match size {
        Size::Count1 => buf[1] = v as u8,
        Size::Count2 => buf[1..].copy_from_slice(&(v as u16).to_be_bytes()),
        Size::Count4 => buf[1..].copy_from_slice(&(v as u32).to_be_bytes()),
        Size::Count8 => buf[1..].copy_from_slice(&(v as u64).to_be_bytes()),
        Size::Inline(_) => (),
    }
    (1 + size.extra_size(), buf)
}

/// Cursor used to insert head bytes before containers.
struct Cursor {
    index: usize,
    size: u64,
}

pub struct Serializer {
    output: Vec<u8>,
}
impl Serializer {
    pub fn new() -> Serializer {
        Serializer { output: Vec::new() }
    }

    fn write_u8(&mut self, value: u8) { self.output.push(value) }

    fn write_slice(&mut self, slice: &[u8]) {
        self.output.extend_from_slice(slice);
    }

    /// Encode a length given a major value. All composites use this format.
    fn write_len(&mut self, major: Major, value: u64) {
        let (len, buf) = encode_len(major, value);
        self.write_slice(&buf[..len]);
    }

    fn enter_container(&self) -> Cursor {
        Cursor {
            index: self.output.len(),
            size: 0,
        }
    }

    fn exit_container(&mut self, major: Major, cur: Cursor) {
        let Cursor { index, size } = cur;
        let (len, buf) = encode_len(major, size);
        self.output.splice(index..index, buf[..len].iter().copied());
    }
}

impl Encoder for Serializer {
    type ListEncoder = Collection;
    type MapEncoder = Collection;

    fn encode_null(&mut self) -> Result<(), Error> {
        Ok(self.write_u8(marker::NULL))
    }

    fn encode_bool(&mut self, value: bool) -> Result<(), Error> {
        Ok(self.write_u8(if value { marker::TRUE } else { marker::FALSE }))
    }

    fn encode_int(&mut self, value: i128) -> Result<(), Error> {
        let (major, value) = if value < 0 {
            (Major::Negative, -value - 1)
        }
        else {
            (Major::Positive, value)
        };

        match value.try_into() {
            Ok(value) => Ok(self.write_len(major, value)),
            Err(_) => Err(Error::custom("out of range")),
        }
    }

    fn encode_float(&mut self, value: f64) -> Result<(), Error> {
        self.write_u8(marker::F64);
        Ok(self.write_slice(&value.to_be_bytes()))
    }

    fn encode_string(&mut self, value: &str) -> Result<(), Error> {
        self.write_len(Major::String, value.len()
            .try_into()
            .map_err(|_| Error::custom("string too long"))?
        );
        Ok(self.write_slice(&value.as_bytes()))
    }

    fn encode_bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        self.write_len(Major::String, value.len()
            .try_into()
            .map_err(|_| Error::custom("bytes too long"))?
        );
        Ok(self.write_slice(value))
    }

    fn encode_link(&mut self, value: &[u8]) -> Result<(), Error> {
        self.write_len(Major::Tag, CID_TAG as u64);
        Ok(self.write_slice(value))
    }
}

struct Collection {
    cur: Option<Cursor>,
}
impl Collection {
    fn begin(enc: &mut Serializer, size: Option<usize>, major: Major)
        -> Result<Self, Error>
    {
        // Set it up so if we know the size ahead of time, we don't have to
        // adjust the size later.
        Ok(match size {
            Some(size) => {
                enc.write_len(major, size
                    .try_into()
                    .map_err(|_| Error::custom(format_args!(
                        "{major:?} too long"
                    )))?
                );
                Self { cur: None }
            },
            None => Self { cur: Some(enc.enter_container()) },
        })
    }

    fn end(self, enc: &mut Serializer, major: Major) {
        if let Some(cur) = self.cur {
            enc.exit_container(major, cur);
        }
    }
}

impl ListEncoder<Serializer> for Collection {
    fn begin(enc: &mut Serializer, size: Option<usize>)
        -> Result<Self, Error>
    {
        Self::begin(enc, size, Major::Array)
    }

    fn element(&mut self, _enc: &mut Serializer) -> Result<(), Error> {
        Ok(if let Some(cur) = self.cur.as_mut() {
            cur.size += 1;
        })
    }

    fn end(self, enc: &mut Serializer) -> Result<(), Error> {
        Ok(self.end(enc, Major::Array))
    }
}

impl MapEncoder<Serializer> for Collection {
    fn begin(enc: &mut Serializer, size: Option<usize>) -> Result<Self, Error> {
        Self::begin(enc, size, Major::Map)
    }

    fn key(&mut self, enc: &mut Serializer, key: &str) -> Result<(), Error> {
        if let Some(cur) = self.cur.as_mut() {
            cur.size += 1;
        }
        enc.encode_string(key)
    }

    fn end(self, enc: &mut Serializer) -> Result<(), Error> {
        Ok(self.end(enc, Major::Map))
    }
}