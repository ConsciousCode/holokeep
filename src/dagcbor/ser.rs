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
        Size::Count2 => buf[1..3].copy_from_slice(&(v as u16).to_be_bytes()),
        Size::Count4 => buf[1..5].copy_from_slice(&(v as u32).to_be_bytes()),
        Size::Count8 => buf[1..9].copy_from_slice(&v.to_be_bytes()),
        Size::Inline(_) => (),
    }
    (1 + size.extra_size(), buf)
}

/// Cursor used to insert head bytes before containers.
struct Cursor {
    index: usize,
    size: u64,
}

/// A map being serialized. Each entry is buffered so they can be sorted.
struct MapFrame {
    /// The output the map is being written into, set aside meanwhile.
    parent: Vec<u8>,
    /// Finished (encoded key, encoded value) entries.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// The encoded key whose value is being written to the output.
    key: Option<Vec<u8>>,
}

pub struct Serializer {
    pub(super) output: Vec<u8>,
    maps: Vec<MapFrame>,
}

impl Default for Serializer {
    fn default() -> Self { Self::new() }
}

impl Serializer {
    pub fn new() -> Serializer {
        Serializer { output: Vec::new(), maps: Vec::new() }
    }

    /// Get the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> { self.output }

    fn write_u8(&mut self, value: u8) { self.output.push(value) }

    fn write_slice(&mut self, slice: &[u8]) {
        self.output.extend_from_slice(slice);
    }

    /// Encode a length given a major value. All composites use this format.
    fn write_len(&mut self, major: Major, value: u64) {
        let (len, buf) = encode_len(major, value);
        self.write_slice(&buf[..len]);
    }

    fn write_payload(&mut self, major: Major, value: &[u8]) -> Result<(), Error> {
        self.write_len(major, value.len()
            .try_into()
            .map_err(|_| Error::custom(format_args!("{major:?} too long")))?
        );
        self.write_slice(value);
        Ok(())
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

    /// The value of the current map entry is complete.
    fn close_entry(&mut self) {
        if let Some(frame) = self.maps.last_mut()
            && let Some(key) = frame.key.take()
        {
            frame.entries.push((key, std::mem::take(&mut self.output)));
        }
    }
}

impl Encoder for Serializer {
    type ListEncoder = List;
    type MapEncoder = Map;

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
        if !value.is_finite() {
            return Err(Error::custom("DAG-CBOR forbids NaN and infinities"));
        }
        // Always 64 bit, even when a shorter float would be exact
        self.write_u8(marker::F64);
        Ok(self.write_slice(&value.to_be_bytes()))
    }

    fn encode_string(&mut self, value: &str) -> Result<(), Error> {
        self.write_payload(Major::String, value.as_bytes())
    }

    fn encode_bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        self.write_payload(Major::Bytes, value)
    }

    fn encode_link(&mut self, value: &[u8]) -> Result<(), Error> {
        // Tag 42 around the binary CID with an identity multibase prefix
        self.write_len(Major::Tag, CID_TAG.into());
        let len = value.len().checked_add(1)
            .and_then(|len| u64::try_from(len).ok())
            .ok_or_else(|| Error::custom("CID too long"))?;
        self.write_len(Major::Bytes, len);
        self.write_u8(0);
        Ok(self.write_slice(value))
    }
}

pub struct List {
    /// Only for lists of unknown length, which get their head at the end.
    cur: Option<Cursor>,
}

impl ListEncoder<Serializer> for List {
    fn begin(enc: &mut Serializer, size: Option<usize>)
        -> Result<Self, Error>
    {
        // Set it up so if we know the size ahead of time, we don't have to
        // adjust the size later.
        Ok(match size {
            Some(size) => {
                enc.write_len(Major::Array, size
                    .try_into()
                    .map_err(|_| Error::custom("Array too long"))?
                );
                Self { cur: None }
            },
            None => Self { cur: Some(enc.enter_container()) },
        })
    }

    fn element(&mut self, _enc: &mut Serializer) -> Result<(), Error> {
        Ok(if let Some(cur) = self.cur.as_mut() {
            cur.size += 1;
        })
    }

    fn end(self, enc: &mut Serializer) -> Result<(), Error> {
        if let Some(cur) = self.cur {
            enc.exit_container(Major::Array, cur);
        }
        Ok(())
    }
}

pub struct Map;

impl MapEncoder<Serializer> for Map {
    fn begin(enc: &mut Serializer, _size: Option<usize>) -> Result<Self, Error> {
        // The head comes after sorting, when the size is known anyway
        let parent = std::mem::take(&mut enc.output);
        enc.maps.push(MapFrame { parent, entries: Vec::new(), key: None });
        Ok(Map)
    }

    fn key(&mut self, enc: &mut Serializer, key: &str) -> Result<(), Error> {
        enc.close_entry();
        enc.encode_string(key)?;
        let key = std::mem::take(&mut enc.output);
        if let Some(frame) = enc.maps.last_mut() {
            frame.key = Some(key);
        }
        Ok(())
    }

    fn end(self, enc: &mut Serializer) -> Result<(), Error> {
        enc.close_entry();
        let Some(MapFrame { parent, mut entries, .. }) = enc.maps.pop() else {
            return Err(Error::custom("map ended without beginning"));
        };
        enc.output = parent;

        // Sorting the encoded keys bytewise sorts them by length first,
        // since the length comes first in the head
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        if let Some([(key, _), _]) = entries.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(Error::custom(format_args!(
                "duplicate map key {:?}", String::from_utf8_lossy(key)
            )));
        }

        enc.write_len(Major::Map, entries.len()
            .try_into()
            .map_err(|_| Error::custom("Map too long"))?
        );
        for (key, value) in entries {
            enc.write_slice(&key);
            enc.write_slice(&value);
        }
        Ok(())
    }
}
