use serde::ser::{Error as _};

use super::{CID_TAG, Major, marker};

use crate::{dagcbor::Size, serde::{Encoder, Error, ListEncoder, MapEncoder}};

/// A head: the initial byte, then the payload in as few bytes as hold it.
struct Head {
    buf: [u8; 9],
    len: usize,
}

impl Head {
    fn new(major: Major, v: u64) -> Self {
        let size = Size::from_payload(v);
        let extra = size.extra_size();
        let mut buf = [0u8; 9];
        let [initial, rest @ ..] = &mut buf;
        *initial = major.initial(size.to_ai());
        // The payload's last `extra` big-endian bytes, the rest being zeros
        let payload = v.to_be_bytes();
        if let (Some(to), Some(from)) = (rest.get_mut(..extra), payload.get(payload.len().saturating_sub(extra)..)) {
            to.copy_from_slice(from);
        }
        Self { buf, len: extra.saturating_add(1) }
    }

    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&self.buf)
    }
}

/// Cursor used to insert head bytes before containers.
#[derive(Clone, Copy)]
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
    pub const fn new() -> Self {
        Self { output: Vec::new(), maps: Vec::new() }
    }

    /// Get the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> { self.output }

    fn write_u8(&mut self, value: u8) { self.output.push(value) }

    fn write_slice(&mut self, slice: &[u8]) {
        self.output.extend_from_slice(slice);
    }

    /// Encode a length given a major value. All composites use this format.
    fn write_len(&mut self, major: Major, value: u64) {
        self.write_slice(Head::new(major, value).bytes());
    }

    fn write_payload(&mut self, major: Major, value: &[u8]) -> Result<(), Error> {
        self.write_len(major, value.len()
            .try_into()
            .map_err(|_| Error::custom(format_args!("{major:?} too long")))?
        );
        self.write_slice(value);
        Ok(())
    }

    const fn enter_container(&self) -> Cursor {
        Cursor {
            index: self.output.len(),
            size: 0,
        }
    }

    fn exit_container(&mut self, major: Major, cur: Cursor) {
        let Cursor { index, size } = cur;
        self.output.splice(index..index, Head::new(major, size).bytes().iter().copied());
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
        self.write_u8(marker::NULL);
        Ok(())
    }

    fn encode_bool(&mut self, value: bool) -> Result<(), Error> {
        self.write_u8(if value { marker::TRUE } else { marker::FALSE });
        Ok(())
    }

    fn encode_int(&mut self, value: i128) -> Result<(), Error> {
        let (major, value) = if value < 0 {
            // -1 - value, which can't overflow
            (Major::Negative, !value)
        }
        else {
            (Major::Positive, value)
        };

        let value = value.try_into().map_err(|_| Error::custom("out of range"))?;
        self.write_len(major, value);
        Ok(())
    }

    fn encode_float(&mut self, value: f64) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(Error::custom("DAG-CBOR forbids NaN and infinities"));
        }
        // Always 64 bit, even when a shorter float would be exact, and
        // never negative zero
        let value = if value == 0.0 { 0.0 } else { value };
        self.write_u8(marker::F64);
        self.write_slice(&value.to_be_bytes());
        Ok(())
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
        self.write_slice(value);
        Ok(())
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
        if let Some(cur) = self.cur.as_mut() {
            cur.size = cur.size.saturating_add(1);
        }
        Ok(())
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
        Ok(Self)
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
        if let Some(key) = entries.windows(2).find_map(|pair| match pair {
            [(a, _), (b, _)] if a == b => Some(a),
            _ => None,
        }) {
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
