use multibase::Base;
use serde::ser::Error as _;

use crate::cid::{AnyCid, Cid};
use crate::model::Ipld;
use crate::multihash::Inline;
use crate::serde::{Encoder, Error, ListEncoder, MapEncoder};

use super::{format_float, write_string};

/// A map being serialized. Each entry is buffered so they can be sorted.
struct MapFrame {
    /// The output the map is being written into, set aside meanwhile.
    parent: Vec<u8>,
    /// Finished (key, encoded value) entries.
    entries: Vec<(String, Vec<u8>)>,
    /// The key whose value is being written to the output.
    key: Option<String>,
}

pub struct Serializer {
    output: Vec<u8>,
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

    #[allow(clippy::unnecessary_wraps, reason = "lets encoders chain writes with ?")]
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.output.extend_from_slice(bytes);
        Ok(())
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

    fn encode_null(&mut self) -> Result<(), Error> { self.write(b"null") }

    fn encode_bool(&mut self, value: bool) -> Result<(), Error> {
        self.write(if value { b"true" } else { b"false" })
    }

    fn encode_int(&mut self, value: i128) -> Result<(), Error> {
        self.write(value.to_string().as_bytes())
    }

    fn encode_float(&mut self, value: f64) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(Error::custom("DAG-JSON forbids NaN and infinities"));
        }
        self.write(format_float(value).as_bytes())
    }

    fn encode_string(&mut self, value: &str) -> Result<(), Error> {
        write_string(&mut self.output, value);
        Ok(())
    }

    fn encode_bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        self.write(b"{\"/\":{\"bytes\":\"")?;
        self.write(Base::Base64.encode(value).as_bytes())?;
        self.write(b"\"}}")
    }

    fn encode_link(&mut self, value: &[u8]) -> Result<(), Error> {
        let cid = AnyCid::<Inline<64>>::decode(value)
            .map_err(|e| Error::custom(format_args!("invalid CID: {e}")))?;
        self.write(b"{\"/\":\"")?;
        self.write(cid.to_string().as_bytes())?;
        self.write(b"\"}")
    }
}

pub struct List {
    first: bool,
}

impl ListEncoder<Serializer> for List {
    fn begin(enc: &mut Serializer, _size: Option<usize>) -> Result<Self, Error> {
        enc.write(b"[")?;
        Ok(Self { first: true })
    }

    fn element(&mut self, enc: &mut Serializer) -> Result<(), Error> {
        if !std::mem::take(&mut self.first) {
            enc.write(b",")?;
        }
        Ok(())
    }

    fn end(self, enc: &mut Serializer) -> Result<(), Error> {
        enc.write(b"]")
    }
}

pub struct Map;

impl MapEncoder<Serializer> for Map {
    fn begin(enc: &mut Serializer, _size: Option<usize>) -> Result<Self, Error> {
        let parent = std::mem::take(&mut enc.output);
        enc.maps.push(MapFrame { parent, entries: Vec::new(), key: None });
        Ok(Self)
    }

    fn key(&mut self, enc: &mut Serializer, key: &str) -> Result<(), Error> {
        enc.close_entry();
        if let Some(frame) = enc.maps.last_mut() {
            frame.key = Some(key.to_owned());
        }
        Ok(())
    }

    fn end(self, enc: &mut Serializer) -> Result<(), Error> {
        enc.close_entry();
        let Some(MapFrame { parent, mut entries, .. }) = enc.maps.pop() else {
            return Err(Error::custom("map ended without beginning"));
        };
        enc.output = parent;

        // String's Ord is bytewise
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        if let Some([(key, _), _]) = entries.windows(2).find(|w| matches!(w, [(a, _), (b, _)] if a == b)) {
            return Err(Error::custom(format_args!("duplicate map key {key:?}")));
        }
        // A first key of "/" with a link- or bytes-shaped value is either
        // a link or bytes, or (with other keys) invalid DAG-JSON
        if let Some((key, value)) = entries.first() && key == "/" && reads_as_reserved(value) {
            return Err(Error::custom("a \"/\" key with this value is reserved for links and bytes"));
        }

        enc.write(b"{")?;
        for (i, (key, value)) in entries.iter().enumerate() {
            if i > 0 {
                enc.write(b",")?;
            }
            write_string(&mut enc.output, key);
            enc.write(b":")?;
            enc.write(value)?;
        }
        enc.write(b"}")
    }
}

/// Whether a map's sole "/" value has the shape of a link (a string) or
/// bytes (`{"bytes": string}`).
fn reads_as_reserved(value: &[u8]) -> bool {
    match super::from_slice::<Ipld>(value) {
        Ok(Ipld::String(_)) => true,
        Ok(Ipld::Map(map)) => map.len() == 1 && matches!(map.get("bytes"), Some(Ipld::String(_))),
        _ => false,
    }
}
