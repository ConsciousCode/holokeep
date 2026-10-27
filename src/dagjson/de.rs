use std::borrow::Cow;
use std::cell::Cell;
use std::cmp::Ordering;

use multibase::Base;
use serde::de::Error as _;

use crate::cid::{AnyCid, CidRef};
use crate::multihash::Inline;
use crate::serde::{Decoder, Error, Kind, ListDecoder, MapDecoder, SizeHint};

use super::{format_float, write_string};

/// JSON deserializer implementing Decode
#[derive(Clone)]
pub struct Deserializer<'de> {
    /// Input not yet consumed.
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

    /// Skip whitespace, which canonical DAG-JSON has none of.
    const fn ws(&mut self) {
        let start = self.cursor.len();
        self.cursor = self.cursor.trim_ascii_start();
        if self.cursor.len() != start {
            self.noncanonical();
        }
    }

    /// Peek at the next byte after any whitespace.
    fn peek(&mut self) -> Result<u8, Error> {
        self.ws();
        self.cursor.first().copied().ok_or_else(Self::eof)
    }

    /// Consume an expected token after any whitespace.
    fn expect(&mut self, token: &[u8]) -> Result<(), Error> {
        self.ws();
        match self.cursor.strip_prefix(token) {
            Some(rest) => {
                self.cursor = rest;
                Ok(())
            },
            None => Err(Error::custom(format_args!(
                "expected `{}`", String::from_utf8_lossy(token)
            ))),
        }
    }

    /// Consume a number token, without interpreting it.
    fn number(&mut self) -> Result<&'de str, Error> {
        self.ws();
        let len = self.cursor
            .iter()
            .position(|b| !matches!(b, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
            .unwrap_or(self.cursor.len());
        let (token, rest) = self.cursor.split_at(len);
        self.cursor = rest;
        let token = str::from_utf8(token).map_err(|_| Error::custom("invalid number"))?;
        if is_json_number(token) {
            Ok(token)
        }
        else {
            Err(Error::custom(format_args!("invalid number `{token}`")))
        }
    }

    /// Consume a string, borrowing it when it has no escapes.
    fn string(&mut self) -> Result<Cow<'de, str>, Error> {
        self.expect(b"\"")?;
        let input = self.cursor;
        let mut rest = input;
        let mut owned: Option<Vec<u8>> = None;
        let unpaired = || Error::custom("unpaired surrogate");
        let raw = loop {
            let consumed = input.get(..input.len().saturating_sub(rest.len())).unwrap_or_default();
            let Some(&byte) = rest.split_off_first() else {
                return Err(Error::custom("unterminated string"));
            };
            match byte {
                b'"' => break consumed,
                b'\\' => {
                    let out = owned.get_or_insert_with(|| consumed.to_vec());
                    match rest.split_off_first().ok_or_else(Self::eof)? {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut c = hex4(&mut rest)?;
                            // Characters outside the BMP are surrogate pairs
                            if (0xd800..0xdc00).contains(&c) {
                                rest = rest.strip_prefix(b"\\u").ok_or_else(unpaired)?;
                                let low = hex4(&mut rest)?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err(unpaired());
                                }
                                c = (c & 0x3ff).checked_shl(10)
                                    .and_then(|high| (high | (low & 0x3ff)).checked_add(0x10000))
                                    .ok_or_else(unpaired)?;
                            }
                            let c = char::from_u32(c).ok_or_else(unpaired)?;
                            out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                        },
                        _ => return Err(Error::custom("invalid escape")),
                    }
                },
                ..0x20 => return Err(Error::custom("unescaped control character in string")),
                _ => {
                    if let Some(out) = owned.as_mut() {
                        out.push(byte);
                    }
                },
            }
        };
        self.cursor = rest;

        let value = match owned {
            None => Cow::Borrowed(str::from_utf8(raw).map_err(|_| Error::custom("utf-8 parsing"))?),
            Some(bytes) => Cow::Owned(String::from_utf8(bytes).map_err(|_| Error::custom("utf-8 parsing"))?),
        };
        // Escapes JSON.stringify wouldn't have used
        let mut canonical = Vec::with_capacity(raw.len().saturating_add(2));
        write_string(&mut canonical, &value);
        if canonical.get(1..canonical.len().saturating_sub(1)) != Some(raw) {
            self.noncanonical();
        }
        Ok(value)
    }

    /// Look ahead for the reserved forms, consuming nothing. A map whose
    /// first key is "/" is a link if its value is a string, or bytes if
    /// it's `{"bytes": string}`; both must then be the map's only entry,
    /// which decoding them enforces. Any other "/" value is an ordinary map.
    fn reserved(&self) -> Result<Option<Kind>, Error> {
        let mut ahead = self.clone();
        ahead.expect(b"{")?;
        if ahead.peek()? != b'"' || ahead.string()? != "/" {
            return Ok(None);
        }
        ahead.expect(b":")?;
        Ok(match ahead.peek()? {
            b'"' => Some(Kind::Link),
            b'{' => {
                let mut bytes = || -> Option<()> {
                    ahead.expect(b"{").ok()?;
                    (ahead.string().ok()? == "bytes").then_some(())?;
                    ahead.expect(b":").ok()?;
                    (ahead.peek().ok()? == b'"').then_some(())?;
                    ahead.string().ok()?;
                    ahead.expect(b"}").ok()
                };
                bytes().map(|()| Kind::Bytes)
            },
            _ => None,
        })
    }

    /// Consume the `{"/":` opening a link or bytes.
    fn open_reserved(&mut self) -> Result<(), Error> {
        self.expect(b"{")?;
        if self.string()? != "/" {
            return Err(Error::custom("expected the reserved \"/\" key"));
        }
        self.expect(b":")
    }
}

/// The JSON number grammar: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
fn is_json_number(token: &str) -> bool {
    fn digits(s: &str) -> (&str, &str) {
        s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()))
    }
    let s = token.strip_prefix('-').unwrap_or(token);
    let (int, mut rest) = digits(s);
    if int.is_empty() || (int.len() > 1 && int.starts_with('0')) {
        return false;
    }
    if let Some(frac) = rest.strip_prefix('.') {
        let (frac, tail) = digits(frac);
        if frac.is_empty() {
            return false;
        }
        rest = tail;
    }
    if let Some(exp) = rest.strip_prefix(['e', 'E']) {
        let (exp, tail) = digits(exp.strip_prefix(['+', '-']).unwrap_or(exp));
        if exp.is_empty() {
            return false;
        }
        rest = tail;
    }
    rest.is_empty()
}

/// Consume the four hex digits of a `\u` escape.
fn hex4(rest: &mut &[u8]) -> Result<u32, Error> {
    let (hex, tail) = rest.split_first_chunk::<4>()
        .ok_or_else(|| Error::custom("invalid \\u escape"))?;
    let value = str::from_utf8(hex).ok()
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .ok_or_else(|| Error::custom("invalid \\u escape"))?;
    *rest = tail;
    Ok(value)
}

impl<'de> Decoder<'de> for Deserializer<'de> {
    type ListDecoder = List;
    type MapDecoder = Map<'de>;

    fn peek_kind(&mut self) -> Result<Kind, Error> {
        Ok(match self.peek()? {
            b'n' => Kind::Null,
            b't' | b'f' => Kind::Bool,
            b'"' => Kind::String,
            b'[' => Kind::List,
            b'{' => self.reserved()?.unwrap_or(Kind::Map),
            b'-' | b'0'..=b'9' => {
                let mut ahead = self.clone();
                if ahead.number()?.contains(['.', 'e', 'E']) { Kind::Float } else { Kind::Int }
            },
            byte => return Err(Error::custom(format_args!(
                "unexpected `{}`", char::from(byte)
            ))),
        })
    }

    fn skip(&mut self) -> Result<(), Error> {
        match self.peek_kind()? {
            Kind::Null => self.decode_null(),
            Kind::Bool => self.decode_bool().map(drop),
            Kind::Int | Kind::Float => self.number().map(drop),
            Kind::String => self.decode_string().map(drop),
            Kind::Bytes => self.decode_bytes().map(drop),
            Kind::Link => self.decode_link().map(drop),
            Kind::List => {
                let mut list = List::begin(self)?;
                while list.has_next(self)? {
                    Decoder::skip(self)?;
                }
                list.end(self)
            },
            Kind::Map => {
                let mut map = Map::begin(self)?;
                while map.key(self)?.is_some() {
                    Decoder::skip(self)?;
                }
                map.end(self)
            },
        }
    }

    fn is_human_readable() -> bool { true }

    fn finish(&mut self) -> Result<(), Error> {
        self.ws();
        if self.cursor.is_empty() {
            Ok(())
        }
        else {
            Err(Error::custom("trailing characters"))
        }
    }

    fn is_canon(&self) -> bool { self.canon }

    fn decode_null(&mut self) -> Result<(), Error> {
        self.expect(b"null")
    }

    fn decode_bool(&mut self) -> Result<bool, Error> {
        match self.peek()? {
            b't' => self.expect(b"true").map(|()| true),
            _ => self.expect(b"false").map(|()| false),
        }
    }

    fn decode_int(&mut self) -> Result<i128, Error> {
        let token = self.number()?;
        if token.contains(['.', 'e', 'E']) {
            return Err(Error::custom(format_args!("invalid type: float, expected int")));
        }
        if token == "-0" {
            self.noncanonical();
        }
        token.parse().map_err(|_| Error::custom("integer out of range"))
    }

    fn decode_float(&mut self) -> Result<f64, Error> {
        let token = self.number()?;
        let value: f64 = token.parse().map_err(|_| Error::custom("invalid float"))?;
        if !value.is_finite() {
            return Err(Error::custom("DAG-JSON forbids NaN and infinities"));
        }
        if format_float(value) != token {
            self.noncanonical();
        }
        // Negative zero is encoded as zero
        Ok(if value == 0.0 { 0.0 } else { value })
    }

    fn decode_string(&mut self) -> Result<Cow<'de, str>, Error> {
        self.string()
    }

    fn decode_bytes(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        self.open_reserved()?;
        self.expect(b"{")?;
        if self.string()? != "bytes" {
            return Err(Error::custom("expected {\"/\":{\"bytes\":...}}"));
        }
        self.expect(b":")?;
        let encoded = self.string()?;
        self.expect(b"}")?;
        self.expect(b"}")?;
        let bytes = Base::Base64.decode(encoded.as_ref())
            .map_err(|e| Error::custom(format_args!("invalid base64: {e}")))?;
        if Base::Base64.encode(&bytes) != encoded {
            self.noncanonical();
        }
        Ok(Cow::Owned(bytes))
    }

    fn decode_link(&mut self) -> Result<Cow<'de, [u8]>, Error> {
        self.open_reserved()?;
        let encoded = self.string()?;
        self.expect(b"}")?;
        let cid: AnyCid<Inline<64>> = encoded.parse()
            .map_err(|e| Error::custom(format_args!("invalid CID: {e}")))?;
        // Only CIDv0's base58btc and CIDv1's base32 are canonical
        if cid.to_string() != encoded {
            self.noncanonical();
        }
        Ok(Cow::Owned(cid.to_bytes()))
    }
}

pub struct List {
    first: Cell<bool>,
}

impl SizeHint for List {
    fn size_hint(&self) -> Option<usize> { None }
}

impl<'de> ListDecoder<'de, Deserializer<'de>> for List {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        dec.expect(b"[")?;
        Ok(Self { first: Cell::new(true) })
    }

    fn has_next(&self, dec: &mut Deserializer<'de>) -> Result<bool, Error> {
        if dec.peek()? == b']' {
            return Ok(false);
        }
        if !self.first.replace(false) {
            dec.expect(b",")?;
        }
        Ok(true)
    }

    fn end(&mut self, dec: &mut Deserializer<'de>) -> Result<(), Error> {
        dec.expect(b"]")
    }
}

pub struct Map<'de> {
    first: bool,
    /// The previous key, to check they're sorted and unique.
    last: Option<Cow<'de, str>>,
}

impl SizeHint for Map<'_> {
    fn size_hint(&self) -> Option<usize> { None }
}

impl<'de> MapDecoder<'de, Deserializer<'de>> for Map<'de> {
    fn begin(dec: &mut Deserializer<'de>) -> Result<Self, Error> {
        dec.expect(b"{")?;
        Ok(Self { first: true, last: None })
    }

    fn key(&mut self, dec: &mut Deserializer<'de>) -> Result<Option<Cow<'de, str>>, Error> {
        if dec.peek()? == b'}' {
            return Ok(None);
        }
        if !std::mem::take(&mut self.first) {
            dec.expect(b",")?;
        }
        let key = dec.string()?;
        dec.expect(b":")?;
        if let Some(last) = &self.last {
            match last.as_bytes().cmp(key.as_bytes()) {
                Ordering::Less => (),
                Ordering::Equal => return Err(Error::custom(format_args!(
                    "duplicate map key {key:?}"
                ))),
                Ordering::Greater => dec.noncanonical(),
            }
        }
        self.last = Some(key.clone());
        Ok(Some(key))
    }

    fn end(&mut self, dec: &mut Deserializer<'de>) -> Result<(), Error> {
        dec.expect(b"}")
    }
}
