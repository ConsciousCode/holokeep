use std::borrow::Cow;

use serde::{Deserializer as _};
use serde::de::{self, Visitor, Error as _, SeqAccess, MapAccess, EnumAccess, VariantAccess, value::CowStrDeserializer};
use paste::paste;

use crate::cid::CID_SERDE_PRIVATE_IDENTIFIER;
use crate::serde::SizeHint;

use super::{Error, Kind, ListDecoder, MapDecoder, Decoder};

macro_rules! deserialize_int {
    ($($ty:ident),* $(,)? ) => {paste!{$(
        fn [<deserialize_ $ty>]<V: Visitor<'de>>(self, v: V)
            -> Result<V::Value, Self::Error>
        {
            v.[<visit_ $ty>](
                self.dec.decode_int()?
                .try_into()
                .map_err(|_| Error::custom("integer overflow"))?
            )
        }
    )*}};
}

macro_rules! deserialize {
    (
        $(fn $ty:ident($self:ident, $visitor:ident$(,)?) $block:block)*
    ) => {paste!{$(
        fn [<deserialize_ $ty>]<V>($self, $visitor: V)
            -> Result<V::Value, Self::Error>
        where V: Visitor<'de> $block
    )*}};
}

/// How deeply lists and maps may nest. Decoding recurses, so without a
/// limit a small hostile block (a kilobyte of nested lists) overflows the
/// stack. `serde_json` allows 128; `SQLite`'s JSON allows 1000.
pub const MAX_DEPTH: usize = 256;

pub struct Deserializer<D> {
    dec: D,
    depth: usize,
}
impl<D> Deserializer<D> {
    pub const fn new(dec: D) -> Self {
        Self { dec, depth: 0 }
    }

    pub fn into_inner(self) -> D { self.dec }

    /// Descend into a container, run `f`, and come back out.
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::custom(format_args!("nested deeper than {MAX_DEPTH}")));
        }
        self.depth = self.depth.saturating_add(1);
        let result = f(self);
        self.depth = self.depth.saturating_sub(1);
        result
    }
}

impl<'de, D: Decoder<'de>> de::Deserializer<'de> for &mut Deserializer<D> {
    type Error = Error;

    deserialize_int! { i8, i16, i32, i64, i128, u8, u16, u32, u64, u128 }
    deserialize! {
        fn any(self, visitor) {
            match self.dec.peek_kind()? {
                Kind::Null => {
                    self.dec.decode_null()?;
                    visitor.visit_none()
                },
                Kind::Bool => self.deserialize_bool(visitor),
                Kind::Int => self.deserialize_i128(visitor),
                Kind::Float => self.deserialize_f64(visitor),
                Kind::Bytes => self.deserialize_bytes(visitor),
                Kind::String => self.deserialize_str(visitor),
                Kind::Link => visitor.visit_newtype_struct(
                    CidDeserializer::new(self)
                ),
                Kind::List => self.deserialize_seq(visitor),
                Kind::Map => self.deserialize_map(visitor),
            }
        }

        fn bool(self, v) { v.visit_bool(self.dec.decode_bool()?) }
        fn f32(self, v) { v.visit_f64(self.dec.decode_float()?) }
        fn f64(self, v) { v.visit_f64(self.dec.decode_float()?) }
        fn char(self, v) { self.deserialize_str(v) }
        fn bytes(self, v) {
            match self.dec.decode_bytes()? {
                Cow::Borrowed(bs) => v.visit_borrowed_bytes(bs),
                Cow::Owned(bs) => v.visit_byte_buf(bs)
            }
        }
        fn byte_buf(self, v) { self.deserialize_bytes(v) }
        fn str(self, v) {
            match self.dec.decode_string()? {
                Cow::Borrowed(s) => v.visit_borrowed_str(s),
                Cow::Owned(s) => v.visit_string(s),
            }
        }
        fn string(self, v) { self.deserialize_str(v) }

        fn option(self, v) {
            match self.dec.peek_kind()? {
                Kind::Null => {
                    self.dec.decode_null()?;
                    v.visit_none()
                },
                _ => v.visit_some(self),
            }
        }

        fn unit(self, v) {
            self.dec.decode_null()?;
            v.visit_unit()
        }

        fn seq(self, v) {
            self.nested(|de| {
                let container = D::ListDecoder::begin(&mut de.dec)?;
                let mut access = Accessor::new(de, container, None);
                let value = v.visit_seq(&mut access)?;
                access.finish_seq()?;
                Ok(value)
            })
        }

        fn map(self, v) {
            self.nested(|de| {
                let container = D::MapDecoder::begin(&mut de.dec)?;
                let mut access = Accessor::new(de, container, None);
                let value = v.visit_map(&mut access)?;
                access.finish_map()?;
                Ok(value)
            })
        }

        fn identifier(self, v) { self.deserialize_str(v) }
        // Through `any` rather than `Decoder::skip`, which recurses unchecked
        fn ignored_any(self, v) { self.deserialize_any(v) }
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, v: V)
        -> Result<V::Value, Self::Error>
    where V: Visitor<'de> {
        self.deserialize_unit(v)
    }

    fn deserialize_newtype_struct<V>(self, name: &'static str, v: V)
        -> Result<V::Value, Self::Error>
    where V: Visitor<'de> {
        match name {
            CID_SERDE_PRIVATE_IDENTIFIER => match self.dec.peek_kind()? {
                Kind::Link => v.visit_newtype_struct(
                    CidDeserializer::new(self)
                ),
                kind => Err(Error::custom(format_args!(
                    "invalid type: {kind:?}, expected link"
                ))),
            },
            _ => v.visit_newtype_struct(self),
        }
    }

    fn deserialize_tuple<V>(self, len: usize, v: V)
        -> Result<V::Value, Self::Error>
    where V: Visitor<'de> {
        self.nested(|de| {
            let dec = D::ListDecoder::begin(&mut de.dec)?;
            match dec.size_hint() {
                Some(arr) if arr != len =>
                    Err(Error::invalid_length(arr, &"tuple")),
                _ => {
                    let mut access = Accessor::new(de, dec, Some(len));
                    let value = v.visit_seq(&mut access)?;
                    access.finish_seq()?;
                    Ok(value)
                },
            }
        })
    }

    fn deserialize_tuple_struct<V>(self, _: &'static str, len: usize, v: V)
        -> Result<V::Value, Self::Error>
    where V: Visitor<'de> {
        self.deserialize_tuple(len, v)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_map(v)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V
    ) -> Result<V::Value, Self::Error> {
        // Unit variants are bare strings, the rest {variant: value}
        match self.dec.peek_kind()? {
            Kind::String => v.visit_enum(EnumAccessor { de: self, map: None }),
            Kind::Map => self.nested(|de| {
                let map = D::MapDecoder::begin(&mut de.dec)?;
                if map.size_hint().is_some_and(|n| n != 1) {
                    return Err(Error::custom("enum must be a map with one entry"));
                }
                v.visit_enum(EnumAccessor { de, map: Some(map) })
            }),
            kind => Err(Error::custom(format_args!(
                "invalid type: {kind:?}, expected enum"
            ))),
        }
    }

    fn is_human_readable(&self) -> bool { D::is_human_readable() }
}

struct CidDeserializer<'a, D> {
    de: &'a mut Deserializer<D>
}

impl<'a, D> CidDeserializer<'a, D> {
    const fn new(de: &'a mut Deserializer<D>) -> Self {
        Self { de }
    }
}
impl<'de, 'a, D: Decoder<'de>> de::Deserializer<'de> for CidDeserializer<'a, D>
    where 'de: 'a
{
    type Error = Error;

    fn deserialize_any<V: de::Visitor<'de>>(self, v: V) -> Result<V::Value, Self::Error> {
        self.deserialize_bytes(v)
    }

    /// The binary CID of the link.
    fn deserialize_bytes<V: de::Visitor<'de>>(self, v: V)
        -> Result<V::Value, Self::Error>
    {
        match self.de.dec.decode_link()? {
            Cow::Borrowed(bs) => v.visit_borrowed_bytes(bs),
            Cow::Owned(bs) => v.visit_byte_buf(bs)
        }
    }

    serde::forward_to_deserialize_any! {
        bool byte_buf char enum f32 f64 i8 i16 i32 i64 i128 u128 identifier ignored_any
        map newtype_struct option seq str string struct tuple tuple_struct u8 u16 u32 u64
        unit unit_struct
    }
}

struct Accessor<'a, D, C> {
    de: &'a mut Deserializer<D>,
    container: C,
    remain: Option<usize>,
    ended: bool,
}
impl<'de, 'a, D, C> Accessor<'a, D, C>
    where
        D: Decoder<'de>,
        C: SizeHint,
{
    fn new(de: &'a mut Deserializer<D>, container: C, size: Option<usize>)
        -> Self
    {
        let remain = container.size_hint().or(size);
        Self { de, container, remain, ended: false }
    }

    /// Count off an entry, returning whether there could be one.
    const fn take(&mut self) -> bool {
        match self.remain.as_mut() {
            Some(0) => false,
            Some(r) => {
                *r = r.saturating_sub(1);
                true
            },
            None => true,
        }
    }
}

impl<'de, D, C> Accessor<'_, D, C>
    where
        D: Decoder<'de>,
        C: ListDecoder<'de, D>,
{
    fn end_seq(&mut self) -> Result<(), Error> {
        self.ended = true;
        self.container.end(&mut self.de.dec)
    }

    /// Make sure the list is fully consumed after the visitor is done,
    /// which it might not be if the visitor only wanted so many elements.
    fn finish_seq(mut self) -> Result<(), Error> {
        if self.ended {
            Ok(())
        }
        else if self.remain.unwrap_or(0) == 0 && (self.remain.is_some() || !self.container.has_next(&mut self.de.dec)?) {
            self.end_seq()
        }
        else {
            Err(Error::custom("trailing list elements"))
        }
    }
}

impl<'de, D, C> SeqAccess<'de> for Accessor<'_, D, C>
    where
        D: Decoder<'de>,
        C: ListDecoder<'de, D>,
{
    type Error = Error;

    fn next_element_seed<T: de::DeserializeSeed<'de>>(&mut self, seed: T)
        -> Result<Option<T::Value>, Self::Error>
    {
        if self.ended {
            return Ok(None);
        }
        if self.take() && self.container.has_next(&mut self.de.dec)? {
            Ok(Some(seed.deserialize(&mut *self.de)?))
        }
        else {
            self.end_seq()?;
            Ok(None)
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.remain
    }
}

impl<'de, D, C> Accessor<'_, D, C>
    where
        D: Decoder<'de>,
        C: MapDecoder<'de, D>,
{
    fn end_map(&mut self) -> Result<(), Error> {
        self.ended = true;
        self.container.end(&mut self.de.dec)
    }

    /// Make sure the map is fully consumed after the visitor is done.
    fn finish_map(mut self) -> Result<(), Error> {
        if self.ended {
            Ok(())
        }
        else if self.remain.unwrap_or(0) == 0 && (self.remain.is_some() || self.container.key(&mut self.de.dec)?.is_none()) {
            self.end_map()
        }
        else {
            Err(Error::custom("trailing map entries"))
        }
    }
}

impl<'de, D, C> MapAccess<'de> for Accessor<'_, D, C>
    where
        D: Decoder<'de>,
        C: MapDecoder<'de, D>,
{
    type Error = Error;

    fn next_key_seed<K: de::DeserializeSeed<'de>>(&mut self, seed: K)
        -> Result<Option<K::Value>, Self::Error>
    {
        if self.ended {
            return Ok(None);
        }
        let key = if self.take() { self.container.key(&mut self.de.dec)? } else { None };
        if let Some(key) = key { Ok(Some(seed.deserialize(CowStrDeserializer::new(key))?)) } else {
            self.end_map()?;
            Ok(None)
        }
    }

    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V)
        -> Result<V::Value, Self::Error>
    {
        // If we process the value, the key already advanced the iterator
        seed.deserialize(&mut *self.de)
    }

    fn size_hint(&self) -> Option<usize> { self.remain }
}

/// Unit variants are a bare string, everything else a single-entry map
/// `{variant: value}` (`map`, already entered).
struct EnumAccessor<'a, D, M> {
    de: &'a mut Deserializer<D>,
    map: Option<M>,
}

impl<'de, D: Decoder<'de>> EnumAccessor<'_, D, D::MapDecoder> {
    /// Deserialize the variant's value, then close the map around it.
    fn value<T>(self, f: impl FnOnce(&mut Deserializer<D>) -> Result<T, Error>) -> Result<T, Error> {
        let Some(mut map) = self.map else {
            return Err(Error::custom("expected {variant: value}, got a unit variant"));
        };
        let value = f(&mut *self.de)?;
        if map.size_hint().is_none() && map.key(&mut self.de.dec)?.is_some() {
            return Err(Error::custom("enum must be a map with one entry"));
        }
        map.end(&mut self.de.dec)?;
        Ok(value)
    }
}

impl<'de, D: Decoder<'de>> EnumAccess<'de> for EnumAccessor<'_, D, D::MapDecoder> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: de::DeserializeSeed<'de>>(mut self, seed: V)
        -> Result<(V::Value, Self::Variant), Self::Error>
    {
        let variant = match self.map.as_mut() {
            Some(map) => {
                let key = map.key(&mut self.de.dec)?
                    .ok_or_else(|| Error::custom("enum must be a map with one entry"))?;
                seed.deserialize(CowStrDeserializer::new(key))?
            },
            None => seed.deserialize(&mut *self.de)?,
        };
        Ok((variant, self))
    }
}

impl<'de, D: Decoder<'de>> VariantAccess<'de> for EnumAccessor<'_, D, D::MapDecoder> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Self::Error> {
        if self.map.is_some() {
            self.value(|de| de.dec.decode_null())
        }
        else {
            Ok(())
        }
    }

    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T)
        -> Result<T::Value, Self::Error>
    {
        self.value(|de| seed.deserialize(de))
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V)
        -> Result<V::Value, Self::Error>
    {
        self.value(|de| de.deserialize_tuple(len, v))
    }

    fn struct_variant<V>(self, _: &'static [&'static str], v: V)
        -> Result<V::Value, Self::Error>
    where V: Visitor<'de> {
        self.value(|de| de.deserialize_map(v))
    }
}
