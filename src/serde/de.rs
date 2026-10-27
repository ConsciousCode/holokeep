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

pub struct Deserializer<D> {
    dec: D,
}
impl<D> Deserializer<D> {
    pub fn new(dec: D) -> Self {
        Self { dec }
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
        fn f32(self, v) { v.visit_f32(self.dec.decode_float()? as f32) }
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
            let container = D::ListDecoder::begin(&mut self.dec)?;
            v.visit_seq(Accessor::new(self, container, None))
        }

        fn map(self, v) {
            let container = D::MapDecoder::begin(&mut self.dec)?;
            v.visit_map(Accessor::new(self, container, None))
        }

        fn identifier(self, v) { self.deserialize_str(v) }
        fn ignored_any(self, v) {
            self.dec.skip()?;
            v.visit_unit()
        }
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
        let dec = D::ListDecoder::begin(&mut self.dec)?;
        match dec.size_hint() {
            Some(arr) if arr != len =>
                Err(Error::invalid_length(arr, &"tuple")),
            _ => v.visit_seq(Accessor::new(self, dec, Some(len))),
        }
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
        v.visit_enum(EnumAccessor::new(self))
    }

    fn is_human_readable(&self) -> bool { D::is_human_readable() }
}

struct CidDeserializer<'a, D> {
    de: &'a mut Deserializer<D>
}

impl<'a, D> CidDeserializer<'a, D> {
    fn new(de: &'a mut Deserializer<D>) -> Self {
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

    fn deserialize_bytes<V: de::Visitor<'de>>(self, v: V)
        -> Result<V::Value, Self::Error>
    {
        match self.de.dec.decode_bytes()? {
            Cow::Borrowed(bs) => v.visit_borrowed_bytes(bs),
            Cow::Owned(bs) => v.visit_byte_buf(bs)
        }
    }

    fn deserialize_newtype_struct<V>(self, name: &'static str, v: V)
        -> Result<V::Value, Self::Error>
    where V: de::Visitor<'de> {
        match name {
            CID_SERDE_PRIVATE_IDENTIFIER => match self.de.dec.decode_link()? {
                Cow::Borrowed(bs) => v.visit_borrowed_bytes(bs),
                Cow::Owned(bs) => v.visit_byte_buf(bs),
            },
            _ => Err(Error::custom([
                "This deserializer must not be called on newtype structs other than one named `",
                CID_SERDE_PRIVATE_IDENTIFIER,
                "`"
            ].concat()))
        }
    }

    serde::forward_to_deserialize_any! {
        bool byte_buf char enum f32 f64 i8 i16 i32 i64 identifier ignored_any map option seq str
        string struct tuple tuple_struct u8 u16 u32 u64 unit unit_struct
    }
}

struct Accessor<'a, D, C> {
    de: &'a mut Deserializer<D>,
    container: C,
    remain: Option<usize>,
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
        Self { de, container, remain }
    }
}
impl<'de, 'a, D, C> SeqAccess<'de> for Accessor<'a, D, C>
    where
        D: Decoder<'de>,
        C: ListDecoder<'de, D>,
{
    type Error = Error;

    fn next_element_seed<T: de::DeserializeSeed<'de>>(&mut self, seed: T)
        -> Result<Option<T::Value>, Self::Error>
    {
        if let Some(r) = self.remain.as_mut() {
            if let Some(s) = r.checked_sub(1) {
                *r = s;
            }
            else {
                return Ok(None)
            }
        }
        Ok(if self.container.has_next(&mut self.de.dec)? {
            Some(seed.deserialize(&mut *self.de)?)
        }
        else {
            self.container.end(&mut self.de.dec);
            None
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.remain
    }
}
impl<'a, 'de, D, C> MapAccess<'de> for Accessor<'a, D, C>
    where
        D: Decoder<'de>,
        C: MapDecoder<'de, D>,
{
    type Error = Error;

    fn next_key_seed<K: de::DeserializeSeed<'de>>(&mut self, seed: K)
        -> Result<Option<K::Value>, Self::Error>
    {
        if let Some(r) = self.remain.as_mut() {
            match r.checked_sub(1) {
                Some(s) => *r = s,
                None => return Ok(None),
            }
        }
        Ok(match self.container.key(&mut self.de.dec)? {
            Some(key) => Some(seed.deserialize(CowStrDeserializer::new(key))?),
            None => { self.container.end(&mut self.de.dec); None }
        })
    }

    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V)
        -> Result<V::Value, Self::Error>
    {
        // If we process the value, the key already advanced the iterator
        seed.deserialize(&mut *self.de)
    }

    fn size_hint(&self) -> Option<usize> { self.remain }
}

struct EnumAccessor<'a, R> {
    de: &'a mut Deserializer<R>,
}
impl<'a, R> EnumAccessor<'a, R> {
    fn new(de: &'a mut Deserializer<R>) -> Self {
        Self { de }
    }
}

impl<'de, 'a, D: Decoder<'de>> EnumAccess<'de> for EnumAccessor<'a, D> {
    type Error = Error;
    type Variant = EnumAccessor<'a, D>;

    fn variant_seed<V: de::DeserializeSeed<'de>>(self, seed: V)
        -> Result<(V::Value, Self::Variant), Self::Error>
    {
        Ok((seed.deserialize(&mut *self.de)?, self))
    }
}

impl<'de, 'a, D: Decoder<'de>> VariantAccess<'de> for EnumAccessor<'a, D> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Self::Error> { Ok(()) }

    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T)
        -> Result<T::Value, Self::Error>
    {
        seed.deserialize(&mut *self.de)
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V)
        -> Result<V::Value, Self::Error>
    {
        self.de.deserialize_tuple(len, v)
    }

    fn struct_variant<V>(self, _: &'static [&'static str], v: V)
        -> Result<V::Value, Self::Error>
    where V: Visitor<'de> {
        self.de.deserialize_map(v)
    }
}