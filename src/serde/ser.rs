use serde::ser::{self, Error as _, Impossible, Serialize, SerializeSeq, SerializeMap, SerializeStruct, SerializeStructVariant, SerializeTuple, SerializeTupleStruct, SerializeTupleVariant};
use paste::paste;

use crate::{cid::CID_SERDE_PRIVATE_IDENTIFIER};

use super::{ListEncoder, MapEncoder, Encoder, Error};

pub struct Serializer<Enc> {
    enc: Enc,
}
impl<Enc> Serializer<Enc> {
    pub const fn new(enc: Enc) -> Self {
        Self { enc }
    }

    pub fn into_inner(self) -> Enc { self.enc }
}

macro_rules! serialize_primitive {
    (
        $(
            $kind:ident as $cast:ident ( $($ty:ident),* $(,)? )
        ),* $(,)?
    ) => {paste!{$($(
        fn [<serialize_ $ty>](self, v: $ty) -> Result<(), Error> {
            self.enc.[<encode_ $kind>]($cast::from(v))
        }
    )*)*}};
}

macro_rules! serialize {
    ($(
        fn $toser:ident $(<$gen:ident>)?
        ($self:ident $(,$name:tt : $ty:ty)* $(,)?) $block:block
    )*) => {paste!{$(
        fn [<serialize_ $toser>] $(<$gen>)* ($self $(, $name: $ty)*)
            -> Result<(), Error>
            $(where $gen: ?Sized + Serialize)* $block
    )*}};
}

impl<'se, Enc: Encoder> ser::Serializer for &'se mut Serializer<Enc> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Collection<'se, Enc, Enc::ListEncoder>;
    type SerializeMap = Collection<'se, Enc, Enc::MapEncoder>;
    type SerializeStruct = Collection<'se, Enc, Enc::MapEncoder>;
    type SerializeStructVariant = Variant<Collection<'se, Enc, Enc::MapEncoder>, Enc::MapEncoder>;
    type SerializeTuple = Collection<'se, Enc, Enc::ListEncoder>;
    type SerializeTupleStruct = Collection<'se, Enc, Enc::ListEncoder>;
    type SerializeTupleVariant = Variant<Collection<'se, Enc, Enc::ListEncoder>, Enc::MapEncoder>;

    serialize_primitive! {
        bool as bool(bool),
        int as i128(i8, i16, i32, i64, i128, u8, u16, u32, u64),
        float as f64(f32, f64),
    }

    serialize! {
        fn char(self, v: char) {
            let mut buf = [0; char::MAX_LEN_UTF8];
            self.serialize_str(v.encode_utf8(&mut buf))
        }
        fn str(self, v: &str) { self.enc.encode_string(v) }
        fn bytes(self, v: &[u8]) { self.enc.encode_bytes(v) }
        fn none(self) { self.enc.encode_null() }
        fn some<T>(self, v: &T) { v.serialize(self) }
        fn unit(self) { self.enc.encode_null() }
        fn unit_struct(self, _: &'static str) { self.serialize_unit() }
        fn unit_variant(self, _: &'static str, _: u32, variant: &'static str) {
            self.serialize_str(variant)
        }
        fn newtype_struct<T>(self, name: &'static str, value: &T) {
            if name == CID_SERDE_PRIVATE_IDENTIFIER {
                value.serialize(&mut CidSerializer::new(self))
            }
            else {
                value.serialize(self)
            }
        }
        fn newtype_variant<T>(
            self,
            _: &'static str,
            _: u32,
            variant: &'static str,
            value: &T,
        ) { // {variant: {...value}}
            let mut outer = Enc::MapEncoder::begin(&mut self.enc, Some(1))?;
            outer.key(&mut self.enc, variant)?;
            value.serialize(&mut *self)?;
            outer.end(&mut self.enc)
        }
    }

    fn serialize_seq(self, len: Option<usize>)
        -> Result<Self::SerializeSeq, Error>
    {
        let enc = Enc::ListEncoder::begin(&mut self.enc, len)?;
        Ok(Collection::new(self, enc))
    }

    fn serialize_tuple(self, len: usize)
        -> Result<Self::SerializeTuple, Error>
    {
        let enc = Enc::ListEncoder::begin(&mut self.enc, Some(len))?;
        Ok(Collection::new(self, enc))
    }

    fn serialize_tuple_struct(self, _: &'static str, len: usize)
        -> Result<Self::SerializeTupleStruct, Error>
    {
        self.serialize_tuple(len)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        // {name: [...tuple]}
        let mut outer = Enc::MapEncoder::begin(&mut self.enc, Some(1))?;
        outer.key(&mut self.enc, variant)?;
        Ok(Variant::new(self.serialize_tuple(len)?, outer))
    }

    fn serialize_map(self, len: Option<usize>)
        -> Result<Self::SerializeMap, Error>
    {
        let enc = Enc::MapEncoder::begin(&mut self.enc, len)?;
        Ok(Collection::new(self, enc))
    }

    fn serialize_struct(self, _: &'static str, len: usize)
        -> Result<Self::SerializeStruct, Error>
    {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        // {variant: {...struct}}
        let mut outer = Enc::MapEncoder::begin(&mut self.enc, Some(1))?;
        outer.key(&mut self.enc, variant)?;
        Ok(Variant::new(self.serialize_struct(name, len)?, outer))
    }
}

macro_rules! skip_serialization {
    (
        [error = $error:literal] $(
            fn $what:ident$(<$T:ident>)?
                ($($ty:ty),* $(,)?) -> $ret:ident;
        )*
    ) => {paste! {$(
        fn [<serialize_ $what>]$(<$T>)*(self $(, _: $ty)*)
            -> Result<Self::$ret, Error>
            $(where $T: ?Sized + Serialize)*
        { Err(Error::custom($error)) }
    )*}};
}
macro_rules! skip_primitive {
    ([error = $error:literal] $($ty:ident),* $(,)?) => {
        skip_serialization! {
            [error = $error]
            $(fn $ty($ty) -> Ok;)*
        }
    };
}

struct CidSerializer<'a, E> {
    ser: &'a mut Serializer<E>
}
impl<'a, E> CidSerializer<'a, E> {
    const fn new(ser: &'a mut Serializer<E>) -> Self {
        Self { ser }
    }
}

impl<'a, E> ser::Serializer for &'a mut CidSerializer<'a, E>
    where
        E: Encoder,
{
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Impossible<(), Error>;
    type SerializeTuple = Impossible<(), Error>;
    type SerializeTupleStruct = Impossible<(), Error>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    skip_primitive! {
        [error="CID"]
        bool, char,
        i8, i16, i32, i64,
        u8, u16, u32, u64,
        f32, f64,
    }
    skip_serialization! {
        [error="CID"]
        fn str(&str) -> Ok;
        fn none() -> Ok;
        fn some<T>(&T) -> Ok;
        fn unit() -> Ok;
        fn unit_struct(&str) -> Ok;
        fn unit_variant(&str, u32, &str) -> Ok;
        fn newtype_struct<T>(&str, &T) -> Ok;
        fn newtype_variant<T>(&str, u32, &str, &T) -> Ok;
        fn seq(Option<usize>) -> SerializeSeq;
        fn tuple(usize) -> SerializeTuple;
        fn tuple_struct(&str, usize) -> SerializeTupleStruct;
        fn tuple_variant(&str, u32, &str, usize) -> SerializeTupleVariant;
        fn map(Option<usize>) -> SerializeMap;
        fn struct(&str, usize) -> SerializeStruct;
        fn struct_variant(&str, u32, &str, usize) -> SerializeStructVariant;
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), Error> {
        self.ser.enc.encode_link(value)
    }
}

struct MapKeySerializer<'a, E, M> {
    enc: &'a mut E,
    map: &'a mut M,
}

impl<'a, E, M> ser::Serializer for &'a mut MapKeySerializer<'a, E, M>
    where
        E: Encoder,
        M: MapEncoder<E>,
{
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Impossible<(), Error>;
    type SerializeTuple = Impossible<(), Error>;
    type SerializeTupleStruct = Impossible<(), Error>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    skip_primitive! {
        [error="map key"]
        bool,
        i8, i16, i32, i64,
        u8, u16, u32, u64,
        f32, f64,
    }
    skip_serialization! {
        [error="map key"]
        fn bytes(&[u8]) -> Ok;
        fn none() -> Ok;
        fn some<T>(&T) -> Ok;
        fn unit() -> Ok;
        fn unit_struct(&str) -> Ok;
        fn newtype_variant<T>(&str, u32, &str, &T) -> Ok;
        fn seq(Option<usize>) -> SerializeSeq;
        fn tuple(usize) -> SerializeTuple;
        fn tuple_struct(&str, usize) -> SerializeTupleStruct;
        fn tuple_variant(&str, u32, &str, usize) -> SerializeTupleVariant;
        fn map(Option<usize>) -> SerializeMap;
        fn struct(&str, usize) -> SerializeStruct;
        fn struct_variant(&str, u32, &str, usize) -> SerializeStructVariant;
    }

    fn serialize_char(self, value: char) -> Result<(), Error> {
        // Coerce chars to str
        let mut buf = [0; char::MAX_LEN_UTF8];
        self.serialize_str(value.encode_utf8(&mut buf))
    }

    fn serialize_str(self, value: &str) -> Result<(), Error> {
        // Everything comes to this point
        self.map.key(self.enc, value)
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        // Allow newtype string wrappers
        value.serialize(self)
    }
}

pub struct Collection<'se, E: Encoder, C> {
    ser: &'se mut Serializer<E>,
    container: C,
}
impl<'se, E: Encoder, C> Collection<'se, E, C> {
    const fn new(ser: &'se mut Serializer<E>, container: C) -> Self {
        Self { ser, container }
    }
}

//---------------------//
//-[ List collection ]-//
//---------------------//

impl<'se, E, C> Collection<'se, E, C>
    where
        E: Encoder,
        C: ListEncoder<E>,
{
    fn list_element<T>(&mut self, value: &T) -> Result<(), Error>
    where T: ?Sized + Serialize {
        self.container.element(&mut self.ser.enc)?;
        value.serialize(&mut *self.ser)
    }

    fn list_end(self) -> Result<(), Error> {
        self.container.end(&mut self.ser.enc)
    }

    /// Return serializer for variant to reuse
    fn variant_list_end(self) -> Result<&'se mut Serializer<E>, Error> {
        self.container.end(&mut self.ser.enc)?;
        Ok(self.ser)
    }
}

impl<E, C> SerializeSeq for Collection<'_, E, C>
    where
        E: Encoder,
        C: ListEncoder<E>,
{
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where T: ?Sized + Serialize {
        self.list_element(value)
    }

    fn end(self) -> Result<(), Error> { self.list_end() }
}

impl<E, C> SerializeTuple for Collection<'_, E, C>
    where
        E: Encoder,
        C: ListEncoder<E>,
{
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where T: ?Sized + Serialize {
        self.list_element(value)
    }

    fn end(self) -> Result<(), Error> { self.list_end() }
}

impl<E, C> SerializeTupleStruct for Collection<'_, E, C>
    where
        E: Encoder,
        C: ListEncoder<E>,
{
    type Ok = ();
    type Error = Error;
    
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where T: ?Sized + Serialize {
        self.list_element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> { self.list_end() }
}

//--------------------//
//-[ Map collection ]-//
//--------------------//

impl<'se, E, C> Collection<'se, E, C>
    where
        E: Encoder,
        C: MapEncoder<E>,
{
    fn map_end(self) -> Result<(), Error> {
        self.container.end(&mut self.ser.enc)
    }

    /// Return serializer for variant to reuse
    fn variant_map_end(self) -> Result<&'se mut Serializer<E>, Error> {
        self.container.end(&mut self.ser.enc)?;
        Ok(self.ser)
    }
}

impl<E, C> SerializeMap for Collection<'_, E, C>
    where
        E: Encoder,
        C: MapEncoder<E>,
{
    type Ok = ();
    type Error = Error;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Error>
        where T: ?Sized + Serialize
    {
        key.serialize(&mut MapKeySerializer {
            enc: &mut self.ser.enc,
            map: &mut self.container,
        })
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Error>
        where T: ?Sized + Serialize
    {
        value.serialize(&mut *self.ser)
    }

    fn end(self) -> Result<(), Error> { self.map_end() }
}

impl<E, C> SerializeStruct for Collection<'_, E, C>
    where
        E: Encoder,
        C: MapEncoder<E>,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.serialize_key(key)?;
        self.serialize_value(value)
    }

    fn end(self) -> Result<(), Error> { self.map_end() }
}

impl<E, C> SerializeStructVariant for Collection<'_, E, C>
    where
        E: Encoder,
        C: MapEncoder<E>,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        <Self as SerializeStruct>::serialize_field(self, key, value)
    }

    fn end(self) -> Result<(), Error> { self.map_end() }
}

//---------------------------//
//-[ Variant serialization ]-//
//---------------------------//

pub struct Variant<Inner, Outer> {
    inner: Inner,
    outer: Outer,
}
impl<Inner, Outer> Variant<Inner, Outer> {
    const fn new(inner: Inner, outer: Outer) -> Self {
        Self { inner, outer }
    }
}

impl<Enc, Inner, Outer> SerializeStructVariant 
    for Variant<Collection<'_, Enc, Inner>, Outer>
    where
        Enc: Encoder,
        Inner: MapEncoder<Enc>,
        Outer: MapEncoder<Enc>,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize
    {
        SerializeStruct::serialize_field(&mut self.inner, key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let ser = self.inner.variant_map_end()?;
        self.outer.end(&mut ser.enc)
    }
}

impl<Enc, Inner, Outer> SerializeTupleVariant
    for Variant<Collection<'_, Enc, Inner>, Outer>
    where
        Enc: Encoder,
        Inner: ListEncoder<Enc>,
        Outer: MapEncoder<Enc>,
{
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where T: ?Sized + Serialize {
        SerializeTuple::serialize_element(&mut self.inner, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let ser = self.inner.variant_list_end()?;
        self.outer.end(&mut ser.enc)
    }
}