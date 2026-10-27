use std::borrow::Cow;
use std::num::NonZeroU32;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::de::{Error as _};
use serde::{Serialize, Deserialize};

use crate::cid::AnyCid;
use crate::serde::{Error, Kind};

#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(super) enum FieldType {
    /// Variable-length integer using leb128.
    Varint = 0,
    /// Fixed 64-bit integer (also for used for floats etc). Sign is a matter
    /// of bit casting.
    Fixed64 = 1,
    /// A length-prefixed value, used by Bytes, String, and submessages.
    Length = 2,
    //Sgroup = 3, Start of group, deprecated since 2008 and unused by dag-pb.
    //Egroup = 4, End of group
    /// Fixed 32-bit integer, sign is bit-cast.
    Fixed32 = 5,
}

/// Raw type identifier as extracted from a tag.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub(super) struct TypeId(u8);
impl TypeId {
    pub fn new(tag: u8) -> Self {
        Self(tag >> 3)
    }
}
impl TryFrom<TypeId> for FieldType {
    type Error = Error;

    fn try_from(value: TypeId) -> Result<Self, Self::Error> {
        value.0
            .try_into()
            .map_err(|_| Error::custom("garbage field tag type"))
    }
}

impl From<FieldType> for TypeId {
    fn from(value: FieldType) -> Self {
        Self(value.into())
    }
}

/// Raw field identifier as extracted from a tag.
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub(super) struct FieldId(u8);
impl FieldId {
    pub fn new(tag: u8) -> Self {
        Self(tag & 7)
    }
}
impl From<FieldId> for u8 {
    fn from(value: FieldId) -> Self { value.0 }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum Msg {
    /// Initial state before stepping into Node.
    Init,
    /// The outermost map.
    Node,
    /// UnixFSv1 Data field.
    Data,
    /// mtime within UnixFSv1.
    UnixTime,
    /// An element of Node.Links[].
    Link,
}
impl Msg {
    /// Get the path of the message.
    pub fn path(&self) -> &'static str {
        match self {
            Self::Init => "{..}",
            Self::Node => "Node",
            Self::Data => "Node.Data",
            Self::UnixTime => "Node.Data.mtime",
            Self::Link => "Node.Links"
        }
    }

    /// Get the message which contains this message.
    pub fn parent(&self) -> Msg {
        match self {
            Self::Init|Self::Node => Self::Init,
            Self::Data|Self::Link => Self::Node,
            Self::UnixTime => Self::Data,
        }
    }
}

macro_rules! first {
    ($first:expr $(,$other:expr)* $(,)?) => { $first };
}

/// Declaratively define the fields of dag-pb.
macro_rules! field {
    (
        $vis:vis enum $outer:ident {$(
            enum $msg:ident $(<$gen:tt>)? {$(
                $field:ident $(($rename:expr))?:
                $(optional:ident)? $type:ident ($kind:ident) = $tag:literal
            ),* $(,)?}
        )*}
    ) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        $vis enum $outer {$(
            $($field,)*
        )*}
        impl $outer {
            fn metadata(&self) -> (Msg, FieldType, FieldId, Kind, &'static str) {
                match self {$(
                    $($outer::$field => (
                        Msg::$msg,
                        FieldType::$type,
                        FieldId($tag),
                        Kind::$kind, {
                            const NORMAL: &'static str = stringify!($field);
                            first!($($rename,)*NORMAL)
                        }
                    ),)*
                )*}
            }
        }

        impl Msg {
            pub fn field(&self, field: FieldId) -> Option<Field> {
                match (self, field.0) {
                    $(
                        $((Self::$msg, $tag) => Some($outer::$field),)*
                    )*
                    _ => None
                }
            }
        }
    };
}

field! {
    pub(super) enum Field {
        enum Node {
            Links: Length (List) = 2,
            Data: Length (Bytes) = 1,
        }
        enum Link {
            Hash: Length (Link) = 1,
            Name: Length (String) = 2,
            Tsize: Varint (Int) = 3,
        }
        enum Data {
            Type: Varint (Int) = 1,
            UData("Data"): Length (Bytes) = 2,
            Filesize("filesize"): Varint (Int) = 3,
            Blocksizes("blocksizes"): Length (List) = 4,
            HashType("hashType"): Varint (Int) = 5,
            Fanout("fanout"): Varint (Int) = 6,
            Mode("mode"): Varint (Int) = 7,
            Mtime("mtime"): Length (Map) = 8,
        }
        enum UnixTime {
            Seconds: Varint (Int) = 1,
            FractionalNanoseconds: Fixed32 (Int) = 2,
        }
    }
}

impl Field {
    /// Get the message that a field can contain, otherwise None. This is
    /// only valid for Length-type fields.
    pub fn contains_msg(&self) -> Option<Msg> {
        Some(match self {
            Self::Data => Msg::Data,
            Self::Mtime => Msg::UnixTime,
            Self::Links => Msg::Link,
            _ => return None
        })
    }

    pub fn tag(&self) -> u8 {
        let ft:u8 = self.field_type().into();
        let fi: u8 = self.field_id().into();
        ft<<3 | fi
    }

    /// The message that contains this field.
    pub fn msg(&self) -> Msg { self.metadata().0 }
    /// The type of the field.
    pub fn field_type(&self) -> FieldType { self.metadata().1 }
    /// The field's id.
    pub fn field_id(&self) -> FieldId { self.metadata().2 }
    /// The IPLD kind of the field.
    pub fn kind(&self) -> Kind { self.metadata().3 }

    // Get the name of the field.
    pub fn name(&self) -> &'static str {
        match self {
            Field::UData => "Data",
            _ => self.metadata().4,
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.msg().path(), self.name())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    Raw = 0, // deprecated, use raw codec blocks without dag-pb instead
    Directory = 1,
    File = 2,
    Metadata = 3, // reserved for future use
    Symlink = 4,
    HAMTShard = 5,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Link<'a> {
    #[serde(rename = "Hash")]
    pub hash: AnyCid<Cow<'a, [u8]>>,
    #[serde(rename = "Name", default)]
    pub name: &'a str,
    #[serde(rename = "Tsize", default)]
    pub tsize: Option<u64>,
}

impl<'a> Link<'a> {
    pub fn named(hash: AnyCid<&'a [u8]>, name: &'a str, tsize: u64) -> Self {
        Self { hash, name, tsize: Some(tsize) }
    }
    pub fn unnamed(hash: AnyCid<&'a [u8]>, tsize: u64) -> Self {
        Self::named(hash, "", tsize)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DagPb<'a, T>
    where T: 'a
{
    #[serde(rename = "Data")]
    pub data: T,
    #[serde(rename = "Links")]
    #[serde(borrow)]
    pub links: Vec<Link<'a>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvalidFractionalNanoseconds(pub u32);
impl core::fmt::Display for InvalidFractionalNanoseconds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FractionalNanoseconds must be in 1..1e9, got {}",
            self.0
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FractionalNanoseconds(NonZeroU32);
impl TryFrom<u32> for FractionalNanoseconds {
    type Error = InvalidFractionalNanoseconds;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if let Some(nz) = NonZeroU32::new(value) && value < 1_000_000_000 {
            Ok(Self(nz))
        }
        else {
            Err(InvalidFractionalNanoseconds(value))
        }
    }
}
impl Serialize for FractionalNanoseconds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer
    {
        serializer.serialize_u32(self.0.into())
    }
}
impl<'de> Deserialize<'de> for FractionalNanoseconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: serde::Deserializer<'de>
    {
        let value = u32::deserialize(deserializer)?;
        FractionalNanoseconds::try_from(value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct UnixTime {
    #[serde(rename = "Seconds")]
    pub seconds: i64,
    #[serde(rename = "FractionalNanoseconds", default)]
    pub fractional_nanoseconds: Option<FractionalNanoseconds>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawUnixfsv1<'a> {
    #[serde(rename = "DataType")]
    pub data_type: DataType,
    #[serde(rename = "Data", default)]
    pub data: Option<&'a [u8]>,
    #[serde(rename = "filesize", default)]
    pub filesize: Option<u64>,
    #[serde(rename = "blocksizes", default)]
    pub blocksizes: Option<Vec<u64>>,
    #[serde(rename = "hashType", default)]
    pub hash_type: Option<u64>,
    #[serde(rename = "fanout", default)]
    pub fanout: Option<u64>,
    #[serde(rename = "mode", default)]
    pub mode: Option<u32>,
    #[serde(rename = "mtime", default)]
    pub mtime: Option<UnixTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Unixfsv1<'a> {
    Raw {
        data: &'a [u8],
        mode: Option<u32>,
        mtime: Option<UnixTime>,
    },
    Directory {
        mode: Option<u32>,
        mtime: Option<UnixTime>,
    },
    File {
        data: &'a [u8],
        filesize: u64,
        blocksizes: Vec<u64>,
        mode: Option<u32>,
        mtime: Option<UnixTime>,
    },
    // Metadata {},
    Symlink {
        data: &'a [u8],
        filesize: u64,
        mode: Option<u32>,
        mtime: Option<UnixTime>,
    },
    HAMTShard {
        hash_type: u64,
        fanout: u64,
        mode: Option<u32>,
        mtime: Option<UnixTime>,
    },
}

impl<'a> Unixfsv1<'a> {
    pub fn data_type(&self) -> DataType {
        match self {
            Self::Raw { .. } => DataType::Raw,
            Self::Directory { .. } => DataType::Directory,
            Self::File { .. } => DataType::File,
            Self::Symlink { .. } => DataType::Symlink,
            Self::HAMTShard { .. } => DataType::HAMTShard,
        }
    }

    pub fn data(&self) -> Option<&'a [u8]> {
        match self {
            Self::Raw { data, .. } |
            Self::File { data, .. } |
            Self::Symlink { data, .. } => Some(*data),
            _ => None
        }
    }

    pub fn filesize(&self) -> Option<u64> {
        match self {
            Self::File { filesize, .. } |
            Self::Symlink { filesize, .. } => Some(*filesize),
            _ => None
        }
    }

    pub fn blocksizes(&self) -> Option<&Vec<u64>> {
        match self {
            Self::File { blocksizes, .. } => Some(blocksizes),
            _ => None
        }
    }

    pub fn hash_type(&self) -> Option<u64> {
        match self {
            Self::HAMTShard { hash_type, .. } => Some(*hash_type),
            _ => None
        }
    }

    pub fn fanout(&self) -> Option<u64> {
        match self {
            Self::HAMTShard { fanout, .. } => Some(*fanout),
            _ => None
        }
    }

    pub fn mode(&self) -> Option<u32> {
        match self {
            Self::Raw { mode, .. } |
            Self::Directory { mode, .. } |
            Self::File { mode, .. } |
            Self::Symlink { mode, .. } |
            Self::HAMTShard { mode, .. } => *mode,
        }
    }

    pub fn mtime(&self) -> Option<&UnixTime> {
        match self {
            Self::Raw { mtime, .. } |
            Self::Directory { mtime, .. } |
            Self::File { mtime, .. } |
            Self::Symlink { mtime, .. } |
            Self::HAMTShard { mtime, .. } => mtime.as_ref()
        }
    }
}

impl<'a> TryFrom<RawUnixfsv1<'a>> for Unixfsv1<'a> {
    type Error = Error;

    fn try_from(value: RawUnixfsv1<'a>) -> Result<Self, Self::Error> {
        Ok(match value {
            RawUnixfsv1 {
                data_type: DataType::Raw,
                data: Some(data),
                // Rest
                filesize: None,
                blocksizes: None,
                hash_type: None,
                fanout: None,
                mode,
                mtime,
            } => Unixfsv1::Raw { data, mode, mtime },

            RawUnixfsv1 {
                data_type: DataType::Directory,
                // Rest
                data: None,
                filesize: None,
                blocksizes: None,
                hash_type: None,
                fanout: None,
                mode,
                mtime,
            } => Unixfsv1::Directory { mode, mtime },

            RawUnixfsv1 {
                data_type: DataType::File,
                data: Some(data),
                filesize,
                blocksizes: Some(blocksizes),
                // Rest
                hash_type: None,
                fanout: None,
                mode,
                mtime,
            } => {
                let filesize = filesize.unwrap_or(0);
                Unixfsv1::File { data, filesize, blocksizes, mode, mtime }
            },

            RawUnixfsv1 {
                data_type: DataType::Symlink,
                data: Some(data),
                filesize,
                // Rest
                blocksizes: None,
                hash_type: None,
                fanout: None,
                mode,
                mtime,
            } => {
                let filesize = filesize.unwrap_or(0);
                Unixfsv1::Symlink { data, filesize, mode, mtime }
            },

            RawUnixfsv1 {
                data_type: DataType::HAMTShard,
                hash_type: Some(hash_type),
                fanout: Some(fanout),
                // Rest
                data: None,
                filesize: None,
                blocksizes: None,
                mode,
                mtime,
            } => Unixfsv1::HAMTShard { hash_type, fanout, mode, mtime },

            _ => return Err(Error::custom(format_args!(
                "While parsing {:?}, got {:?}",
                value.data_type, value
            )))
        })
    }
}

impl<'a> From<Unixfsv1<'a>> for RawUnixfsv1<'a> {
    fn from(value: Unixfsv1<'a>) -> Self {
        Self {
            data_type: value.data_type(),
            data: value.data(),
            filesize: value.filesize(),
            blocksizes: value.blocksizes().cloned(),
            hash_type: value.hash_type(),
            fanout: value.fanout(),
            mode: value.mode(),
            mtime: value.mtime().cloned(),
        }
    }
}

impl<'a> DagPb<'a, Unixfsv1<'a>> {
    pub fn chunked_file(links: Vec<AnyCid<D>>, blocksizes: Vec<u64>) {
        Self {
            data: Unixfsv1::File {
                filesize,
                blocksizes,
            }
        }
    }
}