//! UnixFS node types and encoding.
//!
//! This module provides the core data structures for representing UnixFS
//! content in IPFS. UnixFS is a data format for encoding files, directories,
//! and symlinks as a DAG (Directed Acyclic Graph) of content-addressed blocks.

use bytes::{Bytes, BytesMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::canon::{Canon, CanonBuilder};

use super::error::{Error, InnerError, Origin, try_context};
use super::dagpb::PbNode;
use super::pb::{self, PbField, Int64, PbDecode, PbType, PbEncode, Uint64};

/// Field in a UnixTime message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(super) enum UnixTimeF {
    Seconds = 1,
    FractionalNanoseconds = 2,
}

/// UnixTime message in unixfsv1 dag-pb.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnixTime {
    sec: i64,
    nsec: Option<i32>
}

impl PbEncode for UnixTime {
    fn pb_size(&self) -> u64 {
        PbField::size(Int64(self.sec)) +
        PbField::size(self.nsec)
    }

    fn pb_encode(&self, buf: &mut bytes::BytesMut) {
        PbField(UnixTimeF::Seconds, Int64(self.sec)).pb_encode(buf);
        PbField(
            UnixTimeF::FractionalNanoseconds, self.nsec
        ).pb_encode(buf);
    }
}
impl PbDecode for UnixTime {
    type Output = Canon<Self>;
    type Error = Error;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        let mut link = CanonBuilder::new(UnixTime { sec: 0, nsec: None });
        let mut seen_sec = false;
        let mut last = 0u8;
        while let Some((fx, tx)) = pb::next_field(buf) {
            try_context(Origin::UnixTime, fx, tx, || {
                let t = tx.try_into().map_err(|_| InnerError::InvalidTag)?;
                if let Ok(f) = fx.try_into() {
                    // https://ipld.io/specs/codecs/dag-pb/spec/#protobuf-strictness
                    if fx == last {
                        // 3. Duplicate entries in the binary form are invalid; blocks with duplicate field values should be rejected.
                        // It's unclear if this is for unixfsv1 too or just dag-pb.
                        return Err(InnerError::Duplicate.into());
                    }
                    if fx < last {
                        // Kubo canonical encoding is in ascending order and 
                        link.noncanonical();
                    }
                    last = fx;

                    match (f, t) {
                        (UnixTimeF::Seconds, PbType::Varint) => {
                            seen_sec = true;
                            link.sec = Int64::pb_decode(buf)?;
                        },
                        (UnixTimeF::FractionalNanoseconds, PbType::Varint) =>
                            link.nsec = Some(i32::pb_decode(buf)?),
                        _ => return Err(InnerError::WrongType.into()),
                    }
                }
                else { // Unknown field
                    link.noncanonical();
                }
                Ok(())
            });
        }

        // seen is required, but assumed 0 if not found.
        if !seen_sec {
            link.noncanonical();
        }
        
        Ok(link.finish())
    }
}

/// UnixFSv1 Field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(super) enum UFSv1F {
    Type = 1,
    Data = 2,
    Filesize = 3,
    Blocksizes = 4,
    HashType = 5,
    Fanout = 6,
    Mode = 7,
    Mtime = 8,
}

/// The type of data stored in a UnixFS node.
///
/// UnixFS supports several data types for representing different kinds
/// of filesystem content. The most common are `File` and `Directory`.
///
/// # Kubo Reference
///
/// Corresponds to the `Type` field in the UnixFS protobuf Data message.
/// See `boxo/ipld/unixfs/pb/unixfs.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u64)]
pub enum DataType {
    Raw = 0, // Deprecated
    Directory = 1,
    File = 2,
    Metadata = 3, // Reserved, don't bother
    Symlink = 4,
    HamtShard = 5,
}

/// Model of the valid subsets of unixfsv1 Data enumerated over the
/// DataType property.
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum DataInner {
    Raw {} = 0,
    Directory = 1,
    File {
        data: Option<Bytes>,
        filesize: u64,
        blocksizes: Vec<u64>,
    } = 2,
    Metadata {} = 3,
    Symlink {
        data: Bytes,
    } = 4,
    HamtShard {
        hash_type: u64,
        fanout: u64,
    } = 5,
}

impl DataInner {
    pub fn field_id(&self) -> u64 {
        match self {
            Self::Raw {..} => 0,
            Self::Directory {..} => 1,
            Self::File {..} => 2,
            Self::Metadata {..} => 3,
            Self::Symlink {..} => 4,
            Self::HamtShard {..} => 5,
        }
    }
}

/// Model of unixfsv1 Data with common properties pulled out.
#[derive(Debug, Clone)]
pub struct Data {
    pub data: DataInner,
    pub mode: Option<u32>,
    pub mtime: Option<UnixTime>,
}

impl PbEncode for Data {
    fn pb_size(&self) -> u64 {
        match &self.data {
            DataInner::Raw {} => PbField::size(0),
            DataInner::Directory => PbField::size(1),
            DataInner::File { data, filesize, blocksizes} => {
                PbField::size(2) +
                PbField::size(data) +
                PbField::size(&Uint64(*filesize)) +
                blocksizes
                    .iter()
                    .map(PbField::size)
                    .sum::<u64>()
            },
            DataInner::Metadata {} => PbField::size(3),
            DataInner::Symlink { data } => {
                PbField::size(4) +
                PbField::size(data)
            },
            DataInner::HamtShard { hash_type, fanout } => {
                PbField::size(5) +
                PbField::size(hash_type) +
                PbField::size(fanout)
            },
        }
    }

    fn pb_encode(&self, buf: &mut bytes::BytesMut) {
        PbField(UFSv1F::Type, self.data.field_id()).pb_encode(buf);
        match &self.data {
            DataInner::Raw {} => {
                // Should not be written, let it pass
            },
            DataInner::Directory => {},
            DataInner::File { data, filesize, blocksizes } => {
                PbField(UFSv1F::Data, data).pb_encode(buf);
                PbField(UFSv1F::Filesize, filesize).pb_encode(buf);
                for bs in blocksizes {
                    PbField(UFSv1F::Blocksizes, bs).pb_encode(buf);
                }
            },
            DataInner::Metadata {} => {
                // Ignore
            },
            DataInner::Symlink { data } => {
                PbField(UFSv1F::Data, data).pb_encode(buf);
            },
            DataInner::HamtShard { hash_type, fanout } => {
                PbField(UFSv1F::HashType, hash_type).pb_encode(buf);
                PbField(UFSv1F::Fanout, fanout).pb_encode(buf);
            }
        }
        PbField(UFSv1F::Mode, self.mode).pb_encode(buf);
        PbField(UFSv1F::Mtime, self.mtime.as_ref()).pb_encode(buf);
    }
}
impl PbDecode for Data {
    type Output = Canon<Self>;
    type Error = Error;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        // jfc... "parse don't verify", but we might not know what the
        // DataType is until the very end so we have to track everything.
        let mut dtype = None;
        let mut data = None;
        let mut filesize = None;
        let mut blocksizes = None;
        let mut hash_type = None;
        let mut fanout = None;
        let mut mode = None;
        let mut mtime = None;

        // Parse the protobuf
        let mut canon = CanonBuilder::new(());
        let mut last = 0u8;
        while let Some((fx, tx)) = pb::next_field(buf) {
            try_context(Origin::Unixfsv1, fx, tx, || {
                let t = tx.try_into().map_err(|_| InnerError::InvalidTag)?;
                if let Ok(f) = fx.try_into() {
                    if fx < last {
                        // Kubo canonical encoding is in ascending order.
                        // blocksizes is repeated so 
                        canon.noncanonical();
                    }
                    last = fx;
                    
                    match (f, t) {
                        (UFSv1F::Type, PbType::Varint) =>
                            dtype = Some(Uint64::pb_decode(buf)?),
                        (UFSv1F::Data, PbType::Length) =>
                            data = Some(Bytes::pb_decode(buf)?),
                        (UFSv1F::Filesize, PbType::Varint) =>
                            filesize = Some(Uint64::pb_decode(buf)?),
                        (UFSv1F::Blocksizes, PbType::Varint) =>
                            blocksizes
                                .get_or_insert_with(Vec::new)
                                .push(Uint64::pb_decode(buf)?),
                        (UFSv1F::HashType, PbType::Varint) =>
                            hash_type = Some(Uint64::pb_decode(buf)?),
                        (UFSv1F::Fanout, PbType::Varint) =>
                            fanout = Some(Uint64::pb_decode(buf)?),
                        (UFSv1F::Mode, PbType::Fixed32) =>
                            mode = Some(u32::pb_decode(buf)?),
                        (UFSv1F::Mtime, PbType::Length) =>
                            mtime = Some(canon.taint(UnixTime::pb_decode(buf)?)),
                        _ => return Err(InnerError::WrongType.into()),
                    }
                }
                else { // Unknown field
                    canon.noncanonical();
                }
                Ok(())
            })?;
        }

        // Sort through the mess
        let dtype = try_context(
            Origin::Unixfsv1, UFSv1F::Type, PbType::Varint,
            || dtype
                .ok_or(InnerError::Missing)?
                .try_into()
                .map_err(|_| InnerError::DataType.into())
        )?;
        let value = match dtype {
            DataType::Raw => {
                canon.noncanonical();
                DataInner::Raw {}
            },
            DataType::Directory => {
                // Not valid on Directory
                if data.is_some() || filesize.is_some() || blocksizes.is_some() || hash_type.is_some() || fanout.is_some() {
                    canon.noncanonical();
                }
                DataInner::Directory
            },
            DataType::File => {
                // Not valid on File
                if hash_type.is_some() || fanout.is_some() {
                    canon.noncanonical();
                }
                DataInner::File {
                    data,
                    filesize: filesize.unwrap_or_else(|| {
                        // https://specs.ipfs.tech/unixfs/#decode-pbnode-data-filesize
                        // MUST include this field when creating File or Raw nodes
                        // When reading, if this field is absent, MUST interpret it
                        // as 0 (zero-length file)
                        canon.noncanonical();
                        0
                    }),
                    blocksizes: blocksizes.unwrap_or_else(Vec::new)
                }
            },
            DataType::Metadata => {
                canon.noncanonical();
                DataInner::Metadata {}
            },
            DataType::Symlink => {
                // Not valid on Symlink
                if filesize.is_some() || blocksizes.is_some() || hash_type.is_some() || fanout.is_some() {
                    canon.noncanonical();
                }
                DataInner::Symlink {
                    data: data.unwrap_or_else(|| {
                        // Symlink without a target?
                        canon.noncanonical();
                        Bytes::new()
                    })
                }
            },
            DataType::HamtShard => {
                if data.is_some() || filesize.is_some() || blocksizes.is_some() || hash_type.is_some() || fanout.is_some() {
                    canon.noncanonical();
                }
                DataInner::HamtShard {
                    hash_type: hash_type.unwrap_or_else(|| {
                        // Required field, but implementations only use murmur
                        canon.noncanonical();
                        crate::multihash::MultihashFunc::Murmur3_x64_64.into()
                    }),
                    fanout: fanout.ok_or_else(||
                        InnerError::Missing.with_context(
                            Origin::Unixfsv1, UFSv1F::Fanout, PbType::Varint
                        )
                    )?
                }
            },
        };
        
        Ok(canon.finish().map(|()| Data {
            data: value,
            mode,
            mtime,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct UnixfsNode(PbNode<Data>);

impl UnixfsNode {
    pub fn read(buf: &mut Bytes) -> Result<Canon<Self>, Error> {
        Self::pb_decode(buf)
    }

    pub fn write(&self, buf: &mut BytesMut) {
        self.pb_encode(buf)
    }
}

impl PbEncode for UnixfsNode {
    fn pb_size(&self) -> u64 {
        self.0.pb_size()
    }

    fn pb_encode(&self, buf: &mut BytesMut) {
        self.0.pb_encode(buf);
    }
}
impl PbDecode for UnixfsNode {
    type Output = Canon<Self>;
    type Error = Error;

    fn pb_decode(buf: &mut Bytes) -> Result<Self::Output, Self::Error> {
        let data = PbNode::<Data>::pb_decode(buf)?;
        match data.inner() {
            PbNode {
                links,
                data: Some(Data {
                    data: DataInner::File {
                        blocksizes, ..
                    }, ..
                })
             } if links.len() != blocksizes.len() =>
                return Err(InnerError::Mismatch),
            
            PbNode {
                links, data: None
            } if links.len() != 0 =>
                return Err(InnerError::Mismatch),

            _ => Ok(data.map(UnixfsNode))
        }
    }
}
