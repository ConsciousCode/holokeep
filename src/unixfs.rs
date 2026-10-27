//! Minimal encoder for dag-pb nodes carrying UnixFSv1 data.
//!
//! This only writes, and only the canonical form: dag-pb Links (field 2)
//! before Data (field 1), UnixFS fields in ascending order, no mode/mtime.
//! That's exactly what Kubo produces, so byte-identical blocks give
//! identical CIDs. Parsing lives in the (WIP) serde-based `dagpb` module.
//!
//! <https://specs.ipfs.tech/unixfs/>

use num_enum::IntoPrimitive;

use crate::block::Block;
use crate::cid::{CidRef, Cidv1, Cidv1Spec, DAG_PB_CODEC};
use crate::multihash::MultihashFunc;
use crate::varint;

/// UnixFSv1 `Data.Type`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoPrimitive)]
#[repr(u64)]
pub enum DataType {
    Raw = 0,
    Directory = 1,
    File = 2,
    Metadata = 3,
    Symlink = 4,
    HAMTShard = 5,
}

/// The UnixFSv1 `Data` message, carried in `PBNode.Data`.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names, reason = "names mirror the spec")]
pub struct Data<'a> {
    pub data_type: DataType,
    pub data: Option<&'a [u8]>,
    pub filesize: Option<u64>,
    pub blocksizes: &'a [u64],
    pub hash_type: Option<u64>,
    pub fanout: Option<u64>,
}

impl<'a> Data<'a> {
    const fn new(data_type: DataType) -> Self {
        Self {
            data_type,
            data: None,
            filesize: None,
            blocksizes: &[],
            hash_type: None,
            fanout: None,
        }
    }

    /// Interior node of a chunked file.
    pub const fn file(filesize: u64, blocksizes: &'a [u64]) -> Self {
        Self { filesize: Some(filesize), blocksizes, ..Self::new(DataType::File) }
    }

    /// Basic (unsharded) directory.
    pub const fn directory() -> Self {
        Self::new(DataType::Directory)
    }

    /// Symlink; Kubo stores the target without a filesize.
    pub const fn symlink(target: &'a [u8]) -> Self {
        Self { data: Some(target), ..Self::new(DataType::Symlink) }
    }

    /// One node of a HAMT-sharded directory.
    pub const fn hamt_shard(bitfield: &'a [u8], hash_type: u64, fanout: u64) -> Self {
        Self {
            data: Some(bitfield),
            hash_type: Some(hash_type),
            fanout: Some(fanout),
            ..Self::new(DataType::HAMTShard)
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_uint(buf, 1, self.data_type.into());
        if let Some(data) = self.data {
            put_bytes(buf, 2, data);
        }
        if let Some(filesize) = self.filesize {
            put_uint(buf, 3, filesize);
        }
        // proto2 `repeated uint64` is unpacked, one tag per element
        for &size in self.blocksizes {
            put_uint(buf, 4, size);
        }
        if let Some(hash_type) = self.hash_type {
            put_uint(buf, 5, hash_type);
        }
        if let Some(fanout) = self.fanout {
            put_uint(buf, 6, fanout);
        }
    }
}

/// A dag-pb `PBLink`.
#[derive(Debug, Clone)]
pub struct Link<'a> {
    pub hash: &'a Cidv1,
    pub name: &'a [u8],
    /// Cumulative serialized size of the linked DAG.
    pub tsize: u64,
}

impl Link<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_bytes(buf, 1, &self.hash.to_bytes());
        // Kubo always writes Name, even when empty
        put_bytes(buf, 2, self.name);
        put_uint(buf, 3, self.tsize);
    }
}

/// Serialize a dag-pb node.
pub fn encode_node(links: &[Link<'_>], data: &Data<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    for link in links {
        scratch.clear();
        link.encode(&mut scratch);
        put_bytes(&mut buf, 2, &scratch);
    }
    scratch.clear();
    data.encode(&mut scratch);
    put_bytes(&mut buf, 1, &scratch);
    buf
}

/// Serialize a dag-pb node and wrap it in a block with a CIDv1.
pub fn node_block(links: &[Link<'_>], data: &Data<'_>) -> Block {
    let spec = Cidv1Spec::new(DAG_PB_CODEC, MultihashFunc::Sha2_256);
    Block::hash(spec, encode_node(links, data).into_boxed_slice())
}

//------------------------//
//-[ Protobuf primitives ]-//
//------------------------//

const VARINT: u64 = 0;
const LEN: u64 = 2;

fn put_tag(buf: &mut Vec<u8>, field: u64, wire: u64) {
    varint::write(buf, field << 3 | wire);
}

fn put_uint(buf: &mut Vec<u8>, field: u64, value: u64) {
    put_tag(buf, field, VARINT);
    varint::write(buf, value);
}

fn put_bytes(buf: &mut Vec<u8>, field: u64, value: &[u8]) {
    put_tag(buf, field, LEN);
    varint::write(buf, u64::try_from(value.len()).unwrap_or(u64::MAX));
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_data() {
        // Empty directory as Kubo writes it: Data{Type: Directory}
        assert_eq!(encode_node(&[], &Data::directory()), [0x0a, 0x02, 0x08, 0x01]);
    }

    #[test]
    fn symlink_data() {
        // Dumped from Kubo: a symlink to "../empty"
        assert_eq!(
            encode_node(&[], &Data::symlink(b"../empty")),
            b"\x0a\x0c\x08\x04\x12\x08../empty"
        );
    }

    #[test]
    fn empty_directory_cid() {
        let block = node_block(&[], &Data::directory());
        assert_eq!(
            block.cid().to_string(),
            "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354"
        );
    }
}
