//! UnixFS HAMT directory sharding, matching boxo's `hamt` package.
//!
//! Each level of the trie consumes log2(fanout) bits of the murmur3-x64-64
//! hash of the entry name, most significant bits first. A bucket holds
//! either one entry or a child shard; two entries in one bucket push both
//! down into a new child shard.
//!
//! <https://specs.ipfs.tech/unixfs/#hamt-directories>

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;

use crate::dag::{BlockSink, DagLink};
use crate::multihash::{MultihashDigest, MultihashFunc};
use crate::unixfs::{self, Data, Link};

/// Kubo's unixfs-v1-2025 profile: entries per HAMT node.
pub const HAMT_FANOUT: u32 = 256;

#[derive(Debug, Clone, Copy)]
pub struct Hamt {
    /// Power of two, at most 256 (bucket indices are bytes).
    pub fanout: u32,
}

impl Default for Hamt {
    fn default() -> Self {
        Self { fanout: HAMT_FANOUT }
    }
}

impl Hamt {
    const HASH: MultihashFunc = MultihashFunc::Murmur3_x64_64;

    /// Bits of hash consumed per level.
    const fn bits(self) -> u32 {
        self.fanout.trailing_zeros()
    }

    /// Hex digits in a link name prefix, e.g. "FF" for 256.
    fn pad(self) -> usize {
        format!("{:X}", self.fanout.saturating_sub(1)).len()
    }

    /// Build a sharded directory from its (name, link) entries.
    pub fn build(self, entries: BTreeMap<Vec<u8>, DagLink>, sink: &mut impl BlockSink) -> io::Result<DagLink> {
        if !self.fanout.is_power_of_two() || !(2..=256).contains(&self.fanout) {
            return Err(io::Error::other(format!("unsupported HAMT fanout {}", self.fanout)));
        }

        let mut root = Shard::default();
        for (name, link) in entries {
            let hash = name_hash(&name)?;
            root.insert(self, 0, Entry { hash, name, link })?;
        }
        root.finalize(self, sink)
    }
}

/// The 64 hash bits of a directory entry name.
fn name_hash(name: &[u8]) -> io::Result<u64> {
    let mh = Hamt::HASH.digest::<[u8; 8]>(name).map_err(io::Error::other)?;
    Ok(u64::from_be_bytes(*mh.digest()))
}

struct Entry {
    hash: u64,
    name: Vec<u8>,
    link: DagLink,
}

enum Bucket {
    Entry(Entry),
    Shard(Shard),
}

#[derive(Default)]
struct Shard {
    buckets: BTreeMap<u8, Bucket>,
}

impl Shard {
    fn insert(&mut self, hamt: Hamt, depth: u32, entry: Entry) -> io::Result<()> {
        let index = bucket_index(hamt, depth, entry.hash)?;
        let bucket = match self.buckets.remove(&index) {
            None => Bucket::Entry(entry),
            Some(Bucket::Shard(mut child)) => {
                child.insert(hamt, depth.saturating_add(1), entry)?;
                Bucket::Shard(child)
            }
            Some(Bucket::Entry(existing)) => {
                let mut child = Self::default();
                let next = depth.saturating_add(1);
                child.insert(hamt, next, existing)?;
                child.insert(hamt, next, entry)?;
                Bucket::Shard(child)
            }
        };
        self.buckets.insert(index, bucket);
        Ok(())
    }

    /// Emit this shard and everything below it, children first.
    fn finalize(self, hamt: Hamt, sink: &mut impl BlockSink) -> io::Result<DagLink> {
        let pad = hamt.pad();
        let mut bitfield = [0u8; 32];
        let mut named: Vec<(Vec<u8>, DagLink)> = Vec::with_capacity(self.buckets.len());

        for (index, bucket) in self.buckets {
            let byte = bitfield.len().saturating_sub(usize::from(index / 8).saturating_add(1));
            if let Some(b) = bitfield.get_mut(byte) {
                *b |= 1 << (index % 8);
            }

            let mut name = String::with_capacity(pad);
            let _ = write!(name, "{index:0pad$X}");
            let mut name = name.into_bytes();
            let link = match bucket {
                Bucket::Shard(child) => child.finalize(hamt, sink)?,
                Bucket::Entry(entry) => {
                    name.extend_from_slice(&entry.name);
                    entry.link
                }
            };
            named.push((name, link));
        }

        // Kubo writes the bitfield as a big-endian big.Int, which drops
        // leading zero bytes
        let first = bitfield.iter().position(|&b| b != 0).unwrap_or(bitfield.len());
        let bitfield = bitfield.get(first..).unwrap_or_default();

        let links: Vec<Link<'_>> = named
            .iter()
            .map(|(name, link)| Link { hash: &link.cid, name, tsize: link.tsize })
            .collect();
        let data = Data::hamt_shard(bitfield, Hamt::HASH.into(), u64::from(hamt.fanout));
        let block = unixfs::node_block(&links, &data);
        let child_tsize = named.iter().map(|(_, l)| l.tsize).sum();
        DagLink::emit(block, child_tsize, 0, sink)
    }
}

/// Which bucket a hash falls in at the given depth.
fn bucket_index(hamt: Hamt, depth: u32, hash: u64) -> io::Result<u8> {
    let bits = hamt.bits();
    let shift = depth
        .checked_add(1)
        .and_then(|d| d.checked_mul(bits))
        .and_then(|used| 64u32.checked_sub(used))
        .ok_or_else(|| io::Error::other("HAMT hash collision, ran out of hash bits"))?;
    let mask = (1u64 << bits).saturating_sub(1);
    u8::try_from((hash >> shift) & mask).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_is_hex_digits() {
        assert_eq!(Hamt::default().pad(), 2);
        assert_eq!(Hamt { fanout: 16 }.pad(), 1);
    }

    #[test]
    fn index_takes_high_bits_first() {
        let hamt = Hamt::default();
        let hash = 0x0123_4567_89ab_cdef;
        assert_eq!(bucket_index(hamt, 0, hash).ok(), Some(0x01));
        assert_eq!(bucket_index(hamt, 7, hash).ok(), Some(0xef));
        assert!(bucket_index(hamt, 8, hash).is_err());
    }
}
