// Ported from: kubo/boxo/chunker
// Kubo version: v0.39.0
// Original: https://github.com/ipfs/kubo/tree/v0.39.0/boxo/chunker
//
// Original work: Copyright (c) Protocol Labs, Inc.
// Port: Copyright (c) 2026 ferripfs contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Chunking algorithms for splitting files into blocks.

use bytes::{Bytes, BytesMut};

/// Default chunk size (256 KiB)
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Maximum links per node in balanced DAG
pub const DEFAULT_LINKS_PER_BLOCK: usize = 174;

/// UnixFS error type
#[derive(Debug, thiserror::Error)]
pub enum UnixfsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    //#[error("Blockstore error: {0}")]
    //Blockstore(#[from] ferripfs_blockstore::BlockstoreError),

    //#[error("Protobuf encode error: {0}")]
    //ProtobufEncode(#[from] prost::EncodeError),

    //#[error("Protobuf decode error: {0}")]
    //ProtobufDecode(#[from] prost::DecodeError),

    #[error("Invalid UnixFS data: {0}")]
    InvalidData(String),

    #[error("CID error: {0}")]
    Cid(String),

    #[error("Not a file: {0}")]
    NotAFile(String),

    #[error("Not a directory: {0}")]
    NotADirectory(String),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),
}

type UnixfsResult<T> = Result<T, UnixfsError>;

pub trait Chunker {
    /// Feed more input, emitting any chunks which are now complete.
    fn push(&mut self, input: &[u8], emit: impl FnMut(Bytes));

    /// No more input, emit whatever remains (if anything).
    fn finish(&mut self, emit: impl FnMut(Bytes));
}

/// Size-based chunker that splits data at fixed intervals.
pub struct SizeChunker {
    chunk_size: usize,
    buffer: BytesMut,
}

impl SizeChunker {
    /// Create a new size-based chunker with the default chunk size (256 KiB).
    pub fn new() -> Self {
        Self::with_size(DEFAULT_CHUNK_SIZE)
    }

    /// Create a new size-based chunker with a specific chunk size.
    pub fn with_size(chunk_size: usize) -> Self {
        Self { chunk_size, buffer: BytesMut::new() }
    }

    /// Get the chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

// Iterator<Item = UnixfsResult<Bytes>>
impl Chunker for SizeChunker {
    fn push(&mut self, input: &[u8], mut emit: impl FnMut(Bytes)) {
        self.buffer.extend_from_slice(input);
        
        // Strictly greater so a full trailing chunk waits for finish
        while self.buffer.len() > self.chunk_size {
            emit(self.buffer.split_to(self.chunk_size).freeze());
        }
    }

    fn finish(&mut self, mut emit: impl FnMut(Bytes)) {
        if !self.buffer.is_empty() {
            emit(self.buffer.split().freeze());
        }
    }
}

/// Constants and tables for implementing rabin rolling hash window
mod rabin_const {
    const POLY: u64 = 0x3DA3358B4DC173;

    pub const TABLE: [u64; 256] = {
        let mut table = [0u64; 256];
        let mut i = 0;
        while i < 256 {
            let mut hash = i as u64;
            let mut j = 0;
            while j < 8 {
                if hash & 1 == 1 {
                    hash = (hash >> 1) ^ POLY;
                }
                else {
                    hash >>= 1;
                }
                j += 1;
            }
            table[i] = hash;
            i += 1;
        }
        table
    };

    // Calculate out table for window removal
    pub const OUT_TABLE: [u64; 256] = {
        let mut out_table = [0u64; 256];
        let mut i = 0;
        while i < 256 {
            let mut hash = TABLE[i];
            let mut j = 0;
            while j < 64 {
                if hash & 1 == 1 {
                    hash = (hash >> 1) ^ POLY;
                }
                else {
                    hash >>= 1;
                }
                j += 1;
            }
            out_table[i] = hash;
            i += 1;
        }
        out_table
    };
}

/// Rabin rolling hash window
struct RabinWindow {
    window: [u8; 64],
    wpos: usize,
    hash: u64,
    mask: u64,
}

impl RabinWindow {
    fn new(avg_size: usize) -> Self {
        // Calculate mask for average chunk size
        // We want mask such that (hash & mask) == 0 with probability 1/avg_size
        let bits = (avg_size as f64).log2().floor() as u32;
        let mask = (1u64 << bits) - 1;

        Self {
            window: [0u8; 64],
            wpos: 0,
            hash: 0,
            mask,
        }
    }

    fn reset(&mut self) {
        self.window = [0u8; 64];
        self.wpos = 0;
        self.hash = 0;
    }

    fn slide(&mut self, byte: u8) -> u64 {
        let out = self.window[self.wpos];
        self.window[self.wpos] = byte;
        self.wpos = (self.wpos + 1) & 63;

        self.hash =
            rabin_const::TABLE[(self.hash ^ byte as u64) as u8 as usize]
            ^ rabin_const::OUT_TABLE[out as usize];

        self.hash
    }

    fn is_boundary(&self) -> bool {
        (self.hash & self.mask) == 0
    }
}

/// Rabin fingerprint chunker for content-defined chunking.
///
/// Uses a rolling hash to find natural break points in data,
/// which improves deduplication when similar files are added.
pub struct RabinChunker {
    min_size: usize,
    #[allow(dead_code)]
    avg_size: usize,
    max_size: usize,
    window: RabinWindow,
    buffer: BytesMut,
    chunk_len: usize,
}

impl RabinChunker {
    /// Create a new Rabin chunker with default parameters.
    ///
    /// Default: min=128KB, avg=256KB, max=1MB
    pub fn new() -> Self {
        Self::with_params(128 * 1024, 256 * 1024, 1024 * 1024)
    }

    /// Create a new Rabin chunker with custom parameters.
    pub fn with_params(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        Self {
            min_size,
            avg_size,
            max_size,
            window: RabinWindow::new(avg_size),
            buffer: BytesMut::new(),
            chunk_len: 0,
        }
    }
}

impl Chunker for RabinChunker {
    fn push(&mut self, input: &[u8], mut emit: impl FnMut(Bytes)) {
        self.buffer.extend_from_slice(input);

        for &byte in input {
            self.window.slide(byte);
            self.chunk_len += 1;

            if self.window.is_boundary() || self.chunk_len >= self.max_size {
                if self.chunk_len >= self.min_size {
                    emit(self.buffer.split_to(self.chunk_len).freeze());
                    self.chunk_len = 0;
                }
            }
        }
    }

    fn finish(&mut self, mut emit: impl FnMut(Bytes)) {
        if !self.buffer.is_empty() {
            emit(self.buffer.split().freeze());
        }
        self.chunk_len = 0;
        self.window.reset();
    }
}

/// Chunker type enum for configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkerType {
    /// Fixed-size chunking
    Size(usize),
    /// Rabin fingerprint chunking
    Rabin { min: usize, avg: usize, max: usize },
}

impl Default for ChunkerType {
    fn default() -> Self {
        ChunkerType::Size(DEFAULT_CHUNK_SIZE)
    }
}

impl ChunkerType {
    /// Parse a chunker spec string (e.g., "size-262144" or "rabin-262144-524288-1048576")
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(size_str) = s.strip_prefix("size-") {
            size_str.parse().ok().map(ChunkerType::Size)
        }
        else if let Some(params) = s.strip_prefix("rabin-") {
            let parts: Vec<&str> = params.split('-').collect();
            match parts[..] {
                [min, avg, max] => Some(ChunkerType::Rabin {
                    min: min.parse().ok()?,
                    avg: avg.parse().ok()?,
                    max: max.parse().ok()?,
                }),
                [avg] => {
                    let avg = avg.parse().ok()?;
                    Some(ChunkerType::Rabin {
                        min: avg / 2,
                        avg,
                        max: avg * 4,
                    })
                },
                _ => None,
            }
        }
        else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_chunker_small() {
        let data = b"hello world";
        let mut chunker = SizeChunker::new();

        let mut chunks = 0;
        let mut check = |chunk: Bytes| {
            assert_eq!(&chunk[..], data);
            chunks += 1;
        };
        chunker.push(data, &mut check);
        chunker.finish(&mut check);
        assert_eq!(chunks, 1);
    }

    #[test]
    fn test_size_chunker_multiple() {
        let data = vec![0u8; 1000];
        let mut chunker = SizeChunker::with_size(300);

        let mut total = 0;
        let mut chunks = 0;
        
        let mut count = |chunk: Bytes| {
            total += chunk.len();
            chunks += 1;
        };
        for win in data.chunks(10) {
            chunker.push(win, &mut count);
        }
        chunker.finish(&mut count);

        assert_eq!(total, 1000);
        assert_eq!(chunks, 4); // 300 + 300 + 300 + 100
    }

    #[test]
    fn test_size_chunker_exact() {
        let data = vec![0u8; 600];
        let mut chunker = SizeChunker::with_size(300);

        let mut chunks = 0;
        let mut check = |chunk: Bytes| {
            assert_eq!(chunk.len(), 300);
            chunks += 1;
        };
        chunker.push(&data, &mut check);
        chunker.finish(&mut check);
        assert_eq!(chunks, 2);
    }

    #[test]
    fn test_rabin_chunker() {
        // Create data with some patterns
        let mut data = Vec::new();
        for i in 0..100 {
            data.extend_from_slice(&[i as u8; 1000]);
        }
        let dlen = data.len();

        let mut chunker = RabinChunker::with_params(
            1024,  // min 1KB
            4096,  // avg 4KB
            16384, // max 16KB
        );

        let mut total = 0;
        let mut chunks = 0;
        let mut check = |chunk: Bytes| {
            assert!(chunk.len() >= 1024 || total + chunk.len() == dlen);
            assert!(chunk.len() <= 16384);
            total += chunk.len();
            chunks += 1;
        };
        for win in data.chunks(100) {
            chunker.push(win, &mut check);
        }
        chunker.finish(&mut check);

        assert_eq!(total, dlen);
        assert!(chunks > 1);
    }

    #[test]
    fn test_chunker_type_parse() {
        assert_eq!(
            ChunkerType::parse("size-262144"),
            Some(ChunkerType::Size(262144))
        );

        assert_eq!(
            ChunkerType::parse("rabin-131072-262144-1048576"),
            Some(ChunkerType::Rabin {
                min: 131072,
                avg: 262144,
                max: 1048576
            })
        );

        assert_eq!(
            ChunkerType::parse("rabin-262144"),
            Some(ChunkerType::Rabin {
                min: 131072,
                avg: 262144,
                max: 1048576
            })
        );

        assert!(ChunkerType::parse("invalid").is_none());
    }
}
