//! Import files and directories into UnixFSv1, like `ipfs add`.
//!
//! Defaults follow Kubo's unixfs-v1-2025 profile (IPIP-499): CIDv1,
//! sha2-256, raw leaves, 1 MiB chunks, balanced layout with 1024 links,
//! HAMT directories over 256 KiB with fanout 256.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use bytes::Bytes;

use crate::block::Block;
use crate::chunker::{Chunker, SizeChunker};
use crate::cid::{Cidv1Spec, RAW_CODEC};
use crate::dag::{
    self, BalancedLayout, BlockSink, DagLink, DirLayoutBuilder, DirLayoutStrategy,
    DynamicDirectory, FileLayoutBuilder, FileLayoutStrategy,
};
use crate::multihash::MultihashFunc;

/// Kubo's unixfs-v1-2025 profile: fixed chunk size.
pub const CHUNK_SIZE: usize = 1024 * 1024;

const READ_BUF: usize = 64 * 1024;

pub struct Importer<F = BalancedLayout, D = DynamicDirectory> {
    pub chunk_size: usize,
    pub layout: F,
    pub directory: D,
    /// Include dotfiles (`ipfs add --hidden`).
    pub hidden: bool,
}

impl Default for Importer {
    fn default() -> Self {
        Self {
            chunk_size: CHUNK_SIZE,
            layout: BalancedLayout::default(),
            directory: DynamicDirectory::default(),
            hidden: false,
        }
    }
}

impl<F: FileLayoutStrategy, D: DirLayoutStrategy> Importer<F, D> {
    /// Import whatever is at `path` without following symlinks. Every
    /// entry added is passed to `report` with its path. Returns None for
    /// things UnixFS can't represent (sockets, devices, ...).
    pub fn add_path(
        &self,
        path: &Path,
        sink: &mut impl BlockSink,
        report: &mut impl FnMut(&Path, &DagLink),
    ) -> io::Result<Option<DagLink>> {
        let kind = fs::symlink_metadata(path)?.file_type();
        let link = if kind.is_file() {
            self.add_file(File::open(path)?, sink)?
        }
        else if kind.is_dir() {
            self.add_dir(path, sink, report)?
        }
        else if kind.is_symlink() {
            dag::symlink_node(fs::read_link(path)?.as_os_str().as_bytes(), sink)?
        }
        else {
            eprintln!("skipping {}: not a file, directory or symlink", path.display());
            return Ok(None);
        };
        report(path, &link);
        Ok(Some(link))
    }

    /// Import a file's contents.
    pub fn add_file(&self, mut reader: impl Read, sink: &mut impl BlockSink) -> io::Result<DagLink> {
        let mut chunker = SizeChunker::with_size(self.chunk_size);
        let mut layout = self.layout.builder();
        let mut chunks: Vec<Bytes> = Vec::new();
        let mut buf = vec![0u8; READ_BUF];
        let mut any = false;

        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            chunker.push(buf.get(..n).unwrap_or_default(), |c| chunks.push(c));
            for chunk in std::mem::take(&mut chunks) {
                any = true;
                layout.add_chunk(leaf(&chunk, sink)?, sink)?;
            }
        }
        chunker.finish(|c| chunks.push(c));
        // An empty file is a single empty leaf
        if !any && chunks.is_empty() {
            chunks.push(Bytes::new());
        }
        for chunk in chunks {
            layout.add_chunk(leaf(&chunk, sink)?, sink)?;
        }

        layout.finalize(sink)
    }

    /// Import a directory and everything in it.
    pub fn add_dir(
        &self,
        path: &Path,
        sink: &mut impl BlockSink,
        report: &mut impl FnMut(&Path, &DagLink),
    ) -> io::Result<DagLink> {
        let mut dir = self.directory.builder();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            if !self.hidden && name.as_bytes().starts_with(b".") {
                continue;
            }
            if let Some(link) = self.add_path(&entry.path(), sink, report)? {
                dir.add_link(name.as_bytes().to_vec(), link, sink)?;
            }
        }
        dir.finalize(sink)
    }
}

/// Store a chunk as a raw leaf.
fn leaf(chunk: &[u8], sink: &mut impl BlockSink) -> io::Result<DagLink> {
    let spec = Cidv1Spec::new(RAW_CODEC, MultihashFunc::Sha2_256);
    let block: Block = Block::hash(spec, chunk.into());
    let size = dag::len64(chunk);
    let cid = block.cid().clone();
    sink.put(block)?;
    Ok(DagLink { cid, tsize: size, filesize: size })
}
