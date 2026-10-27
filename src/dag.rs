//! Laying out files and directories as UnixFSv1 DAGs.

use std::collections::BTreeMap;
use std::io;

use crate::block::Block;
use crate::cid::Cidv1;
use crate::hamt::Hamt;
use crate::unixfs::{self, Data, Link};

/// Kubo's unixfs-v1-2025 profile: max links per file node.
pub const FILE_WIDTH: usize = 1024;
/// Kubo's unixfs-v1-2025 profile: basic directories larger than this (in
/// serialized bytes) are sharded into a HAMT.
pub const HAMT_THRESHOLD: usize = 256 * 1024;

/// Somewhere to put blocks as the DAG is built.
pub trait BlockSink {
    fn put(&mut self, block: Block) -> io::Result<()>;
}

/// Discard blocks, for when only the CIDs matter (`ipfs add --only-hash`).
pub struct NullSink;
impl BlockSink for NullSink {
    fn put(&mut self, _block: Block) -> io::Result<()> { Ok(()) }
}

/// Book-keeping for links which track the size of their DAG.
#[derive(Debug, Clone)]
pub struct DagLink {
    pub cid: Cidv1,
    /// Cumulative serialized size of every block in the DAG, used as the
    /// parent's link Tsize.
    pub tsize: u64,
    /// Bytes of file content under this DAG, used for blocksizes. Zero for
    /// anything which isn't a file.
    pub filesize: u64,
}

impl DagLink {
    /// Emit a freshly built node and get a link to it.
    pub fn emit(block: Block, child_tsize: u64, filesize: u64, sink: &mut impl BlockSink) -> io::Result<Self> {
        let tsize = len64(block.data()).saturating_add(child_tsize);
        let cid = block.cid().clone();
        sink.put(block)?;
        Ok(Self { cid, tsize, filesize })
    }
}

pub fn len64(data: &[u8]) -> u64 {
    u64::try_from(data.len()).unwrap_or(u64::MAX)
}

//-----------//
//-[ Files ]-//
//-----------//

/// Implements how to layout a file within the IPLD DAG
pub trait FileLayoutBuilder {
    /// Add a chunk (leaf) to the file layout.
    fn add_chunk(&mut self, chunk: DagLink, sink: &mut impl BlockSink) -> io::Result<()>;

    /// Finalize the file layout, returning the root.
    fn finalize(self, sink: &mut impl BlockSink) -> io::Result<DagLink>;
}

/// A generic strategy for constructing `FileLayoutBuilder`s
pub trait FileLayoutStrategy {
    type Builder: FileLayoutBuilder;

    /// Construct a builder implementing the strategy.
    fn builder(&self) -> Self::Builder;
}

/// Construct files with a balanced layout, all leaves at the same depth.
#[derive(Debug, Clone, Copy)]
pub struct BalancedLayout {
    pub width: usize,
}

impl Default for BalancedLayout {
    fn default() -> Self {
        Self { width: FILE_WIDTH }
    }
}

impl FileLayoutStrategy for BalancedLayout {
    type Builder = BalancedLayoutBuilder;

    fn builder(&self) -> Self::Builder {
        BalancedLayoutBuilder { levels: Vec::new(), width: self.width.max(2) }
    }
}

pub struct BalancedLayoutBuilder {
    /// Pending links per level, `levels[0]` being the leaves. Think of it
    /// as a number where each level is a digit in base `width`.
    levels: Vec<Vec<DagLink>>,
    width: usize,
}

impl BalancedLayoutBuilder {
    /// Push a link into a level, carrying full levels upwards. A level
    /// only carries once something *else* needs to go in it, so a level
    /// with exactly `width` links can still become the root.
    fn push(&mut self, mut level: usize, mut link: DagLink, sink: &mut impl BlockSink) -> io::Result<()> {
        loop {
            while self.levels.len() <= level {
                self.levels.push(Vec::with_capacity(self.width));
            }
            let Some(links) = self.levels.get_mut(level) else { continue };
            if links.len() < self.width {
                links.push(link);
                return Ok(());
            }
            // Full, replace with the new link and carry the old ones up
            let full = std::mem::replace(links, vec![link]);
            link = file_node(&full, sink)?;
            level = level.saturating_add(1);
        }
    }
}

impl FileLayoutBuilder for BalancedLayoutBuilder {
    fn add_chunk(&mut self, chunk: DagLink, sink: &mut impl BlockSink) -> io::Result<()> {
        self.push(0, chunk, sink)
    }

    fn finalize(mut self, sink: &mut impl BlockSink) -> io::Result<DagLink> {
        // A lone leaf is its own root
        if let [leaves] = self.levels.as_slice() && let [leaf] = leaves.as_slice() {
            return Ok(leaf.clone());
        }

        // Close off every partial level from the bottom up. Pushing can
        // carry and grow the tree, so re-check the height each time.
        let mut level = 0;
        loop {
            let links = self.levels.get_mut(level).map(std::mem::take).unwrap_or_default();
            if level.saturating_add(1) >= self.levels.len() {
                return file_node(&links, sink);
            }
            if !links.is_empty() {
                let node = file_node(&links, sink)?;
                self.push(level.saturating_add(1), node, sink)?;
            }
            level = level.saturating_add(1);
        }
    }
}

/// Build an interior file node over the given children.
fn file_node(children: &[DagLink], sink: &mut impl BlockSink) -> io::Result<DagLink> {
    let blocksizes: Vec<u64> = children.iter().map(|c| c.filesize).collect();
    let filesize = blocksizes.iter().sum();
    let links: Vec<Link<'_>> = children
        .iter()
        .map(|c| Link { hash: &c.cid, name: b"", tsize: c.tsize })
        .collect();
    let block = unixfs::node_block(&links, &Data::file(filesize, &blocksizes));
    let child_tsize = children.iter().map(|c| c.tsize).sum();
    DagLink::emit(block, child_tsize, filesize, sink)
}

/// Build a symlink node.
pub fn symlink_node(target: &[u8], sink: &mut impl BlockSink) -> io::Result<DagLink> {
    DagLink::emit(unixfs::node_block(&[], &Data::symlink(target)), 0, 0, sink)
}

//-----------------//
//-[ Directories ]-//
//-----------------//

/// Implements how to layout a directory within the IPLD DAG
pub trait DirLayoutBuilder {
    /// Add a named entry to the directory layout.
    fn add_link(&mut self, name: Vec<u8>, link: DagLink, sink: &mut impl BlockSink) -> io::Result<()>;

    /// Finalize the directory layout, returning the root.
    fn finalize(self, sink: &mut impl BlockSink) -> io::Result<DagLink>;
}

/// A generic strategy for constructing `DirLayoutBuilder`s
pub trait DirLayoutStrategy {
    type Builder: DirLayoutBuilder;

    /// Construct a builder implementing the strategy.
    fn builder(&self) -> Self::Builder;
}

/// Kubo's dynamic directory: a basic directory, unless its block would
/// exceed `threshold` bytes, in which case it's sharded with `hamt`.
///
/// Adding only ever grows a directory, so rather than switching mid-way
/// like Kubo does it's enough to decide once at the end.
#[derive(Debug, Clone, Copy)]
pub struct DynamicDirectory {
    pub threshold: usize,
    pub hamt: Hamt,
}

impl Default for DynamicDirectory {
    fn default() -> Self {
        Self { threshold: HAMT_THRESHOLD, hamt: Hamt::default() }
    }
}

impl DirLayoutStrategy for DynamicDirectory {
    type Builder = DynamicDirectoryBuilder;

    fn builder(&self) -> Self::Builder {
        DynamicDirectoryBuilder { strategy: *self, entries: BTreeMap::new() }
    }
}

pub struct DynamicDirectoryBuilder {
    strategy: DynamicDirectory,
    /// Sorted bytewise by name, the order Kubo writes basic directories in.
    entries: BTreeMap<Vec<u8>, DagLink>,
}

impl DirLayoutBuilder for DynamicDirectoryBuilder {
    fn add_link(&mut self, name: Vec<u8>, link: DagLink, _sink: &mut impl BlockSink) -> io::Result<()> {
        self.entries.insert(name, link);
        Ok(())
    }

    fn finalize(self, sink: &mut impl BlockSink) -> io::Result<DagLink> {
        let links: Vec<Link<'_>> = self.entries
            .iter()
            .map(|(name, link)| Link { hash: &link.cid, name, tsize: link.tsize })
            .collect();
        let block = unixfs::node_block(&links, &Data::directory());
        drop(links);

        if block.len() > self.strategy.threshold {
            return self.strategy.hamt.build(self.entries, sink);
        }

        let child_tsize = self.entries.values().map(|l| l.tsize).sum();
        DagLink::emit(block, child_tsize, 0, sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::{Cidv1Spec, RAW_CODEC};
    use crate::multihash::MultihashFunc;

    /// Count emitted blocks.
    #[derive(Default)]
    struct Count(usize);
    impl BlockSink for Count {
        fn put(&mut self, _block: Block) -> io::Result<()> {
            self.0 = self.0.saturating_add(1);
            Ok(())
        }
    }

    fn leaf(i: u8) -> DagLink {
        let spec = Cidv1Spec::new(RAW_CODEC, MultihashFunc::Sha2_256);
        DagLink { cid: spec.hash(&[i]), tsize: 1, filesize: 1 }
    }

    fn layout(width: usize, chunks: u8) -> (DagLink, usize) {
        let mut sink = Count::default();
        let mut builder = BalancedLayout { width }.builder();
        for i in 0..chunks {
            builder.add_chunk(leaf(i), &mut sink).expect("add");
        }
        (builder.finalize(&mut sink).expect("finalize"), sink.0)
    }

    #[test]
    fn single_leaf_is_root() {
        let (root, nodes) = layout(2, 1);
        assert_eq!(root.cid, leaf(0).cid);
        assert_eq!(nodes, 0);
    }

    #[test]
    fn exactly_full_root_does_not_carry() {
        // 4 leaves at width 4 is one node, not a root over one node
        assert_eq!(layout(4, 4).1, 1);
    }

    #[test]
    fn balanced_shapes() {
        // width 2: 3 leaves = root[n(0,1), n(2)]
        assert_eq!(layout(2, 3).1, 3);
        // width 2: 5 leaves = root[n(n(0,1), n(2,3)), n(n(4))]
        assert_eq!(layout(2, 5).1, 6);
        assert_eq!(layout(2, 5).0.filesize, 5);
    }
}
