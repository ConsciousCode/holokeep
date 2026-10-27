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
    use crate::pb::PbNode;

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

    /// Keep every emitted block.
    #[derive(Default)]
    struct Keep(Vec<Block>);
    impl BlockSink for Keep {
        fn put(&mut self, block: Block) -> io::Result<()> {
            self.0.push(block);
            Ok(())
        }
    }

    #[test]
    fn tsize_counts_whole_dag() {
        // Includes trees 3+ levels deep, where interior nodes are easy to miss
        for (width, chunks) in [(2, 2), (2, 5), (2, 8), (3, 10), (4, 64), (4, 65)] {
            let mut sink = Keep::default();
            let mut builder = BalancedLayout { width }.builder();
            for i in 0..chunks {
                builder.add_chunk(leaf(i), &mut sink).expect("add");
            }
            let root = builder.finalize(&mut sink).expect("finalize");
            let nodes: u64 = sink.0.iter().map(|b| len64(b.data())).sum();
            assert_eq!(root.tsize, nodes + u64::from(chunks), "width {width}, {chunks} chunks");
            assert_eq!(root.filesize, u64::from(chunks));
            // Children before parents, so the root comes last
            assert_eq!(sink.0.last().map(Block::cid), Some(&root.cid));
        }
    }

    #[test]
    fn balanced_depth() {
        // Full trees don't grow an extra level: width^n leaves is n levels
        assert_eq!(layout(2, 8).1, 4 + 2 + 1);
        assert_eq!(layout(3, 9).1, 3 + 1);
        assert_eq!(layout(3, 10).1, 4 + 2 + 1);
    }

    /// Kubo: a directory of files `a`..`j`, each containing its own name.
    fn letters(strategy: DynamicDirectory, order: impl Iterator<Item = u8>) -> DagLink {
        let mut sink = NullSink;
        let mut dir = strategy.builder();
        for c in order {
            dir.add_link(vec![c], leaf(c), &mut sink).expect("add");
        }
        dir.finalize(&mut sink).expect("finalize")
    }

    #[test]
    fn basic_directory_matches_kubo() {
        let expected = "bafybeieyljareszbgtwnecod7waccwrwxc4hnkhvcfz46jjkvm6lejz6x4";
        let dir = letters(DynamicDirectory::default(), b'a'..=b'j');
        assert_eq!(dir.cid.to_string(), expected);
        // Sorted by name whatever order they were added in
        let dir = letters(DynamicDirectory::default(), (b'a'..=b'j').rev());
        assert_eq!(dir.cid.to_string(), expected);
    }

    #[test]
    fn hamt_directory_matches_kubo() {
        // Import.UnixFSHAMTDirectorySizeThreshold "1B" and
        // Import.UnixFSHAMTDirectoryMaxFanout 256 or 8
        let sharded = |fanout| DynamicDirectory { threshold: 1, hamt: Hamt { fanout } };
        assert_eq!(
            letters(sharded(256), b'a'..=b'j').cid.to_string(),
            "bafybeifigwztatb3igypxcz6gkrtfgcgjfeoheuq4xoh57akbpzt45qdoy"
        );
        // 10 entries in 8 buckets has to nest
        assert_eq!(
            letters(sharded(8), b'a'..=b'j').cid.to_string(),
            "bafybeihjqjwxbsv5swajtldgzdqkoydmgh7yoqkw5rqsylhclnehiix45y"
        );
    }

    #[test]
    fn directory_tsize() {
        let mut sink = Keep::default();
        let mut dir = DynamicDirectory::default().builder();
        for c in b'a'..=b'j' {
            dir.add_link(vec![c], leaf(c), &mut sink).expect("add");
        }
        let root = dir.finalize(&mut sink).expect("finalize");
        assert_eq!(sink.0.len(), 1);
        assert_eq!(root.tsize, len64(sink.0[0].data()) + 10);
        assert_eq!(root.filesize, 0);

        // Sharded: every shard counted once, children before parents
        let mut sink = Keep::default();
        let hamt = Hamt { fanout: 8 };
        let mut dir = DynamicDirectory { threshold: 1, hamt }.builder();
        for c in b'a'..=b'j' {
            dir.add_link(vec![c], leaf(c), &mut sink).expect("add");
        }
        let root = dir.finalize(&mut sink).expect("finalize");
        assert!(sink.0.len() > 1, "nested shards");
        let shards: u64 = sink.0.iter().map(|b| len64(b.data())).sum();
        assert_eq!(root.tsize, shards + 10);
        assert_eq!(sink.0.last().map(Block::cid), Some(&root.cid));
    }

    #[test]
    fn emitted_nodes_are_valid_dag_pb() {
        let mut sink = Keep::default();
        let mut file = BalancedLayout { width: 3 }.builder();
        for i in 0..20 {
            file.add_chunk(leaf(i), &mut sink).expect("add");
        }
        file.finalize(&mut sink).expect("finalize");
        for strategy in [DynamicDirectory::default(), DynamicDirectory { threshold: 1, hamt: Hamt { fanout: 8 } }] {
            let mut dir = strategy.builder();
            for c in (b'a'..=b'z').rev() {
                dir.add_link(vec![c], leaf(c), &mut sink).expect("add");
            }
            dir.finalize(&mut sink).expect("finalize");
        }
        symlink_node(b"target", &mut sink).expect("symlink");

        assert!(sink.0.len() > 10);
        for block in &sink.0 {
            let node = PbNode::decode(block.data()).expect("decode");
            node.validate().expect("links sorted");
            assert_eq!(node.encode(), block.data(), "canonical");
        }
    }

    #[test]
    fn symlink() {
        let mut sink = Keep::default();
        let link = symlink_node(b"hello", &mut sink).expect("symlink");
        // From the Kubo tree in import's tests
        assert_eq!(link.cid.to_string(), "bafybeifmeeehxnbbwguvklqabzdq4choqqi7jdygi2egmgd5kaxxudojxi");
        assert_eq!(link.tsize, len64(sink.0[0].data()));
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
