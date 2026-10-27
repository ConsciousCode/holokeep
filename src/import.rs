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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use crate::dag::NullSink;
    use crate::testutil::Scratch;

    const HELLO: &str = "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e";
    const EMPTY: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    /// `ipfs add --chunker=size-4 --max-file-links=3` of "hello world"
    const HELLO_SMALL: &str = "bafybeighmzuokpuzyho2ninhgybpych6atkhbn2o57c3hlyer2hntezxly";

    fn small() -> Importer {
        Importer { chunk_size: 4, layout: BalancedLayout { width: 3 }, ..Importer::default() }
    }

    fn add(importer: &Importer, reader: impl Read) -> String {
        importer.add_file(reader, &mut NullSink).expect("add").cid.to_string()
    }

    #[test]
    fn files_match_kubo() {
        assert_eq!(add(&Importer::default(), &b"hello world"[..]), HELLO);
        assert_eq!(add(&Importer::default(), &b""[..]), EMPTY);
        assert_eq!(add(&small(), &b"hello world"[..]), HELLO_SMALL);
    }

    /// A reader which dribbles out a byte at a time, interrupted between.
    struct Dribble<'a>(&'a [u8], bool);
    impl Read for Dribble<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.1 = !self.1;
            if self.1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let Some((first, rest)) = self.0.split_first() else { return Ok(0) };
            buf[0] = *first;
            self.0 = rest;
            Ok(1)
        }
    }

    #[test]
    fn short_reads() {
        assert_eq!(add(&small(), Dribble(b"hello world", false)), HELLO_SMALL);
        assert_eq!(add(&Importer::default(), Dribble(b"", false)), EMPTY);
    }

    /// Build the tree Kubo's vectors were made from:
    /// t/hello, t/.hidden, t/sub/empty, t/sub/link -> hello
    fn tree(scratch: &Scratch) -> PathBuf {
        let t = scratch.0.join("t");
        fs::create_dir_all(t.join("sub")).expect("mkdir");
        fs::write(t.join("hello"), "hello world").expect("write");
        fs::write(t.join(".hidden"), "secret").expect("write");
        fs::write(t.join("sub/empty"), "").expect("write");
        symlink("hello", t.join("sub/link")).expect("symlink");
        t
    }

    fn add_tree(importer: &Importer, root: &Path) -> BTreeMap<PathBuf, String> {
        let mut added = BTreeMap::new();
        let base = root.parent().expect("parent");
        let link = importer
            .add_path(root, &mut NullSink, &mut |path, link| {
                let rel = path.strip_prefix(base).expect("under root").to_path_buf();
                added.insert(rel, link.cid.to_string());
            })
            .expect("add")
            .expect("representable");
        assert_eq!(added.get(Path::new("t")), Some(&link.cid.to_string()));
        added
    }

    #[test]
    fn directory_matches_kubo() {
        let scratch = Scratch::new("tree");
        let t = tree(&scratch);

        // `ipfs add -r t`
        let added = add_tree(&Importer::default(), &t);
        let expected = [
            ("t", "bafybeieln7fdrluiqxqnebxsxvajb2grwv7liien3aqu74iryolh4puri4"),
            ("t/hello", HELLO),
            ("t/sub", "bafybeifhwpoqs4s6hlqhnms5p5esn5jymudhmy3xpswph237qxeovkccli"),
            ("t/sub/empty", EMPTY),
            ("t/sub/link", "bafybeifmeeehxnbbwguvklqabzdq4choqqi7jdygi2egmgd5kaxxudojxi"),
        ];
        let expected: BTreeMap<PathBuf, String> =
            expected.iter().map(|(p, c)| (PathBuf::from(p), (*c).to_owned())).collect();
        assert_eq!(added, expected);

        // `ipfs add -r -H t`
        let hidden = Importer { hidden: true, ..Importer::default() };
        let added = add_tree(&hidden, &t);
        assert_eq!(
            added.get(Path::new("t")).map(String::as_str),
            Some("bafybeic2ctdqelmghewrn5cmqebegqlmanbutlym22tzbewrmtr5fm7k3q")
        );
        assert!(added.contains_key(Path::new("t/.hidden")));
    }

    #[test]
    fn missing_path_errors() {
        let scratch = Scratch::new("missing");
        let result = Importer::default().add_path(&scratch.0.join("nope"), &mut NullSink, &mut |_, _| {});
        assert!(result.is_err());
    }
}
