//! Read UnixFS back out, like `ipfs cat` and `ipfs get`.
//!
//! DAGs come from anywhere, so nothing in one is trusted: entry names
//! which could escape the destination are refused, nothing is written
//! through an existing path, and depth is bounded.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::cid::{BaseCid, DAG_PB_CODEC, RAW_CODEC};
use crate::model::Link;
use crate::pb::PbNode;
use crate::store::Catalog;
use crate::unixfs::{DataBuf, DataType};

/// Deeper than any sane DAG, shallow enough not to overflow the stack.
pub const MAX_DEPTH: usize = 1024;

/// Somewhere to get verified blocks from.
pub trait Fetch {
    /// A block's bytes, which must match its CID.
    fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>>;

    /// Blocks about to be fetched, so a source that gets them from
    /// elsewhere can ask for them all at once rather than one by one.
    fn prefetch(&self, _cids: &[Link]) {}
}

impl Fetch for Catalog {
    /// A block here, or, if the catalog fetches through a node, fetched.
    fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>> {
        let missing = || io::Error::new(io::ErrorKind::NotFound, match self.lost_at(cid) {
            Ok(Some(at)) => format!("block {cid} not found: reported lost as of {at}"),
            _ => format!("block {cid} not found"),
        });
        // A block in a file of a mount's being moved out as that's written
        // over: where it was looked up, it's gone, and looking again finds it
        let got = match self.get_block(cid) {
            Err(crate::store::Error::Corrupt(_) | crate::store::Error::Stale(_) | crate::store::Error::Missing(_)) => self.get_block(cid),
            got => got,
        };
        match got {
            Ok(Some(block)) => Ok(block.into_data().into_vec()),
            Ok(None) if self.fetch_missing(std::slice::from_ref(cid)) => match self.get_block(cid) {
                Ok(Some(block)) => Ok(block.into_data().into_vec()),
                Ok(None) => Err(missing()),
                Err(e) => Err(io::Error::other(e)),
            },
            Ok(None) => Err(missing()),
            Err(e) => Err(io::Error::other(e)),
        }
    }

    fn prefetch(&self, cids: &[Link]) {
        use crate::cid::CidRef as _;
        use crate::store::BlockIndex as _;
        let missing: Vec<Link> = cids.iter()
            .filter(|cid| cid.hashcode() != crate::block::IDENTITY && !self.has(cid.multihash()).unwrap_or(true))
            .cloned()
            .collect();
        if !missing.is_empty() {
            self.fetch_missing(&missing);
        }
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A decoded UnixFS node.
enum Node {
    /// A raw leaf: file content.
    Raw(Vec<u8>),
    /// A dag-pb node: its data, its links as (CID, name), and the sizes
    /// its links say what they link to is, which is advisory.
    Pb { data: DataBuf, links: Vec<(Link, Vec<u8>)>, sizes: Vec<Option<u64>> },
}

fn load(src: &impl Fetch, cid: &Link) -> io::Result<Node> {
    let bytes = src.fetch(cid)?;
    match cid.codec() {
        RAW_CODEC => Ok(Node::Raw(bytes)),
        DAG_PB_CODEC => {
            let node = PbNode::decode(&bytes).map_err(|e| invalid(format!("{cid}: {e}")))?;
            let data = DataBuf::decode(node.data.ok_or_else(|| invalid(format!("{cid}: no UnixFS data")))?)
                .map_err(|e| invalid(format!("{cid}: {e}")))?;
            let links = node.links
                .iter()
                .map(|link| Ok((link.cid().map_err(|e| invalid(format!("{cid}: {e}")))?, link.name.unwrap_or_default().to_vec())))
                .collect::<io::Result<_>>()?;
            let sizes = node.links.iter().map(|link| link.tsize).collect();
            Ok(Node::Pb { data, links, sizes })
        },
        codec => Err(invalid(format!("{cid}: codec 0x{codec:x} isn't UnixFS"))),
    }
}

fn deeper(depth: usize) -> io::Result<usize> {
    if depth >= MAX_DEPTH {
        Err(invalid("DAG too deep"))
    }
    else {
        Ok(depth.saturating_add(1))
    }
}

/// Write a file's contents.
pub fn cat(src: &impl Fetch, cid: &Link, out: &mut impl Write) -> io::Result<()> {
    write_file(src, load(src, cid)?, out, 0)
}

fn write_file(src: &impl Fetch, node: Node, out: &mut impl Write, depth: usize) -> io::Result<()> {
    match node {
        Node::Raw(bytes) => out.write_all(&bytes),
        Node::Pb { data, links, .. } => match data.data_type {
            // A file's content is its own data, then its children's
            DataType::File | DataType::Raw => {
                if let Some(bytes) = &data.data {
                    out.write_all(bytes)?;
                }
                let depth = deeper(depth)?;
                for (cid, _) in links {
                    write_file(src, load(src, &cid)?, out, depth)?;
                }
                Ok(())
            },
            DataType::Directory | DataType::HAMTShard => {
                Err(io::Error::new(io::ErrorKind::IsADirectory, "this is a directory, not a file"))
            },
            DataType::Symlink => Err(invalid("this is a symlink, not a file")),
            DataType::Metadata => Err(invalid("UnixFS metadata nodes aren't supported")),
        },
    }
}

/// Write whatever's at a CID to `dest`, which mustn't exist yet.
pub fn get(src: &impl Fetch, cid: &Link, dest: &Path) -> io::Result<()> {
    write_entry(src, cid, dest, 0)
}

fn write_entry(src: &impl Fetch, cid: &Link, dest: &Path, depth: usize) -> io::Result<()> {
    let node = load(src, cid)?;
    let data_type = match &node {
        Node::Raw(_) => DataType::Raw,
        Node::Pb { data, .. } => data.data_type,
    };
    match (data_type, node) {
        (DataType::File | DataType::Raw, node) => {
            // create_new fails rather than following an existing symlink
            let mut file = io::BufWriter::new(File::create_new(dest)?);
            write_file(src, node, &mut file, depth)?;
            file.flush()
        },
        (DataType::Directory, Node::Pb { links, .. }) => {
            fs::create_dir(dest)?;
            let depth = deeper(depth)?;
            for (cid, name) in links {
                write_entry(src, &cid, &dest.join(entry_name(&name)?), depth)?;
            }
            Ok(())
        },
        (DataType::HAMTShard, Node::Pb { data, links, .. }) => {
            fs::create_dir(dest)?;
            write_shard(src, &data, links, dest, depth)
        },
        (DataType::Symlink, Node::Pb { data, .. }) => {
            let target = data.data.unwrap_or_default();
            std::os::unix::fs::symlink(OsStr::from_bytes(&target), dest)
        },
        _ => Err(invalid(format!("{cid}: unsupported UnixFS node"))),
    }
}

/// Write a HAMT shard's entries into `dest`, descending into child shards.
fn write_shard(src: &impl Fetch, data: &DataBuf, links: Vec<(Link, Vec<u8>)>, dest: &Path, depth: usize) -> io::Result<()> {
    let fanout = data.fanout
        .filter(|f| f.is_power_of_two() && (2..=1024).contains(f))
        .ok_or_else(|| invalid("HAMT shard with an invalid fanout"))?;
    // Link names start with the bucket index in hex, eg "FF" for 256
    let pad = format!("{:X}", fanout.saturating_sub(1)).len();
    let depth = deeper(depth)?;
    for (cid, name) in links {
        let (prefix, entry) = name.split_at_checked(pad)
            .ok_or_else(|| invalid("HAMT link name shorter than its prefix"))?;
        if !prefix.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid("HAMT link name without a hex prefix"));
        }
        if entry.is_empty() {
            match load(src, &cid)? {
                Node::Pb { data, links, .. } if data.data_type == DataType::HAMTShard => {
                    write_shard(src, &data, links, dest, depth)?;
                },
                _ => return Err(invalid(format!("{cid}: child shard isn't a HAMT shard"))),
            }
        }
        else {
            write_entry(src, &cid, &dest.join(entry_name(entry)?), depth)?;
        }
    }
    Ok(())
}

/// A directory entry name, if it can only name something in the directory.
fn entry_name(name: &[u8]) -> io::Result<&OsStr> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
        return Err(invalid(format!("refusing unsafe entry name {:?}", String::from_utf8_lossy(name))));
    }
    Ok(OsStr::from_bytes(name))
}

/// What's at a CID, as a filesystem sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A file of so many bytes. Blocks of other codecs read as their bytes.
    File(u64),
    Directory,
    /// A symlink, to this target.
    Symlink(Vec<u8>),
}

/// What's at a CID.
pub fn stat(src: &impl Fetch, cid: &Link) -> io::Result<Kind> {
    if !matches!(cid.codec(), RAW_CODEC | DAG_PB_CODEC) {
        return Ok(Kind::File(len(&src.fetch(cid)?)));
    }
    match load(src, cid)? {
        Node::Raw(bytes) => Ok(Kind::File(len(&bytes))),
        Node::Pb { data, links, .. } => match data.data_type {
            DataType::File | DataType::Raw => Ok(Kind::File(file_size(src, &data, &links, 0)?)),
            DataType::Directory | DataType::HAMTShard => Ok(Kind::Directory),
            DataType::Symlink => Ok(Kind::Symlink(data.data.unwrap_or_default())),
            DataType::Metadata => Err(invalid("UnixFS metadata nodes aren't supported")),
        },
    }
}

fn len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// A file node's size: what it says, or else what its parts add up to.
fn file_size(src: &impl Fetch, data: &DataBuf, links: &[(Link, Vec<u8>)], depth: usize) -> io::Result<u64> {
    if let Some(size) = data.filesize {
        return Ok(size);
    }
    let mut size = len(data.data.as_deref().unwrap_or_default());
    if data.blocksizes.len() == links.len() {
        return Ok(data.blocksizes.iter().fold(size, |size, part| size.saturating_add(*part)));
    }
    let depth = deeper(depth)?;
    for (cid, _) in links {
        size = size.saturating_add(part_size(src, cid, depth)?);
    }
    Ok(size)
}

fn part_size(src: &impl Fetch, cid: &Link, depth: usize) -> io::Result<u64> {
    match load(src, cid)? {
        Node::Raw(bytes) => Ok(len(&bytes)),
        Node::Pb { data, links, .. } if matches!(data.data_type, DataType::File | DataType::Raw) => file_size(src, &data, &links, depth),
        Node::Pb { .. } => Err(invalid(format!("{cid}: part of a file isn't a file"))),
    }
}

/// A file's leaves, the blocks of its bytes, in order, each with where
/// in the file it starts. Raw leaves sized by their parents aren't
/// fetched.
pub fn leaves(src: &impl Fetch, cid: &Link) -> io::Result<Vec<(u64, Link)>> {
    let mut out = Vec::new();
    leaves_of(src, cid, 0, None, &mut out, 0)?;
    Ok(out)
}

/// A part of a file's leaves, from `offset`, and its size.
fn leaves_of(src: &impl Fetch, cid: &Link, offset: u64, size: Option<u64>, out: &mut Vec<(u64, Link)>, depth: usize) -> io::Result<u64> {
    if let (RAW_CODEC, Some(size)) = (cid.codec(), size) {
        out.push((offset, cid.clone()));
        return Ok(size);
    }
    match load(src, cid)? {
        Node::Raw(bytes) => {
            out.push((offset, cid.clone()));
            Ok(len(&bytes))
        },
        Node::Pb { data, links, .. } if matches!(data.data_type, DataType::File | DataType::Raw) => {
            if links.is_empty() {
                out.push((offset, cid.clone()));
                return file_size(src, &data, &links, depth);
            }
            let depth = deeper(depth)?;
            let sized = data.blocksizes.len() == links.len();
            let mut at = len(data.data.as_deref().unwrap_or_default());
            for (i, (child, _)) in links.iter().enumerate() {
                let size = data.blocksizes.get(i).copied().filter(|_| sized);
                at = at.saturating_add(leaves_of(src, child, offset.saturating_add(at), size, out, depth)?);
            }
            Ok(at)
        },
        Node::Pb { .. } => Err(invalid(format!("{cid}: not a file"))),
    }
}

/// Up to `size` bytes of a file from `offset`, fetching only the parts
/// of it they're in. Fewer at the end of the file.
pub fn read_at(src: &impl Fetch, cid: &Link, offset: u64, size: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size.min(1 << 20));
    if matches!(cid.codec(), RAW_CODEC | DAG_PB_CODEC) {
        read_part(src, load(src, cid)?, offset, size, &mut out, 0)?;
    } else {
        take(&src.fetch(cid)?, offset, size, &mut out);
    }
    Ok(out)
}

/// Read what's wanted of a part of a file, `offset` into it.
fn read_part(src: &impl Fetch, node: Node, mut offset: u64, size: usize, out: &mut Vec<u8>, depth: usize) -> io::Result<()> {
    match node {
        Node::Raw(bytes) => {
            take(&bytes, offset, size, out);
            Ok(())
        },
        Node::Pb { data, links, .. } => match data.data_type {
            DataType::File | DataType::Raw => {
                let inline = data.data.as_deref().unwrap_or_default();
                take(inline, offset, size, out);
                offset = offset.saturating_sub(len(inline));
                let depth = deeper(depth)?;
                let sized = data.blocksizes.len() == links.len();
                if sized {
                    src.prefetch(&in_range(&links, &data.blocksizes, offset, size.saturating_sub(out.len())));
                }
                for (i, (cid, _)) in links.iter().enumerate() {
                    if out.len() >= size {
                        break;
                    }
                    let part = match data.blocksizes.get(i) {
                        Some(&part) if sized => part,
                        _ => part_size(src, cid, depth)?,
                    };
                    if offset >= part {
                        offset = offset.saturating_sub(part);
                        continue;
                    }
                    read_part(src, load(src, cid)?, offset, size, out, depth)?;
                    offset = 0;
                }
                Ok(())
            },
            DataType::Directory | DataType::HAMTShard => Err(io::Error::new(io::ErrorKind::IsADirectory, "this is a directory, not a file")),
            DataType::Symlink => Err(invalid("this is a symlink, not a file")),
            DataType::Metadata => Err(invalid("UnixFS metadata nodes aren't supported")),
        },
    }
}

/// The parts of a file a read of `size` bytes from `offset` past its
/// inline data is in.
fn in_range(links: &[(Link, Vec<u8>)], sizes: &[u64], offset: u64, size: usize) -> Vec<Link> {
    let end = offset.saturating_add(u64::try_from(size).unwrap_or(u64::MAX));
    let mut start = 0u64;
    let mut parts = Vec::new();
    for ((cid, _), part) in links.iter().zip(sizes) {
        let next = start.saturating_add(*part);
        if next > offset && start < end {
            parts.push(cid.clone());
        }
        if start >= end {
            break;
        }
        start = next;
    }
    parts
}

/// Add bytes from `offset` to `out`, up to `size` in all.
fn take(bytes: &[u8], offset: u64, size: usize, out: &mut Vec<u8>) {
    let Ok(start) = usize::try_from(offset) else {
        return;
    };
    if let Some(rest) = bytes.get(start..) {
        let wanted = size.saturating_sub(out.len()).min(rest.len());
        out.extend_from_slice(rest.get(..wanted).unwrap_or_default());
    }
}

/// An entry of a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: Vec<u8>,
    pub cid: Link,
    /// The size the directory says what it links to is: for a raw block,
    /// the file's, if the directory's honest. Advisory only, since it isn't
    /// checked against the block.
    pub size: Option<u64>,
}

/// A directory's entries, a sharded one's gathered from its shards.
/// Names which could name anything outside it are left out.
///
/// What isn't raw among them is prefetched, being what a listing needs to
/// read to say what each entry is; a raw block is a file, whose size the
/// directory says.
pub fn list(src: &impl Fetch, cid: &Link) -> io::Result<Vec<Listed>> {
    let mut entries = Vec::new();
    match load(src, cid)? {
        Node::Pb { data, links, sizes } if data.data_type == DataType::Directory => {
            src.prefetch(&structure(&links));
            entries.extend(
                links.into_iter()
                    .zip(sizes)
                    .filter(|((_, name), _)| entry_name(name).is_ok())
                    .map(|((cid, name), size)| Listed { name, cid, size }),
            );
        },
        Node::Pb { data, links, sizes } if data.data_type == DataType::HAMTShard => list_shard(src, &data, links, sizes, &mut entries, 0)?,
        _ => return Err(io::Error::new(io::ErrorKind::NotADirectory, format!("{cid} isn't a directory"))),
    }
    Ok(entries)
}

/// The links which aren't to raw blocks.
fn structure(links: &[(Link, Vec<u8>)]) -> Vec<Link> {
    links.iter().filter(|(cid, _)| cid.codec() != RAW_CODEC).map(|(cid, _)| cid.clone()).collect()
}

fn list_shard(src: &impl Fetch, data: &DataBuf, links: Vec<(Link, Vec<u8>)>, sizes: Vec<Option<u64>>, entries: &mut Vec<Listed>, depth: usize) -> io::Result<()> {
    let fanout = data.fanout
        .filter(|f| f.is_power_of_two() && (2..=1024).contains(f))
        .ok_or_else(|| invalid("HAMT shard with an invalid fanout"))?;
    let pad = format!("{:X}", fanout.saturating_sub(1)).len();
    let depth = deeper(depth)?;
    src.prefetch(&structure(&links));
    for ((cid, name), size) in links.into_iter().zip(sizes) {
        let (prefix, entry) = name.split_at_checked(pad)
            .ok_or_else(|| invalid("HAMT link name shorter than its prefix"))?;
        if !prefix.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid("HAMT link name without a hex prefix"));
        }
        if entry.is_empty() {
            match load(src, &cid)? {
                Node::Pb { data, links, sizes } if data.data_type == DataType::HAMTShard => list_shard(src, &data, links, sizes, entries, depth)?,
                _ => return Err(invalid(format!("{cid}: child shard isn't a HAMT shard"))),
            }
        } else if entry_name(entry).is_ok() {
            entries.push(Listed { name: entry.to_vec(), cid, size });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::block::Block;
    use crate::cid::{AnyCid, CidVersion, Cidv1Spec};
    use crate::dag::{BalancedLayout, DynamicDirectory};
    use crate::hamt::Hamt;
    use crate::import::Importer;
    use crate::store::{Db, Catalog};
    use crate::testutil::Scratch;
    use crate::unixfs;

    fn router() -> Catalog {
        Catalog::standard(Db::memory().expect("db")).expect("router")
    }

    /// Small chunks, links and shards so little data makes deep DAGs.
    fn importer() -> Importer {
        Importer {
            chunk_size: 64,
            layout: BalancedLayout { width: 3 },
            directory: DynamicDirectory { threshold: 400, hamt: Hamt { fanout: 8 } },
            hidden: true,
        }
    }

    fn add(router: &mut Catalog, path: &Path) -> Link {
        let root = importer().add_path(path, router, &mut |_, _| {}).expect("import").expect("root");
        AnyCid::V1(root.cid)
    }

    fn put(router: &Catalog, block: &Block) -> Link {
        router.put_block(block, CidVersion::V1).expect("put");
        AnyCid::V1(block.cid().clone())
    }

    /// Every kind of entry.
    fn tree(dir: &Path) -> PathBuf {
        let t = dir.join("t");
        let deep = t.join("a/b/c");
        let shard = t.join("shard");
        fs::create_dir_all(&deep).expect("mkdir");
        fs::create_dir_all(&shard).expect("mkdir");
        fs::create_dir_all(t.join("empty-dir")).expect("mkdir");
        fs::write(t.join("small"), "hello world").expect("write");
        fs::write(deep.join("big"), (0..20_000u32).map(|i| i.to_le_bytes()[0] ^ i.to_le_bytes()[1]).collect::<Vec<_>>()).expect("write");
        fs::write(t.join("empty"), "").expect("write");
        fs::write(t.join(".hidden"), "secret").expect("write");
        fs::write(t.join("ünïcödé 名前"), "hi").expect("write");
        std::os::unix::fs::symlink("small", t.join("link")).expect("symlink");
        std::os::unix::fs::symlink("/nonexistent/target", t.join("dangling")).expect("symlink");
        for i in 0..40 {
            fs::write(shard.join(format!("entry-{i}")), i.to_string()).expect("write");
        }
        t
    }

    /// Compare two trees: names, kinds, contents and symlink targets.
    fn assert_same_tree(a: &Path, b: &Path) {
        let (ma, mb) = (fs::symlink_metadata(a).expect("a"), fs::symlink_metadata(b).expect("b"));
        assert_eq!(ma.file_type(), mb.file_type(), "{}", b.display());
        if ma.is_symlink() {
            assert_eq!(fs::read_link(a).expect("link"), fs::read_link(b).expect("link"));
        }
        else if ma.is_file() {
            assert!(fs::read(a).expect("read") == fs::read(b).expect("read"), "{} differs", b.display());
        }
        else {
            let names = |dir: &Path| {
                let mut names: Vec<_> = fs::read_dir(dir).expect("list").map(|e| e.expect("entry").file_name()).collect();
                names.sort();
                names
            };
            let (na, nb) = (names(a), names(b));
            assert_eq!(na, nb, "{}", b.display());
            for name in na {
                assert_same_tree(&a.join(&name), &b.join(&name));
            }
        }
    }

    /// Walk a tree as a filesystem would, against the original.
    fn walk(router: &Catalog, cid: &Link, path: &Path) {
        let meta = fs::symlink_metadata(path).expect("meta");
        match stat(router, cid).expect("stat") {
            Kind::Directory => {
                assert!(meta.is_dir(), "{}", path.display());
                let mut names: Vec<Vec<u8>> = fs::read_dir(path).expect("list").map(|e| e.expect("entry").file_name().as_bytes().to_vec()).collect();
                names.sort();
                let entries = list(router, cid).expect("list");
                let mut listed: Vec<Vec<u8>> = entries.iter().map(|entry| entry.name.clone()).collect();
                listed.sort();
                assert_eq!(listed, names, "{}", path.display());
                for Listed { name, cid: child, size } in entries {
                    // A raw block's size, as the directory says, is right here
                    if child.codec() == RAW_CODEC {
                        assert_eq!(size, Some(fs::metadata(path.join(OsStr::from_bytes(&name))).expect("meta").len()));
                    }
                    walk(router, &child, &path.join(OsStr::from_bytes(&name)));
                }
            },
            Kind::File(size) => {
                let original = fs::read(path).expect("read");
                assert_eq!(size, u64::try_from(original.len()).expect("size"), "{}", path.display());
                assert_eq!(read_at(router, cid, 0, original.len().saturating_add(10)).expect("read"), original);
                // Every window, across chunk and branch boundaries
                for offset in (0..original.len().saturating_add(3)).step_by(37) {
                    for size in [1, 63, 64, 65, 200, 1000] {
                        let want = original.get(offset..).map_or(&[][..], |rest| &rest[..size.min(rest.len())]);
                        assert_eq!(read_at(router, cid, u64::try_from(offset).expect("offset"), size).expect("read"), want, "{} at {offset}+{size}", path.display());
                    }
                }
            },
            Kind::Symlink(target) => assert_eq!(target, fs::read_link(path).expect("link").as_os_str().as_bytes()),
        }
    }

    #[test]
    fn reading_anywhere_in_a_tree() {
        let scratch = Scratch::new("export-read-at");
        let t = tree(scratch.path());
        let mut router = router();
        let root = add(&mut router, &t);
        walk(&router, &root, &t);
        // Other codecs read as their bytes
        let block = Block::hash(Cidv1Spec::new(crate::cid::DAG_CBOR_CODEC, crate::multihash::MultihashFunc::Sha2_256), b"\xa0".as_slice().into());
        let cid = put(&router, &block);
        assert_eq!(stat(&router, &cid).expect("stat"), Kind::File(1));
        assert_eq!(read_at(&router, &cid, 0, 10).expect("read"), b"\xa0");
    }

    /// A source that notes what's prefetched and what's fetched.
    struct Recording<'a> {
        router: &'a Catalog,
        prefetched: std::cell::RefCell<Vec<Link>>,
        fetched: std::cell::RefCell<Vec<Link>>,
    }

    impl Fetch for Recording<'_> {
        fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>> {
            self.fetched.borrow_mut().push(cid.clone());
            self.router.fetch(cid)
        }

        fn prefetch(&self, cids: &[Link]) {
            self.prefetched.borrow_mut().extend_from_slice(cids);
        }
    }

    impl Recording<'_> {
        /// What was fetched without being prefetched first, but the
        /// first, and what was prefetched but never fetched.
        fn surprises(&self) -> (Vec<Link>, Vec<Link>) {
            let (prefetched, fetched) = (self.prefetched.take(), self.fetched.take());
            let unasked = fetched.iter().skip(1).filter(|cid| !prefetched.contains(cid)).cloned().collect();
            let wasted = prefetched.iter().filter(|cid| !fetched.contains(cid)).cloned().collect();
            (unasked, wasted)
        }
    }

    #[test]
    fn reads_and_listings_say_what_theyll_fetch_first() {
        let scratch = Scratch::new("export-prefetch");
        let t = tree(scratch.path());
        let mut router = router();
        let root = add(&mut router, &t);
        let src = Recording { router: &router, prefetched: std::cell::RefCell::default(), fetched: std::cell::RefCell::default() };
        let lookup = |dir: &Link, name: &str| list(&router, dir).expect("list").into_iter().find(|entry| entry.name == name.as_bytes()).expect("entry").cid;
        let big = lookup(&lookup(&lookup(&lookup(&root, "a"), "b"), "c"), "big");
        let original = fs::read(t.join("a/b/c/big")).expect("read");
        for (offset, size) in [(0, 10), (1000, 200), (5000, 64), (19_990, 100), (0, 30_000)] {
            let got = read_at(&src, &big, offset, size).expect("read");
            assert_eq!(got, original.get(usize::try_from(offset).expect("offset")..).map(|rest| &rest[..size.min(rest.len())]).expect("in range"));
            // Only the root's fetched unannounced, and only what's read is announced
            let (unasked, wasted) = src.surprises();
            assert!(unasked.is_empty(), "{offset}+{size}: {unasked:?}");
            assert!(wasted.is_empty(), "{offset}+{size}: {wasted:?}");
        }
        // A directory's, and a sharded one's, entries are announced together
        for dir in [root.clone(), lookup(&root, "shard")] {
            let entries = list(&src, &dir).expect("list");
            let prefetched = src.prefetched.take();
            // All but raw blocks, files whose sizes the directory says
            assert!(entries.iter().all(|entry| prefetched.contains(&entry.cid) == (entry.cid.codec() != RAW_CODEC)));
            src.fetched.take();
        }
    }

    #[test]
    fn get_round_trips() {
        let scratch = Scratch::new("export-get");
        let t = tree(scratch.path());
        let mut router = router();
        let root = add(&mut router, &t);
        let out = scratch.path().join("out");
        get(&router, &root, &out).expect("get");
        assert_same_tree(&t, &out);
    }

    #[test]
    fn cat_files() {
        let scratch = Scratch::new("export-cat");
        let t = tree(scratch.path());
        let mut router = router();
        for file in ["small", "empty", "a/b/c/big"] {
            let cid = add(&mut router, &t.join(file));
            let mut out = Vec::new();
            cat(&router, &cid, &mut out).expect(file);
            assert!(out == fs::read(t.join(file)).expect("read"), "{file}");
        }

        let dir = add(&mut router, &t);
        let err = cat(&router, &dir, &mut Vec::new()).expect_err("a directory");
        assert_eq!(err.kind(), io::ErrorKind::IsADirectory);
        let link = add(&mut router, &t.join("link"));
        assert!(cat(&router, &link, &mut Vec::new()).is_err());
    }

    #[test]
    fn refuses_unsafe_names() {
        let scratch = Scratch::new("export-unsafe");
        let router = router();
        let file = Block::hash(Cidv1Spec::default(), b"gotcha".to_vec().into_boxed_slice());
        put(&router, &file);

        for name in [&b"../escaped"[..], b"a/b", b".", b"..", b"", b"nul\0"] {
            let link = unixfs::Link { hash: file.cid(), name, tsize: 6 };
            let dir = put(&router, &unixfs::node_block(&[link], &unixfs::Data::directory()));
            let out = scratch.path().join("out");
            let err = get(&router, &dir, &out).expect_err("unsafe name");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{:?}", String::from_utf8_lossy(name));
            let _ = fs::remove_dir_all(&out);
        }
        // HAMT entry names too, after their prefix
        let link = unixfs::Link { hash: file.cid(), name: b"0../escaped", tsize: 6 };
        let shard = put(&router, &unixfs::node_block(&[link], &unixfs::Data::hamt_shard(&[1], 0x22, 8)));
        assert!(get(&router, &shard, &scratch.path().join("shard")).is_err());

        assert!(!scratch.path().join("escaped").exists());
    }

    #[test]
    fn missing_blocks_and_existing_destinations() {
        let scratch = Scratch::new("export-missing");
        let router = router();
        let absent = Block::hash(Cidv1Spec::default(), b"never stored".to_vec().into_boxed_slice());
        let link = unixfs::Link { hash: absent.cid(), name: b"absent", tsize: 12 };
        let dir = put(&router, &unixfs::node_block(&[link], &unixfs::Data::directory()));
        let err = get(&router, &dir, &scratch.path().join("out")).expect_err("missing block");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let file = put(&router, &Block::hash(Cidv1Spec::default(), b"hi".to_vec().into_boxed_slice()));
        fs::write(scratch.path().join("taken"), "mine").expect("write");
        assert!(get(&router, &file, &scratch.path().join("taken")).is_err());
        assert_eq!(fs::read(scratch.path().join("taken")).expect("read"), b"mine");
    }
}
