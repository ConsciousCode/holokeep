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
const MAX_DEPTH: usize = 1024;

/// Somewhere to get verified blocks from.
pub trait Fetch {
    /// A block's bytes, which must match its CID.
    fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>>;
}

impl Fetch for Catalog {
    fn fetch(&self, cid: &Link) -> io::Result<Vec<u8>> {
        match self.get_block(cid) {
            Ok(Some(block)) => Ok(block.into_data().into_vec()),
            Ok(None) => Err(io::Error::new(io::ErrorKind::NotFound, format!("block {cid} not found"))),
            Err(e) => Err(io::Error::other(e)),
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
    Pb { data: DataBuf, links: Vec<(Link, Vec<u8>)> },
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
            Ok(Node::Pb { data, links })
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
        Node::Pb { data, links } => match data.data_type {
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
        (DataType::HAMTShard, Node::Pb { data, links }) => {
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
                Node::Pb { data, links } if data.data_type == DataType::HAMTShard => {
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
