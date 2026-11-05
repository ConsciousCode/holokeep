//! Git objects as `git-raw` blocks, each the same thing in the soup as in
//! git.
//!
//! An object is a block of its own, its bytes git's own (`<type>
//! <size>\0<content>`), uncompressed, and its CID git's SHA-1 of them.
//!
//! A tree links to its entries, a commit to its tree, its parents and what
//! its merge tags tag, and a tag to what it tags, as go-ipld-git reads
//! them. A tree entry that's a submodule's commit (mode `160000`) is a
//! link too, though what it links to is in another repository.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;

use crate::block::Block;
use crate::cid::{BaseCid as _, CidRef as _, Cidv1, GIT_RAW_CODEC};
use crate::model::Link;
use crate::multihash::{DefaultDigest, DigestBuf as _, MultihashCodec as _, MultihashDigest as _, MultihashFunc};

pub mod pack;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a git object: {0}")]
    Invalid(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

fn invalid(what: impl Into<String>) -> Error {
    Error::Invalid(what.into())
}

/// The kinds of git object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    fn parse(name: &[u8]) -> Option<Self> {
        match name {
            b"commit" => Some(Self::Commit),
            b"tree" => Some(Self::Tree),
            b"blob" => Some(Self::Blob),
            b"tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

/// The CID of the object git names by this SHA-1.
pub fn cid_of(sha1: &[u8; 20]) -> Link {
    let digest = DefaultDigest::decode(sha1).unwrap_or_else(|_| crate::multihash::Spill::Heap(sha1.to_vec().into()));
    Cidv1::new(GIT_RAW_CODEC, MultihashFunc::Sha1.wrap(digest)).into()
}

/// The CID of the object git names by this hex SHA-1.
pub fn cid_of_hex(hex: &[u8]) -> Result<Link> {
    let mut sha1 = [0; 20];
    if hex.len() != 40 {
        return Err(invalid(format!("{:?} isn't an object name", String::from_utf8_lossy(hex))));
    }
    for (byte, pair) in sha1.iter_mut().zip(hex.chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).ok().and_then(|pair| u8::from_str_radix(pair, 16).ok());
        *byte = pair.ok_or_else(|| invalid(format!("{:?} isn't an object name", String::from_utf8_lossy(hex))))?;
    }
    Ok(cid_of(&sha1))
}

/// An object's block, from its kind and content.
pub fn block(kind: Kind, content: &[u8]) -> Block {
    let mut data = format!("{} {}\0", kind.name(), content.len()).into_bytes();
    data.extend_from_slice(content);
    let block = Block::hash(crate::cid::Cidv1Spec::new(GIT_RAW_CODEC, MultihashFunc::Sha1), data.into_boxed_slice());
    debug_assert_eq!(block.cid().codec(), GIT_RAW_CODEC);
    block
}

/// An object's kind and content, from its block's bytes.
pub fn parse(data: &[u8]) -> Result<(Kind, &[u8])> {
    let nul = data.iter().position(|&byte| byte == 0).ok_or_else(|| invalid("no header"))?;
    let (header, content) = data.split_at(nul);
    let content = content.get(1..).unwrap_or_default();
    let (kind, size) = header.split_at(header.iter().position(|&byte| byte == b' ').ok_or_else(|| invalid("no size"))?);
    let kind = Kind::parse(kind).ok_or_else(|| invalid(format!("no kind {:?}", String::from_utf8_lossy(kind))))?;
    let size: usize = std::str::from_utf8(size.get(1..).unwrap_or_default()).ok().and_then(|size| size.parse().ok())
        .ok_or_else(|| invalid("a size that isn't a number"))?;
    if size != content.len() {
        return Err(invalid(format!("{size} bytes said, {} there", content.len())));
    }
    Ok((kind, content))
}

/// Every link in an object's block, in order.
pub fn links(data: &[u8]) -> Result<Vec<Link>> {
    let (kind, content) = parse(data)?;
    let mut out = Vec::new();
    match kind {
        Kind::Blob => {},
        Kind::Tree => {
            let mut rest = content;
            while !rest.is_empty() {
                let nul = rest.iter().position(|&byte| byte == 0).ok_or_else(|| invalid("a tree entry without a name's end"))?;
                let sha1 = rest.get(nul.saturating_add(1)..nul.saturating_add(21)).ok_or_else(|| invalid("a tree entry cut short"))?;
                out.push(cid_of(sha1.try_into().map_err(|_| invalid("a tree entry cut short"))?));
                rest = rest.get(nul.saturating_add(21)..).unwrap_or_default();
            }
        },
        Kind::Commit | Kind::Tag => {
            // Headers up to the first blank line; a continuation line, as
            // of a merge tag, starts with a space
            let mut in_mergetag = false;
            for line in content.split(|&byte| byte == b'\n') {
                if line.is_empty() {
                    break;
                }
                if let Some(continued) = line.strip_prefix(b" ") {
                    if in_mergetag && let Some(hex) = continued.strip_prefix(b"object ") {
                        out.push(cid_of_hex(hex)?);
                    }
                    continue;
                }
                in_mergetag = false;
                let (key, value) = line.split_at(line.iter().position(|&byte| byte == b' ').unwrap_or(line.len()));
                let value = value.get(1..).unwrap_or_default();
                match (kind, key) {
                    (Kind::Commit, b"tree" | b"parent") | (Kind::Tag, b"object") => out.push(cid_of_hex(value)?),
                    (Kind::Commit, b"mergetag") => {
                        in_mergetag = true;
                        if let Some(hex) = value.strip_prefix(b"object ") {
                            out.push(cid_of_hex(hex)?);
                        }
                    },
                    _ => {},
                }
            }
        },
    }
    Ok(out)
}

/// The SHA-1 a CID names a git object by, if it does.
pub fn sha1_of(cid: &Link) -> Option<[u8; 20]> {
    (cid.codec() == GIT_RAW_CODEC && cid.hashcode() == MultihashFunc::Sha1.code())
        .then(|| cid.digest_ref().try_into().ok())
        .flatten()
}

/// A loose object's block, from its file: zlib over the object's bytes.
pub fn loose(compressed: &[u8]) -> Result<Block> {
    let mut data = Vec::new();
    flate2::read::ZlibDecoder::new(compressed).read_to_end(&mut data)?;
    let (kind, content) = parse(&data)?;
    Ok(block(kind, content))
}

/// Where a repository's objects are: its `objects` directory, given the
/// repository's working tree, its `.git`, or a bare repository.
pub fn objects_dir(repo: &Path) -> Result<std::path::PathBuf> {
    for candidate in [repo.join(".git/objects"), repo.join("objects")] {
        if candidate.is_dir() {
            return Ok(candidate);
        }
    }
    Err(invalid(format!("no git objects in {}", repo.display())))
}

/// Every object of a repository, loose or packed, each given to `each` as
/// it's read.
///
/// Objects in several places are given as often as they're found. `have`
/// finds an object a thin pack's delta is based on outside it. Returns how
/// many were read.
pub fn objects(
    repo: &Path,
    have: &dyn Fn(&Link) -> Option<Block>,
    each: &mut dyn FnMut(Block) -> Result<()>,
) -> Result<usize> {
    let objects = objects_dir(repo)?;
    let mut count = 0_usize;
    let mut dirs: Vec<_> = std::fs::read_dir(&objects)?.collect::<std::io::Result<_>>()?;
    dirs.sort_by_key(std::fs::DirEntry::file_name);
    for dir in dirs {
        let name = dir.file_name();
        let name = name.as_encoded_bytes();
        if name.len() != 2 || !name.iter().all(u8::is_ascii_hexdigit) {
            continue;
        }
        let mut files: Vec<_> = std::fs::read_dir(dir.path())?.collect::<std::io::Result<_>>()?;
        files.sort_by_key(std::fs::DirEntry::file_name);
        for file in files {
            let rest = file.file_name();
            if rest.len() != 38 || !rest.as_encoded_bytes().iter().all(u8::is_ascii_hexdigit) {
                continue;
            }
            let block = loose(&std::fs::read(file.path())?)?;
            let named = cid_of_hex(&[name, rest.as_encoded_bytes()].concat())?;
            if Link::from(block.cid().clone()) != named {
                return Err(invalid(format!("{} holds {}", file.path().display(), block.cid())));
            }
            each(block)?;
            count = count.saturating_add(1);
        }
    }
    let packs = objects.join("pack");
    if packs.is_dir() {
        let mut files: Vec<_> = std::fs::read_dir(&packs)?.collect::<std::io::Result<_>>()?;
        files.sort_by_key(std::fs::DirEntry::file_name);
        for file in files {
            if file.path().extension().is_some_and(|ext| ext == "pack") {
                count = count.saturating_add(pack::objects(&std::fs::read(file.path())?, have, each)?);
            }
        }
    }
    Ok(count)
}

/// A repository's refs, as (name, object), from `packed-refs` and the
/// files under `refs/`, a file's saying over a packed one; and `HEAD`, if
/// it names an object, directly or by a ref.
pub fn refs(repo: &Path) -> Result<Vec<(String, Link)>> {
    let git = objects_dir(repo)?.parent().map(Path::to_path_buf).ok_or_else(|| invalid("no repository"))?;
    let mut refs: HashMap<String, Link> = HashMap::new();
    if let Ok(packed) = std::fs::read(git.join("packed-refs")) {
        for line in packed.split(|&byte| byte == b'\n') {
            if line.starts_with(b"#") || line.starts_with(b"^") || line.is_empty() {
                continue;
            }
            if let Some((hex, name)) = line.split_at_checked(40) {
                refs.insert(String::from_utf8_lossy(name.trim_ascii()).into_owned(), cid_of_hex(hex)?);
            }
        }
    }
    let mut stack = vec![git.join("refs")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = std::fs::read(&path)?;
            if let (Ok(link), Ok(name)) = (cid_of_hex(text.trim_ascii()), path.strip_prefix(&git)) {
                refs.insert(name.to_string_lossy().into_owned(), link);
            }
        }
    }
    if let Ok(head) = std::fs::read(git.join("HEAD")) {
        let head = head.trim_ascii();
        let link = head.strip_prefix(b"ref: ").map_or_else(
            || cid_of_hex(head).ok(),
            |name| refs.get(&*String::from_utf8_lossy(name)).cloned(),
        );
        if let Some(link) = link {
            refs.insert("HEAD".to_owned(), link);
        }
    }
    let mut refs: Vec<_> = refs.into_iter().collect();
    refs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_is_named_as_git_names_it() {
        // `git hash-object` of "hello\n"
        let blob = block(Kind::Blob, b"hello\n");
        assert_eq!(sha1_of(&blob.cid().clone().into()), Some(hex_macro::hex!("ce013625030ba8dba906f756967f9e9ca394464a")));
        assert_eq!(parse(blob.data()).expect("parse"), (Kind::Blob, &b"hello\n"[..]));
        assert!(links(blob.data()).expect("links").is_empty());
        assert!(parse(b"blob 7\0hello\n").is_err(), "the wrong size");
        assert!(parse(b"thing 0\0").is_err());
    }

    #[test]
    fn trees_commits_and_tags_link_as_go_ipld_git_reads_them() {
        let blob = block(Kind::Blob, b"hello\n");
        let sha = sha1_of(&blob.cid().clone().into()).expect("sha1");
        let mut tree = b"100644 a.txt\0".to_vec();
        tree.extend_from_slice(&sha);
        tree.extend_from_slice(b"160000 sub\0");
        tree.extend_from_slice(&[7; 20]);
        let tree = block(Kind::Tree, &tree);
        let blob_link: Link = blob.cid().clone().into();
        assert_eq!(links(tree.data()).expect("tree"), vec![blob_link, cid_of(&[7; 20])]);

        let tree_link: Link = tree.cid().clone().into();
        let hex = |link: &Link| sha1_of(link).expect("sha1").iter().fold(String::new(), |hex, b| hex + &format!("{b:02x}"));
        let commit = format!(
            "tree {}\nparent {}\nparent {}\nauthor a <a@a> 1 +0000\ncommitter a <a@a> 1 +0000\nmergetag object {}\n type commit\n tag v1\n\n sig\ngpgsig -----BEGIN\n parent {}\n\ntree in the message {}\n",
            hex(&tree_link), "1".repeat(40), "2".repeat(40), "3".repeat(40), "4".repeat(40), "5".repeat(40),
        );
        let commit = block(Kind::Commit, commit.as_bytes());
        let ones = cid_of(&[0x11; 20]);
        let twos = cid_of(&[0x22; 20]);
        assert_eq!(links(commit.data()).expect("commit"), vec![tree_link.clone(), ones, twos, cid_of(&[0x33; 20])]);

        let tag = block(Kind::Tag, format!("object {}\ntype tree\ntag t\n\nobject {}\n", hex(&tree_link), "6".repeat(40)).as_bytes());
        assert_eq!(links(tag.data()).expect("tag"), vec![tree_link]);
    }

    #[test]
    fn a_loose_object_is_its_inflated_bytes() {
        use std::io::Write as _;
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(b"blob 6\0hello\n").expect("write");
        let block = loose(&zlib.finish().expect("finish")).expect("loose");
        assert_eq!(block, super::block(Kind::Blob, b"hello\n"));
    }
}
