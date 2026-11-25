//! Checking `Same` claims: that their targets are the same, read through
//! the claim's lens.
//!
//! A CID's codec says how to decode a block, not what it means: a UnixFS
//! file's root decodes as a dag-pb node, while the file is what the UnixFS
//! ADL reads from it and the blocks under it. So a `Same` claim names how
//! its targets are read, its *lens*, and they're the same if they read
//! the same through it:
//!
//! - No lens: each codec's own data model. dag-cbor and dag-json holding
//!   one value are the same, and a raw block is its bytes, as a dag-cbor
//!   byte string holding them is.
//! - `unixfs`: what the UnixFS ADL reads. A file is its contents, however
//!   it's chunked and laid out, and a raw block, a file of its bytes, so
//!   a whole file's multihash is the same as its root. A directory is its
//!   entries, each name's CID, whether it's basic or a HAMT, and a symlink
//!   its target.
//!
//! A raw target beside others is checked by its multihash, against what
//! they read as, so it needn't be fetched: a kept file's whole multihash
//! is no block anyone can get. Other lenses can't be checked yet.

use std::io::{self, Write};

use sha2::{Digest, Sha256};

use crate::block::IDENTITY;
use crate::cid::{BaseCid, CidRef, DAG_CBOR_CODEC, DAG_JSON_CODEC, DAG_PB_CODEC, RAW_CODEC};
use crate::export::{self, Fetch, Kind};
use crate::model::{Ipld, Link};
use crate::multihash::{DefaultDigest, Multihash, MultihashDigest, MultihashFunc};

/// The lens of the UnixFS ADL.
pub const UNIXFS: &str = "unixfs";

/// sha2-256's multihash code.
const SHA2_256: u64 = 0x12;

/// How much of a file is kept to check multihashes other than sha2-256
/// against, which are hashed once it's all read.
const KEPT: usize = 64 << 20;

/// Why targets weren't found the same.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0} and {1} aren't the same")]
    Differ(Link, Link),
    #[error("{0} can't be read through {1}")]
    Unreadable(Link, String),
    #[error("{0}: {1}")]
    Io(Link, io::Error),
    #[error("no lens {0} is known")]
    Lens(String),
}

/// Whether the targets are the same, read through `lens`, as a `Same`
/// claim of them would say.
pub fn check(src: &impl Fetch, targets: &[Link], lens: Option<&str>) -> Result<(), Error> {
    match lens {
        None => data_model(src, targets),
        Some(UNIXFS) => unixfs(src, targets),
        Some(lens) => Err(Error::Lens(lens.to_owned())),
    }
}

/// The lens's name, as people see it.
pub fn named(lens: Option<&str>) -> &str {
    lens.unwrap_or("data")
}

fn data_model(src: &impl Fetch, targets: &[Link]) -> Result<(), Error> {
    let mut first: Option<(&Link, Vec<u8>)> = None;
    for target in targets {
        let bytes = src.fetch(target).map_err(|e| Error::Io(target.clone(), e))?;
        let unreadable = || Error::Unreadable(target.clone(), "its data model".to_owned());
        let value: Ipld = match target.codec() {
            RAW_CODEC => Ipld::Bytes(bytes),
            DAG_CBOR_CODEC => crate::dagcbor::from_slice(&bytes).map_err(|_| unreadable())?,
            DAG_JSON_CODEC => crate::dagjson::from_slice(&bytes).map_err(|_| unreadable())?,
            _ => return Err(unreadable()),
        };
        // Equal values encode alike, canonically
        let canonical = crate::dagcbor::to_vec(&value).map_err(|_| unreadable())?;
        match &first {
            None => first = Some((target, canonical)),
            Some((other, theirs)) if *theirs != canonical => return Err(Error::Differ((*other).clone(), target.clone())),
            Some(_) => {},
        }
    }
    Ok(())
}

/// What a UnixFS target reads as, enough to tell it from others.
#[derive(PartialEq, Eq)]
enum Read {
    /// A file: its length and sha2-256.
    File(u64, [u8; 32]),
    /// A directory's entries, as (name, CID), sorted.
    Directory(Vec<(Vec<u8>, Vec<u8>)>),
    Symlink(Vec<u8>),
}

fn unixfs(src: &impl Fetch, targets: &[Link]) -> Result<(), Error> {
    // Raw targets are checked by their multihashes, against what the others
    // read as, unless they're all raw: then the first is read
    let (raw, read): (Vec<&Link>, Vec<&Link>) = targets.iter().partition(|target| target.codec() == RAW_CODEC);
    let (read, raw) = if read.is_empty() {
        (raw.get(..1).unwrap_or_default().to_vec(), raw.get(1..).unwrap_or_default().to_vec())
    }
    else {
        (read, raw)
    };
    let mut first: Option<(&Link, Read, Option<Hashed>)> = None;
    for target in read {
        let (got, hashed) = read_unixfs(src, target)?;
        match &first {
            None => first = Some((target, got, hashed)),
            Some((other, theirs, _)) if *theirs != got => return Err(Error::Differ((*other).clone(), target.clone())),
            Some(_) => {},
        }
    }
    let Some((reference, _, hashed)) = first else {
        return Ok(());
    };
    for target in raw {
        let Some(hashed) = &hashed else {
            // A raw block is a file, and this isn't one
            return Err(Error::Differ(reference.clone(), target.clone()));
        };
        if !hashed.matches(target)? {
            return Err(Error::Differ(reference.clone(), target.clone()));
        }
    }
    Ok(())
}

fn read_unixfs(src: &impl Fetch, target: &Link) -> Result<(Read, Option<Hashed>), Error> {
    let io = |e| Error::Io(target.clone(), e);
    if !matches!(target.codec(), RAW_CODEC | DAG_PB_CODEC) {
        return Err(Error::Unreadable(target.clone(), UNIXFS.to_owned()));
    }
    match export::stat(src, target).map_err(io)? {
        Kind::File(_) => {
            let mut hashed = Hashed::default();
            export::cat(src, target, &mut hashed).map_err(io)?;
            Ok((Read::File(hashed.len, hashed.sha256.clone().finalize().into()), Some(hashed)))
        },
        Kind::Directory => {
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = export::list(src, target).map_err(io)?
                .into_iter()
                .map(|entry| (entry.name, entry.cid.to_bytes()))
                .collect();
            entries.sort();
            Ok((Read::Directory(entries), None))
        },
        Kind::Symlink(to) => Ok((Read::Symlink(to), None)),
    }
}

/// A file's bytes as they're read, hashed with sha2-256, and kept while
/// they're few enough to hash otherwise.
#[derive(Default)]
pub(crate) struct Hashed {
    sha256: Sha256,
    len: u64,
    kept: Option<Vec<u8>>,
    /// More than `KEPT` was read, so none is.
    over: bool,
}

impl Write for Hashed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sha256.update(buf);
        self.len = self.len.saturating_add(crate::dag::len64(buf));
        if !self.over {
            let kept = self.kept.get_or_insert_with(Vec::new);
            if kept.len().saturating_add(buf.len()) > KEPT {
                self.kept = None;
                self.over = true;
            }
            else {
                kept.extend_from_slice(buf);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl Hashed {
    /// Whether a raw block's multihash is of these bytes.
    pub(crate) fn matches(&self, target: &Link) -> Result<bool, Error> {
        let multihash = target.multihash();
        if multihash.code() == SHA2_256 {
            return Ok(multihash.digest_ref() == self.sha256.clone().finalize().as_slice());
        }
        let Some(kept) = self.kept.as_deref().or(if self.len == 0 { Some(&[]) } else { None }) else {
            return Err(Error::Unreadable(target.clone(), format!("{UNIXFS}, but by sha2-256 alone, since it's over {} MiB", KEPT >> 20)));
        };
        if multihash.code() == IDENTITY {
            return Ok(multihash.digest_ref() == kept);
        }
        let func = MultihashFunc::try_from(multihash.code())
            .map_err(|_| Error::Unreadable(target.clone(), format!("{UNIXFS}, its hash function 0x{:x} being unknown", multihash.code())))?;
        let ours: Multihash<DefaultDigest> = func.digest(kept)
            .map_err(|_| Error::Unreadable(target.clone(), UNIXFS.to_owned()))?;
        Ok(ours.digest_ref() == multihash.digest_ref())
    }
}
