//! Reading a git pack into its objects: each entry inflated, and deltas
//! applied to their bases, wherever those are.

use std::collections::HashMap;
use std::io::Read as _;
use std::rc::Rc;

use sha1::Digest as _;

use crate::block::Block;
use crate::model::Link;

use super::{Error, Kind, Object, Result, block, cid_of, invalid, parse};

/// The most of a pack's resolved objects kept to resolve deltas on, before
/// they're let go of and resolved again as needed.
const CACHE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
enum Base {
    Whole(Kind),
    /// Delta on the entry at this offset.
    At(usize),
    /// Delta on the object by this name, in the pack or not.
    Named([u8; 20]),
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    offset: usize,
    base: Base,
    /// Where its zlib stream starts.
    data: usize,
}

struct Pack<'a> {
    bytes: &'a [u8],
    by_offset: HashMap<usize, Entry>,
    by_name: HashMap<[u8; 20], usize>,
    /// The CIDs of the entries resolved, by offset.
    cids: HashMap<usize, Link>,
    cache: HashMap<usize, (Kind, Rc<Vec<u8>>)>,
    cached: usize,
    have: &'a dyn Fn(&Link) -> Option<Block>,
}

/// Every object in a pack, given to `each` in the pack's order, but for
/// deltas on objects later in it, which come once their bases have.
/// Returns how many there were.
pub fn objects(bytes: &[u8], have: &dyn Fn(&Link) -> Option<Block>, each: &mut dyn FnMut(Object) -> Result<()>) -> Result<usize> {
    let entries = entries(bytes)?;
    let mut pack = Pack { bytes, by_offset: entries.iter().map(|entry| (entry.offset, *entry)).collect(), by_name: HashMap::new(), cids: HashMap::new(), cache: HashMap::new(), cached: 0, have };
    let mut waiting = Vec::new();
    for entry in &entries {
        match pack.resolve(entry.offset) {
            Ok(object) => each(object)?,
            Err(Wait) => waiting.push(entry.offset),
        }
    }
    // Deltas on what came after them, till nothing more resolves
    while !waiting.is_empty() {
        let before = waiting.len();
        let mut still = Vec::new();
        for offset in waiting {
            match pack.resolve(offset) {
                Ok(object) => each(object)?,
                Err(Wait) => still.push(offset),
            }
        }
        if still.len() == before {
            return Err(invalid(format!("{} deltas on objects not in the pack or here", still.len())));
        }
        waiting = still;
    }
    Ok(entries.len())
}

/// A delta whose base isn't known yet.
struct Wait;

impl Pack<'_> {
    /// An entry as an object, and if it's a delta, that delta made one
    /// between whole blocks.
    fn resolve(&mut self, offset: usize) -> std::result::Result<Object, Wait> {
        let entry = *self.by_offset.get(&offset).ok_or(Wait)?;
        let (kind, content) = self.content(offset)?;
        let block = block(kind, &content);
        let link: Link = block.cid().clone().into();
        if let Some(sha1) = super::sha1_of(&link) {
            self.by_name.insert(sha1, offset);
        }
        self.cids.insert(offset, link);
        let delta = match entry.base {
            Base::Whole(_) => None,
            Base::At(at) => self.base_link(at).map(|base| (base, Lookup::At(at))),
            Base::Named(name) => Some((cid_of(&name), self.by_name.get(&name).map_or_else(|| Lookup::Have(name), |&at| Lookup::At(at)))),
        };
        let delta = match delta {
            None => None,
            Some((base, lookup)) => {
                let base_content = match lookup {
                    Lookup::At(at) => self.content(at)?.1,
                    Lookup::Have(name) => self.had(&name)?.1,
                };
                let raw = inflate(self.bytes.get(entry.data..).unwrap_or_default()).map_err(|_| Wait)?.0;
                let skip = format!("{} {}\0", kind.name(), base_content.len()).len();
                let header = format!("{} {}\0", kind.name(), content.len());
                crate::delta::behind_headers(&raw, skip, header.as_bytes()).ok().map(|delta| (base, delta))
            },
        };
        Ok(Object { block, delta })
    }

    fn base_link(&mut self, at: usize) -> Option<Link> {
        if let Some(link) = self.cids.get(&at) {
            return Some(link.clone());
        }
        let (kind, content) = self.content(at).ok()?;
        let link: Link = block(kind, &content).cid().clone().into();
        self.cids.insert(at, link.clone());
        Some(link)
    }

    /// An object outside the pack, as a thin pack's delta is on.
    fn had(&self, name: &[u8; 20]) -> std::result::Result<(Kind, Rc<Vec<u8>>), Wait> {
        let block = (self.have)(&cid_of(name)).ok_or(Wait)?;
        let (kind, content) = parse(block.data()).map_err(|_| Wait)?;
        Ok((kind, Rc::new(content.to_vec())))
    }

    /// An entry's kind and content, resolved.
    fn content(&mut self, offset: usize) -> std::result::Result<(Kind, Rc<Vec<u8>>), Wait> {
        if let Some((kind, content)) = self.cache.get(&offset) {
            return Ok((*kind, content.clone()));
        }
        let entry = *self.by_offset.get(&offset).ok_or(Wait)?;
        let data = inflate(self.bytes.get(entry.data..).unwrap_or_default()).map_err(|_| Wait)?.0;
        let (kind, content) = match entry.base {
            Base::Whole(kind) => (kind, data),
            Base::At(base) => {
                let (kind, base) = self.content(base)?;
                (kind, crate::delta::apply(&base, &data).map_err(|_| Wait)?)
            },
            Base::Named(name) => {
                let (kind, base) = if let Some(&at) = self.by_name.get(&name) {
                    self.content(at)?
                }
                else {
                    self.had(&name)?
                };
                (kind, crate::delta::apply(&base, &data).map_err(|_| Wait)?)
            },
        };
        let content = Rc::new(content);
        if self.cached.saturating_add(content.len()) > CACHE {
            self.cache.clear();
            self.cached = 0;
        }
        self.cached = self.cached.saturating_add(content.len());
        self.cache.insert(offset, (kind, content.clone()));
        Ok((kind, content))
    }
}

/// Where a delta's base is.
enum Lookup {
    At(usize),
    Have([u8; 20]),
}

/// A zlib stream's inflated bytes, and how many bytes of it there were.
fn inflate(bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut zlib = flate2::bufread::ZlibDecoder::new(bytes);
    let mut out = Vec::new();
    zlib.read_to_end(&mut out)?;
    Ok((out, usize::try_from(zlib.total_in()).map_err(|_| invalid("a huge entry"))?))
}

/// A pack's entries, in order, checked against its trailing SHA-1.
fn entries(bytes: &[u8]) -> Result<Vec<Entry>> {
    let body_len = bytes.len().checked_sub(20).ok_or_else(|| invalid("a pack cut short"))?;
    let (body, trailer) = bytes.split_at(body_len);
    if sha1::Sha1::digest(body).as_slice() != trailer {
        return Err(invalid("a pack whose checksum doesn't match"));
    }
    let header = body.get(..12).ok_or_else(|| invalid("a pack cut short"))?;
    let word = |at: usize| header.get(at..at.saturating_add(4)).and_then(|word| word.try_into().ok()).map(u32::from_be_bytes);
    if header.get(..4) != Some(b"PACK") || !matches!(word(4), Some(2 | 3)) {
        return Err(invalid("not a pack of version 2 or 3"));
    }
    let count = word(8).and_then(|count| usize::try_from(count).ok()).ok_or_else(|| invalid("no count"))?;
    let mut entries = Vec::with_capacity(count.min(1 << 20));
    let mut at = 12_usize;
    let byte = |at: usize| body.get(at).copied().ok_or_else(|| invalid("an entry cut short"));
    for _ in 0..count {
        let offset = at;
        let mut c = byte(at)?;
        at = at.saturating_add(1);
        let kind = (c >> 4) & 7;
        while c & 0x80 != 0 {
            c = byte(at)?;
            at = at.saturating_add(1);
        }
        let base = match kind {
            1 => Base::Whole(Kind::Commit),
            2 => Base::Whole(Kind::Tree),
            3 => Base::Whole(Kind::Blob),
            4 => Base::Whole(Kind::Tag),
            6 => {
                let mut c = byte(at)?;
                at = at.saturating_add(1);
                let mut back = usize::from(c & 0x7f);
                while c & 0x80 != 0 {
                    c = byte(at)?;
                    at = at.saturating_add(1);
                    back = back.checked_add(1).and_then(|back| back.checked_mul(128)).ok_or_else(|| invalid("a delta's base too far back"))? | usize::from(c & 0x7f);
                }
                Base::At(offset.checked_sub(back).filter(|_| back > 0).ok_or_else(|| invalid("a delta's base before the pack"))?)
            },
            7 => {
                let name = body.get(at..at.saturating_add(20)).ok_or_else(|| invalid("an entry cut short"))?;
                at = at.saturating_add(20);
                Base::Named(name.try_into().map_err(|_| invalid("an entry cut short"))?)
            },
            other => return Err(invalid(format!("an entry of type {other}"))),
        };
        let used = inflate(body.get(at..).unwrap_or_default())?.1;
        entries.push(Entry { offset, base, data: at });
        at = at.saturating_add(used);
    }
    Ok(entries)
}

impl From<Wait> for Error {
    fn from(_: Wait) -> Self {
        invalid("a delta whose base can't be had")
    }
}
