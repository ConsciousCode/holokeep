//! CAR files (Content Addressable aRchives), the interchange format for
//! blocks between repos, Kubo's included: `ipfs dag import` and `ipfs dag
//! export`.
//!
//! A `CARv1` is a varint-prefixed dag-cbor header, `{"roots": [CID…],
//! "version": 1}`, then sections of varint length, binary CID and block
//! bytes. A `CARv2` wraps a `CARv1` with a fixed header saying where it is,
//! and an optional index after it; reading one reads the `CARv1` inside and
//! ignores the index.
//!
//! A CAR comes from anywhere, so nothing in one is trusted: every block is
//! verified against its CID, and lengths are bounded before anything is
//! allocated for them.

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read, Write};

use crate::block::Block;
use crate::cid::{BaseCid, Cid, CidRef, CidVersion};
use crate::dagcbor;
use crate::export::Fetch;
use crate::model::{Ipld, Link};
use crate::multihash::Multihash;

/// go-car's limits: no header or section is larger than these.
const MAX_HEADER: u64 = 32 << 20;
const MAX_SECTION: u64 = 8 << 20;

/// What starts a `CARv2`: a `CARv1` header saying `{"version": 2}`.
const V2_PRAGMA: [u8; 11] = [0x0a, 0xa1, 0x67, b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x02];

/// The size of a `CARv2`'s header after its pragma: characteristics, then
/// the data's offset and size and the index's offset, little-endian.
const V2_HEADER: usize = 40;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Read a varint, or None at a clean end of input.
fn read_varint(reader: &mut impl Read) -> io::Result<Option<u64>> {
    let mut buf = Vec::with_capacity(10);
    loop {
        let mut byte = [0];
        if reader.read(&mut byte)? == 0 {
            return if buf.is_empty() { Ok(None) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        }
        buf.extend(byte);
        if byte[0] & 0x80 == 0 || buf.len() >= 10 {
            break;
        }
    }
    crate::varint::read_minimal(&mut buf.as_slice())
        .map(Some)
        .map_err(|e| invalid(format!("varint: {e:?}")))
}

/// Read a varint length, then that many bytes.
fn read_frame(reader: &mut impl Read, max: u64, what: &str) -> io::Result<Option<Vec<u8>>> {
    let Some(len) = read_varint(reader)? else {
        return Ok(None);
    };
    if len > max {
        return Err(invalid(format!("{what} of {len} bytes is larger than {max}")));
    }
    let len = usize::try_from(len).map_err(|_| invalid(format!("{what} too large")))?;
    let mut buf = vec![0; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// How long the binary CID at the start of a section is.
fn cid_len(section: &[u8]) -> io::Result<usize> {
    let mut rest = section;
    let truncated = || invalid("section's CID is truncated");
    // A CIDv0 is a bare sha2-256 multihash
    if section.starts_with(&[0x12, 0x20]) {
        return if section.len() >= 34 { Ok(34) } else { Err(truncated()) };
    }
    for _ in 0..3 {
        // version, codec, hash function
        crate::varint::read_minimal(&mut rest).map_err(|_| truncated())?;
    }
    let digest = crate::varint::read_minimal(&mut rest).map_err(|_| truncated())?;
    let digest = usize::try_from(digest).map_err(|_| truncated())?;
    let len = section.len().checked_sub(rest.len()).and_then(|n| n.checked_add(digest)).ok_or_else(truncated)?;
    if len > section.len() { Err(truncated()) } else { Ok(len) }
}

/// Reads a CAR's blocks, verifying each.
pub struct CarReader<R> {
    reader: R,
    roots: Vec<Link>,
}

impl CarReader<Box<dyn Read>> {
    /// Read a CAR's header, of either version.
    pub fn new(mut reader: impl Read + 'static) -> io::Result<Self> {
        let header = read_frame(&mut reader, MAX_HEADER, "header")?.ok_or_else(|| invalid("empty CAR"))?;
        if Some(header.as_slice()) == V2_PRAGMA.get(1..) {
            let mut fixed = [0; V2_HEADER];
            reader.read_exact(&mut fixed)?;
            let field = |i: usize| {
                fixed.get(i..i.saturating_add(8))
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .ok_or_else(|| invalid("CARv2 header"))
            };
            let (offset, size) = (field(16)?, field(24)?);
            // The `CARv1` inside is somewhere after the `CARv2` header
            let read = u64::try_from(V2_PRAGMA.len().saturating_add(V2_HEADER)).unwrap_or(u64::MAX);
            let skip = offset.checked_sub(read).ok_or_else(|| invalid("CARv2 data overlaps its header"))?;
            io::copy(&mut (&mut reader).take(skip), &mut io::sink())?;
            let mut inner = reader.take(size);
            let header = read_frame(&mut inner, MAX_HEADER, "header")?.ok_or_else(|| invalid("empty CARv2 data"))?;
            return Self::v1(Box::new(inner), &header);
        }
        Self::v1(Box::new(reader), &header)
    }
}

impl<R: Read> CarReader<R> {
    fn v1(reader: R, header: &[u8]) -> io::Result<Self> {
        let header: Ipld = dagcbor::from_slice(header).map_err(|e| invalid(format!("CAR header: {e}")))?;
        let Ipld::Map(mut header) = header else {
            return Err(invalid("CAR header isn't a map"));
        };
        if header.get("version") != Some(&Ipld::Integer(1)) {
            return Err(invalid("not a CARv1 or CARv2"));
        }
        let roots = match header.remove("roots") {
            Some(Ipld::List(roots)) => roots
                .into_iter()
                .map(|root| match root {
                    Ipld::Link(link) => Ok(link),
                    _ => Err(invalid("CAR root isn't a CID")),
                })
                .collect::<io::Result<_>>()?,
            _ => return Err(invalid("CAR header has no roots")),
        };
        Ok(Self { reader, roots })
    }

    /// The next block and the version of the CID it's under, verified.
    pub fn next_block(&mut self) -> io::Result<Option<(Block, CidVersion)>> {
        let Some(section) = read_frame(&mut self.reader, MAX_SECTION, "section")? else {
            return Ok(None);
        };
        let (cid, data) = section.split_at(cid_len(&section)?);
        let cid = Link::decode(cid).map_err(|e| invalid(format!("section's CID: {e:?}")))?;
        let version = cid.version();
        let block = Block::verify(cid.clone().into(), data.into())
            .map_err(|_| invalid(format!("block {cid} doesn't match its CID")))?;
        Ok(Some((block, version)))
    }
}

/// Write a `CARv1` header.
fn write_header(out: &mut impl Write, roots: &[Link]) -> io::Result<()> {
    let header = Ipld::Map(BTreeMap::from([
        ("roots".to_owned(), Ipld::List(roots.iter().cloned().map(Ipld::Link).collect())),
        ("version".to_owned(), Ipld::Integer(1)),
    ]));
    let header = dagcbor::to_vec(&header).map_err(io::Error::other)?;
    let mut prefix = Vec::new();
    crate::varint::write(&mut prefix, crate::dag::len64(&header));
    out.write_all(&prefix)?;
    out.write_all(&header)
}

fn write_section(out: &mut impl Write, cid: &Link, data: &[u8]) -> io::Result<()> {
    let cid = cid.to_bytes();
    let mut prefix = Vec::new();
    crate::varint::write(&mut prefix, crate::dag::len64(&cid).saturating_add(crate::dag::len64(data)));
    out.write_all(&prefix)?;
    out.write_all(&cid)?;
    out.write_all(data)
}

/// Write the whole DAG under `root` as a `CARv1`, like `ipfs dag export`:
/// depth first, each block the first time it's reached. Returns how many
/// blocks were written.
pub fn export(src: &impl Fetch, root: &Link, out: &mut impl Write) -> io::Result<u64> {
    write_dag(src, root, out).map(|blocks| count(blocks.len()))
}

/// As `export`, returning the blocks written.
fn write_dag(src: &impl Fetch, root: &Link, out: &mut impl Write) -> io::Result<Vec<Link>> {
    write_header(out, std::slice::from_ref(root))?;
    let mut seen = HashSet::new();
    let mut stack = vec![root.clone()];
    let mut blocks = Vec::new();
    while let Some(cid) = stack.pop() {
        if !seen.insert(cid.to_bytes()) {
            continue;
        }
        let data = src.fetch(&cid)?;
        write_section(out, &cid, &data)?;
        let links = crate::links::links(cid.codec(), &data).map_err(|e| invalid(format!("{cid}: {e}")))?;
        stack.extend(links.into_iter().rev());
        blocks.push(cid);
    }
    Ok(blocks)
}

/// What an export wrote, or would have.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Exported {
    /// Sections of the DAG.
    pub blocks: u64,
    /// Claims written after them.
    pub claims: u64,
    /// Claims about the DAG not asked for.
    pub left_out: u64,
    /// Blocks of older versions of anchors, or reported lost, that aren't here
    /// to write.
    pub unreadable: u64,
    /// The user's root key, sealed, written after them.
    pub sealed: u64,
}

/// What goes in an export besides the DAG and what's said of it.
#[derive(Debug, Default, Clone, Copy)]
pub struct WithClaims {
    /// All that anchors have been, not only what they are.
    pub history: bool,
    /// The user's root key, sealed with their passphrase.
    pub sealed_root: bool,
}

/// As `export`, noting what's left out: claims, which plain interchange
/// doesn't carry, as they say who's kept and tagged what.
pub fn export_noting(catalog: &crate::store::Catalog, root: &Link, out: &mut impl Write) -> io::Result<Exported> {
    let blocks = write_dag(catalog, root, out)?;
    let keys = keys_of(&blocks)?;
    let left_out = catalog.claims_on(&keys).map_err(io::Error::other)?.len();
    Ok(Exported { blocks: count(blocks.len()), left_out: count(left_out), ..Exported::default() })
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Whether what couldn't be fetched isn't here to be: not found, or kept in a
/// file that's changed or gone.
fn gone(e: &io::Error) -> bool {
    use crate::store::Error;
    e.kind() == io::ErrorKind::NotFound
        || matches!(e.get_ref().and_then(|e| e.downcast_ref::<Error>()), Some(Error::Stale(_) | Error::Missing(_) | Error::Corrupt(_)))
}

fn keys_of(blocks: &[Link]) -> io::Result<Vec<Multihash>> {
    blocks.iter().map(|cid| Multihash::decode(&cid.multihash().to_bytes()).map_err(|e| invalid(format!("{cid}: {e:?}")))).collect()
}

/// As `export`, then the claims about what's written, however deep, with what
/// makes them count elsewhere.
///
/// Dissolved ones are sections under their identity CIDs, like any block, so
/// any CAR reader can read this, and what comes before them is what `export`
/// writes. So far as a reader can tell they're blocks nothing links to.
///
/// An anchor reached, by a link or a mount point, is followed to what it is
/// now, or if `history`, to all it's been, what's no longer here of that being
/// counted and passed over. Otherwise its older sets say what it was, with
/// nothing there, as with any block that isn't here.
///
/// With `sealed_root`, a repo with no devices left can become the user again
/// from this and the passphrase. It's refused if there's none to write, as a
/// backup that can't do what it was asked is worse than an error now.
pub fn export_with_claims(catalog: &crate::store::Catalog, root: &Link, with: WithClaims, out: &mut impl Write) -> io::Result<Exported> {
    let WithClaims { history, sealed_root } = with;
    let seals = if sealed_root {
        let seals = catalog.seals().map_err(io::Error::other)?;
        if seals.is_empty() {
            return Err(io::Error::other("this repo has no sealed root key to write"));
        }
        seals
    } else {
        Vec::new()
    };
    write_header(out, std::slice::from_ref(root))?;
    let (mut seen, mut missed) = (HashSet::new(), HashSet::new());
    let mut stack = vec![(root.clone(), true)];
    let mut blocks = Vec::new();
    let mut unreadable = Vec::new();
    while let Some((cid, needed)) = stack.pop() {
        let bytes = cid.to_bytes();
        if needed && missed.contains(&bytes) {
            return Err(invalid(format!("block {cid} not found")));
        }
        if !seen.insert(bytes.clone()) {
            continue;
        }
        let data = match catalog.fetch(&cid) {
            Ok(data) => data,
            // Not needed, or known not to be had, which a backup's no less
            // worth having for
            Err(e) if gone(&e) && (!needed || catalog.lost_at(&cid).is_ok_and(|at| at.is_some())) => {
                missed.insert(bytes);
                unreadable.push(cid);
                continue;
            },
            Err(e) => return Err(e),
        };
        write_section(out, &cid, &data)?;
        // Older versions first on the stack, so they come last, once what's
        // needed has been found
        if crate::claim::is_anchor(&cid) {
            if history {
                let was = catalog.anchor_history(&cid).map_err(io::Error::other)?;
                stack.extend(was.into_iter().rev().map(|(_, value)| (value, false)));
            }
            let heads = catalog.anchor_heads(&cid).map_err(io::Error::other)?;
            stack.extend(heads.into_iter().rev().map(|(_, value, _)| (value, needed)));
        }
        let mut links = crate::links::links(cid.codec(), &data).map_err(|e| invalid(format!("{cid}: {e}")))?;
        links.extend(crate::store::mount_point(cid.codec(), &data));
        stack.extend(links.into_iter().rev().map(|link| (link, needed)));
        blocks.push(cid);
    }
    // What's not here may have been reported lost, which belongs with it
    // A seal goes last, as what it's about is the rest
    let seal_cids: Vec<Link> = seals.into_iter().map(|(cid, _)| cid).filter(|cid| !seen.contains(&cid.to_bytes())).collect();
    let mut sealed = 0u64;
    for cid in &seal_cids {
        write_section(out, cid, &catalog.fetch(cid)?)?;
        seen.insert(cid.to_bytes());
        sealed = sealed.saturating_add(1);
    }
    let about: Vec<Link> = blocks.iter().chain(&unreadable).chain(&seal_cids).cloned().collect();
    let claims = catalog.claims_on(&keys_of(&about)?).map_err(io::Error::other)?;
    let mut written = 0u64;
    for (cid, data) in &claims {
        if !seen.contains(&cid.to_bytes()) {
            write_section(out, cid, data)?;
            written = written.saturating_add(1);
        }
    }
    Ok(Exported {
        blocks: count(blocks.len()),
        claims: written,
        left_out: 0,
        unreadable: count(unreadable.len()),
        sealed,
    })
}

/// Somewhere to put the blocks of a CAR.
pub trait Import {
    fn import(&mut self, block: &Block, version: CidVersion) -> io::Result<()>;
}

impl Import for crate::store::Catalog {
    fn import(&mut self, block: &Block, version: CidVersion) -> io::Result<()> {
        self.put_block(block, version).map_err(io::Error::other)?;
        self.breathe().map_err(io::Error::other)
    }
}

/// Put every block of a CAR, returning its roots and how many blocks it
/// held.
pub fn import(reader: impl Read + 'static, sink: &mut impl Import) -> io::Result<(Vec<Link>, u64)> {
    let mut car = CarReader::new(reader)?;
    let mut count = 0u64;
    while let Some((block, version)) = car.next_block()? {
        sink.import(&block, version)?;
        count = count.saturating_add(1);
    }
    Ok((car.roots, count))
}

#[cfg(test)]
mod tests;
