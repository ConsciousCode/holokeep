//! Keeping whole, in the shards, files whose leaves are whole in the delta
//! store.
//!
//! Leaves come to be there as copies of a file imported in place that was
//! about to stop being where it was (`Provenance::Superseded`), for an
//! older version to be a delta on, as one written over is. Most never get
//! a delta: a file moved, removed or let go of is copied whole, and stays
//! that way, the database holding what a kept file would, as big. This
//! moves such a file into the shards, as `hk add` keeps big files, its
//! leaves becoming ranges of it, wherever nothing's a delta on them and
//! the database doesn't hold them much smaller compressed. What it frees
//! in the database `Catalog::compact` gives back.

use std::io::Write as _;

use rusqlite::{OptionalExtension, params};

use super::offset::Whole;
use super::{Catalog, Error, Id, Result, decode_key};
use crate::multihash::Multihash;

/// The least a file's leaves may take in the database, in tenths of its
/// size, to be worth keeping whole: what compresses better stays.
const WORTH: u128 = 9;

/// What `Catalog::rehome` did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rehomed {
    /// Files kept whole.
    pub files: u64,
    /// Their bytes, which the database no longer holds.
    pub bytes: u64,
}

/// A file which may be kept whole: its root, and its size.
struct Candidate {
    root: Id,
    multihash: Multihash,
    size: u64,
}

impl Catalog {
    /// Keep whole in the shards files whose leaves are all whole in the
    /// delta store, biggest first, until `budget` bytes of them have
    /// been. Each is one transaction, so stopping partway loses nothing.
    pub fn rehome(&self, budget: u64) -> Result<Rehomed> {
        let mut done = Rehomed::default();
        if self.shards.is_none() || self.offsets.is_none() {
            return Ok(done);
        }
        for candidate in self.rehome_candidates()? {
            if done.bytes >= budget {
                break;
            }
            if self.rehome_file(&candidate)? {
                done.files = done.files.saturating_add(1);
                done.bytes = done.bytes.saturating_add(candidate.size);
            }
        }
        Ok(done)
    }

    /// Files bigger than the shards' threshold with a leaf whole in the
    /// delta store: the tops of what's found up the links from those
    /// leaves which are files no file links to. Biggest first.
    fn rehome_candidates(&self) -> Result<Vec<Candidate>> {
        let threshold = self.shards.as_ref().and_then(|shards| shards.threshold).unwrap_or_default();
        let file = i64::try_from(u64::from(crate::unixfs::DataType::File)).unwrap_or_default();
        // The name's kept off an index: every link in a file has the same
        // one, so that'd be searched through for each step
        let rows: Vec<(Id, Vec<u8>, i64)> = self.db.conn()
            .prepare_cached(
                "WITH RECURSIVE up (node) AS (
                     SELECT l.node FROM delta_blocks d JOIN unixfs_links l ON l.target = d.block
                     WHERE d.base IS NULL AND +l.name = x''
                     UNION SELECT l.node FROM up JOIN unixfs_links l ON l.target = up.node AND +l.name = x''
                 )
                 SELECT up.node, m.multihash, n.filesize FROM up
                 JOIN unixfs_nodes n ON n.block = up.node
                 JOIN multihashes m ON m.id = up.node
                 WHERE n.type = ?1 AND n.filesize > ?2
                     AND NOT EXISTS (
                         SELECT 1 FROM unixfs_links l JOIN unixfs_nodes p ON p.block = l.node
                         WHERE l.target = up.node AND +l.name = x'' AND p.type = ?1)
                 ORDER BY n.filesize DESC",
            )?
            .query_map(params![file, i64::try_from(threshold).unwrap_or(i64::MAX)], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|(root, multihash, size)| Ok(Candidate {
                root,
                multihash: decode_key("rehome", &multihash)?,
                size: u64::try_from(size).unwrap_or_default(),
            }))
            .collect()
    }

    /// A file's leaves in order, if they're all raw blocks, the file's
    /// bytes as they are: none if any isn't, so it can't be ranges.
    fn raw_leaves(&self, node: Id, leaves: &mut Vec<(Id, Multihash)>) -> Result<bool> {
        let links: Vec<(Id, Vec<u8>, Vec<u8>)> = self.db.conn()
            .prepare_cached(
                "SELECT l.target, l.prefix, m.multihash FROM unixfs_links l JOIN multihashes m ON m.id = l.target
                 WHERE l.node = ?1 ORDER BY l.idx",
            )?
            .query_map([node], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if links.is_empty() {
            return Ok(false);
        }
        for (target, prefix, multihash) in links {
            let inner = self.db.conn().prepare_cached("SELECT 1 FROM unixfs_links WHERE node = ?1")?.exists([target])?;
            if inner {
                if !self.raw_leaves(target, leaves)? {
                    return Ok(false);
                }
            }
            else if prefix == [0x01, 0x55] {
                leaves.push((target, decode_key("rehome", &multihash)?));
            }
            else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Keep a file whole if every leaf is whole in the delta store with
    /// nothing a delta on it, and they take most of its size there:
    /// whether it was.
    fn rehome_file(&self, candidate: &Candidate) -> Result<bool> {
        let (Some(shards), Some(offsets)) = (&self.shards, &self.offsets) else {
            return Ok(false);
        };
        let Some(offset_store) = self.placement.iter().find(|&&(volume, store)| {
            self.volumes.get(volume).and_then(|v| v.stores().get(store)).is_some_and(|store| store.name() == "offset")
        }).map(|&(volume, _)| volume) else {
            return Ok(false);
        };
        let mut leaves = Vec::new();
        if !self.raw_leaves(candidate.root, &mut leaves)? {
            return Ok(false);
        }
        let mut stored = 0_i64;
        for (leaf, _) in &leaves {
            let whole: Option<(bool, i64)> = self.db.conn()
                .prepare_cached(
                    "SELECT d.base IS NULL AND NOT EXISTS (SELECT 1 FROM delta_blocks x WHERE x.base = d.block), length(d.data)
                     FROM delta_blocks d WHERE d.block = ?1",
                )?
                .query_row([*leaf], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()?;
            let Some((true, len)) = whole else {
                return Ok(false);
            };
            stored = stored.saturating_add(len);
        }
        if u128::try_from(stored).unwrap_or_default().saturating_mul(10) < u128::from(candidate.size).saturating_mul(WORTH) {
            return Ok(false);
        }
        // Written out, each leaf checked against its CID as it's read
        let mut temp = shards.temp()?;
        let mut whole = Whole::default();
        let mut ranges: Vec<(Multihash, u64, u64)> = Vec::with_capacity(leaves.len());
        for (_, key) in leaves {
            let Some(block) = self.readable(key.as_ref())? else {
                return Ok(false);
            };
            let len = crate::dag::len64(block.data());
            ranges.push((key, whole.len(), len));
            whole.push(whole.len(), block.data())?;
            temp.write_all(block.data())?;
        }
        if whole.len() != candidate.size {
            return Ok(false);
        }
        let blob = whole.finish();
        let existed = shards.path(blob.as_ref()).exists();
        shards.persist(temp, blob.as_ref())?;
        let moved = self.db.atomically(|| {
            offsets.add_ranges(blob.as_ref(), &ranges)?;
            for (key, ..) in &ranges {
                let id = self.db.intern(key.as_ref())?;
                // A block's in one form a volume, so out of the delta
                // store first, its links kept, as it's still here
                for placed in self.placements(key.as_ref())?.into_iter().filter(|(_, form)| form == "delta") {
                    self.named(&placed)?.remove(key.as_ref())?;
                    let volume = *self.ids.get(placed.0).ok_or_else(|| Error::UnknownStore(placed.1.clone()))?;
                    self.db.conn().prepare_cached("DELETE FROM blocks WHERE block = ?1 AND volume = ?2")?.execute([id, volume])?;
                }
                self.record(id, &(offset_store, "offset".to_owned()))?;
            }
            shards.record_root(blob.as_ref(), candidate.multihash.as_ref())?;
            self.say_kept_root(blob.as_ref(), &Self::kept_root(blob.as_ref(), candidate.multihash.as_ref())?)
        });
        if let Err(e) = moved {
            // Nothing refers to it, so it's not left to pass for a block
            if !existed {
                shards.forget(blob.as_ref())?;
            }
            return Err(e);
        }
        Ok(true)
    }
}

/// How often the node looks for files to keep whole.
const EVERY: std::time::Duration = std::time::Duration::from_mins(10);

/// The most it keeps whole each time, so a repo with a lot to move moves
/// it over a while, not all at once.
const ROUND: u64 = 4 << 30;

/// Keep files whole, as `Catalog::rehome`, every `EVERY`, on a thread of
/// its own with its own catalog, since it reads and writes gigabytes,
/// until `stop`.
pub fn run(repo: std::path::PathBuf, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;
    std::thread::Builder::new()
        .name("rehome".into())
        .spawn(move || {
            let mut catalog = None;
            while !stop.load(Ordering::Relaxed) {
                if catalog.is_none() {
                    catalog = Catalog::open_repo(&repo).map_err(|e| eprintln!("not keeping copied files whole: {e}")).ok();
                }
                if let Some(catalog) = &catalog {
                    match catalog.rehome(ROUND) {
                        Ok(done) if done.files > 0 => eprintln!("kept {} files whole, {} bytes out of the database", done.files, done.bytes),
                        Ok(_) => {},
                        Err(e) => eprintln!("not keeping copied files whole: {e}"),
                    }
                }
                let deadline = std::time::Instant::now().checked_add(EVERY);
                while !stop.load(Ordering::Relaxed) && deadline.is_some_and(|deadline| std::time::Instant::now() < deadline) {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
        })
        .map_err(|e| eprintln!("not keeping copied files whole: {e}"))
        .ok();
}
