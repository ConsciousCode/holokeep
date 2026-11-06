//! Giving back to the filesystem what databases have freed.
//!
//! A database keeps the pages it frees to use again, as an allocator does,
//! so this is only ever asked for: after an import that won't be repeated,
//! say. `VACUUM` rewrites a database, passing all of it through the WAL.
//! Readers carry on meanwhile, but writers wait, which holds up a mount
//! entirely once it needs to write, and only so long, which is why one that
//! may take long isn't started unless it's asked for.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{Catalog, Db, Result, free_space};

/// The most of a database rewritten without being asked to take long:
/// well within what writers wait for by default (`WRITER_WAIT`), at the
/// 50 MiB/s or so of a slow disk.
const LONGEST: u64 = 256 * 1024 * 1024;

/// How a database's bytes are used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Space {
    pub volume: String,
    /// What it takes on disk, its WAL too.
    pub bytes: u64,
    /// How much of that's free pages, which would be given back.
    pub free: u64,
}

/// What to do.
#[derive(Debug, Clone, Copy, Default)]
pub struct Compact {
    /// Only say what would be done.
    pub dry_run: bool,
    /// Compact even what may keep writers waiting longer than they will,
    /// nothing else writing to it.
    pub long: bool,
}

/// What became of a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It has no free pages.
    AlreadyCompact,
    WouldCompact,
    /// `wal_left` if a reader kept its WAL from being emptied: it's as
    /// big as the database till that's done, by the next compact or once
    /// nothing has the database open.
    Compacted { took: Duration, wal_left: bool },
    /// Refused: writers might give up waiting.
    TooLong,
    /// Refused: its filesystem has too little left for the WAL.
    NoRoom { needed: u64, available: u64 },
}

impl Outcome {
    pub const fn refused(self) -> bool {
        matches!(self, Self::TooLong | Self::NoRoom { .. })
    }
}

/// A database, and what became of it: its bytes on disk before and after.
/// After a dry run, the bytes it would have at most.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compaction {
    pub volume: String,
    pub before: u64,
    pub after: u64,
    pub outcome: Outcome,
}

/// A database's pages: (in all, free, and their size).
fn pages(db: &Db) -> Result<(u64, u64, u64)> {
    let pragma = |name: &str| -> Result<u64> {
        Ok(db.conn().query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0)).map(|n| u64::try_from(n).unwrap_or_default())?)
    };
    Ok((pragma("page_count")?, pragma("freelist_count")?, pragma("page_size")?))
}

/// A database's file, if it's a file.
fn file(db: &Db) -> Result<Option<PathBuf>> {
    let path: String = db.conn().query_row("SELECT file FROM pragma_database_list WHERE name = 'main'", [], |row| row.get(0))?;
    Ok((!path.is_empty()).then(|| PathBuf::from(path)))
}

/// What a database takes on disk, its WAL too.
fn on_disk(db: &Db) -> Result<u64> {
    let Some(path) = file(db)? else {
        let (pages, _, size) = pages(db)?;
        return Ok(pages.saturating_mul(size));
    };
    let len = |path: &Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
    let mut wal = path.clone().into_os_string();
    wal.push("-wal");
    Ok(len(&path).saturating_add(len(Path::new(&wal))))
}

/// Why rewriting `live` bytes isn't to be started, if it isn't.
const fn refusal(live: u64, room: Option<u64>, longest: u64, long: bool) -> Option<Outcome> {
    match room {
        Some(available) if available < live => Some(Outcome::NoRoom { needed: live, available }),
        _ if live > longest && !long => Some(Outcome::TooLong),
        _ => None,
    }
}

/// Rewrite a database, then empty its WAL, which the rewrite went through,
/// whether or not it got to the end. Returns whether a reader kept it from
/// being emptied.
fn rewrite(db: &Db) -> Result<bool> {
    let vacuumed = db.conn().execute_batch("VACUUM");
    let busy = db.conn().query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get::<_, i64>(0));
    vacuumed?;
    Ok(busy? != 0)
}

impl Catalog {
    /// How each attached database's bytes are used.
    pub fn space(&self) -> Result<Vec<Space>> {
        self.volumes.iter()
            .filter_map(|volume| volume.db().map(|db| (volume, db)))
            .map(|(volume, db)| {
                let (_, free, size) = pages(db)?;
                Ok(Space { volume: volume.name.clone(), bytes: on_disk(db)?, free: free.saturating_mul(size) })
            })
            .collect()
    }

    /// Give back each attached database's free pages, telling `report`
    /// what became of each as it's done. What's refused doesn't stop the
    /// rest.
    pub fn compact(&self, compact: Compact, report: &mut dyn FnMut(&Compaction)) -> Result<()> {
        self.compact_within(compact, LONGEST, report)
    }

    fn compact_within(&self, compact: Compact, longest: u64, report: &mut dyn FnMut(&Compaction)) -> Result<()> {
        for volume in &self.volumes {
            let Some(db) = volume.db() else {
                continue;
            };
            let (all, free, size) = pages(db)?;
            let live = all.saturating_sub(free).saturating_mul(size);
            let before = on_disk(db)?;
            let room = file(db)?.as_deref().and_then(Path::parent).and_then(free_space);
            let (after, outcome) = if free == 0 {
                (before, Outcome::AlreadyCompact)
            }
            else if let Some(refused) = refusal(live, room, longest, compact.long) {
                (before, refused)
            }
            else if compact.dry_run {
                (live, Outcome::WouldCompact)
            }
            else {
                let start = Instant::now();
                let wal_left = rewrite(db)?;
                (on_disk(db)?, Outcome::Compacted { took: start.elapsed(), wal_left })
            };
            report(&Compaction { volume: volume.name.clone(), before, after, outcome });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::cid::{CidVersion, Cidv1Spec};
    use crate::dag::Provenance;
    use crate::model::Link;
    use crate::testutil::Scratch;

    fn compacted(catalog: &Catalog, compact: Compact, longest: u64) -> Vec<Compaction> {
        let mut done = Vec::new();
        catalog.compact_within(compact, longest, &mut |compaction| done.push(compaction.clone())).expect("compact");
        done
    }

    /// Versions of a file, whole in the database, the older then made
    /// deltas, freeing most of what they took.
    fn versions(catalog: &Catalog) -> Vec<Block> {
        let text = |n: usize| -> Vec<u8> { (0..4000).flat_map(|i| format!("line {i} of {}\n", if i % 500 == 0 { n } else { 0 }).into_bytes()).collect() };
        let versions: Vec<Block> = (0..40).map(|n| Block::hash(Cidv1Spec::default(), text(n).into())).collect();
        for version in &versions {
            catalog.put_block_from(version, CidVersion::V1, Provenance::Superseded).expect("put");
        }
        for pair in versions.windows(2) {
            if let [older, newer] = pair {
                let link = |block: &Block| -> Link { block.cid().clone().into() };
                assert!(catalog.revise(&link(older), &link(newer)).expect("revise"));
            }
        }
        versions
    }

    #[test]
    fn free_pages_are_given_back_and_nothing_else_changes() {
        let scratch = Scratch::new("compact");
        let catalog = Catalog::open_repo(scratch.path()).expect("open");
        let versions = versions(&catalog);
        let space = catalog.space().expect("space");
        let [Space { volume, bytes, free }] = space.as_slice() else {
            panic!("{space:?}");
        };
        assert!(*free > 0, "{bytes} bytes, {free} free");

        // A look changes nothing
        let looked = compacted(&catalog, Compact { dry_run: true, long: false }, LONGEST);
        let [Compaction { before, after, outcome: Outcome::WouldCompact, .. }] = looked.as_slice() else {
            panic!("{looked:?}");
        };
        assert!(after < before);
        assert_eq!(catalog.space().expect("space")[0].free, *free);

        // Refused, even if asked only to look, and said so
        let refused = compacted(&catalog, Compact { dry_run: true, long: false }, 0);
        assert_eq!(refused[0].outcome, Outcome::TooLong);
        assert!(refused[0].outcome.refused());
        assert_eq!(catalog.space().expect("space")[0].free, *free);

        // Another connection beside it, idle, as a mount's or daemon's is
        let idle = rusqlite::Connection::open(scratch.path().join("blocks.db")).expect("open");
        let count = |conn: &rusqlite::Connection| conn.query_row("SELECT count(*) FROM delta_blocks", [], |row| row.get::<_, i64>(0)).expect("count");
        let rows = count(&idle);
        let done = compacted(&catalog, Compact::default(), LONGEST);
        let [Compaction { volume: named, before, after, outcome: Outcome::Compacted { wal_left: false, .. } }] = done.as_slice() else {
            panic!("{done:?}");
        };
        assert_eq!(named, volume);
        assert!(after < before, "{before} to {after}");
        assert_eq!(catalog.space().expect("space")[0].free, 0);
        assert_eq!(count(&idle), rows, "it reads on");
        for version in &versions {
            assert_eq!(catalog.get_block(&version.cid().clone().into()).expect("get").as_ref().map(Block::data), Some(version.data()));
        }

        // Nothing to do, and it's still what it was on opening again
        let again = compacted(&catalog, Compact::default(), LONGEST);
        assert_eq!(again[0].outcome, Outcome::AlreadyCompact);
        assert_eq!(again[0].before, again[0].after);
        drop((idle, catalog));
        let catalog = Catalog::open_repo(scratch.path()).expect("reopen");
        for version in &versions {
            assert!(catalog.get_block(&version.cid().clone().into()).expect("get").is_some());
        }
    }

    #[test]
    fn every_attached_database_is_compacted_and_a_reader_is_reported() {
        let scratch = Scratch::new("compact-volumes");
        let mut catalog = Catalog::open_repo(scratch.path().join("repo").as_path()).expect("open");
        let other = scratch.path().join("other.db");
        catalog.add_sqlite_volume("other", &other).expect("add");
        let beside = rusqlite::Connection::open(&other).expect("open");
        beside.execute_batch(
            "CREATE TABLE junk AS WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000) SELECT zeroblob(4000) AS b FROM n;
             DROP TABLE junk;",
        ).expect("junk");
        // A reader mid-transaction holds the WAL, not the rewrite
        beside.execute_batch("BEGIN; SELECT count(*) FROM sqlite_schema;").expect("read");
        beside.busy_timeout(Duration::ZERO).expect("timeout");
        let space = catalog.space().expect("space");
        let free = space.iter().find(|space| space.volume == "other").expect("other").free;
        assert!(free > 4_000_000, "{space:?}");
        // So it doesn't wait for long on a reader that won't finish
        catalog.volumes.iter().find(|volume| volume.name == "other").and_then(|volume| volume.db()).expect("db").conn().busy_timeout(Duration::from_millis(50)).expect("timeout");
        let done = compacted(&catalog, Compact::default(), LONGEST);
        let reported = done.iter().find(|done| done.volume == "other").expect("other");
        assert!(matches!(reported.outcome, Outcome::Compacted { wal_left: true, .. }), "{reported:?}");
        assert_eq!(catalog.space().expect("space").iter().find(|space| space.volume == "other").expect("other").free, 0);
        beside.execute_batch("COMMIT").expect("commit");
        drop(beside);
        // It's still the volume it was: found again by its label
        drop(catalog);
        let catalog = Catalog::open_repo(scratch.path().join("repo").as_path()).expect("reopen");
        assert!(catalog.volume_list().expect("list").iter().any(|volume| volume.name == "other" && volume.attached));
    }

    #[test]
    fn what_may_take_long_or_not_fit_is_refused() {
        assert_eq!(refusal(10, Some(100), 50, false), None);
        assert_eq!(refusal(10, None, 50, false), None, "room that can't be told");
        assert_eq!(refusal(60, Some(100), 50, false), Some(Outcome::TooLong));
        assert_eq!(refusal(60, Some(100), 50, true), None, "asked for");
        assert_eq!(refusal(60, Some(59), 50, true), Some(Outcome::NoRoom { needed: 60, available: 59 }), "whether or not it's asked for");
    }
}
