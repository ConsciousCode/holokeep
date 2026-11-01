//! Collecting garbage: letting go of what nothing keeps, everywhere, after
//! a grace period: `/holokeep/condemn/1.0.0`.
//!
//! Collection is incremental, top down. A node condemns a block it holds
//! when nothing here references it: no structure links to it, and no keep
//! that counts targets it (tags don't keep what they tag, and a tomb's
//! link is the opposite of a reference). Claims themselves are never
//! collected; they're the history of what's kept.
//!
//! Not knowing of a reference isn't there being none, so the node asks
//! every member whether it keeps what's condemned, by whether a keep it
//! knows of reaches it. A member that keeps it pardons it, as does a
//! reference arriving here. A condemned block goes once
//!
//! - it's been condemned for the grace period (a week, as long as a
//!   sighting's believed), so what stops being kept stays a while,
//!   unlike `rm`;
//! - every member has said since that it doesn't keep it: a member away
//!   holds collection up until it's back, or is no longer a member;
//! - and nothing here references it still.
//!
//! What a block that went linked to may then have nothing referencing it.
//! It's condemned as of when what linked to it was, so it's due as soon
//! as members have answered for it: a DAG goes a level per round of
//! answers, a week after its root was condemned, however deep it is.
//!
//! Blocks condemned together are a batch, with one time and one answer
//! from each member, so bookkeeping grows with batches, not blocks.
//!
//! A keep added elsewhere after its member said it kept nothing races
//! collection, but a keep is only added by a node holding all of what it
//! keeps, so that copy survives and is replicated again. Condemned blocks
//! aren't audited, nor count as held to a member trimming, so a keeper's
//! copy isn't let go of on the strength of copies about to be collected.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{PeerId, StreamProtocol};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::multihash::Multihash;
use crate::store::{Catalog, Db, Key};

use super::mesh::Result;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/condemn/1.0.0");

/// How long a block stays condemned before it may be let go of.
pub const GRACE: Duration = super::durability::TTL;

/// The most blocks in a batch, and so asked of in one request.
pub const BATCH: usize = 512;

/// A batch of condemned blocks, as this node knows it.
pub type BatchId = i64;

/// Blocks condemned, to ask a member whether it keeps them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Condemn {
    blocks: Vec<ByteBuf>,
}

/// Which of the blocks asked of the member keeps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Verdict {
    kept: Vec<ByteBuf>,
}

/// What collecting did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Blocks newly condemned.
    pub condemned: usize,
    /// Blocks pardoned, being referenced after all.
    pub pardoned: usize,
    /// Blocks let go of.
    pub collected: usize,
    /// Bytes freed.
    pub freed: u64,
}

impl Report {
    pub const fn add(&mut self, other: &Self) {
        self.condemned = self.condemned.saturating_add(other.condemned);
        self.pardoned = self.pardoned.saturating_add(other.pardoned);
        self.collected = self.collected.saturating_add(other.collected);
        self.freed = self.freed.saturating_add(other.freed);
    }
}

fn now() -> i64 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn decode(bytes: &[u8]) -> Option<Multihash> {
    <Multihash>::decode(bytes).ok()
}

/// The blocks condemned here, in batches, each since when and which
/// members have said since that they don't keep its blocks.
pub struct Condemned {
    db: Db,
    grace: Duration,
}

impl Condemned {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "-- Condemnation by block, from before batches.
             DROP TABLE IF EXISTS condemned;
             DROP TABLE IF EXISTS condemn_acks;
             -- Blocks condemned together, and since when.
             CREATE TABLE IF NOT EXISTS condemn_batches (
                 id INTEGER PRIMARY KEY,
                 since INTEGER NOT NULL
             );
             -- Blocks this node knows of nothing referencing, by batch.
             CREATE TABLE IF NOT EXISTS condemned_blocks (
                 block INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 batch INTEGER NOT NULL REFERENCES condemn_batches (id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS condemned_blocks_batch ON condemned_blocks (batch);
             -- Members which have said they keep none of a batch's blocks.
             CREATE TABLE IF NOT EXISTS batch_acks (
                 batch INTEGER NOT NULL REFERENCES condemn_batches (id) ON DELETE CASCADE,
                 peer TEXT NOT NULL,
                 PRIMARY KEY (batch, peer)
             ) WITHOUT ROWID;",
        )?;
        Ok(Self { db, grace: GRACE })
    }

    /// Wait this long before letting go instead.
    #[must_use]
    pub const fn with_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Condemn whichever of these blocks aren't already, in batches, as of
    /// `since` or now. Returns how many were newly condemned.
    pub fn condemn(&self, keys: &[Multihash], since: Option<i64>) -> Result<usize> {
        let since = since.unwrap_or_else(now);
        let mut condemned = 0usize;
        for chunk in keys.chunks(BATCH) {
            self.db.atomically(|| {
                let conn = self.db.conn();
                conn.prepare_cached("INSERT INTO condemn_batches (since) VALUES (?1)")?.execute([since])?;
                let batch = conn.last_insert_rowid();
                let mut added = 0usize;
                for key in chunk {
                    let id = self.db.intern(key.as_ref())?;
                    added = added.saturating_add(
                        conn.prepare_cached("INSERT OR IGNORE INTO condemned_blocks (block, batch) VALUES (?1, ?2)")?.execute([id, batch])?,
                    );
                }
                if added == 0 {
                    conn.prepare_cached("DELETE FROM condemn_batches WHERE id = ?1")?.execute([batch])?;
                }
                condemned = condemned.saturating_add(added);
                Ok::<_, crate::store::Error>(())
            })?;
        }
        Ok(condemned)
    }

    /// Pardon a block, returning whether it was condemned. A batch left
    /// empty goes too.
    pub fn pardon(&self, key: Key<'_>) -> Result<bool> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(false);
        };
        let conn = self.db.conn();
        let batch: Option<BatchId> = conn
            .prepare_cached("DELETE FROM condemned_blocks WHERE block = ?1 RETURNING batch")?
            .query_row([id], |row| row.get(0))
            .optional()?;
        if let Some(batch) = batch {
            conn.prepare_cached("DELETE FROM condemn_batches WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM condemned_blocks WHERE batch = ?1)")?
                .execute([batch])?;
        }
        Ok(batch.is_some())
    }

    pub fn is_condemned(&self, key: Key<'_>) -> Result<bool> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(false);
        };
        Ok(self.db.conn().prepare_cached("SELECT 1 FROM condemned_blocks WHERE block = ?1")?.exists([id])?)
    }

    fn blocks(&self, batch: BatchId) -> Result<Vec<Multihash>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT m.multihash FROM condemned_blocks c JOIN multihashes m ON m.id = c.block WHERE c.batch = ?1",
        )?;
        let rows = stmt.query_map([batch], |row| row.get::<_, Vec<u8>>(0))?;
        let mut keys = Vec::new();
        for row in rows {
            keys.extend(decode(&row?));
        }
        Ok(keys)
    }

    /// Batches a member's yet to answer for, oldest first, with their
    /// blocks.
    pub fn unasked(&self, peer: &PeerId, limit: usize) -> Result<Vec<(BatchId, Vec<Multihash>)>> {
        let batches: Vec<BatchId> = self.db.conn()
            .prepare_cached(
                "SELECT b.id FROM condemn_batches b
                 WHERE NOT EXISTS (SELECT 1 FROM batch_acks a WHERE a.batch = b.id AND a.peer = ?1)
                 ORDER BY b.since, b.id LIMIT ?2",
            )?
            .query_map(params![peer.to_string(), i64::try_from(limit).unwrap_or(i64::MAX)], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        batches.into_iter().map(|batch| Ok((batch, self.blocks(batch)?))).collect()
    }

    /// A member's answer for a batch: what it keeps is pardoned, and it's
    /// said it keeps none of the rest. Returns how many were pardoned.
    pub fn heard(&self, batch: BatchId, peer: &PeerId, verdict: &Verdict) -> Result<usize> {
        let mut pardoned = 0usize;
        for key in verdict.kept.iter().filter_map(|key| decode(key)) {
            pardoned = pardoned.saturating_add(usize::from(self.pardon(key.as_ref())?));
        }
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO batch_acks (batch, peer) SELECT id, ?2 FROM condemn_batches WHERE id = ?1")?
            .execute(params![batch, peer.to_string()])?;
        Ok(pardoned)
    }

    /// Batches past their grace which every member has answered for, with
    /// when they were condemned and their blocks.
    pub fn due(&self, members: &[PeerId]) -> Result<Vec<(i64, Vec<Multihash>)>> {
        let grace = i64::try_from(self.grace.as_secs()).unwrap_or(i64::MAX);
        let cutoff = now().saturating_sub(grace);
        let rows: Vec<(BatchId, i64, String)> = self.db.conn()
            .prepare_cached(
                "SELECT b.id, b.since, coalesce(group_concat(a.peer, ' '), '') FROM condemn_batches b
                 LEFT JOIN batch_acks a ON a.batch = b.id
                 WHERE b.since <= ?1 GROUP BY b.id",
            )?
            .query_map([cutoff], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut due = Vec::new();
        for (batch, since, acks) in rows {
            let acked: Vec<PeerId> = acks.split(' ').filter_map(|peer| PeerId::from_str(peer).ok()).collect();
            if members.iter().all(|member| acked.contains(member)) {
                due.push((since, self.blocks(batch)?));
            }
        }
        Ok(due)
    }

    /// How many blocks are condemned.
    pub fn count(&self) -> Result<u64> {
        let n: i64 = self.db.conn().prepare_cached("SELECT count(*) FROM condemned_blocks")?.query_row([], |row| row.get(0))?;
        Ok(u64::try_from(n).unwrap_or_default())
    }
}

/// Whether nothing here references a block garbage collection could let
/// go of.
pub fn unreferenced(catalog: &Catalog, key: Key<'_>) -> Result<bool> {
    Ok(catalog.can_collect(key)? && !catalog.referenced(key)?)
}

/// Condemn what of these blocks nothing here references, as of `since` or
/// now, and pardon what's condemned but referenced now.
pub fn judge(catalog: &Catalog, condemned: &Condemned, keys: &[Multihash], since: Option<i64>) -> Result<Report> {
    let mut report = Report::default();
    let mut doomed = Vec::new();
    for key in keys {
        if unreferenced(catalog, key.as_ref())? {
            doomed.push(key.clone());
        } else {
            report.pardoned = report.pardoned.saturating_add(usize::from(condemned.pardon(key.as_ref())?));
        }
    }
    report.condemned = condemned.condemn(&doomed, since)?;
    Ok(report)
}

/// What a member asks of: whichever of the blocks a keep here reaches.
pub fn answer(catalog: &Catalog, condemn: &Condemn) -> Result<Verdict> {
    let mut kept = Vec::new();
    for key in &condemn.blocks {
        if let Some(multihash) = decode(key)
            && catalog.kept_under(multihash.as_ref())?
        {
            kept.push(key.clone());
        }
    }
    Ok(Verdict { kept })
}

/// The request asking a member of these blocks.
pub fn ask(keys: &[Multihash]) -> Condemn {
    Condemn { blocks: keys.iter().map(|key| ByteBuf::from(key.to_bytes())).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Multihash {
        Multihash::try_wrap(0x12, &[n; 32]).expect("multihash")
    }

    #[test]
    fn batches_are_due_once_past_grace_and_every_member_has_answered() {
        let db = Db::memory().expect("db");
        let (a, b) = (PeerId::random(), PeerId::random());
        let condemned = Condemned::open(db.clone()).expect("open").with_grace(Duration::ZERO);
        assert_eq!(condemned.condemn(&[key(1), key(2)], None).expect("condemn"), 2);
        assert_eq!(condemned.condemn(&[key(1)], None).expect("condemn"), 0, "once");
        let asked = condemned.unasked(&a, 10).expect("unasked");
        assert_eq!(asked.len(), 1, "one batch");
        let batch = asked[0].0;

        condemned.heard(batch, &a, &Verdict::default()).expect("heard");
        assert!(condemned.unasked(&a, 10).expect("unasked").is_empty());
        assert!(condemned.due(&[a, b]).expect("due").is_empty(), "b's yet to answer");
        let verdict = Verdict { kept: vec![ByteBuf::from(key(2).to_bytes())] };
        assert_eq!(condemned.heard(batch, &b, &verdict).expect("heard"), 1);
        let due: Vec<Vec<Multihash>> = condemned.due(&[a, b]).expect("due").into_iter().map(|(_, keys)| keys).collect();
        assert_eq!(due, [vec![key(1)]], "b keeps 2, which is pardoned");
        assert!(!condemned.is_condemned(key(2).as_ref()).expect("condemned"));

        // Condemned again, it's a new batch, asked of afresh
        condemned.condemn(&[key(2)], Some(0)).expect("condemn");
        let asked: Vec<Vec<Multihash>> = condemned.unasked(&a, 10).expect("unasked").into_iter().map(|(_, keys)| keys).collect();
        assert_eq!(asked, [vec![key(2)]]);

        // Pardoning a batch's last block lets the batch go
        condemned.pardon(key(1).as_ref()).expect("pardon");
        condemned.pardon(key(2).as_ref()).expect("pardon");
        assert_eq!(condemned.count().expect("count"), 0);
        assert!(condemned.unasked(&a, 10).expect("unasked").is_empty());

        // And nothing's due before its grace is up
        let patient = Condemned::open(db).expect("open");
        patient.condemn(&[key(3)], None).expect("condemn");
        assert!(patient.due(&[]).expect("due").is_empty());
    }
}
