//! Collecting garbage: letting go of what nothing keeps, everywhere, after
//! a grace period: `/holokeep/condemn/1.0.0`.
//!
//! A node condemns a leaf it holds when it knows of no keep reaching it,
//! by backrefs up to a `Keep` claim. Not knowing of one isn't knowing
//! there's none, so it asks every member whether they keep it, and only
//! lets go once
//!
//! - it's been condemned for the grace period (a week, as long as a
//!   sighting's believed), so what's let go of stops being kept a while
//!   before it's gone, unlike `rm`;
//! - every member has said since it was condemned that it doesn't keep
//!   it: a member away holds collection up until it's back, or is no
//!   longer a member;
//! - and it's still kept by nothing this node knows of.
//!
//! A member that keeps it says so, and that pardons it. So does a keep
//! arriving here, noticed as structure is. A keep added elsewhere after
//! its member said it kept nothing races collection, but a keep is only
//! added by a node holding all of what it keeps, so that copy survives
//! and is replicated again. Condemned blocks aren't audited, nor count as
//! held to a member trimming, so a keeper's copy isn't let go of on the
//! strength of copies about to be collected.
//!
//! Only leaves are collected, as only leaves are trimmed; structure stays.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::{PeerId, StreamProtocol};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::multihash::Multihash;
use crate::store::{Catalog, Db, Key};

use super::mesh::Result;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/condemn/1.0.0");

/// How long a block stays condemned before it may be let go of.
pub const GRACE: Duration = super::durability::TTL;

/// The most blocks asked of in one request.
pub const BATCH: usize = 512;

/// Blocks condemned, to ask a member whether it keeps them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Condemn {
    blocks: Vec<ByteBuf>,
}

impl Condemn {
    pub fn keys(&self) -> Vec<Vec<u8>> {
        self.blocks.iter().map(|key| key.to_vec()).collect()
    }
}

/// Which of the blocks asked of the member keeps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Verdict {
    kept: Vec<ByteBuf>,
}

impl Verdict {
    pub fn kept(&self) -> impl Iterator<Item = &[u8]> {
        self.kept.iter().map(|key| key.as_slice())
    }
}

/// What collecting did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Blocks newly condemned.
    pub condemned: usize,
    /// Blocks pardoned, being kept after all.
    pub pardoned: usize,
    /// Blocks let go of.
    pub collected: usize,
    /// Bytes freed.
    pub freed: u64,
}

fn now() -> i64 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn decode(bytes: &[u8]) -> Option<Multihash> {
    <Multihash>::decode(bytes).ok()
}

/// The blocks condemned here, since when, and which members have said
/// since that they don't keep them.
pub struct Condemned {
    db: Db,
    grace: Duration,
}

impl Condemned {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "-- Blocks this node knows of nothing keeping, and since when.
             CREATE TABLE IF NOT EXISTS condemned (
                 block INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 since INTEGER NOT NULL
             );
             -- Members which have said they don't keep a condemned block,
             -- since it was condemned.
             CREATE TABLE IF NOT EXISTS condemn_acks (
                 block INTEGER NOT NULL REFERENCES condemned (block) ON DELETE CASCADE,
                 peer TEXT NOT NULL,
                 PRIMARY KEY (block, peer)
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

    pub const fn grace(&self) -> Duration {
        self.grace
    }

    /// Condemn a block as of now, unless it already is. Returns whether
    /// it's newly condemned.
    pub fn condemn(&self, key: Key<'_>) -> Result<bool> {
        let id = self.db.intern(key)?;
        Ok(self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO condemned (block, since) VALUES (?1, ?2)")?
            .execute(params![id, now()])? > 0)
    }

    /// Pardon a block, returning whether it was condemned.
    pub fn pardon(&self, key: Key<'_>) -> Result<bool> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(false);
        };
        Ok(self.db.conn().prepare_cached("DELETE FROM condemned WHERE block = ?1")?.execute([id])? > 0)
    }

    pub fn is_condemned(&self, key: Key<'_>) -> Result<bool> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(false);
        };
        Ok(self.db.conn().prepare_cached("SELECT 1 FROM condemned WHERE block = ?1")?.exists([id])?)
    }

    /// A member said it doesn't keep a condemned block.
    pub fn ack(&self, key: Key<'_>, peer: &PeerId) -> Result<()> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(());
        };
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO condemn_acks (block, peer) SELECT block, ?2 FROM condemned WHERE block = ?1")?
            .execute(params![id, peer.to_string()])?;
        Ok(())
    }

    /// Condemned blocks a member's yet to say it doesn't keep.
    pub fn unasked(&self, peer: &PeerId, limit: usize) -> Result<Vec<Multihash>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT m.multihash FROM condemned c JOIN multihashes m ON m.id = c.block
             WHERE NOT EXISTS (SELECT 1 FROM condemn_acks a WHERE a.block = c.block AND a.peer = ?1)
             ORDER BY c.since LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![peer.to_string(), i64::try_from(limit).unwrap_or(i64::MAX)], |row| row.get::<_, Vec<u8>>(0))?;
        let mut keys = Vec::new();
        for row in rows {
            keys.extend(decode(&row?));
        }
        Ok(keys)
    }

    /// Condemned blocks past their grace which every member has said it
    /// doesn't keep.
    pub fn due(&self, members: &[PeerId]) -> Result<Vec<Multihash>> {
        let grace = i64::try_from(self.grace.as_secs()).unwrap_or(i64::MAX);
        let cutoff = now().saturating_sub(grace);
        let rows: Vec<(Vec<u8>, String)> = {
            let mut stmt = self.db.conn().prepare_cached(
                "SELECT m.multihash, coalesce(group_concat(a.peer, ' '), '') FROM condemned c
                 JOIN multihashes m ON m.id = c.block
                 LEFT JOIN condemn_acks a ON a.block = c.block
                 WHERE c.since <= ?1 GROUP BY c.block",
            )?;
            stmt.query_map([cutoff], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?
        };
        let mut due = Vec::new();
        for (key, acks) in rows {
            let acked: Vec<PeerId> = acks.split(' ').filter_map(|peer| PeerId::from_str(peer).ok()).collect();
            if members.iter().all(|member| acked.contains(member)) {
                due.extend(decode(&key));
            }
        }
        Ok(due)
    }

    /// How many blocks are condemned.
    pub fn count(&self) -> Result<u64> {
        let n: i64 = self.db.conn().prepare_cached("SELECT count(*) FROM condemned")?.query_row([], |row| row.get(0))?;
        Ok(u64::try_from(n).unwrap_or_default())
    }
}

/// Condemn what of these blocks nothing here keeps and could be let go
/// of, and pardon what's condemned but kept now. Returns how many of each.
pub fn judge(catalog: &Catalog, condemned: &Condemned, keys: &[Multihash]) -> Result<(usize, usize)> {
    let (mut newly, mut pardoned) = (0usize, 0usize);
    for key in keys {
        if catalog.can_drop(key.as_ref())? && !catalog.kept_under(key.as_ref())? {
            newly = newly.saturating_add(usize::from(condemned.condemn(key.as_ref())?));
        } else {
            pardoned = pardoned.saturating_add(usize::from(condemned.pardon(key.as_ref())?));
        }
    }
    Ok((newly, pardoned))
}

/// What a member asks of: whichever of the blocks are kept here.
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

/// Take in a member's verdict on blocks it was asked of: what it keeps is
/// pardoned, the rest it's said it doesn't. Returns how many were
/// pardoned.
pub fn heard(condemned: &Condemned, peer: &PeerId, asked: &[Vec<u8>], verdict: &Verdict) -> Result<usize> {
    let kept: Vec<&[u8]> = verdict.kept().collect();
    let mut pardoned = 0usize;
    for key in asked {
        let Some(multihash) = decode(key) else {
            continue;
        };
        if kept.contains(&key.as_slice()) {
            pardoned = pardoned.saturating_add(usize::from(condemned.pardon(multihash.as_ref())?));
        } else {
            condemned.ack(multihash.as_ref(), peer)?;
        }
    }
    Ok(pardoned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Multihash {
        Multihash::try_wrap(0x12, &[n; 32]).expect("multihash")
    }

    #[test]
    fn due_once_past_grace_and_every_member_has_said() {
        let db = Db::memory().expect("db");
        let (a, b) = (PeerId::random(), PeerId::random());
        let condemned = Condemned::open(db.clone()).expect("open").with_grace(Duration::ZERO);
        assert!(condemned.condemn(key(1).as_ref()).expect("condemn"));
        assert!(!condemned.condemn(key(1).as_ref()).expect("condemn"), "once");
        condemned.condemn(key(2).as_ref()).expect("condemn");
        assert_eq!(condemned.unasked(&a, 10).expect("unasked").len(), 2);

        // Only what every member's said it doesn't keep
        heard(&condemned, &a, &[key(1).to_bytes(), key(2).to_bytes()], &Verdict::default()).expect("heard");
        assert!(condemned.unasked(&a, 10).expect("unasked").is_empty());
        assert!(condemned.due(&[a, b]).expect("due").is_empty(), "b's yet to say");
        let verdict = Verdict { kept: vec![ByteBuf::from(key(2).to_bytes())] };
        assert_eq!(heard(&condemned, &b, &[key(1).to_bytes(), key(2).to_bytes()], &verdict).expect("heard"), 1);
        assert_eq!(condemned.due(&[a, b]).expect("due"), [key(1)], "b keeps 2, which is pardoned");
        assert!(!condemned.is_condemned(key(2).as_ref()).expect("condemned"));

        // Condemned again, it's asked of afresh
        condemned.condemn(key(2).as_ref()).expect("condemn");
        assert_eq!(condemned.unasked(&a, 10).expect("unasked"), [key(2)]);

        // And not before its grace is up
        let patient = Condemned::open(db).expect("open");
        assert!(patient.due(&[a, b]).expect("due").is_empty());
    }
}
