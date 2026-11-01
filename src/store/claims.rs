//! A store specialized for claims, keeping each as rows rather than bytes:
//! a tag is a row, not a blob. So far `Group` claims, which are tags,
//! `Keep`s, and `Tomb`s, which retract them.
//!
//! A claim is admitted only if it's exactly a claim in canonical form (see
//! `claim::Claim::parse`); anything else that's dag-cbor belongs to the
//! IPLD store. Links are rows by interned multihash, as everywhere, with
//! their CID prefixes kept to manifest them, so the rows double as a
//! `RefIndex` and as an index of tags.
//!
//! A dissolved claim (see `claim`) is rows with no multihash of its own:
//! its CID is its bytes, so it's found by what it says. A precipitated one
//! is rows under its multihash, like any block.
//!
//! A claim counts unless a tomb that counts targets it. Once the database
//! has a user, a claim counts only if it's signed, by a `sign` claim,
//! with a key the user has authorized: its root key, or a key a `device`
//! claim certifies, signed by the root and not tombed by a tomb the root
//! signed. A database with no user, such as a test's, takes every claim
//! at its word. Tombed claims keep their rows, dissolved or not, since
//! the tomb may not count for long: its signer can be revoked.

use rusqlite::{OptionalExtension, params};

use crate::block::{Block, IDENTITY};
use crate::cid::{BaseCid, Cid, CidRef, Cidv1, DAG_CBOR_CODEC};
use crate::claim::{Claim, Group, Keep, Set, Tomb};
use crate::model::Link;
use crate::multihash::Multihash;

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Id, Key, Put, RefIndex, Result, Store, query_keys, split_cid};

const NAME: &str = "claims";

/// A key's CID prefix: CIDv1, `libp2p-key`.
const KEY_PREFIX: [u8; 2] = [0x01, 0x72];

/// Whether a claims row, by its alias, is signed by a key the user has
/// authorized, or there's no user to say.
macro_rules! signed {
    ($alias:literal) => {
        concat!(
            "(NOT EXISTS (SELECT 1 FROM users) OR EXISTS (
                SELECT 1 FROM claim_keys sk JOIN claim_targets st ON st.target = sk.key
                JOIN sign_claims sg ON sg.id = st.claim JOIN authorized au ON au.key = sg.by
                WHERE sk.claim = ", $alias, ".id))"
        )
    };
}

/// `LIVE`, of a claims row by another alias than `c`.
pub(super) fn live(alias: &str) -> String {
    LIVE.replace("c.id", &format!("{alias}.id"))
}

/// Whether the claims row `c` counts: it's signed, if it has to be, and
/// no tomb that counts targets it.
pub(super) const LIVE: &str = concat!(
    "(", signed!("c"), " AND NOT EXISTS (
        SELECT 1 FROM claim_keys tk JOIN claim_targets x ON x.target = tk.key JOIN claims k ON k.id = x.claim
        WHERE tk.claim = c.id AND k.kind = 'tomb' AND ", signed!("k"), "))"
);

/// What the user's root key signed, by its alias in `claim_keys`.
macro_rules! rooted {
    ($alias:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM claim_targets rt JOIN sign_claims rs ON rs.id = rt.claim
                WHERE rt.target = ", $alias, ".key AND rs.by IN (SELECT key FROM users))"
        )
    };
}

/// The keys the user has authorized: its root, and devices the root has
/// certified and not revoked.
const AUTHORIZE: &str = concat!(
    "DELETE FROM authorized;
     INSERT OR IGNORE INTO authorized (key) SELECT key FROM users;
     INSERT OR IGNORE INTO authorized (key)
         SELECT t.target FROM claims d JOIN claim_targets t ON t.claim = d.id JOIN claim_keys dk ON dk.claim = d.id
         WHERE d.kind = 'device' AND ", rooted!("dk"), " AND NOT EXISTS (
             SELECT 1 FROM claim_targets tt JOIN claims tb ON tb.id = tt.claim JOIN claim_keys tbk ON tbk.claim = tb.id
             WHERE tt.target = dk.key AND tb.kind = 'tomb' AND ", rooted!("tbk"), "
         );"
);

/// Who signed what, and who may: see the module's documentation.
const AUTH_TABLES: &str = "
         -- The multihash every claim is known by: its own, or for a
         -- dissolved one its identity, which is what claims about it
         -- target.
         CREATE TABLE IF NOT EXISTS claim_keys (
             claim INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             key INTEGER NOT NULL REFERENCES multihashes (id)
         );
         CREATE INDEX IF NOT EXISTS claim_keys_key ON claim_keys (key);
         -- Who signed a claim, when they say, and the signature, checked
         -- before it's put.
         CREATE TABLE IF NOT EXISTS sign_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             by INTEGER NOT NULL REFERENCES multihashes (id),
             at INTEGER NOT NULL,
             sig BLOB NOT NULL
         );
         CREATE INDEX IF NOT EXISTS sign_claims_by ON sign_claims (by);
         -- The user's root key, by its name's multihash: once there is
         -- one, claims count only if a key it authorized signs them.
         CREATE TABLE IF NOT EXISTS users (
             key INTEGER PRIMARY KEY REFERENCES multihashes (id)
         );
         -- The keys the user has authorized, kept up to date as
         -- certificates and revocations arrive.
         CREATE TABLE IF NOT EXISTS authorized (
             key INTEGER PRIMARY KEY
         );";

/// The tables and views, made if they're not there.
fn schema() -> String {
    format!(
        "-- Every claim, of any type. `claim` is a precipitated claim's
         -- multihash, NULL for a dissolved one, which has none; `kind` is
         -- its type, as the claim's own `claim` key says it.
         CREATE TABLE IF NOT EXISTS claims (
             id INTEGER PRIMARY KEY,
             claim INTEGER UNIQUE REFERENCES multihashes (id),
             kind TEXT NOT NULL CHECK (kind IN ('group', 'keep', 'set', 'tomb', 'sign', 'device'))
         );
         -- Every claim's targets, which every type has.
         CREATE TABLE IF NOT EXISTS claim_targets (
             claim INTEGER NOT NULL REFERENCES claims (id) ON DELETE CASCADE,
             target INTEGER NOT NULL REFERENCES multihashes (id),
             prefix BLOB NOT NULL,
             PRIMARY KEY (claim, target, prefix)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS claim_targets_target ON claim_targets (target);
         -- What a set says its anchors are, and as of when.
         CREATE TABLE IF NOT EXISTS set_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             value INTEGER NOT NULL REFERENCES multihashes (id),
             value_prefix BLOB NOT NULL,
             at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS set_claims_value ON set_claims (value);
         -- Which time a keep keeps its targets, if not the first.
         CREATE TABLE IF NOT EXISTS keep_n (
             claim INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             n INTEGER NOT NULL
         );
         -- What's particular to each type; a tomb has nothing but targets.
         CREATE TABLE IF NOT EXISTS group_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             into_ INTEGER NOT NULL REFERENCES multihashes (id),
             into_prefix BLOB NOT NULL
         );
         CREATE INDEX IF NOT EXISTS group_claims_into ON group_claims (into_);
         -- Where a keep's reach stops, if it does short of all its targets
         -- link to.
         CREATE TABLE IF NOT EXISTS keep_beyond (
             claim INTEGER NOT NULL REFERENCES claims (id) ON DELETE CASCADE,
             target INTEGER NOT NULL REFERENCES multihashes (id),
             prefix BLOB NOT NULL,
             PRIMARY KEY (claim, target, prefix)
         ) WITHOUT ROWID;
         -- Every block's tags that still count. A simple tag's name is its
         -- identity digest, after the multihash's code and length varint
         -- (one byte, or two from 128).
         CREATE VIEW IF NOT EXISTS tags (target, tag, name) AS
             SELECT DISTINCT t.target, g.into_,
                 CASE WHEN g.into_prefix = x'0155' AND substr(i.multihash, 1, 1) = x'00' THEN
                     CAST(substr(i.multihash, CASE WHEN length(i.multihash) <= 129 THEN 3 ELSE 4 END) AS TEXT)
                 END
             FROM claim_targets t
             JOIN claims c ON c.id = t.claim
             JOIN group_claims g ON g.id = c.id
             JOIN multihashes i ON i.id = g.into_
             WHERE {LIVE};
         -- What each anchor is now: its latest set that counts, by `at`
         -- and then the value's multihash.
         CREATE VIEW IF NOT EXISTS anchor_values (anchor, value, prefix, claim) AS
             SELECT t.target, s.value, s.value_prefix, c.id FROM set_claims s
             JOIN claims c ON c.id = s.id
             JOIN claim_targets t ON t.claim = c.id
             JOIN multihashes v ON v.id = s.value
             WHERE {LIVE} AND NOT EXISTS (
                 SELECT 1 FROM set_claims s2
                 JOIN claims c2 ON c2.id = s2.id
                 JOIN claim_targets t2 ON t2.claim = c2.id
                 JOIN multihashes v2 ON v2.id = s2.value
                 WHERE t2.target = t.target AND {live2}
                     AND (s2.at > s.at OR (s2.at = s.at AND v2.multihash > v.multihash))
             );",
        live2 = live("c2"),
    )
}

/// Admits canonical claims, keeping them as rows.
pub struct ClaimStore {
    db: Db,
}

/// A link back out of its prefix and multihash.
fn link(prefix: &[u8], multihash: &[u8]) -> Result<Link> {
    Link::decode(&[prefix, multihash].concat())
        .map_err(|e| Error::Invalid { store: NAME, reason: format!("CID: {e:?}") })
}

/// A link's prefix and multihash, for rows.
fn split(link: &Link) -> Result<(Vec<u8>, Multihash)> {
    let bytes = link.to_bytes();
    let (prefix, multihash) = split_cid(&bytes).ok_or_else(|| Error::Invalid { store: NAME, reason: format!("CID {link}") })?;
    Ok((prefix.to_vec(), super::decode_key(NAME, &multihash.to_bytes())?))
}

/// Rows of (prefix, multihash) as links.
fn links(rows: impl Iterator<Item = rusqlite::Result<(Vec<u8>, Vec<u8>)>>) -> Result<Vec<Link>> {
    rows.map(|row| {
        let (prefix, multihash) = row?;
        link(&prefix, &multihash)
    })
    .collect()
}

fn pair(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, Vec<u8>)> {
    Ok((row.get(0)?, row.get(1)?))
}

impl ClaimStore {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(&schema())?;
        db.conn().execute_batch(AUTH_TABLES)?;
        widen_kinds(&db)?;
        let store = Self { db };
        store.key_claims()?;
        Ok(store)
    }

    /// Give every claim its row in `claim_keys`, for claims put before
    /// there was the table.
    fn key_claims(&self) -> Result<()> {
        let rows: Vec<(Id, Option<Id>, String)> = self.db.conn()
            .prepare_cached("SELECT id, claim, kind FROM claims WHERE id NOT IN (SELECT claim FROM claim_keys)")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, claim, kind) in rows {
            let key = match (claim, self.claim(id, &kind)) {
                (Some(key), _) => key,
                (None, Ok(claim)) => self.db.intern(claim.cid().multihash())?,
                // Rows which aren't a whole claim have nothing to be about
                (None, Err(_)) => continue,
            };
            self.db.conn().prepare_cached("INSERT INTO claim_keys (claim, key) VALUES (?1, ?2)")?.execute([id, key])?;
        }
        Ok(())
    }

    /// Recompute the keys the user has authorized.
    fn authorize(&self) -> Result<()> {
        self.db.conn().execute_batch(AUTHORIZE)?;
        Ok(())
    }

    /// The user's root key, if the database has a user.
    pub fn user(&self) -> Result<Option<Link>> {
        let row: Option<Vec<u8>> = self.db.conn()
            .prepare_cached("SELECT m.multihash FROM users u JOIN multihashes m ON m.id = u.key")?
            .query_row([], |row| row.get(0))
            .optional()?;
        row.map(|multihash| link(&KEY_PREFIX, &multihash)).transpose()
    }

    /// Make `root` the user, in place of any other.
    pub fn set_user(&self, root: &Link) -> Result<()> {
        if !crate::keys::is_key(root) {
            return Err(Error::Invalid { store: NAME, reason: format!("{root} isn't a key") });
        }
        self.db.atomically(|| {
            let key = self.db.intern(root.multihash())?;
            self.db.conn().execute("DELETE FROM users", [])?;
            self.db.conn().execute("INSERT INTO users (key) VALUES (?1)", [key])?;
            self.authorize()
        })
    }

    /// Whether a key is the user's root or a device it's authorized.
    pub fn authorized(&self, key: &Link) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM authorized a JOIN multihashes m ON m.id = a.key WHERE m.multihash = ?1")?
            .exists([key.multihash().to_bytes()])?)
    }

    /// Every key a device claim names, and whether it's authorized now.
    pub fn devices(&self) -> Result<Vec<(Link, bool)>> {
        let rows: Vec<(Vec<u8>, Vec<u8>, bool)> = self.db.conn()
            .prepare_cached(
                "SELECT DISTINCT t.prefix, m.multihash, t.target IN (SELECT key FROM authorized) FROM claims d
                 JOIN claim_targets t ON t.claim = d.id JOIN multihashes m ON m.id = t.target
                 WHERE d.kind = 'device' ORDER BY m.multihash",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(prefix, multihash, ok)| Ok((link(&prefix, &multihash)?, ok))).collect()
    }

    /// The CIDs of claims, other than signs and certificates, which a key
    /// signed as of no later than `until`, and which no other authorized
    /// key has signed: what revoking it would leave unsigned, unless it's
    /// signed again.
    pub fn signed_only_by(&self, key: &Link, until: u64) -> Result<Vec<Link>> {
        let until = i64::try_from(until).unwrap_or(i64::MAX);
        self.claims_where(
            "c.kind NOT IN ('sign', 'device')
             AND EXISTS (
                 SELECT 1 FROM claim_targets st JOIN sign_claims sg ON sg.id = st.claim JOIN multihashes b ON b.id = sg.by
                 WHERE st.target = ck.key AND b.multihash = ?1 AND sg.at <= ?2)
             AND NOT EXISTS (
                 SELECT 1 FROM claim_targets st JOIN sign_claims sg ON sg.id = st.claim JOIN multihashes b ON b.id = sg.by
                 JOIN authorized au ON au.key = sg.by
                 WHERE st.target = ck.key AND b.multihash != ?1)",
            &[&key.multihash().to_bytes(), &until],
        )
    }

    /// The CIDs of the claims matching a condition on `c` and its key `ck`.
    fn claims_where(&self, condition: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<Link>> {
        let rows: Vec<(Id, String, Option<Vec<u8>>)> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT c.id, c.kind, m.multihash FROM claims c JOIN claim_keys ck ON ck.claim = c.id
                 LEFT JOIN multihashes m ON m.id = c.claim WHERE {condition} ORDER BY c.id"
            ))?
            .query_map(params, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|(id, kind, multihash)| match multihash {
                Some(multihash) => Ok(crate::cid::AnyCid::V1(Cidv1::new(DAG_CBOR_CODEC, super::decode_key(NAME, &multihash)?))),
                None => Ok(self.claim(id, &kind)?.cid()),
            })
            .collect()
    }

    /// Whether a key has signed a claim, by the claim's CID.
    pub fn signed_by(&self, claim: &Link, key: &Link) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes c JOIN claim_targets st ON st.target = c.id JOIN sign_claims sg ON sg.id = st.claim
                 JOIN multihashes b ON b.id = sg.by WHERE c.multihash = ?1 AND b.multihash = ?2",
            )?
            .exists([claim.multihash().to_bytes(), key.multihash().to_bytes()])?)
    }

    fn sign(&self, id: Id) -> Result<crate::claim::Sign> {
        let (by, at, sig): (Vec<u8>, i64, Vec<u8>) = self.db.conn()
            .prepare_cached("SELECT b.multihash, s.at, s.sig FROM sign_claims s JOIN multihashes b ON b.id = s.by WHERE s.id = ?1")?
            .query_row([id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let [target] = <[Link; 1]>::try_from(self.targets(id)?)
            .map_err(|_| Error::Invalid { store: NAME, reason: "a sign of other than one claim".into() })?;
        Ok(crate::claim::Sign::from_parts(target, link(&KEY_PREFIX, &by)?, u64::try_from(at).unwrap_or_default(), sig))
    }

    fn group(&self, id: Id) -> Result<Group> {
        let (prefix, into) = self.db.conn()
            .prepare_cached("SELECT g.into_prefix, i.multihash FROM group_claims g JOIN multihashes i ON i.id = g.into_ WHERE g.id = ?1")?
            .query_row([id], pair)?;
        Group::new(self.targets(id)?, link(&prefix, &into)?)
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "a group with no targets".into() })
    }

    fn targets(&self, id: Id) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT t.prefix, m.multihash FROM claim_targets t JOIN multihashes m ON m.id = t.target WHERE t.claim = ?1",
        )?;
        links(stmt.query_map([id], pair)?)
    }

    fn keep_n(&self, id: Id) -> Result<u64> {
        let n: Option<i64> = self.db.conn()
            .prepare_cached("SELECT n FROM keep_n WHERE claim = ?1")?
            .query_row([id], |row| row.get(0))
            .optional()?;
        Ok(n.and_then(|n| u64::try_from(n).ok()).unwrap_or_default())
    }

    /// Whether a tomb retracts a claim, by its CID.
    pub fn retracted(&self, claim: &Link) -> Result<bool> {
        self.tombstoned(claim.multihash())
    }

    fn beyond(&self, id: Id) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT b.prefix, m.multihash FROM keep_beyond b JOIN multihashes m ON m.id = b.target WHERE b.claim = ?1",
        )?;
        links(stmt.query_map([id], pair)?)
    }

    /// The claim in a row, by its type.
    fn claim(&self, id: Id, kind: &str) -> Result<Claim> {
        match kind {
            "group" => self.group(id).map(Claim::Group),
            "keep" => Keep::bounded(self.targets(id)?, self.beyond(id)?)
                .map(|keep| Claim::Keep(keep.again(self.keep_n(id).unwrap_or_default())))
                .ok_or_else(|| Error::Invalid { store: NAME, reason: "a keep with no targets".into() }),
            "set" => self.set(id).map(Claim::Set),
            "tomb" => self.tomb(id).map(Claim::Tomb),
            "sign" => self.sign(id).map(Claim::Sign),
            "device" => crate::claim::Device::new(self.targets(id)?)
                .map(Claim::Device)
                .ok_or_else(|| Error::Invalid { store: NAME, reason: "a device claim of no keys".into() }),
            _ => Err(Error::Invalid { store: NAME, reason: format!("a claim of kind {kind}") }),
        }
    }

    fn set(&self, id: Id) -> Result<Set> {
        let (prefix, value, at): (Vec<u8>, Vec<u8>, i64) = self.db.conn()
            .prepare_cached("SELECT s.value_prefix, v.multihash, s.at FROM set_claims s JOIN multihashes v ON v.id = s.value WHERE s.id = ?1")?
            .query_row([id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Set::new(self.targets(id)?, link(&prefix, &value)?, u64::try_from(at).unwrap_or_default())
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "a set with no targets".into() })
    }

    /// What an anchor is now, if any set says.
    pub fn value_of(&self, anchor: Key<'_>) -> Result<Option<Link>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self.db.conn()
            .prepare_cached(
                "SELECT a.prefix, v.multihash FROM multihashes m
                 JOIN anchor_values a ON a.anchor = m.id JOIN multihashes v ON v.id = a.value
                 WHERE m.multihash = ?1",
            )?
            .query_row([anchor.to_bytes()], pair)
            .optional()?;
        row.map(|(prefix, value)| link(&prefix, &value)).transpose()
    }

    /// Every set of an anchor that counts, as (at, value), oldest first.
    pub fn history(&self, anchor: Key<'_>) -> Result<Vec<(u64, Link)>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT s.at, s.value_prefix, v.multihash FROM multihashes m
             JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim
             JOIN set_claims s ON s.id = c.id
             JOIN multihashes v ON v.id = s.value
             WHERE m.multihash = ?1 AND {LIVE}
             ORDER BY s.at, v.multihash"
        ))?;
        let rows = stmt.query_map([anchor.to_bytes()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?)))?;
        rows.map(|row| {
            let (at, prefix, value) = row?;
            Ok((u64::try_from(at).unwrap_or_default(), link(&prefix, &value)?))
        })
        .collect()
    }

    fn tomb(&self, id: Id) -> Result<Tomb> {
        Tomb::new(self.targets(id)?).ok_or_else(|| Error::Invalid { store: NAME, reason: "a tomb with no targets".into() })
    }

    /// A precipitated claim, by its multihash.
    fn load(&self, key: Key<'_>) -> Result<Option<Claim>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(None);
        };
        let row = self.db.conn()
            .prepare_cached("SELECT id, kind FROM claims WHERE claim = ?1")?
            .query_row([id], |r| Ok((r.get::<_, Id>(0)?, r.get::<_, String>(1)?)))
            .optional()?;
        row.map(|(id, kind)| self.claim(id, &kind)).transpose()
    }

    /// The row of a dissolved claim, which has a single target, found by
    /// what it says.
    fn find_dissolved(&self, claim: &Claim) -> Result<Option<Id>> {
        let [target] = claim.target() else {
            return Ok(None);
        };
        let (prefix, multihash) = split(target)?;
        let Some(target) = self.db.lookup(multihash.as_ref())? else {
            return Ok(None);
        };
        Ok(match claim {
            Claim::Group(group) => {
                let (into_prefix, into) = split(group.group())?;
                let Some(into) = self.db.lookup(into.as_ref())? else {
                    return Ok(None);
                };
                self.db.conn()
                    .prepare_cached(
                        "SELECT c.id FROM claims c JOIN group_claims g ON g.id = c.id JOIN claim_targets t ON t.claim = c.id
                         WHERE c.claim IS NULL AND g.into_ = ?1 AND g.into_prefix = ?2 AND t.target = ?3 AND t.prefix = ?4",
                    )?
                    .query_row(params![into, into_prefix, target, prefix], |r| r.get(0))
                    .optional()?
            },
            Claim::Set(set) => {
                let (value_prefix, value) = split(set.value())?;
                let Some(value) = self.db.lookup(value.as_ref())? else {
                    return Ok(None);
                };
                self.db.conn()
                    .prepare_cached(
                        "SELECT c.id FROM claims c JOIN set_claims s ON s.id = c.id JOIN claim_targets t ON t.claim = c.id
                         WHERE c.claim IS NULL AND s.value = ?1 AND s.value_prefix = ?2 AND s.at = ?3 AND t.target = ?4 AND t.prefix = ?5",
                    )?
                    .query_row(params![value, value_prefix, i64::try_from(set.at()).unwrap_or(i64::MAX), target, prefix], |r| r.get(0))
                    .optional()?
            },
            Claim::Sign(_) => None,
            Claim::Keep(_) | Claim::Tomb(_) | Claim::Device(_) => {
                let n = match claim {
                    Claim::Keep(keep) => keep.n(),
                    _ => 0,
                };
                let kind = claim.kind();
                self.db.conn()
                    .prepare_cached(
                        "SELECT c.id FROM claims c JOIN claim_targets t ON t.claim = c.id
                         WHERE c.claim IS NULL AND c.kind = ?3 AND t.target = ?1 AND t.prefix = ?2
                             AND coalesce((SELECT n FROM keep_n k WHERE k.claim = c.id), 0) = ?4",
                    )?
                    .query_row(params![target, prefix, kind, i64::try_from(n).unwrap_or(i64::MAX)], |r| r.get(0))
                    .optional()?
            },
        })
    }

    /// Whether a tomb targets a claim's multihash.
    fn tombstoned(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN claim_targets t ON t.target = m.id JOIN claims c ON c.id = t.claim
                 WHERE m.multihash = ?1 AND c.kind = 'tomb' LIMIT 1",
            )?
            .exists([key.to_bytes()])?)
    }

    /// Every dissolved claim here.
    pub fn dissolved(&self) -> Result<Vec<Claim>> {
        let rows: Vec<(Id, String)> = self.db.conn()
            .prepare_cached("SELECT id, kind FROM claims WHERE claim IS NULL ORDER BY id")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(id, kind)| self.claim(id, &kind)).collect()
    }

    /// The dissolved claim in a row, if it's one.
    pub fn dissolved_row(&self, id: Id) -> Result<Option<Claim>> {
        let kind: Option<String> = self.db.conn()
            .prepare_cached("SELECT kind FROM claims WHERE id = ?1 AND claim IS NULL")?
            .query_row([id], |r| r.get(0))
            .optional()?;
        kind.map(|kind| self.claim(id, &kind)).transpose()
    }

    /// Whether a dissolved claim is here.
    pub fn has_dissolved(&self, claim: &Claim) -> Result<bool> {
        Ok(self.find_dissolved(claim)?.is_some())
    }

    /// Put a claim, under its multihash if it's precipitated.
    fn insert(&self, claim: &Claim, multihash: Option<Key<'_>>) -> Result<()> {
        let id = multihash.map(|key| self.db.intern(key)).transpose()?;
        let conn = self.db.conn();
        conn.prepare_cached("INSERT INTO claims (claim, kind) VALUES (?1, ?2)")?.execute(params![id, claim.kind()])?;
        let row = conn.last_insert_rowid();
        let key = match id {
            Some(id) => id,
            None => self.db.intern(claim.cid().multihash())?,
        };
        conn.prepare_cached("INSERT INTO claim_keys (claim, key) VALUES (?1, ?2)")?.execute([row, key])?;
        if let Claim::Sign(sign) = claim {
            conn.prepare_cached("INSERT INTO sign_claims (id, by, at, sig) VALUES (?1, ?2, ?3, ?4)")?
                .execute(params![row, self.db.intern(sign.by().multihash())?, i64::try_from(sign.at()).unwrap_or(i64::MAX), sign.sig()])?;
        }
        if let Claim::Set(set) = claim {
            let (value_prefix, value) = split(set.value())?;
            conn.prepare_cached("INSERT INTO set_claims (id, value, value_prefix, at) VALUES (?1, ?2, ?3, ?4)")?
                .execute(params![row, self.db.intern(value.as_ref())?, value_prefix, i64::try_from(set.at()).unwrap_or(i64::MAX)])?;
        }
        if let Claim::Group(group) = claim {
            let (into_prefix, into) = split(group.group())?;
            conn.prepare_cached("INSERT INTO group_claims (id, into_, into_prefix) VALUES (?1, ?2, ?3)")?
                .execute(params![row, self.db.intern(into.as_ref())?, into_prefix])?;
        }
        let mut stmt = conn.prepare_cached("INSERT OR IGNORE INTO claim_targets (claim, target, prefix) VALUES (?1, ?2, ?3)")?;
        for target in claim.target() {
            let (prefix, multihash) = split(target)?;
            stmt.execute(params![row, self.db.intern(multihash.as_ref())?, prefix])?;
        }
        if let Claim::Keep(keep) = claim
            && keep.n() > 0
        {
            conn.prepare_cached("INSERT INTO keep_n (claim, n) VALUES (?1, ?2)")?
                .execute(params![row, i64::try_from(keep.n()).unwrap_or(i64::MAX)])?;
        }
        if let Claim::Keep(keep) = claim {
            let mut stmt = conn.prepare_cached("INSERT OR IGNORE INTO keep_beyond (claim, target, prefix) VALUES (?1, ?2, ?3)")?;
            for beyond in keep.beyond() {
                let (prefix, multihash) = split(beyond)?;
                stmt.execute(params![row, self.db.intern(multihash.as_ref())?, prefix])?;
            }
        }
        Ok(())
    }

    /// Whether a keep that counts targets a block, under any CID.
    pub fn kept(&self, target: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(&format!(
                "SELECT 1 FROM multihashes m JOIN claim_targets t ON t.target = m.id JOIN claims c ON c.id = t.claim
                 WHERE m.multihash = ?1 AND c.kind = 'keep' AND {LIVE}"
            ))?
            .exists([target.to_bytes()])?)
    }

    /// Every block a keep that counts targets, under the CIDs it was kept
    /// by.
    pub fn keeps(&self) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT t.prefix, m.multihash FROM claims c
             JOIN claim_targets t ON t.claim = c.id
             JOIN multihashes m ON m.id = t.target
             WHERE c.kind = 'keep' AND {LIVE}
             ORDER BY m.multihash, t.prefix"
        ))?;
        links(stmt.query_map([], pair)?)
    }

    /// The keeps that count of a block, as CIDs.
    pub fn keeping(&self, target: Key<'_>) -> Result<Vec<Link>> {
        let rows: Vec<(Id, Option<Vec<u8>>)> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT DISTINCT c.id, k.multihash FROM multihashes m
                 JOIN claim_targets t ON t.target = m.id
                 JOIN claims c ON c.id = t.claim
                 LEFT JOIN multihashes k ON k.id = c.claim
                 WHERE m.multihash = ?1 AND c.kind = 'keep' AND {LIVE}"
            ))?
            .query_map([target.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|(id, multihash)| match multihash {
                Some(multihash) => Ok(crate::cid::AnyCid::V1(Cidv1::new(DAG_CBOR_CODEC, super::decode_key(NAME, &multihash)?))),
                None => Ok(self.claim(id, "keep")?.cid()),
            })
            .collect()
    }

    /// Every tag on a block that counts, under any CID.
    pub fn tags(&self, target: Key<'_>) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT g.into_prefix, i.multihash FROM multihashes m
             JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim
             JOIN group_claims g ON g.id = c.id
             JOIN multihashes i ON i.id = g.into_
             WHERE m.multihash = ?1 AND {LIVE}
             ORDER BY i.multihash"
        ))?;
        links(stmt.query_map([target.to_bytes()], pair)?)
    }

    /// Every block with a tag that counts, under the CIDs it was tagged by.
    pub fn tagged(&self, tag: Key<'_>) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT t.prefix, m.multihash FROM multihashes i
             JOIN group_claims g ON g.into_ = i.id
             JOIN claims c ON c.id = g.id
             JOIN claim_targets t ON t.claim = c.id
             JOIN multihashes m ON m.id = t.target
             WHERE i.multihash = ?1 AND {LIVE}
             ORDER BY m.multihash, t.prefix"
        ))?;
        links(stmt.query_map([tag.to_bytes()], pair)?)
    }

    /// The claims that count which tag a block with a tag, as CIDs and
    /// what they say.
    pub fn tagging(&self, target: Key<'_>, tag: Key<'_>) -> Result<Vec<(Link, Group)>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT c.id, k.multihash FROM multihashes m
             JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim
             JOIN group_claims g ON g.id = c.id
             JOIN multihashes i ON i.id = g.into_
             LEFT JOIN multihashes k ON k.id = c.claim
             WHERE m.multihash = ?1 AND i.multihash = ?2 AND {LIVE}"
        ))?;
        let rows = stmt.query_map([target.to_bytes(), tag.to_bytes()], |row| Ok((row.get::<_, Id>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)))?;
        rows.map(|row| {
            let (id, multihash) = row?;
            let group = self.group(id)?;
            let cid = match multihash {
                Some(multihash) => crate::cid::AnyCid::V1(Cidv1::new(DAG_CBOR_CODEC, super::decode_key(NAME, &multihash)?)),
                None => Claim::Group(group.clone()).cid(),
            };
            Ok((cid, group))
        })
        .collect()
    }
}

/// Let a claims table made before some kinds of claim hold them: its CHECK
/// constraint, which doesn't touch how rows are stored, is rewritten in
/// place, as `SQLite` documents for such changes.
fn widen_kinds(db: &Db) -> Result<()> {
    const KINDS: &str = "CHECK (kind IN ('group', 'keep', 'set', 'tomb', 'sign', 'device'))";
    let conn = db.conn();
    let sql: String = conn.query_row("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'claims'", [], |row| row.get(0))?;
    if sql.contains(KINDS) {
        return Ok(());
    }
    let Some(start) = sql.find("CHECK (kind IN (") else {
        return Ok(());
    };
    let Some(len) = sql.get(start..).and_then(|rest| rest.find("))")) else {
        return Ok(());
    };
    let Some(old) = sql.get(start..start.saturating_add(len).saturating_add(2)) else {
        return Ok(());
    };
    let version: i64 = conn.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
    conn.execute_batch("PRAGMA writable_schema = ON")?;
    let widened = conn.execute(
        "UPDATE sqlite_schema SET sql = replace(sql, ?1, ?2) WHERE type = 'table' AND name = 'claims'",
        params![old, KINDS],
    );
    let bumped = conn.execute_batch(&format!("PRAGMA schema_version = {}", version.saturating_add(1)));
    conn.execute_batch("PRAGMA writable_schema = OFF")?;
    widened?;
    bumped?;
    Ok(())
}

/// The multihash a claim row is known by: its own if precipitated, its
/// identity if dissolved.
fn key_of(claim: Option<Vec<u8>>, dissolved: impl FnOnce() -> Result<Claim>) -> Result<Multihash> {
    if let Some(bytes) = claim {
        return super::decode_key(NAME, &bytes);
    }
    Ok(Multihash::from(dissolved()?.block().cid().clone()))
}

impl Store for ClaimStore {
    fn name(&self) -> &'static str { NAME }
    fn refs(&self) -> Option<&dyn RefIndex> { Some(self) }
}

impl BlockIndex for ClaimStore {
    /// Precipitated claims; dissolved ones aren't blocks, but their CIDs.
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.load(key)?.is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(
            &self.db,
            NAME,
            "SELECT m.multihash FROM multihashes m WHERE m.id IN (SELECT claim FROM claims)",
        )
    }
}

impl BlockSource for ClaimStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        Ok(self.load(key)?.map(|claim| claim.block().into_data().into_vec()))
    }
}

impl BlockStore for ClaimStore {
    fn put(&self, block: &Block) -> Result<Put> {
        if block.cid().codec() != DAG_CBOR_CODEC {
            return Ok(Put::Declined);
        }
        let Some(claim) = Claim::parse(block.data()) else {
            return Ok(Put::Declined);
        };
        let key = block.cid().multihash();
        let dissolved = block.cid().hashcode() == IDENTITY;
        // An identity CID for a claim that should be hashed isn't one
        if dissolved && !claim.dissolves() {
            return Ok(Put::Declined);
        }
        // A signature that isn't its key's is no claim at all
        if let Claim::Sign(sign) = &claim
            && !sign.verify()
        {
            return Ok(Put::Declined);
        }
        let present = if dissolved { self.has_dissolved(&claim)? } else { self.has(key)? };
        if present {
            return Ok(Put::Stored);
        }
        self.db.atomically(|| {
            self.insert(&claim, (!dissolved).then_some(key))?;
            if matches!(claim, Claim::Sign(_) | Claim::Device(_) | Claim::Tomb(_)) {
                self.authorize()?;
            }
            Ok(Put::Stored)
        })
    }
}

impl RefIndex for ClaimStore {
    /// Claims with a link to the multihash, as a target, what they're
    /// into, or what they set an anchor to.
    fn backrefs(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT c.id, c.kind, k.multihash FROM multihashes m JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim LEFT JOIN multihashes k ON k.id = c.claim WHERE m.multihash = ?1
             UNION
             SELECT c.id, c.kind, k.multihash FROM multihashes m JOIN group_claims g ON g.into_ = m.id
             JOIN claims c ON c.id = g.id LEFT JOIN multihashes k ON k.id = c.claim WHERE m.multihash = ?1
             UNION
             SELECT c.id, c.kind, k.multihash FROM multihashes m JOIN set_claims s ON s.value = m.id
             JOIN claims c ON c.id = s.id LEFT JOIN multihashes k ON k.id = c.claim WHERE m.multihash = ?1",
        )?;
        let rows: Vec<(Id, String, Option<Vec<u8>>)> = stmt
            .query_map([key.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(id, kind, claim)| key_of(claim, || self.claim(id, &kind))).collect()
    }
}
