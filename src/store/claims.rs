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

/// Whether a claims row, by its alias, is signed by a key the user `u`
/// has authorized.
macro_rules! signed_for {
    ($alias:literal) => {
        concat!(
            "EXISTS (
                SELECT 1 FROM claim_keys sk JOIN claim_targets st ON st.target = sk.key
                JOIN sign_claims sg ON sg.id = st.claim JOIN authorized au ON au.key = sg.by AND au.user = u.key
                WHERE sk.claim = ", $alias, ".id)"
        )
    };
}

/// Whether the claims row `c` counts for one of the users the condition
/// on `u` allows: one of their keys signed it and none signed a tomb of
/// it. With no users, every claim counts that no tomb targets.
macro_rules! live {
    ($users:literal) => {
        concat!(
            "(CASE WHEN NOT EXISTS (SELECT 1 FROM users) THEN NOT EXISTS (
                 SELECT 1 FROM claim_keys tk JOIN claim_targets x ON x.target = tk.key JOIN claims k ON k.id = x.claim
                 WHERE tk.claim = c.id AND k.kind = 'tomb')
             ELSE EXISTS (SELECT 1 FROM users u WHERE ", $users, " AND ", signed_for!("c"), " AND NOT EXISTS (
                 SELECT 1 FROM claim_keys tk JOIN claim_targets x ON x.target = tk.key JOIN claims k ON k.id = x.claim
                 WHERE tk.claim = c.id AND k.kind = 'tomb' AND ", signed_for!("k"), ")) END)"
        )
    };
}

/// The acting user's id, by `acting_user()`, the multihash its catalog
/// set: NULL when it acts for everyone.
macro_rules! acting {
    () => {
        "(SELECT id FROM multihashes WHERE multihash = acting_user())"
    };
}

/// Whether the claims row `c` counts for the acting user, or for anyone
/// when it acts for everyone: what it sees.
pub(super) const LIVE: &str = live!("(acting_user() IS NULL OR u.key = (SELECT id FROM multihashes WHERE multihash = acting_user()))");

/// Whether the claims row `c` counts for anyone: what collecting must
/// respect, whoever's acting.
pub(super) const LIVE_ANY: &str = live!("1");

/// Whether the claims row `c` counts for any user but the acting one.
pub(super) const LIVE_OTHERS: &str = live!("u.key IS NOT (SELECT id FROM multihashes WHERE multihash = acting_user())");

/// The keys each user has authorized: itself, and devices it has
/// certified and not revoked.
const AUTHORIZE: &str = "
    DELETE FROM authorized;
    INSERT OR IGNORE INTO authorized (user, key) SELECT key, key FROM users;
    INSERT OR IGNORE INTO authorized (user, key)
        SELECT rs.by, t.target FROM claims d JOIN claim_targets t ON t.claim = d.id JOIN claim_keys dk ON dk.claim = d.id
        JOIN claim_targets rt ON rt.target = dk.key JOIN sign_claims rs ON rs.id = rt.claim
        WHERE d.kind = 'device' AND rs.by IN (SELECT key FROM users) AND NOT EXISTS (
            SELECT 1 FROM claim_targets tt JOIN claims tb ON tb.id = tt.claim JOIN claim_keys tbk ON tbk.claim = tb.id
            JOIN claim_targets rt2 ON rt2.target = tbk.key JOIN sign_claims rs2 ON rs2.id = rt2.claim
            WHERE tt.target = dk.key AND tb.kind = 'tomb' AND rs2.by = rs.by
        );";

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
         -- Who signed claims, when they say, the sign they made before,
         -- by multihash, and the signature, checked before it's put.
         CREATE TABLE IF NOT EXISTS sign_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             by INTEGER NOT NULL REFERENCES multihashes (id),
             at INTEGER NOT NULL,
             sig BLOB NOT NULL,
             prev INTEGER REFERENCES multihashes (id)
         );
         CREATE INDEX IF NOT EXISTS sign_claims_by ON sign_claims (by);
         -- The host's users who keep things here, by uid: the key this
         -- repo signs with for each, and the user's root key, once it has
         -- one. Until then an account's device key is its user.
         CREATE TABLE IF NOT EXISTS accounts (
             uid INTEGER PRIMARY KEY,
             device INTEGER REFERENCES multihashes (id),
             user INTEGER REFERENCES multihashes (id)
         );
         -- Every user claims count for: once there are any, a claim
         -- counts only for a user one of whose keys signs it.
         CREATE VIEW IF NOT EXISTS users (key) AS
             SELECT DISTINCT coalesce(user, device) FROM accounts WHERE coalesce(user, device) IS NOT NULL;
         -- The keys each user has authorized, kept up to date as
         -- certificates and revocations arrive.
         CREATE TABLE IF NOT EXISTS authorized (
             user INTEGER NOT NULL,
             key INTEGER NOT NULL,
             PRIMARY KEY (user, key)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS authorized_key ON authorized (key);";

/// The views, made afresh each time, since what counts changes.
fn views() -> String {
    format!(
        "DROP VIEW IF EXISTS tags;
         DROP VIEW IF EXISTS anchor_values;
         DROP VIEW IF EXISTS anchor_values_any;
         -- Every block's tags that count for the acting user. A simple
         -- tag's name is its identity digest, after the multihash's code
         -- and length varint (one byte, or two from 128).
         CREATE VIEW tags (target, tag, name) AS
             SELECT DISTINCT t.target, g.into_,
                 CASE WHEN g.into_prefix = x'0155' AND substr(i.multihash, 1, 1) = x'00' THEN
                     CAST(substr(i.multihash, CASE WHEN length(i.multihash) <= 129 THEN 3 ELSE 4 END) AS TEXT)
                 END
             FROM claim_targets t
             JOIN claims c ON c.id = t.claim
             JOIN group_claims g ON g.id = c.id
             JOIN multihashes i ON i.id = g.into_
             WHERE {LIVE};
         {acting}
         {any}",
        acting = anchor_values("anchor_values", LIVE),
        any = anchor_values("anchor_values_any", LIVE_ANY),
    )
}

/// A view of what each anchor is now: its latest set that counts, by
/// `at` and then the value's multihash.
fn anchor_values(name: &str, live: &str) -> String {
    let live2 = live.replace("c.id", "c2.id");
    format!(
        "CREATE VIEW {name} (anchor, value, prefix, claim) AS
             SELECT t.target, s.value, s.value_prefix, c.id FROM set_claims s
             JOIN claims c ON c.id = s.id
             JOIN claim_targets t ON t.claim = c.id
             JOIN multihashes v ON v.id = s.value
             WHERE {live} AND NOT EXISTS (
                 SELECT 1 FROM set_claims s2
                 JOIN claims c2 ON c2.id = s2.id
                 JOIN claim_targets t2 ON t2.claim = c2.id
                 JOIN multihashes v2 ON v2.id = s2.value
                 WHERE t2.target = t.target AND {live2}
                     AND (s2.at > s.at OR (s2.at = s.at AND v2.multihash > v.multihash))
             );"
    )
}

/// The tables, made if they're not there.
const SCHEMA: &str =
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
         ) WITHOUT ROWID;";

/// One of a key's signs, as a chain has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub sign: Link,
    /// The sign before it, unless it's the key's first.
    pub prev: Option<Link>,
    /// When it says it was.
    pub at: u64,
    /// How many claims it signs.
    pub claims: usize,
}

/// Admits canonical claims, keeping them as rows.
pub struct ClaimStore {
    db: Db,
    /// The multihash of the user the catalog acts as, which SQL reads as
    /// `acting_user()`: None for everyone.
    acting: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

/// One of the host's users, as this repo knows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    /// The key the repo signs with for it, if it's said anything yet.
    pub device: Option<Link>,
    /// Its user's root key, once it's in a mesh.
    pub user: Option<Link>,
}

impl Account {
    /// Who claims count for when it acts: its user, or until it has one,
    /// its device.
    pub fn acts_for(&self) -> Option<&Link> {
        self.user.as_ref().or(self.device.as_ref())
    }
}

/// A sign's CID, from its multihash: it's never dissolved.
fn sign_cid(multihash: &[u8]) -> Result<Link> {
    link(&[0x01, 0x71], multihash)
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
        let acting = std::sync::Arc::new(std::sync::Mutex::new(None));
        let state = std::sync::Arc::clone(&acting);
        db.conn().create_scalar_function("acting_user", 0, rusqlite::functions::FunctionFlags::SQLITE_UTF8, move |_| {
            Ok(state.lock().ok().and_then(|acting| acting.clone()))
        })?;
        db.conn().execute_batch(SCHEMA)?;
        // From when a repo had one user, in a table, and authorized keys
        // weren't anyone's in particular
        let single: Option<Id> = if db.conn().prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'users'")?.exists([])? {
            let user = db.conn().query_row("SELECT key FROM users", [], |row| row.get(0)).optional()?;
            db.conn().execute_batch("DROP TABLE users")?;
            user
        } else {
            None
        };
        if !db.conn().prepare("SELECT 1 FROM pragma_table_info('authorized') WHERE name = 'user'")?.exists([])? {
            db.conn().execute_batch("DROP TABLE IF EXISTS authorized")?;
        }
        db.conn().execute_batch(AUTH_TABLES)?;
        if let Some(user) = single {
            db.conn().execute(
                "INSERT INTO accounts (uid, user) VALUES (?1, ?2) ON CONFLICT (uid) DO UPDATE SET user = excluded.user",
                params![rustix::process::getuid().as_raw(), user],
            )?;
        }
        db.conn().execute_batch(&views())?;
        let chained = db.conn().prepare("SELECT 1 FROM pragma_table_info('sign_claims') WHERE name = 'prev'")?.exists([])?;
        if !chained {
            db.conn().execute_batch("ALTER TABLE sign_claims ADD COLUMN prev INTEGER REFERENCES multihashes (id)")?;
        }
        db.conn().execute_batch("CREATE INDEX IF NOT EXISTS sign_claims_prev ON sign_claims (prev)")?;
        widen_kinds(&db)?;
        let store = Self { db, acting };
        store.key_claims()?;
        store.authorize()?;
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

    /// Act as a user, so what's seen is what counts for it, or with
    /// None, for everyone.
    pub fn act_as(&self, user: Option<&Link>) {
        if let Ok(mut acting) = self.acting.lock() {
            *acting = user.map(|user| user.multihash().to_bytes());
        }
    }

    /// An account by uid, if it's here.
    pub fn account(&self, uid: u32) -> Result<Option<Account>> {
        type Keys = (Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<Keys> = self.db.conn()
            .prepare_cached(
                "SELECT d.multihash, u.multihash FROM accounts a
                 LEFT JOIN multihashes d ON d.id = a.device LEFT JOIN multihashes u ON u.id = a.user WHERE a.uid = ?1",
            )?
            .query_row([uid], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        row.map(|(device, user)| Ok(Account {
            uid,
            device: device.map(|key| link(&KEY_PREFIX, &key)).transpose()?,
            user: user.map(|key| link(&KEY_PREFIX, &key)).transpose()?,
        }))
        .transpose()
    }

    /// Every account here, by uid.
    pub fn accounts(&self) -> Result<Vec<Account>> {
        let uids: Vec<u32> = self.db.conn()
            .prepare_cached("SELECT uid FROM accounts ORDER BY uid")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        uids.into_iter().filter_map(|uid| self.account(uid).transpose()).collect()
    }

    /// The key an account signs with here.
    pub fn set_device(&self, uid: u32, device: &Link) -> Result<()> {
        self.set_account(uid, "device", device)
    }

    /// Make `root` an account's user, in place of any other: joining a
    /// user's mesh.
    pub fn set_user(&self, uid: u32, root: &Link) -> Result<()> {
        self.set_account(uid, "user", root)
    }

    fn set_account(&self, uid: u32, column: &str, key: &Link) -> Result<()> {
        if !crate::keys::is_key(key) {
            return Err(Error::Invalid { store: NAME, reason: format!("{key} isn't a key") });
        }
        self.db.atomically(|| {
            let key = self.db.intern(key.multihash())?;
            self.db.conn().execute(
                &format!("INSERT INTO accounts (uid, {column}) VALUES (?1, ?2) ON CONFLICT (uid) DO UPDATE SET {column} = excluded.{column}"),
                params![uid, key],
            )?;
            self.authorize()
        })
    }

    /// Whether a claim, by multihash, is another account's to tell, not
    /// the account `uid`'s mesh: a sign by another account's keys here, or
    /// a claim signed, but only by them. What the host's users say through
    /// one node stays theirs.
    pub fn withheld(&self, key: Key<'_>, uid: u32) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "WITH others (key) AS (
                     SELECT device FROM accounts WHERE uid != ?2 AND device IS NOT NULL
                     UNION SELECT user FROM accounts WHERE uid != ?2 AND user IS NOT NULL
                     EXCEPT SELECT device FROM accounts WHERE uid = ?2 AND device IS NOT NULL
                     EXCEPT SELECT user FROM accounts WHERE uid = ?2 AND user IS NOT NULL
                 ),
                 this (id, kind, key) AS (
                     SELECT c.id, c.kind, ck.key FROM claims c JOIN claim_keys ck ON ck.claim = c.id
                     JOIN multihashes m ON m.id = ck.key WHERE m.multihash = ?1
                 )
                 SELECT EXISTS (SELECT 1 FROM this JOIN sign_claims s ON s.id = this.id WHERE s.by IN others)
                     OR EXISTS (
                         SELECT 1 FROM this WHERE this.kind != 'sign'
                         AND EXISTS (SELECT 1 FROM claim_targets st JOIN sign_claims sg ON sg.id = st.claim WHERE st.target = this.key)
                         AND NOT EXISTS (
                             SELECT 1 FROM claim_targets st JOIN sign_claims sg ON sg.id = st.claim
                             WHERE st.target = this.key AND sg.by NOT IN others
                         )
                     )",
            )?
            .query_row(params![key.to_bytes(), uid], |row| row.get(0))?)
    }

    /// Whether the acting user, or with none, anyone, has authorized a
    /// key.
    pub fn authorized(&self, key: &Link) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(concat!(
                "SELECT 1 FROM authorized a JOIN multihashes m ON m.id = a.key
                 WHERE m.multihash = ?1 AND (acting_user() IS NULL OR a.user = ", acting!(), ")",
            ))?
            .exists([key.multihash().to_bytes()])?)
    }

    /// Every key the acting user has certified, or anyone has, with
    /// none, and whether it's authorized now.
    pub fn devices(&self) -> Result<Vec<(Link, bool)>> {
        let rows: Vec<(Vec<u8>, Vec<u8>, bool)> = self.db.conn()
            .prepare_cached(concat!(
                "SELECT DISTINCT t.prefix, m.multihash, t.target IN (
                     SELECT key FROM authorized WHERE acting_user() IS NULL OR user = ", acting!(), "
                 ) FROM claims d
                 JOIN claim_targets t ON t.claim = d.id JOIN multihashes m ON m.id = t.target JOIN claim_keys dk ON dk.claim = d.id
                 WHERE d.kind = 'device' AND EXISTS (
                     SELECT 1 FROM claim_targets rt JOIN sign_claims rs ON rs.id = rt.claim
                     WHERE rt.target = dk.key AND (acting_user() IS NULL OR rs.by = ", acting!(), ")
                 ) ORDER BY m.multihash",
            ))?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(prefix, multihash, ok)| Ok((link(&prefix, &multihash)?, ok))).collect()
    }

    /// The CIDs of claims, other than signs and certificates, which a key
    /// signed in its sign `cutoff` or one before it in its chain, and
    /// which no other authorized key has signed: what revoking it would
    /// leave unsigned, unless it's signed again.
    pub fn signed_only_by(&self, key: &Link, cutoff: &Link) -> Result<Vec<Link>> {
        let chain = self.chain(key, cutoff)?.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        let chain = format!("[{chain}]");
        self.claims_where(
            "c.kind NOT IN ('sign', 'device')
             AND EXISTS (
                 SELECT 1 FROM claim_targets st JOIN claims sc ON sc.id = st.claim
                 WHERE st.target = ck.key AND sc.claim IN (SELECT value FROM json_each(?2)))
             AND NOT EXISTS (
                 SELECT 1 FROM claim_targets st JOIN sign_claims sg ON sg.id = st.claim JOIN multihashes b ON b.id = sg.by
                 JOIN authorized au ON au.key = sg.by
                 WHERE st.target = ck.key AND b.multihash != ?1
                     AND (acting_user() IS NULL OR au.user = (SELECT id FROM multihashes WHERE multihash = acting_user())))",
            &[&key.multihash().to_bytes(), &chain],
        )
    }

    /// A key's sign `cutoff` and those before it in its chain, by their
    /// multihashes' ids.
    fn chain(&self, key: &Link, cutoff: &Link) -> Result<Vec<Id>> {
        let by = self.db.lookup(key.multihash())?;
        let mut current = self.db.lookup(cutoff.multihash())?;
        let mut chain = Vec::new();
        while let Some(id) = current {
            let prev: Option<Option<Id>> = self.db.conn()
                .prepare_cached("SELECT s.prev FROM claims c JOIN sign_claims s ON s.id = c.id WHERE c.claim = ?1 AND s.by = ?2")?
                .query_row(params![id, by], |row| row.get(0))
                .optional()?;
            let Some(prev) = prev else {
                break;
            };
            chain.push(id);
            current = prev;
        }
        if chain.is_empty() {
            return Err(Error::Invalid { store: NAME, reason: format!("{cutoff} isn't one of {key}'s signs") });
        }
        Ok(chain)
    }

    /// The sign a key made last, here: the latest of its signs no other
    /// of its signs follows.
    pub fn head(&self, key: &Link) -> Result<Option<Link>> {
        let row: Option<Vec<u8>> = self.db.conn()
            .prepare_cached(
                "SELECT m.multihash FROM sign_claims s JOIN claims c ON c.id = s.id JOIN multihashes m ON m.id = c.claim
                 JOIN multihashes b ON b.id = s.by
                 WHERE b.multihash = ?1 AND NOT EXISTS (SELECT 1 FROM sign_claims n WHERE n.by = s.by AND n.prev = c.claim)
                 ORDER BY c.id DESC LIMIT 1",
            )?
            .query_row([key.multihash().to_bytes()], |row| row.get(0))
            .optional()?;
        row.map(|multihash| sign_cid(&multihash)).transpose()
    }

    /// Every sign a key made that's here, in the order they came.
    pub fn signs_by(&self, key: &Link) -> Result<Vec<Signed>> {
        type Row = (Vec<u8>, Option<Vec<u8>>, i64, i64);
        let rows: Vec<Row> = self.db.conn()
            .prepare_cached(
                "SELECT m.multihash, p.multihash, s.at, (SELECT count(*) FROM claim_targets t WHERE t.claim = c.id)
                 FROM sign_claims s JOIN claims c ON c.id = s.id JOIN multihashes m ON m.id = c.claim
                 JOIN multihashes b ON b.id = s.by LEFT JOIN multihashes p ON p.id = s.prev
                 WHERE b.multihash = ?1 ORDER BY c.id",
            )?
            .query_map([key.multihash().to_bytes()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|(sign, prev, at, count)| Ok(Signed {
                sign: sign_cid(&sign)?,
                prev: prev.map(|prev| sign_cid(&prev)).transpose()?,
                at: u64::try_from(at).unwrap_or_default(),
                claims: usize::try_from(count).unwrap_or_default(),
            }))
            .collect()
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
        let (by, at, sig, prev): (Vec<u8>, i64, Vec<u8>, Option<Vec<u8>>) = self.db.conn()
            .prepare_cached(
                "SELECT b.multihash, s.at, s.sig, p.multihash FROM sign_claims s JOIN multihashes b ON b.id = s.by
                 LEFT JOIN multihashes p ON p.id = s.prev WHERE s.id = ?1",
            )?
            .query_row([id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
        let prev = prev.map(|prev| sign_cid(&prev)).transpose()?;
        crate::claim::Sign::from_parts(self.targets(id)?, link(&KEY_PREFIX, &by)?, u64::try_from(at).unwrap_or_default(), prev, sig)
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "a sign of no claims".into() })
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
            let prev = sign.prev().map(|prev| self.db.intern(prev.multihash())).transpose()?;
            conn.prepare_cached("INSERT INTO sign_claims (id, by, at, sig, prev) VALUES (?1, ?2, ?3, ?4, ?5)")?
                .execute(params![row, self.db.intern(sign.by().multihash())?, i64::try_from(sign.at()).unwrap_or(i64::MAX), sign.sig(), prev])?;
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
