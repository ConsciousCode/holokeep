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
use super::decode_key;
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
const AUTHORIZED: &str = "
    SELECT key AS user, key FROM users
    UNION SELECT key, key FROM mesh_users
    UNION
        SELECT rs.by, t.target FROM claims d JOIN claim_targets t ON t.claim = d.id JOIN claim_keys dk ON dk.claim = d.id
        JOIN claim_targets rt ON rt.target = dk.key JOIN sign_claims rs ON rs.id = rt.claim
        WHERE d.kind = 'device' AND (rs.by IN (SELECT key FROM users) OR rs.by IN (SELECT key FROM mesh_users)) AND NOT EXISTS (
            SELECT 1 FROM claim_targets tt JOIN claims tb ON tb.id = tt.claim JOIN claim_keys tbk ON tbk.claim = tb.id
            JOIN claim_targets rt2 ON rt2.target = tbk.key JOIN sign_claims rs2 ON rs2.id = rt2.claim
            WHERE tt.target = dk.key AND tb.kind = 'tomb' AND rs2.by = rs.by
        )";

/// The id of the user whose view of anchors is looked at: the one the
/// catalog views (`viewing_owner()`), or else the one it acts for. NULL
/// when it acts for everyone and views no one in particular.
const OWNER: &str = "(SELECT id FROM multihashes WHERE multihash = coalesce(viewing_owner(), acting_user()))";

/// Whether the set `s`, the claims row `c`, on the anchor `t.target`,
/// counts in the view of the user with id `owner`: a set for its signer's
/// own view, signed by them, or one for theirs (`s.owner`), signed by
/// them, a user they've given `/anchor/write` on it, or one whose set they
/// said stands on taking it away; not tombed by them. A visitor, no user
/// of the mesh, signs with its own key, which is itself. With no users,
/// every set counts that no tomb targets.
pub(super) fn in_view(c: &str, s: &str, t: &str, owner: &str) -> String {
    format!(
        "(CASE WHEN NOT EXISTS (SELECT 1 FROM users) THEN NOT EXISTS (
             SELECT 1 FROM claim_keys tk JOIN claim_targets x ON x.target = tk.key JOIN claims k ON k.id = x.claim
             WHERE tk.claim = {c}.id AND k.kind = 'tomb')
         ELSE (EXISTS (
             SELECT 1 FROM claim_keys sk JOIN claim_targets st ON st.target = sk.key JOIN sign_claims sg ON sg.id = st.claim
             WHERE sk.claim = {c}.id AND {s}.owner = {owner} AND (
                 EXISTS (SELECT 1 FROM anchor_access aw WHERE aw.owner = {owner} AND aw.anchor = {t}.target AND aw.user = sg.by AND aw.command = 'write')
                 OR EXISTS (SELECT 1 FROM anchor_stood ao WHERE ao.owner = {owner} AND ao.anchor = {t}.target AND ao.user = sg.by AND ao.claim = sk.key)))
         OR EXISTS (
             SELECT 1 FROM claim_keys sk JOIN claim_targets st ON st.target = sk.key
             JOIN sign_claims sg ON sg.id = st.claim JOIN authorized au ON au.key = sg.by
             WHERE sk.claim = {c}.id AND (
                 ({s}.owner IS NULL AND au.user = {owner})
                 OR ({s}.owner = {owner} AND (
                     au.user = {owner}
                     OR EXISTS (SELECT 1 FROM anchor_access aw WHERE aw.owner = {owner} AND aw.anchor = {t}.target AND aw.user = au.user AND aw.command = 'write')
                     OR EXISTS (SELECT 1 FROM anchor_stood ao WHERE ao.owner = {owner} AND ao.anchor = {t}.target AND ao.user = au.user AND ao.claim = sk.key))))))
             AND NOT EXISTS (
                 SELECT 1 FROM claim_keys tk JOIN claim_targets x ON x.target = tk.key JOIN claims k ON k.id = x.claim
                 JOIN claim_keys kk ON kk.claim = k.id JOIN claim_targets kt ON kt.target = kk.key
                 JOIN sign_claims ks ON ks.id = kt.claim JOIN authorized ka ON ka.key = ks.by AND ka.user = {owner}
                 WHERE tk.claim = {c}.id AND k.kind = 'tomb') END)"
    )
}

/// Whether the set `s`, the claims row `c`, on `t.target`, is shared with
/// the user with id `guest`: it counts in a view of the anchor they may
/// read, or it's for their own view.
pub(super) fn shared_with(c: &str, s: &str, t: &str, guest: &str) -> String {
    format!(
        "({s}.owner = {guest} OR EXISTS (
             SELECT 1 FROM anchor_access ar WHERE ar.anchor = {t}.target AND ar.user = {guest} AND ar.command = 'read'
             AND {counts}))",
        counts = in_view(c, s, t, "ar.owner"),
    )
}

/// Whether the user with id `user` may read `owner`'s view of the anchor
/// `t.target`: it's theirs, or they've been given `/anchor/read` on it.
fn may_read(t: &str, owner: &str, user: &str) -> String {
    format!("({owner} = {user} OR EXISTS (SELECT 1 FROM anchor_access ar WHERE ar.owner = {owner} AND ar.anchor = {t}.target AND ar.user = {user} AND ar.command = 'read'))")
}

/// Whether the set `s`, the claims row `c`, on `t.target`, counts in the
/// view looked at (see `OWNER`), if the acting user may read it: for no
/// one in particular, if it counts for anyone.
fn here(c: &str, s: &str, t: &str) -> String {
    let live = LIVE.replace("c.id", &format!("{c}.id"));
    format!(
        "(CASE WHEN coalesce(viewing_owner(), acting_user()) IS NULL THEN {live}
         ELSE (viewing_owner() IS NULL OR acting_user() IS NULL OR {readable}) AND {counts} END)",
        readable = may_read(t, OWNER, acting!()),
        counts = in_view(c, s, t, OWNER),
    )
}

/// The views below, each `CREATE VIEW` as it's kept, if they're as they are
/// now: they're only made again if not, since that's a write, and makes
/// every connection prepare what it had again.
fn views_current(db: &Db, views: &str) -> Result<bool> {
    for name in ["tags", "anchor_values", "anchor_values_any", "anchor_history", "anchor_history_any"] {
        let start = format!("CREATE VIEW {name} ");
        let wanted = views.find(&start).and_then(|at| views.get(at..)).and_then(|rest| rest.split(';').next());
        let kept: Option<String> = db.conn().query_row("SELECT sql FROM sqlite_schema WHERE type = 'view' AND name = ?1", [name], |row| row.get(0)).optional()?;
        if wanted.is_none() || kept.as_deref() != wanted {
            return Ok(false);
        }
    }
    Ok(true)
}

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
         CREATE INDEX IF NOT EXISTS authorized_key ON authorized (key);
         -- Who may read or write users' views of anchors, as the main
         -- mesh's grants say: worked out from them, and kept here for
         -- counting sets, by `owner`'s view, `user` given `command`.
         CREATE TABLE IF NOT EXISTS anchor_access (
             owner INTEGER NOT NULL,
             anchor INTEGER NOT NULL,
             user INTEGER NOT NULL,
             command TEXT NOT NULL CHECK (command IN ('read', 'write')),
             PRIMARY KEY (owner, anchor, user, command)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS anchor_access_user ON anchor_access (user, anchor);
         -- The main mesh's users, as its grants say, whether or not they've
         -- an account here: whose devices are worked out too, so what they
         -- sign for others' views, and others' views they're let read, can
         -- be told to be theirs.
         CREATE TABLE IF NOT EXISTS mesh_users (
             key INTEGER PRIMARY KEY
         );
         -- Sets, by multihash, that count in `owner`'s view of an anchor
         -- though `user`, who made them, may no longer write it: what a
         -- grant taking write away said stands, and before it.
         CREATE TABLE IF NOT EXISTS anchor_stood (
             owner INTEGER NOT NULL,
             anchor INTEGER NOT NULL,
             user INTEGER NOT NULL,
             claim INTEGER NOT NULL,
             PRIMARY KEY (owner, anchor, user, claim)
         ) WITHOUT ROWID;
         -- Users' views of anchors linked to here (see `claim::view`):
         -- what each is a view of, and whose, as SQL can't work it out.
         CREATE TABLE IF NOT EXISTS anchor_views (
             view INTEGER PRIMARY KEY,
             anchor INTEGER NOT NULL,
             owner INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS anchor_views_anchor ON anchor_views (anchor);";

/// The views, made afresh each time, since what counts changes.
fn views() -> String {
    // Sets for the acting user's view by others: their own are `LIVE`
    let mine = ["(s.owner = ", acting!(), " AND ", &in_view("c", "s", "t", acting!()), ")"].concat();
    format!(
        "DROP VIEW IF EXISTS tags;
         DROP VIEW IF EXISTS anchor_values;
         DROP VIEW IF EXISTS anchor_values_any;
         DROP VIEW IF EXISTS anchor_history;
         DROP VIEW IF EXISTS anchor_history_any;
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
         {values}
         {any}
         -- Everything an anchor's been: what's referenced, as it's the
         -- anchor's history, till the sets saying so are tombed. For the
         -- acting user, what counts in any view of it they may read, and
         -- in each view of it linked to here, as that view.
         CREATE VIEW anchor_history (anchor, value) AS
             SELECT t.target, s.value FROM set_claims s
             JOIN claims c ON c.id = s.id JOIN claim_targets t ON t.claim = c.id
             WHERE {LIVE} OR (acting_user() IS NOT NULL AND ({mine} OR EXISTS (
                 SELECT 1 FROM anchor_access ar WHERE ar.anchor = t.target AND ar.user = {acting} AND ar.command = 'read' AND {read})))
             UNION ALL
             SELECT v.view, s.value FROM anchor_views v
             JOIN claim_targets t ON t.target = v.anchor JOIN claims c ON c.id = t.claim JOIN set_claims s ON s.id = c.id
             WHERE (acting_user() IS NULL OR {readable}) AND {viewed};
         CREATE VIEW anchor_history_any (anchor, value) AS
             SELECT t.target, s.value FROM set_claims s
             JOIN claims c ON c.id = s.id JOIN claim_targets t ON t.claim = c.id
             WHERE {LIVE_ANY}
             UNION ALL
             SELECT v.view, s.value FROM anchor_views v
             JOIN claim_targets t ON t.target = v.anchor JOIN claims c ON c.id = t.claim JOIN set_claims s ON s.id = c.id
             WHERE {viewed};",
        acting = acting!(),
        mine = mine,
        read = in_view("c", "s", "t", "ar.owner"),
        readable = may_read("t", "v.owner", acting!()),
        viewed = in_view("c", "s", "t", "v.owner"),
        values = anchor_values("anchor_values", &here("c", "s", "t"), &here("c2", "s2", "t2")),
        any = anchor_values("anchor_values_any", LIVE_ANY, &LIVE_ANY.replace("c.id", "c2.id")),
    )
}

/// A view of what each anchor is now: its heads, the sets that count which
/// no other that counts replaces, by naming it in its `prev` or, for an
/// older build's set, saying none, by coming after it, by `at` and then the
/// value's multihash. More than one row for an anchor is a fork.
fn anchor_values(name: &str, live: &str, live2: &str) -> String {
    format!(
        "CREATE VIEW {name} (anchor, value, prefix, claim, at) AS
             SELECT t.target, s.value, s.value_prefix, c.id, s.at FROM set_claims s
             JOIN claims c ON c.id = s.id
             JOIN claim_targets t ON t.claim = c.id
             JOIN multihashes v ON v.id = s.value
             WHERE {live} AND NOT EXISTS (
                 SELECT 1 FROM set_prev p
                 JOIN claims c2 ON c2.id = p.claim
                 JOIN set_claims s2 ON s2.id = c2.id
                 JOIN claim_targets t2 ON t2.claim = c2.id
                 WHERE p.prev = (SELECT key FROM claim_keys WHERE claim = c.id) AND t2.target = t.target AND {live2}
             ) AND NOT EXISTS (
                 SELECT 1 FROM set_claims s2
                 JOIN claims c2 ON c2.id = s2.id
                 JOIN claim_targets t2 ON t2.claim = c2.id
                 JOIN multihashes v2 ON v2.id = s2.value
                 WHERE t2.target = t.target AND s2.after = 0 AND {live2}
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
             kind TEXT NOT NULL CHECK (kind IN ('group', 'keep', 'set', 'tomb', 'sign', 'device', 'lost', 'grant', 'serve', 'same'))
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
         -- When a lost claim says its targets couldn't be found.
         CREATE TABLE IF NOT EXISTS lost_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             at INTEGER NOT NULL
         );
         -- The sets a set replaces, by their multihashes, as its `prev`
         -- says; a set saying none has none here, and `after` set.
         CREATE TABLE IF NOT EXISTS set_prev (
             claim INTEGER NOT NULL REFERENCES claims (id) ON DELETE CASCADE,
             prev INTEGER NOT NULL REFERENCES multihashes (id),
             prefix BLOB NOT NULL,
             PRIMARY KEY (claim, prev, prefix)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS set_prev_prev ON set_prev (prev);
         -- The paths a set says it wrote, though they hold what they did.
         CREATE TABLE IF NOT EXISTS set_wrote (
             claim INTEGER NOT NULL REFERENCES claims (id) ON DELETE CASCADE,
             path BLOB NOT NULL,
             PRIMARY KEY (claim, path)
         ) WITHOUT ROWID;
         -- Which time a keep keeps its targets, if not the first.
         CREATE TABLE IF NOT EXISTS keep_n (
             claim INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             n INTEGER NOT NULL
         );
         -- How many failures it takes to lose what a keep keeps, if it
         -- says, rather than leaving it to the mesh.
         CREATE TABLE IF NOT EXISTS keep_copies (
             claim INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             copies INTEGER NOT NULL
         );
         -- A grant, as its canonical bytes: they're read only to work out
         -- who holds what in a mesh, all at once.
         CREATE TABLE IF NOT EXISTS grant_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             data BLOB NOT NULL
         );
         -- Serve claims, whole, with when and whose view each is for,
         -- which is how they count, as sets do.
         CREATE TABLE IF NOT EXISTS serve_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             data BLOB NOT NULL,
             at INTEGER NOT NULL,
             owner INTEGER REFERENCES multihashes (id)
         );
         -- The lens a same claim reads its targets through, NULL for each
         -- codec's data model.
         CREATE TABLE IF NOT EXISTS same_claims (
             id INTEGER PRIMARY KEY REFERENCES claims (id) ON DELETE CASCADE,
             lens TEXT
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
    /// The multihash of the user whose views of anchors are looked at,
    /// which SQL reads as `viewing_owner()`: None for the acting user's.
    viewing: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
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

/// A claim's CID, by its multihash: a CIDv1 of dag-cbor, as every claim
/// is, its multihash an identity one if it's dissolved.
fn claim_link(multihash: &[u8]) -> Result<Link> {
    link(&[0x01, 0x71], multihash)
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
        let viewing = std::sync::Arc::new(std::sync::Mutex::new(None));
        let state = std::sync::Arc::clone(&viewing);
        db.conn().create_scalar_function("viewing_owner", 0, rusqlite::functions::FunctionFlags::SQLITE_UTF8, move |_| {
            Ok(state.lock().ok().and_then(|viewing| viewing.clone()))
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
        if !db.conn().prepare("SELECT 1 FROM pragma_table_info('set_claims') WHERE name = 'after'")?.exists([])? {
            // Whether a set says which it replaces, as `prev`, or is an
            // older build's, replacing every set before it
            db.conn().execute_batch("ALTER TABLE set_claims ADD COLUMN after INTEGER NOT NULL DEFAULT 0")?;
        }
        if !db.conn().prepare("SELECT 1 FROM pragma_table_info('set_claims') WHERE name = 'owner'")?.exists([])? {
            // Whose view of its anchors a set's for, if not its signer's
            db.conn().execute_batch("ALTER TABLE set_claims ADD COLUMN owner INTEGER REFERENCES multihashes (id)")?;
        }
        let views = views();
        if !views_current(&db, &views)? {
            db.conn().execute_batch(&views)?;
        }
        let chained = db.conn().prepare("SELECT 1 FROM pragma_table_info('sign_claims') WHERE name = 'prev'")?.exists([])?;
        if !chained {
            db.conn().execute_batch("ALTER TABLE sign_claims ADD COLUMN prev INTEGER REFERENCES multihashes (id)")?;
        }
        db.conn().execute_batch("CREATE INDEX IF NOT EXISTS sign_claims_prev ON sign_claims (prev)")?;
        widen_kinds(&db)?;
        let store = Self { db, acting, viewing };
        store.key_claims()?;
        if !store.authorized_current()? {
            store.authorize()?;
        }
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

    /// Whether a claim coming might change the keys users have authorized:
    /// see `AUTHORIZED`. That's a certificate, which may be signed already; a
    /// tomb of one; or a user's signature, of either. A device's signature,
    /// which most are, says nothing about who's authorized.
    fn changes_who_is_authorized(&self, claim: &Claim) -> Result<bool> {
        Ok(match claim {
            Claim::Device(_) => true,
            Claim::Sign(sign) => self.db.conn()
                .prepare_cached(
                    "SELECT 1 FROM multihashes m WHERE m.multihash = ?1
                     AND (m.id IN (SELECT key FROM users) OR m.id IN (SELECT key FROM mesh_users))",
                )?
                .exists([sign.by().multihash().to_bytes()])?,
            Claim::Tomb(tomb) => {
                let mut certificate = self.db.conn().prepare_cached(
                    "SELECT 1 FROM multihashes m JOIN claim_keys k ON k.key = m.id JOIN claims c ON c.id = k.claim
                     WHERE m.multihash = ?1 AND c.kind = 'device'",
                )?;
                let mut any = false;
                for target in tomb.target() {
                    any = any || certificate.exists([target.multihash().to_bytes()])?;
                }
                any
            },
            _ => false,
        })
    }

    /// Recompute the keys the user has authorized.
    fn authorize(&self) -> Result<()> {
        self.db.conn().execute_batch(&format!("DELETE FROM authorized; INSERT OR IGNORE INTO authorized (user, key) {AUTHORIZED};"))?;
        Ok(())
    }

    /// Whether the keys kept as authorized are those that are.
    #[cfg(test)]
    pub(crate) fn is_authorized_current(&self) -> Result<bool> {
        self.authorized_current()
    }

    /// Whether the keys kept as authorized are those that are.
    fn authorized_current(&self) -> Result<bool> {
        let differs: bool = self.db.conn().query_row(
            &format!(
                "SELECT EXISTS (SELECT user, key FROM authorized EXCEPT SELECT * FROM ({AUTHORIZED}))
                     OR EXISTS (SELECT * FROM ({AUTHORIZED}) EXCEPT SELECT user, key FROM authorized)"
            ),
            [],
            |row| row.get(0),
        )?;
        Ok(!differs)
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
        // As it's said each time a repo's opened, which needn't write
        if self.account(uid)?.is_some_and(|account| account.device.as_ref() == Some(device)) {
            return Ok(());
        }
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

    /// The claims shared with a user, as `Catalog::as_guest` says, by
    /// multihash: sets and serve claims that count in views of anchors they
    /// may read, and those for their own views; tombs of those on anchors
    /// they may read; and the signs of all those.
    pub fn guest_claims(&self, guest: &Link) -> Result<Vec<Multihash>> {
        let sql = format!(
            "WITH g (id) AS (SELECT id FROM multihashes WHERE multihash = ?1),
             sets (key) AS (
                 SELECT ck.key FROM set_claims s JOIN claims c ON c.id = s.id JOIN claim_targets t ON t.claim = c.id
                 JOIN claim_keys ck ON ck.claim = c.id
                 WHERE {shared}
             ),
             serves (key) AS (
                 SELECT ck.key FROM serve_claims s JOIN claims c ON c.id = s.id JOIN claim_targets t ON t.claim = c.id
                 JOIN claim_keys ck ON ck.claim = c.id
                 WHERE {shared}
             ),
             tombs (key) AS (
                 SELECT kk.key FROM claims k JOIN claim_keys kk ON kk.claim = k.id JOIN claim_targets x ON x.claim = k.id
                 JOIN claim_keys tk ON tk.key = x.target JOIN claims tc ON tc.id = tk.claim AND tc.kind IN ('set', 'serve')
                 JOIN claim_targets t ON t.claim = tc.id
                 WHERE k.kind = 'tomb' AND EXISTS (
                     SELECT 1 FROM anchor_access ar WHERE ar.anchor = t.target AND ar.user = (SELECT id FROM g) AND ar.command = 'read')
             ),
             claimed (key) AS (SELECT key FROM sets UNION SELECT key FROM serves UNION SELECT key FROM tombs)
             SELECT DISTINCT m.multihash FROM (
                 SELECT key FROM claimed
                 UNION SELECT sk.key FROM claimed JOIN claim_targets st ON st.target = claimed.key
                     JOIN sign_claims sg ON sg.id = st.claim JOIN claim_keys sk ON sk.claim = sg.id
             ) x JOIN multihashes m ON m.id = x.key ORDER BY m.multihash",
            shared = shared_with("c", "s", "t", "(SELECT id FROM g)"),
        );
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(&sql)?
            .query_map([guest.multihash().to_bytes()], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        rows.iter().map(|multihash| decode_key(NAME, multihash)).collect()
    }

    /// The users who share a view of an anchor with this one, either way.
    pub fn related(&self, user: &Link) -> Result<Vec<Link>> {
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(
                "WITH u (id) AS (SELECT id FROM multihashes WHERE multihash = ?1)
                 SELECT DISTINCT m.multihash FROM (
                     SELECT user AS who FROM anchor_access WHERE owner = (SELECT id FROM u)
                     UNION SELECT owner FROM anchor_access WHERE user = (SELECT id FROM u)
                 ) r JOIN multihashes m ON m.id = r.who WHERE r.who != (SELECT id FROM u) ORDER BY m.multihash",
            )?
            .query_map([user.multihash().to_bytes()], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|multihash| link(&KEY_PREFIX, &multihash)).collect()
    }

    /// Whether a user has authorized a key: its own, or one it certified
    /// and hasn't revoked, if it's one of the users here or the mesh's.
    pub fn authorizes(&self, user: &Link, key: &Link) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM authorized a JOIN multihashes k ON k.id = a.key JOIN multihashes u ON u.id = a.user
                 WHERE k.multihash = ?1 AND u.multihash = ?2",
            )?
            .exists(params![key.multihash().to_bytes(), user.multihash().to_bytes()])?)
    }

    /// Every key these users have certified, revoked or not.
    pub fn certified_by(&self, users: &[Link]) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT DISTINCT t.prefix, m.multihash FROM claims d
             JOIN claim_targets t ON t.claim = d.id JOIN multihashes m ON m.id = t.target JOIN claim_keys dk ON dk.claim = d.id
             WHERE d.kind = 'device' AND EXISTS (
                 SELECT 1 FROM claim_targets rt JOIN sign_claims rs ON rs.id = rt.claim JOIN multihashes b ON b.id = rs.by
                 WHERE rt.target = dk.key AND b.multihash = ?1
             ) ORDER BY m.multihash",
        )?;
        let mut keys = Vec::new();
        for user in users {
            let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt.query_map([user.multihash().to_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
            for (prefix, multihash) in rows {
                keys.push(link(&prefix, &multihash)?);
            }
        }
        Ok(keys)
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

    /// The CIDs of what it'd cost to revoke a key, signing nothing again:
    /// claims, other than signs and certificates, not retracted, which it's
    /// signed and no other authorized key has.
    pub fn signed_alone_by(&self, key: &Link) -> Result<Vec<Link>> {
        self.claims_where(
            "c.kind NOT IN ('sign', 'device')
             AND EXISTS (
                 SELECT 1 FROM claim_targets st JOIN sign_claims sg ON sg.id = st.claim JOIN multihashes b ON b.id = sg.by
                 WHERE st.target = ck.key AND b.multihash = ?1)
             AND NOT EXISTS (
                 SELECT 1 FROM claim_targets st JOIN sign_claims sg ON sg.id = st.claim JOIN multihashes b ON b.id = sg.by
                 JOIN authorized au ON au.key = sg.by
                 WHERE st.target = ck.key AND b.multihash != ?1
                     AND (acting_user() IS NULL OR au.user = (SELECT id FROM multihashes WHERE multihash = acting_user())))
             AND NOT EXISTS (
                 SELECT 1 FROM claim_targets x JOIN claims k ON k.id = x.claim WHERE x.target = ck.key AND k.kind = 'tomb')",
            &[&key.multihash().to_bytes()],
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

    /// The keys that have signed a claim, by the claim's CID.
    pub fn signers(&self, claim: &Link) -> Result<Vec<Link>> {
        let keys: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(
                "SELECT DISTINCT b.multihash FROM multihashes c JOIN claim_targets st ON st.target = c.id JOIN sign_claims sg ON sg.id = st.claim
                 JOIN multihashes b ON b.id = sg.by WHERE c.multihash = ?1 ORDER BY b.multihash",
            )?
            .query_map([claim.multihash().to_bytes()], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        keys.iter().map(|key| link(&KEY_PREFIX, key)).collect()
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

    fn keep_copies(&self, id: Id) -> Result<Option<u64>> {
        let copies: Option<i64> = self.db.conn()
            .prepare_cached("SELECT copies FROM keep_copies WHERE claim = ?1")?
            .query_row([id], |row| row.get(0))
            .optional()?;
        Ok(copies.and_then(|copies| u64::try_from(copies).ok()))
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
                .map(|keep| Claim::Keep(keep.again(self.keep_n(id).unwrap_or_default()).with_copies(self.keep_copies(id).unwrap_or_default())))
                .ok_or_else(|| Error::Invalid { store: NAME, reason: "a keep with no targets".into() }),
            "set" => self.set(id).map(Claim::Set),
            "tomb" => self.tomb(id).map(Claim::Tomb),
            "sign" => self.sign(id).map(Claim::Sign),
            "device" => crate::claim::Device::new(self.targets(id)?)
                .map(Claim::Device)
                .ok_or_else(|| Error::Invalid { store: NAME, reason: "a device claim of no keys".into() }),
            "lost" => {
                let at: i64 = self.db.conn().prepare_cached("SELECT at FROM lost_claims WHERE id = ?1")?.query_row([id], |row| row.get(0))?;
                crate::claim::Lost::new(self.targets(id)?, u64::try_from(at).unwrap_or_default())
                    .map(Claim::Lost)
                    .ok_or_else(|| Error::Invalid { store: NAME, reason: "a lost claim of nothing".into() })
            },
            "grant" => {
                let data: Vec<u8> = self.db.conn().prepare_cached("SELECT data FROM grant_claims WHERE id = ?1")?.query_row([id], |row| row.get(0))?;
                Claim::parse(&data)
                    .filter(|claim| matches!(claim, Claim::Grant(_)))
                    .ok_or_else(|| Error::Invalid { store: NAME, reason: "a grant that isn't one".into() })
            },
            "serve" => {
                let data: Vec<u8> = self.db.conn().prepare_cached("SELECT data FROM serve_claims WHERE id = ?1")?.query_row([id], |row| row.get(0))?;
                Claim::parse(&data)
                    .filter(|claim| matches!(claim, Claim::Serve(_)))
                    .ok_or_else(|| Error::Invalid { store: NAME, reason: "a serve claim that isn't one".into() })
            },
            "same" => {
                let lens: Option<String> = self.db.conn().prepare_cached("SELECT lens FROM same_claims WHERE id = ?1")?.query_row([id], |row| row.get(0))?;
                crate::claim::Same::new(self.targets(id)?, lens)
                    .map(Claim::Same)
                    .ok_or_else(|| Error::Invalid { store: NAME, reason: "a same claim of one target".into() })
            },
            _ => Err(Error::Invalid { store: NAME, reason: format!("a claim of kind {kind}") }),
        }
    }

    fn set(&self, id: Id) -> Result<Set> {
        let (prefix, value, at, after, owner): (Vec<u8>, Vec<u8>, i64, bool, Option<Vec<u8>>) = self.db.conn()
            .prepare_cached(
                "SELECT s.value_prefix, v.multihash, s.at, s.after, o.multihash FROM set_claims s JOIN multihashes v ON v.id = s.value
                 LEFT JOIN multihashes o ON o.id = s.owner WHERE s.id = ?1",
            )?
            .query_row([id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?;
        let owner = owner.map(|owner| link(&KEY_PREFIX, &owner)).transpose()?;
        let prev = if after { Some(self.set_prev(id)?) } else { None };
        let wrote: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached("SELECT path FROM set_wrote WHERE claim = ?1")?
            .query_map([id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Set::new(self.targets(id)?, link(&prefix, &value)?, u64::try_from(at).unwrap_or_default())
            .map(|set| set.after(prev).wrote(wrote).for_view(owner))
            .ok_or_else(|| Error::Invalid { store: NAME, reason: "a set with no targets".into() })
    }

    fn set_prev(&self, id: Id) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT p.prefix, m.multihash FROM set_prev p JOIN multihashes m ON m.id = p.prev WHERE p.claim = ?1",
        )?;
        links(stmt.query_map([id], pair)?)
    }

    /// Look at a user's view of an anchor, if `anchor` is one (see
    /// `claim::view`), while `f` does, with the anchor it's of; or else at
    /// the acting user's, with the anchor itself.
    fn viewing<T>(&self, anchor: Key<'_>, f: impl FnOnce(Key<'_>) -> Result<T>) -> Result<T> {
        let cid = Link::V1(Cidv1::new(DAG_CBOR_CODEC, super::owned(anchor)?));
        let Some((of, owner)) = crate::claim::viewed(&cid) else {
            return f(anchor);
        };
        let before = self.viewing.lock().ok().and_then(|mut viewing| viewing.replace(owner.multihash().to_bytes()));
        let result = f(of.multihash());
        if let Ok(mut viewing) = self.viewing.lock() {
            *viewing = before;
        }
        result
    }

    /// An anchor's heads, in the view looked at: the sets that count which
    /// no other replaces, as (set, value, at), by `at`, the value's
    /// multihash, and the set's. More than one is a fork, to be merged. A
    /// user's view of an anchor (see `claim::view`) is theirs, if the acting
    /// user may read it, and nothing otherwise.
    pub fn heads(&self, anchor: Key<'_>) -> Result<Vec<(Link, Link, u64)>> {
        self.viewing(anchor, |anchor| self.heads_here(anchor))
    }

    /// Every set of an anchor that counts, as `heads` looks: see `sets_here`.
    pub fn sets(&self, anchor: Key<'_>) -> Result<Vec<super::SetOf>> {
        self.viewing(anchor, |anchor| self.sets_here(anchor))
    }

    /// What each set of an anchor that counts wrote, as `heads` looks.
    pub fn wrote(&self, anchor: Key<'_>) -> Result<Vec<(Link, Vec<u8>)>> {
        self.viewing(anchor, |anchor| self.wrote_here(anchor))
    }

    /// What an anchor is now, as `heads` looks: see `value_of_here`.
    pub fn value_of(&self, anchor: Key<'_>) -> Result<Option<Link>> {
        self.viewing(anchor, |anchor| self.value_of_here(anchor))
    }

    /// Every set of an anchor that counts, as `heads` looks, as (at, value).
    pub fn history(&self, anchor: Key<'_>) -> Result<Vec<(u64, Link)>> {
        self.viewing(anchor, |anchor| self.history_here(anchor))
    }

    /// Whether the acting user may set a user's view of an anchor, if
    /// `anchor` is one: it's theirs, or they've been given `/anchor/write`
    /// on it. Their own view of any anchor, they may.
    pub fn may_write(&self, anchor: &Link) -> Result<bool> {
        let Some((of, owner)) = crate::claim::viewed(anchor) else {
            return Ok(true);
        };
        if self.acting().as_deref().is_none_or(|acting| acting == owner.multihash().to_bytes()) {
            return Ok(true);
        }
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM anchor_access a JOIN multihashes o ON o.id = a.owner JOIN multihashes n ON n.id = a.anchor
                 JOIN multihashes u ON u.id = a.user
                 WHERE o.multihash = ?1 AND n.multihash = ?2 AND u.multihash = acting_user() AND a.command = 'write'",
            )?
            .exists(params![owner.multihash().to_bytes(), of.multihash().to_bytes()])?)
    }

    /// The multihash of the user this acts for, if it acts for one.
    pub fn acting(&self) -> Option<Vec<u8>> {
        self.acting.lock().ok().and_then(|acting| acting.clone())
    }

    /// Whether `user` may read, and may write, `owner`'s view of `anchor`:
    /// both, if it's theirs; otherwise as grants on it say.
    pub fn access(&self, owner: &Link, anchor: &Link, user: &Link) -> Result<(bool, bool)> {
        if owner.multihash() == user.multihash() {
            return Ok((true, true));
        }
        let commands: Vec<String> = self.db.conn()
            .prepare_cached(
                "SELECT DISTINCT a.command FROM anchor_access a JOIN multihashes o ON o.id = a.owner JOIN multihashes n ON n.id = a.anchor
                 JOIN multihashes u ON u.id = a.user
                 WHERE o.multihash = ?1 AND n.multihash = ?2 AND u.multihash = ?3",
            )?
            .query_map(params![owner.multihash().to_bytes(), anchor.multihash().to_bytes(), user.multihash().to_bytes()], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok((commands.iter().any(|command| command == "read"), commands.iter().any(|command| command == "write")))
    }

    /// Whether the acting user may see a user's view of an anchor, if
    /// `anchor` is one: it's theirs, or they've been given `/anchor/read`.
    pub fn may_read(&self, anchor: &Link) -> Result<bool> {
        let Some((of, owner)) = crate::claim::viewed(anchor) else {
            return Ok(true);
        };
        if self.acting().as_deref().is_none_or(|acting| acting == owner.multihash().to_bytes()) {
            return Ok(true);
        }
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM anchor_access a JOIN multihashes o ON o.id = a.owner JOIN multihashes n ON n.id = a.anchor
                 JOIN multihashes u ON u.id = a.user
                 WHERE o.multihash = ?1 AND n.multihash = ?2 AND u.multihash = acting_user() AND a.command = 'read'",
            )?
            .exists(params![owner.multihash().to_bytes(), of.multihash().to_bytes()])?)
    }

    /// Whether a key the user authorized signed a claim.
    pub fn signed_by_user(&self, claim: &Link, user: &Link) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN claim_targets st ON st.target = m.id JOIN sign_claims sg ON sg.id = st.claim
                 JOIN multihashes u ON u.multihash = ?2
                 WHERE m.multihash = ?1 AND (sg.by = u.id OR EXISTS (SELECT 1 FROM authorized au WHERE au.key = sg.by AND au.user = u.id))",
            )?
            .exists(params![claim.multihash().to_bytes(), user.multihash().to_bytes()])?)
    }

    /// Note a view of an anchor linked to here (see `claim::view`), so what
    /// links to it reaches what it is.
    pub fn note_view(&self, view: &Link) -> Result<()> {
        let Some((anchor, owner)) = crate::claim::viewed(view) else {
            return Ok(());
        };
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO anchor_views (view, anchor, owner) VALUES (?1, ?2, ?3)")?
            .execute(params![self.db.intern(view.multihash())?, self.db.intern(anchor.multihash())?, self.db.intern(owner.multihash())?])?;
        Ok(())
    }

    /// Put who may read and write users' views of anchors, as the grants
    /// worked out say, in place of what was: with, for those write's been
    /// taken from, the sets of theirs that stand, and before them.
    pub fn set_access(&self, shares: &[crate::grants::Share], users: &[Link]) -> Result<()> {
        use crate::claim::covers;
        let conn = self.db.conn();
        let before: Vec<Id> = conn.prepare_cached("SELECT key FROM mesh_users ORDER BY key")?.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
        let mut after = users.iter().map(|user| self.db.intern(user.multihash())).collect::<Result<Vec<Id>>>()?;
        after.sort_unstable();
        after.dedup();
        if before != after {
            conn.execute_batch("DELETE FROM mesh_users")?;
            for user in &after {
                conn.prepare_cached("INSERT INTO mesh_users (key) VALUES (?1)")?.execute([user])?;
            }
            self.authorize()?;
        }
        conn.execute_batch("DELETE FROM anchor_access; DELETE FROM anchor_stood;")?;
        for share in shares {
            let (owner, anchor, user) = (self.db.intern(share.owner.multihash())?, self.db.intern(share.anchor.multihash())?, self.db.intern(share.user.multihash())?);
            for (command, name) in [(crate::grants::READ, "read"), (crate::grants::WRITE, "write")] {
                if share.held.iter().any(|held| covers(held, command)) {
                    conn.prepare_cached("INSERT OR IGNORE INTO anchor_access (owner, anchor, user, command) VALUES (?1, ?2, ?3, ?4)")?
                        .execute(params![owner, anchor, user, name])?;
                }
            }
            // What stands, and every set before it
            let mut pending: Vec<Id> = Vec::new();
            for set in &share.stands {
                pending.push(self.db.intern(set.multihash())?);
            }
            let mut seen = std::collections::HashSet::new();
            while let Some(set) = pending.pop() {
                if !seen.insert(set) {
                    continue;
                }
                conn.prepare_cached("INSERT OR IGNORE INTO anchor_stood (owner, anchor, user, claim) VALUES (?1, ?2, ?3, ?4)")?
                    .execute(params![owner, anchor, user, set])?;
                let before: Vec<Id> = conn
                    .prepare_cached("SELECT p.prev FROM claim_keys k JOIN set_prev p ON p.claim = k.claim WHERE k.key = ?1")?
                    .query_map([set], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                pending.extend(before);
            }
        }
        Ok(())
    }

    /// An anchor's heads: the sets that count which no other replaces, as
    /// (set, value, at), by `at`, the value's multihash, and the set's. More than
    /// one is a fork, to be merged.
    ///
    /// Which count is asked once a set, and which are replaced worked out
    /// here, as `anchor_values` says: asking the view whether each set's
    /// replaced asks again whether each that might replace it counts.
    fn heads_here(&self, anchor: Key<'_>) -> Result<Vec<(Link, Link, u64)>> {
        type Row = (Id, Id, Vec<u8>, Vec<u8>, Vec<u8>, i64, bool);
        let counting: Vec<Row> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT c.id, ck.key, k.multihash, s.value_prefix, v.multihash, s.at, s.after FROM multihashes m
                 JOIN claim_targets t ON t.target = m.id
                 JOIN claims c ON c.id = t.claim
                 JOIN set_claims s ON s.id = c.id
                 JOIN multihashes v ON v.id = s.value
                 JOIN claim_keys ck ON ck.claim = c.id
                 JOIN multihashes k ON k.id = ck.key
                 WHERE m.multihash = ?1 AND {}
                 ORDER BY s.at, v.multihash, k.multihash",
                here("c", "s", "t"),
            ))?
            .query_map([anchor.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let ids: std::collections::HashSet<Id> = counting.iter().map(|row| row.0).collect();
        // What the sets that count say they replace, by the replaced's key
        let replaced: std::collections::HashSet<Id> = self.db.conn()
            .prepare_cached(
                "SELECT p.claim, p.prev FROM multihashes m JOIN claim_targets t ON t.target = m.id JOIN set_prev p ON p.claim = t.claim
                 WHERE m.multihash = ?1",
            )?
            .query_map([anchor.to_bytes()], |row| Ok((row.get::<_, Id>(0)?, row.get::<_, Id>(1)?)))?
            .filter_map(|row| row.map(|(claim, prev)| ids.contains(&claim).then_some(prev)).transpose())
            .collect::<rusqlite::Result<_>>()?;
        // An older build's set replaces every set before it, by `at` and
        // then the value's multihash: so whatever's before the latest
        let latest_older = counting.iter().filter(|row| !row.6).map(|row| (row.5, &row.4)).max();
        counting
            .iter()
            .filter(|row| !replaced.contains(&row.1) && latest_older.is_none_or(|latest| latest <= (row.5, &row.4)))
            .map(|(_, _, key, prefix, value, at, _)| Ok((claim_link(key)?, link(prefix, value)?, u64::try_from(*at).unwrap_or_default())))
            .collect()
    }

    /// Every set of an anchor that counts, as (set, value, at, prev), by
    /// `at`, the value's multihash, and the set's: its history, as a graph,
    /// in the same order wherever it is.
    fn sets_here(&self, anchor: Key<'_>) -> Result<Vec<super::SetOf>> {
        let ids: Vec<(Id, Vec<u8>)> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT c.id, k.multihash FROM multihashes m
                 JOIN claim_targets t ON t.target = m.id
                 JOIN claims c ON c.id = t.claim
                 JOIN set_claims s ON s.id = c.id
                 JOIN multihashes v ON v.id = s.value
                 JOIN claim_keys ck ON ck.claim = c.id
                 JOIN multihashes k ON k.id = ck.key
                 WHERE m.multihash = ?1 AND {}
                 ORDER BY s.at, v.multihash, k.multihash",
                here("c", "s", "t"),
            ))?
            .query_map([anchor.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        ids.into_iter()
            .map(|(id, key)| {
                let set = self.set(id)?;
                Ok((claim_link(&key)?, set.value().clone(), set.at(), set.prev().map(<[Link]>::to_vec)))
            })
            .collect()
    }

    /// The paths each set of an anchor that counts says it wrote, by the
    /// set's CID, for those that say any.
    fn wrote_here(&self, anchor: Key<'_>) -> Result<Vec<(Link, Vec<u8>)>> {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT k.multihash, w.path FROM multihashes m
                 JOIN claim_targets t ON t.target = m.id
                 JOIN claims c ON c.id = t.claim
                 JOIN set_claims s ON s.id = c.id
                 JOIN set_wrote w ON w.claim = c.id
                 JOIN claim_keys ck ON ck.claim = c.id
                 JOIN multihashes k ON k.id = ck.key
                 WHERE m.multihash = ?1 AND {}",
                here("c", "s", "t"),
            ))?
            .query_map([anchor.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(key, path)| Ok((claim_link(&key)?, path))).collect()
    }

    /// What an anchor is now, if any set says: its latest head. Where it's
    /// forked, the catalog merges its heads.
    fn value_of_here(&self, anchor: Key<'_>) -> Result<Option<Link>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self.db.conn()
            .prepare_cached(
                "SELECT a.prefix, v.multihash FROM multihashes m
                 JOIN anchor_values a ON a.anchor = m.id JOIN multihashes v ON v.id = a.value
                 WHERE m.multihash = ?1
                 ORDER BY a.at DESC, v.multihash DESC LIMIT 1",
            )?
            .query_row([anchor.to_bytes()], pair)
            .optional()?;
        row.map(|(prefix, value)| link(&prefix, &value)).transpose()
    }

    /// Every anchor some set that counts says is something, with what.
    pub fn anchors(&self) -> Result<Vec<(Link, Link)>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT DISTINCT t.prefix, m.multihash, a.prefix, v.multihash FROM anchor_values a
             JOIN claim_targets t ON t.claim = a.claim AND t.target = a.anchor
             JOIN multihashes m ON m.id = a.anchor JOIN multihashes v ON v.id = a.value
             ORDER BY m.multihash",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?)))?;
        let mut anchors: Vec<(Link, Link)> = Vec::new();
        for row in rows {
            let (anchor_prefix, anchor, prefix, value) = row?;
            let anchor = link(&anchor_prefix, &anchor)?;
            // A forked anchor once, by one of its heads
            if anchors.last().is_none_or(|(last, _)| *last != anchor) {
                anchors.push((anchor, link(&prefix, &value)?));
            }
        }
        Ok(anchors)
    }

    /// Every set of an anchor that counts, as (at, value), oldest first.
    fn history_here(&self, anchor: Key<'_>) -> Result<Vec<(u64, Link)>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT s.at, s.value_prefix, v.multihash FROM multihashes m
             JOIN claim_targets t ON t.target = m.id
             JOIN claims c ON c.id = t.claim
             JOIN set_claims s ON s.id = c.id
             JOIN multihashes v ON v.id = s.value
             WHERE m.multihash = ?1 AND {}
             ORDER BY s.at, v.multihash",
            here("c", "s", "t"),
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
                let owner = match set.owner() {
                    Some(owner) => match self.db.lookup(owner.multihash())? {
                        Some(owner) => Some(owner),
                        None => return Ok(None),
                    },
                    None => None,
                };
                let ids: Vec<Id> = self.db.conn()
                    .prepare_cached(
                        "SELECT c.id FROM claims c JOIN set_claims s ON s.id = c.id JOIN claim_targets t ON t.claim = c.id
                         WHERE c.claim IS NULL AND s.value = ?1 AND s.value_prefix = ?2 AND s.at = ?3 AND t.target = ?4 AND t.prefix = ?5
                             AND s.after = ?6 AND s.owner IS ?7",
                    )?
                    .query_map(params![value, value_prefix, i64::try_from(set.at()).unwrap_or(i64::MAX), target, prefix, set.prev().is_some(), owner], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                // The same sets replaced, too
                let mut same = None;
                for id in ids {
                    let mut prev = self.set_prev(id)?;
                    prev.sort_by_key(Link::to_bytes);
                    if prev.as_slice() == set.prev().unwrap_or_default() {
                        same = Some(id);
                        break;
                    }
                }
                same
            },
            // Never dissolved
            Claim::Sign(_) | Claim::Grant(_) | Claim::Serve(_) | Claim::Same(_) => None,
            Claim::Lost(lost) => self.db.conn()
                .prepare_cached(
                    "SELECT c.id FROM claims c JOIN lost_claims l ON l.id = c.id JOIN claim_targets t ON t.claim = c.id
                     WHERE c.claim IS NULL AND t.target = ?1 AND t.prefix = ?2 AND l.at = ?3",
                )?
                .query_row(params![target, prefix, i64::try_from(lost.at()).unwrap_or(i64::MAX)], |r| r.get(0))
                .optional()?,
            Claim::Keep(_) | Claim::Tomb(_) | Claim::Device(_) => {
                let (n, copies) = match claim {
                    Claim::Keep(keep) => (keep.n(), keep.copies().unwrap_or_default()),
                    _ => (0, 0),
                };
                let kind = claim.kind();
                self.db.conn()
                    .prepare_cached(
                        "SELECT c.id FROM claims c JOIN claim_targets t ON t.claim = c.id
                         WHERE c.claim IS NULL AND c.kind = ?3 AND t.target = ?1 AND t.prefix = ?2
                             AND coalesce((SELECT n FROM keep_n k WHERE k.claim = c.id), 0) = ?4
                             AND coalesce((SELECT copies FROM keep_copies k WHERE k.claim = c.id), 0) = ?5",
                    )?
                    .query_row(params![target, prefix, kind, i64::try_from(n).unwrap_or(i64::MAX), i64::try_from(copies).unwrap_or(i64::MAX)], |r| r.get(0))
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

    /// Every tomb here.
    pub fn tombs(&self) -> Result<Vec<Claim>> {
        let rows: Vec<Id> = self.db.conn()
            .prepare_cached("SELECT id FROM claims WHERE kind = 'tomb' ORDER BY id")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|id| self.claim(id, "tomb")).collect()
    }

    /// Every grant here, by CID, and the keys that signed each.
    pub fn grants(&self) -> Result<Vec<(Link, crate::claim::Grant, Vec<Link>)>> {
        let rows: Vec<(Id, Vec<u8>)> = self.db.conn()
            .prepare_cached("SELECT c.id, m.multihash FROM claims c JOIN multihashes m ON m.id = c.claim WHERE c.kind = 'grant' ORDER BY c.id")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut grants = Vec::new();
        for (id, multihash) in rows {
            let Claim::Grant(grant) = self.claim(id, "grant")? else {
                continue;
            };
            let by: Vec<Vec<u8>> = self.db.conn()
                .prepare_cached(
                    "SELECT DISTINCT b.multihash FROM claim_keys k JOIN claim_targets st ON st.target = k.key
                     JOIN sign_claims sg ON sg.id = st.claim JOIN multihashes b ON b.id = sg.by WHERE k.claim = ?1 ORDER BY b.multihash",
                )?
                .query_map([id], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let by = by.iter().map(|multihash| link(&KEY_PREFIX, multihash)).collect::<Result<_>>()?;
            grants.push((link(&[0x01, 0x71], &multihash)?, grant, by));
        }
        Ok(grants)
    }

    /// The users whose root key is this key, or who've certified it as a
    /// device and not revoked it: whoever it can sign for.
    pub fn users_of(&self, key: &Link) -> Result<Vec<Link>> {
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(
                "SELECT DISTINCT u.multihash FROM multihashes m JOIN claim_targets t ON t.target = m.id
                 JOIN claims d ON d.id = t.claim JOIN claim_keys dk ON dk.claim = d.id
                 JOIN claim_targets rt ON rt.target = dk.key JOIN sign_claims rs ON rs.id = rt.claim JOIN multihashes u ON u.id = rs.by
                 WHERE m.multihash = ?1 AND d.kind = 'device' AND NOT EXISTS (
                     SELECT 1 FROM claim_targets tt JOIN claims tb ON tb.id = tt.claim JOIN claim_keys tbk ON tbk.claim = tb.id
                     JOIN claim_targets rt2 ON rt2.target = tbk.key JOIN sign_claims rs2 ON rs2.id = rt2.claim
                     WHERE tt.target = dk.key AND tb.kind = 'tomb' AND rs2.by = rs.by)
                 ORDER BY u.multihash",
            )?
            .query_map([key.multihash().to_bytes()], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut users = vec![key.clone()];
        for multihash in rows {
            users.push(link(&KEY_PREFIX, &multihash)?);
        }
        Ok(users)
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
            let owner = set.owner().map(|owner| self.db.intern(owner.multihash())).transpose()?;
            conn.prepare_cached("INSERT INTO set_claims (id, value, value_prefix, at, after, owner) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
                .execute(params![row, self.db.intern(value.as_ref())?, value_prefix, i64::try_from(set.at()).unwrap_or(i64::MAX), set.prev().is_some(), owner])?;
            let mut stmt = conn.prepare_cached("INSERT OR IGNORE INTO set_prev (claim, prev, prefix) VALUES (?1, ?2, ?3)")?;
            for prev in set.prev().unwrap_or_default() {
                let (prefix, multihash) = split(prev)?;
                stmt.execute(params![row, self.db.intern(multihash.as_ref())?, prefix])?;
            }
            let mut stmt = conn.prepare_cached("INSERT OR IGNORE INTO set_wrote (claim, path) VALUES (?1, ?2)")?;
            for path in set.written() {
                stmt.execute(params![row, path])?;
            }
        }
        if let Claim::Grant(_) = claim {
            conn.prepare_cached("INSERT INTO grant_claims (id, data) VALUES (?1, ?2)")?.execute(params![row, claim.block().data()])?;
        }
        if let Claim::Serve(serve) = claim {
            let owner = serve.owner().map(|owner| self.db.intern(owner.multihash())).transpose()?;
            conn.prepare_cached("INSERT INTO serve_claims (id, data, at, owner) VALUES (?1, ?2, ?3, ?4)")?
                .execute(params![row, claim.block().data(), i64::try_from(serve.at()).unwrap_or(i64::MAX), owner])?;
        }
        if let Claim::Same(same) = claim {
            conn.prepare_cached("INSERT INTO same_claims (id, lens) VALUES (?1, ?2)")?.execute(params![row, same.lens()])?;
        }
        if let Claim::Lost(lost) = claim {
            conn.prepare_cached("INSERT INTO lost_claims (id, at) VALUES (?1, ?2)")?
                .execute(params![row, i64::try_from(lost.at()).unwrap_or(i64::MAX)])?;
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
        if let Claim::Keep(keep) = claim
            && let Some(copies) = keep.copies()
        {
            conn.prepare_cached("INSERT INTO keep_copies (claim, copies) VALUES (?1, ?2)")?
                .execute(params![row, i64::try_from(copies).unwrap_or(i64::MAX)])?;
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

    /// The latest a lost claim that counts says a block couldn't be found,
    /// whether or not it's been found since.
    pub fn lost(&self, target: Key<'_>) -> Result<Option<u64>> {
        let at: Option<i64> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT max(l.at) FROM multihashes m JOIN claim_targets t ON t.target = m.id
                 JOIN claims c ON c.id = t.claim JOIN lost_claims l ON l.id = c.id
                 WHERE m.multihash = ?1 AND c.kind = 'lost' AND {LIVE}"
            ))?
            .query_row([target.to_bytes()], |row| row.get(0))?;
        Ok(at.map(|at| u64::try_from(at).unwrap_or_default()))
    }

    /// Who serves an anchor, as the latest serve claim that counts in the
    /// view looked at says, as a set of it would count.
    pub fn serving(&self, anchor: Key<'_>) -> Result<Option<crate::claim::Serve>> {
        Ok(self.serves(anchor)?.into_iter().next().map(|(_, serve)| serve))
    }

    /// Every anchor a node serves, as the serve claims that count in the
    /// view looked at say, and how.
    pub fn served_by(&self, node: &[u8]) -> Result<Vec<(Link, crate::claim::Serve)>> {
        let anchors: Vec<(Vec<u8>, Vec<u8>)> = self.db.conn()
            .prepare_cached(
                "SELECT DISTINCT t.prefix, m.multihash FROM claims c JOIN claim_targets t ON t.claim = c.id
                 JOIN multihashes m ON m.id = t.target WHERE c.kind = 'serve' ORDER BY m.multihash",
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut served = Vec::new();
        for (prefix, multihash) in anchors {
            let anchor = link(&prefix, &multihash)?;
            if let Some(serve) = self.serving(anchor.multihash())?.filter(|serve| serve.node() == node) {
                served.push((anchor, serve));
            }
        }
        Ok(served)
    }

    /// The serve claims that count of an anchor, in the view looked at, by
    /// their CIDs, latest first: what's withdrawn by a tomb.
    pub fn serves(&self, anchor: Key<'_>) -> Result<Vec<(Link, crate::claim::Serve)>> {
        self.viewing(anchor, |anchor| self.serves_here(anchor))
    }

    fn serves_here(&self, anchor: Key<'_>) -> Result<Vec<(Link, crate::claim::Serve)>> {
        let anchor = super::owned(anchor)?.to_bytes();
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT s.data FROM claim_targets t JOIN multihashes m ON m.id = t.target
                 JOIN claims c ON c.id = t.claim JOIN serve_claims s ON s.id = c.id
                 WHERE m.multihash = ?1 AND c.kind = 'serve' AND {here}
                 ORDER BY s.at DESC, c.id DESC",
                here = here("c", "s", "t"),
            ))?
            .query_map([anchor], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|data| match Claim::parse(&data) {
                Some(claim @ Claim::Serve(_)) => {
                    let cid = claim.cid();
                    let Claim::Serve(serve) = claim else { return None };
                    Some((cid, serve))
                },
                _ => None,
            })
            .collect())
    }

    /// The lenses that same claims that count of a block read it through,
    /// by its CID, as it's named in them: none for each codec's data model.
    pub fn same_lenses(&self, target: &Link) -> Result<Vec<Option<String>>> {
        let (prefix, multihash) = split(target)?;
        Ok(self.db.conn()
            .prepare_cached(&format!(
                "SELECT DISTINCT s.lens FROM multihashes m JOIN claim_targets t ON t.target = m.id
                 JOIN claims c ON c.id = t.claim JOIN same_claims s ON s.id = c.id
                 WHERE m.multihash = ?1 AND t.prefix = ?2 AND c.kind = 'same' AND {LIVE}
                 ORDER BY s.lens"
            ))?
            .query_map(params![multihash.to_bytes(), prefix], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// What same claims that count say a block is the same as, read through
    /// `lens`, by CID: all that's the same as it, or as what is, and so on,
    /// but itself.
    pub fn same_as(&self, target: &Link, lens: Option<&str>) -> Result<Vec<Link>> {
        let (prefix, multihash) = split(target)?;
        // By CID, not multihash: one multihash is different things to
        // different codecs
        let rows = self.db.conn()
            .prepare_cached(&format!(
                "WITH RECURSIVE class (target, prefix) AS (
                     SELECT id, ?2 FROM multihashes WHERE multihash = ?1
                     UNION SELECT t2.target, t2.prefix FROM class
                     JOIN claim_targets t ON t.target = class.target AND t.prefix = class.prefix
                     JOIN claims c ON c.id = t.claim JOIN same_claims s ON s.id = c.id
                     JOIN claim_targets t2 ON t2.claim = c.id
                     WHERE c.kind = 'same' AND s.lens IS ?3 AND {LIVE}
                 )
                 SELECT class.prefix, m.multihash FROM class JOIN multihashes m ON m.id = class.target
                 ORDER BY m.multihash, class.prefix"
            ))?
            .query_map(params![multihash.to_bytes(), prefix, lens], pair)?
            .collect::<Vec<_>>();
        Ok(links(rows.into_iter())?.into_iter().filter(|link| link != target).collect())
    }

    /// The same claims that count which say, through `lens`, that `a` and
    /// `b` are the same, by their CIDs: what's taken back by a tomb.
    pub fn saying_same(&self, a: &Link, b: &Link, lens: Option<&str>) -> Result<Vec<Link>> {
        let ((a_prefix, a), (b_prefix, b)) = (split(a)?, split(b)?);
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT k.multihash FROM claims c JOIN same_claims s ON s.id = c.id
                 JOIN claim_targets ta ON ta.claim = c.id JOIN multihashes ma ON ma.id = ta.target
                 JOIN claim_targets tb ON tb.claim = c.id JOIN multihashes mb ON mb.id = tb.target
                 JOIN multihashes k ON k.id = c.claim
                 WHERE ma.multihash = ?1 AND ta.prefix = ?2 AND mb.multihash = ?3 AND tb.prefix = ?4
                     AND c.kind = 'same' AND s.lens IS ?5 AND {LIVE}"
            ))?
            .query_map(params![a.to_bytes(), a_prefix, b.to_bytes(), b_prefix, lens], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        rows.iter().map(|multihash| claim_link(multihash)).collect()
    }

    /// The same claims that count which name `target` itself, read through
    /// `lens`, by their CIDs, at most `limit` of them.
    pub fn saying_same_of(&self, target: &Link, lens: Option<&str>, limit: usize) -> Result<Vec<Link>> {
        let (prefix, multihash) = split(target)?;
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT k.multihash FROM multihashes m JOIN claim_targets t ON t.target = m.id
                 JOIN claims c ON c.id = t.claim JOIN same_claims s ON s.id = c.id
                 JOIN multihashes k ON k.id = c.claim
                 WHERE m.multihash = ?1 AND t.prefix = ?2 AND c.kind = 'same' AND s.lens IS ?3 AND {LIVE}
                 ORDER BY c.id LIMIT ?4"
            ))?
            .query_map(params![multihash.to_bytes(), prefix, lens, i64::try_from(limit).unwrap_or(i64::MAX)], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        rows.iter().map(|multihash| claim_link(multihash)).collect()
    }

    /// What lost claims that count say, as (block, when), the latest of each.
    pub fn all_lost(&self) -> Result<Vec<(Link, u64)>> {
        let rows: Vec<(Vec<u8>, Vec<u8>, i64)> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT t.prefix, m.multihash, max(l.at) FROM claims c
                 JOIN lost_claims l ON l.id = c.id
                 JOIN claim_targets t ON t.claim = c.id JOIN multihashes m ON m.id = t.target
                 WHERE c.kind = 'lost' AND {LIVE}
                 GROUP BY t.target ORDER BY m.multihash"
            ))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(prefix, multihash, at)| Ok((link(&prefix, &multihash)?, u64::try_from(at).unwrap_or_default()))).collect()
    }

    /// Up to `limit` blocks lost claims put after the row `cursor` are about,
    /// counting or not, and the row to go on from.
    pub fn lost_since(&self, cursor: i64, limit: usize) -> Result<(Vec<Multihash>, i64)> {
        let rows: Vec<(i64, Vec<u8>)> = self.db.conn()
            .prepare_cached(
                "SELECT l.id, m.multihash FROM lost_claims l
                 JOIN claim_targets t ON t.claim = l.id JOIN multihashes m ON m.id = t.target
                 WHERE l.id > ?1 ORDER BY l.id LIMIT ?2",
            )?
            .query_map(params![cursor, i64::try_from(limit).unwrap_or(i64::MAX)], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let latest = rows.last().map_or(cursor, |(id, _)| *id);
        let keys = rows.iter().map(|(_, key)| decode_key(NAME, key)).collect::<Result<_>>()?;
        Ok((keys, latest))
    }

    /// The lost claims that count of a block, by their CIDs.
    pub fn losing(&self, target: Key<'_>) -> Result<Vec<Link>> {
        let rows: Vec<(Id, String)> = self.db.conn()
            .prepare_cached(&format!(
                "SELECT DISTINCT c.id, c.kind FROM multihashes m JOIN claim_targets t ON t.target = m.id JOIN claims c ON c.id = t.claim
                 WHERE m.multihash = ?1 AND c.kind = 'lost' AND {LIVE}"
            ))?
            .query_map([target.to_bytes()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter().map(|(id, kind)| Ok(self.claim(id, &kind)?.cid())).collect()
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

    /// Every tag that counts on anything.
    pub fn all_tags(&self) -> Result<Vec<Link>> {
        let mut stmt = self.db.conn().prepare_cached(&format!(
            "SELECT DISTINCT g.into_prefix, i.multihash FROM claims c
             JOIN group_claims g ON g.id = c.id
             JOIN multihashes i ON i.id = g.into_
             WHERE {LIVE}
             ORDER BY i.multihash"
        ))?;
        links(stmt.query_map([], pair)?)
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
    const KINDS: &str = "CHECK (kind IN ('group', 'keep', 'set', 'tomb', 'sign', 'device', 'lost', 'grant', 'serve', 'same'))";
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
            // Before it's in: a tomb takes a dissolved certificate with it
            let authorizing = self.changes_who_is_authorized(&claim)?;
            self.insert(&claim, (!dissolved).then_some(key))?;
            if authorizing {
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
