//! Blockstores: where blocks are kept and how they're represented.
//!
//! Stores are specialized. Each may restrict which blocks it admits and
//! represent them however suits their structure, so long as it can
//! manifest every block it admits byte-for-byte. A generic store accepts
//! anything; a specialized one declines what it can't represent. The
//! `Catalog` offers each block to its stores from most to least
//! specialized and remembers which one took it.
//!
//! Capabilities are separate traits so a store implements only what it
//! can: a read-only archive has no `BlockStore`, an index has no blocks.
//! Every store is keyed by multihash, the block's identity; the CID's
//! version and codec are a claim about how to read it.
//!
//! Within one database, multihashes are interned: `multihashes` holds each
//! one once, and every other table refers to it by integer id, whether or
//! not the block itself is present. Ids mean nothing outside their
//! database, so they never cross the traits, which take multihash bytes;
//! each database pays for its own copy, and the multihash is the
//! interchange format between them.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::{Connection, OptionalExtension, params};

use crate::block::{Block, IDENTITY};
use crate::claim::{Claim, Group, Tomb};
use crate::cid::{BaseCid, Cid, CidRef, CidVersion, Cidv1};
use crate::dag::{BlockSink, DagLink, Provenance};
use crate::model::Link;
use crate::multihash::Multihash;

mod claims;
mod compact;
mod delta;
mod git;
mod ipld;
mod merge;
mod offset;
pub mod overlay;
mod raw;
mod shards;
mod unixfs;
mod volume;

pub use claims::{Account, ClaimStore, Signed};
pub use delta::DeltaStore;
pub use ipld::IpldStore;
pub use offset::{ExternalFile, OffsetStore};
use offset::{Fingerprint, Location, Whole};
pub use raw::RawStore;
pub use shards::ShardStore;
pub use unixfs::UnixfsStore;
pub use compact::{Compact, Compaction, Outcome, Space};
pub use git::GitDeltas;
pub use volume::{Volume, tolerance};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),

    #[error(transparent)]
    Io(#[from] io::Error),

    /// A store returned bytes which don't hash to the block's CID.
    #[error("block {0} is corrupt: its bytes don't match its CID")]
    Corrupt(String),

    /// No store would take a block.
    #[error("no store admits block {0}")]
    Unplaced(String),

    /// The index names a store which isn't configured.
    #[error("block is in store {0:?}, which isn't configured")]
    UnknownStore(String),

    /// A block is kept as part of a file which has changed or gone.
    #[error("block is kept in {}, which has changed since it was added", .0.display())]
    Stale(PathBuf),

    /// A block is kept as part of a file in the repo which is gone.
    #[error("block is kept in {}, which is missing", .0.display())]
    Missing(PathBuf),

    /// A volume can't be added as asked.
    #[error("{0}")]
    Volume(String),

    /// A block is only on volumes which aren't attached.
    #[error("block {0} is only on volumes which aren't attached")]
    Unattached(String),

    /// Claims were asked for of a router with no claim store.
    #[error("this repo keeps no claims")]
    NoClaims,

    /// The user, or its root key, isn't as asked.
    #[error("{0}")]
    User(String),

    /// A multihash too long to keep; see `MAX_DIGEST_LEN`.
    #[error("multihash digest of {0} bytes is too long to keep")]
    Oversized(usize),

    /// Data in a store which can't be right.
    #[error("invalid data in store {store}: {reason}")]
    Invalid { store: &'static str, reason: String },
}

impl Error {
    /// Whether it failed only since something else was writing: it's worth
    /// trying again later.
    pub const fn is_busy(&self) -> bool {
        matches!(self, Self::Db(e) if is_busy(e))
    }
}

/// Whether a database failed only since something else was writing.
pub const fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(failure, _) if matches!(failure.code, rusqlite::ErrorCode::DatabaseBusy))
}

pub type Result<T> = std::result::Result<T, Error>;

/// What blocks are keyed by: their multihash.
pub type Key<'a> = Multihash<&'a [u8]>;

/// An interned multihash, meaningful only within its database.
pub type Id = i64;

/// The longest digest a database will intern. IPIP-0512 caps identity
/// multihashes at 128 bytes, and no real hash function comes close.
pub const MAX_DIGEST_LEN: usize = 128;

/// What a store did with a block it was offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    /// It has the block now, whether or not it did before.
    Stored,
    /// It can't represent this block; offer it elsewhere.
    Declined,
}

/// Knows which blocks a store has.
pub trait BlockIndex {
    fn has(&self, key: Key<'_>) -> Result<bool>;

    /// Every block's multihash.
    fn keys(&self) -> Result<Vec<Multihash>>;
}

/// Provides blocks' bytes.
pub trait BlockSource {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>>;
}

/// Accepts blocks, or declines them.
pub trait BlockStore {
    fn put(&self, block: &Block) -> Result<Put>;

    /// Put a block along with where its bytes came from, for stores which
    /// can make use of it.
    fn put_from(&self, block: &Block, provenance: Provenance<'_>) -> Result<Put> {
        let _ = provenance;
        self.put(block)
    }
}

/// Knows which blocks link to a block.
pub trait RefIndex {
    /// The multihashes of blocks with a link to this multihash, under any
    /// CID.
    fn backrefs(&self, key: Key<'_>) -> Result<Vec<Multihash>>;
}

/// Blocks a store gained and lost without being told, such as by another
/// node writing to a shared volume.
#[derive(Debug, Default)]
pub struct Changes {
    pub added: Vec<Multihash>,
    pub removed: Vec<Multihash>,
}

/// A store a `Catalog` can place blocks in.
pub trait Store: BlockIndex + BlockSource + BlockStore {
    /// A stable name for its form, recorded in the catalog's index.
    fn name(&self) -> &'static str;

    /// The store's own index of its blocks' links, if it keeps one. A
    /// catalog indexes the links of blocks in stores which don't.
    fn refs(&self) -> Option<&dyn RefIndex> {
        None
    }

    /// Bring whatever the store caches up to date with what it holds,
    /// cheaply, returning what changed. Only stores others can write to
    /// change without being told.
    fn catch_up(&self) -> Result<Changes> {
        Ok(Changes::default())
    }

    /// Rebuild whatever the store caches from what it holds, however long
    /// that takes.
    fn rescan(&self) -> Result<()> {
        Ok(())
    }

    /// Whether a block's kept as a delta on another.
    fn is_delta(&self, key: Key<'_>) -> Result<bool> {
        let _ = key;
        Ok(false)
    }

    /// Let a block go, returning how many bytes that frees, or None if
    /// this store can't let it go by itself, such as a range of a file
    /// other blocks are ranges of too.
    fn remove(&self, key: Key<'_>) -> Result<Option<u64>> {
        let _ = key;
        Ok(None)
    }
}

//--------------//
//-[ Database ]-//
//--------------//

/// How long a write waits for another writer, by default, before failing
/// as busy.
pub const WRITER_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a big import holds the write lock before letting others have it.
/// A second, as that's how long the daemon waits, so it gets its turn.
const BREATHE_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a big import leaves the write lock free. A writer waiting for it
/// looks again every 100 ms at the slowest, as `SQLite` waits.
const BREATH: std::time::Duration = std::time::Duration::from_millis(110);

/// How long a big import that's taken a breath waits for the write lock back,
/// as after all that work it's not to fail for another's being big too.
const BREATHING_WAIT: std::time::Duration = std::time::Duration::from_mins(10);

/// How often what's lost is asked for anyway, as it's read: a copy may have
/// turned up where no one's said so.
const ASK_FOR_LOST: std::time::Duration = std::time::Duration::from_hours(1);

/// How long catching up as a catalog's opened waits for another writer,
/// before leaving it for next time.
const CATCH_UP_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// A shared `SQLite` connection, so stores in the same file can share a
/// transaction.
#[derive(Clone)]
pub struct Db(Rc<Connection>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    /// A private in-memory database, for tests.
    #[cfg(test)]
    pub fn memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             -- Every multihash the database knows of, present or not. The
             -- default foreign key action (NO ACTION) means one can't be
             -- deleted while anything refers to it, so ids are never
             -- reused under a reference.
             CREATE TABLE IF NOT EXISTS multihashes (
                 id INTEGER PRIMARY KEY,
                 multihash BLOB UNIQUE NOT NULL
             );",
        )?;
        conn.busy_timeout(WRITER_WAIT)?;
        Ok(Self(Rc::new(conn)))
    }

    pub fn conn(&self) -> &Connection {
        &self.0
    }

    /// Start a transaction, waiting for the write lock. Writing in one
    /// that's read first wouldn't wait: `SQLite` can't let a reader's view
    /// go, so a writer at that moment, however brief, would fail it at once.
    fn begin(&self) -> Result<()> {
        Ok(self.conn().execute_batch("BEGIN IMMEDIATE")?)
    }

    /// Run `f` atomically, for what usually only reads, so a writer doesn't
    /// hold it up. Should it need to write beside a writer, which it can't
    /// wait for having read, it's undone and run again, waiting: so `f`
    /// must change nothing but the database.
    pub fn reading_first<T>(&self, f: impl Fn() -> Result<T>) -> Result<T> {
        let conn = self.conn();
        if !conn.is_autocommit() {
            return self.atomically(&f);
        }
        conn.execute_batch("BEGIN")?;
        match f().and_then(|value| Ok(conn.execute_batch("COMMIT").map(|()| value)?)) {
            Ok(value) => Ok(value),
            Err(e) => {
                if !conn.is_autocommit() {
                    conn.execute_batch("ROLLBACK")?;
                }
                if e.is_busy() { self.atomically(&f) } else { Err(e) }
            },
        }
    }

    /// Run `f` atomically, for what will write, having waited for the
    /// write lock. Savepoints nest, so this works inside an enclosing
    /// transaction too.
    pub fn atomically<T, E: From<Error>>(&self, f: impl FnOnce() -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        let conn = self.conn();
        if conn.is_autocommit() {
            self.begin()?;
            return match f() {
                Ok(value) => {
                    conn.execute_batch("COMMIT").map_err(Error::from)?;
                    Ok(value)
                },
                Err(e) => {
                    conn.execute_batch("ROLLBACK").map_err(Error::from)?;
                    Err(e)
                },
            };
        }
        conn.execute_batch("SAVEPOINT atomically").map_err(Error::from)?;
        match f() {
            Ok(value) => {
                conn.execute_batch("RELEASE atomically").map_err(Error::from)?;
                Ok(value)
            },
            Err(e) => {
                conn.execute_batch("ROLLBACK TO atomically; RELEASE atomically").map_err(Error::from)?;
                Err(e)
            },
        }
    }

    /// A multihash's id, if the database knows of it.
    pub fn lookup(&self, key: Key<'_>) -> Result<Option<Id>> {
        Ok(self.conn()
            .prepare_cached("SELECT id FROM multihashes WHERE multihash = ?1")?
            .query_row([key.to_bytes()], |row| row.get(0))
            .optional()?)
    }

    /// A multihash's id, adding it if it's new.
    pub fn intern(&self, key: Key<'_>) -> Result<Id> {
        if key.len() > MAX_DIGEST_LEN {
            return Err(Error::Oversized(key.len()));
        }
        if let Some(id) = self.lookup(key)? {
            return Ok(id);
        }
        self.conn()
            .prepare_cached("INSERT INTO multihashes (multihash) VALUES (?1)")?
            .execute([key.to_bytes()])?;
        Ok(self.conn().last_insert_rowid())
    }
}

/// Read a multihash back out of a store.
fn decode_key(store: &'static str, bytes: &[u8]) -> Result<Multihash> {
    Multihash::decode(bytes).map_err(|e| Error::Invalid { store, reason: format!("multihash: {e}") })
}

/// Collect a query's rows of multihashes.
fn query_keys(db: &Db, store: &'static str, sql: &str) -> Result<Vec<Multihash>> {
    let mut stmt = db.conn().prepare(sql)?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    rows.map(|bytes| decode_key(store, &bytes?)).collect()
}

/// Split a binary CID into its prefix (see `cid_prefix`) and multihash,
/// if it's a valid CID.
fn split_cid(cid: &[u8]) -> Option<(&[u8], Key<'_>)> {
    let (prefix, mut rest) = match cid.split_first() {
        Some((0x01, mut rest)) => {
            crate::varint::read_minimal(&mut rest).ok()?;
            cid.split_at_checked(cid.len().checked_sub(rest.len())?)?
        },
        _ => (&[][..], cid),
    };
    let code = crate::varint::read_minimal(&mut rest).ok()?;
    let len = usize::try_from(crate::varint::read_minimal(&mut rest).ok()?).ok()?;
    if rest.len() != len {
        return None;
    }
    // CIDv0 is only ever sha2-256
    if prefix.is_empty() && (code != 0x12 || len != 32) {
        return None;
    }
    Some((prefix, Multihash::wrap(code, rest)))
}

/// The CID's version and codec, without the multihash: empty for CIDv0.
fn cid_prefix(cid: &Cidv1, version: CidVersion) -> Vec<u8> {
    match version {
        CidVersion::V0 => Vec::new(),
        CidVersion::V1 => {
            let mut prefix = vec![1];
            crate::varint::write(&mut prefix, cid.codec());
            prefix
        },
    }
}

//-----------//
//-[ Router ]-//
//-----------//

/// Indexes a repo's volumes: places each block in the most specialized
/// store of any volume which admits it, and remembers where everything
/// went, so a block is found without asking every volume.
///
/// The catalog's database is a volume too, which holds the structure:
/// UnixFS nodes, claims and IPLD, small and what's queried. Other volumes
/// mostly hold bulk, raw leaves and whole files. A block may be in more
/// than one volume, and the catalog knows of volumes which aren't
/// attached: it knows a block is in the repo, and what links to it, while
/// its bytes are somewhere else.
///
/// Placement is derived data: if it's lost or out of date, `reindex`
/// rebuilds it from the attached volumes.
pub struct Catalog {
    db: Db,
    /// Attached volumes, the catalog's own first.
    volumes: Vec<Volume>,
    /// Each attached volume's id in `volumes`.
    ids: Vec<Id>,
    /// The order blocks are offered to stores in, as (volume, store)
    /// indices; the last should admit anything.
    placement: Vec<(usize, usize)>,
    /// The offset store, for sinks to settle the ranges of files they
    /// import.
    offsets: Option<Rc<OffsetStore>>,
    /// Where large blocks and whole files are kept, if anywhere.
    shards: Option<Rc<ShardStore>>,
    /// The claim store, for its index of tags.
    claims: Option<Rc<ClaimStore>>,
    /// This device's key, which signs the claims made here, if it has one.
    signer: Option<crate::keys::Key>,
    /// The account, by the host's uid, the catalog acts for: whose key
    /// signs, and whose user's claims it sees.
    uid: u32,
    /// How many bytes the account this acts for may have here, if it's
    /// limited: a friend's, in a protected mesh.
    quota: Option<u64>,
    /// Claims made in a batch, which its end signs at once.
    unsigned: std::cell::RefCell<Vec<Link>>,
    /// How deep in batches this is.
    batching: usize,
    /// In a batch that breathes: how long between breaths, and when it last
    /// took one.
    breathing: std::cell::Cell<Option<(std::time::Duration, std::time::Instant)>>,
    /// When each lost block was last asked for here, so it's only now and
    /// then.
    lost_asked: std::cell::RefCell<std::collections::HashMap<Vec<u8>, std::time::Instant>>,
    /// Forked anchors' merges, by their heads.
    merges: std::cell::RefCell<std::collections::HashMap<Vec<u8>, Link>>,
    /// Asks a running node for blocks that aren't here, if this fetches
    /// through one.
    fetcher: Option<Fetcher>,
    /// Blocks found missing in a transaction, which can't wait on the node
    /// writing them, to fetch once it's over.
    missed: std::cell::RefCell<Vec<Link>>,
    /// Git commits new here, to keep what their parents have as deltas on
    /// what they have; see `git_deltas`.
    commits: std::cell::RefCell<git::Commits>,
}

/// Asks a running node to fetch blocks, just them, saying whether it
/// could ask.
pub type Fetcher = std::sync::Arc<dyn Fn(&[Link]) -> bool + Send + Sync>;

/// A set of an anchor in its history: the set, what it says the anchor
/// is, as of when, and the sets it replaces, if it says.
pub type SetOf = (Link, Link, u64, Option<Vec<Link>>);

/// Where a block is: an attached volume, by index, and the form it's in.
type Placement = (usize, String);

/// A volume the catalog knows of.
#[derive(Debug)]
pub struct VolumeInfo {
    pub name: String,
    pub kind: String,
    /// Where it was last seen.
    pub path: Option<PathBuf>,
    pub label: Vec<u8>,
    pub attached: bool,
    /// How many blocks are on it, by the index.
    pub blocks: u64,
}

/// What `replicate` did.
#[derive(Debug, Default)]
pub struct Replication {
    /// Copies made.
    pub copied: usize,
    /// Blocks it would still take fewer failures than asked for to lose.
    pub short: Vec<Multihash>,
    /// Dissolved claims copied, which aren't blocks.
    pub claims: usize,
}

/// A file or directory imported in place, mounted on an anchor which is
/// set to whatever it was last imported as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub anchor: Link,
    pub path: PathBuf,
    pub chunk_size: usize,
    pub width: usize,
    pub hidden: bool,
    /// Whether the path holds only what's changed of the anchor, written
    /// through `hk mount`, over what it was: a work directory, imported
    /// with the anchor's overlay marks rather than as all there is.
    pub overlay: bool,
}

impl Mount {
    /// How to import it again.
    pub fn importer(&self) -> crate::import::Importer {
        crate::import::Importer {
            chunk_size: self.chunk_size,
            layout: crate::dag::BalancedLayout { width: self.width },
            hidden: self.hidden,
            ..crate::import::Importer::default()
        }
    }
}

/// What `drop_all` let go of.
#[derive(Debug, Default)]
pub struct Dropping {
    /// The leaves whose copies here were let go of.
    pub dropped: Vec<Multihash>,
    /// The bytes freed, less any moved out of kept files.
    pub freed: u64,
}

/// What `copy_to` did.
#[derive(Debug, Default)]
pub struct CopyReport {
    /// Copies made.
    pub copied: usize,
    /// Blocks which couldn't be read to be copied.
    pub unreadable: Vec<Multihash>,
    /// Dissolved claims copied, which aren't blocks.
    pub claims: usize,
}

/// A copy of a block, as other nodes are told of it: the volume it's on,
/// by label, and what that volume risks, itself included.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Replica {
    #[serde(with = "serde_bytes")]
    pub label: Vec<u8>,
    pub risks: Vec<String>,
}

/// Where a node would keep a block it's sent: its own volume's risks, and
/// the free space there, if it's known.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Offer {
    pub risks: Vec<String>,
    pub free: Option<u64>,
}

/// The risk every volume runs of itself, by its label, so it means the
/// same volume to every catalog which knows it.
fn volume_risk(label: &[u8]) -> String {
    use std::fmt::Write as _;
    label.iter().fold("volume:".to_owned(), |mut risk, byte| {
        let _ = write!(risk, "{byte:02x}");
        risk
    })
}

/// Free space under a path.
fn free_space(path: &Path) -> Option<u64> {
    let stat = rustix::fs::statvfs(path).ok()?;
    Some(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// A multihash of one's own.
fn owned(key: Key<'_>) -> Result<Multihash> {
    Multihash::try_wrap(key.code(), key.digest_ref()).map_err(|_| Error::Oversized(key.len()))
}

fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

/// Where signs fork, given each one's CID and the sign before it: each
/// sign followed by more than one, or `None` for more than one first.
fn forks(signs: &[claims::Signed]) -> Vec<Option<Link>> {
    let mut followers: std::collections::BTreeMap<Option<Vec<u8>>, (Option<Link>, usize)> = std::collections::BTreeMap::new();
    for claims::Signed { prev, .. } in signs {
        let entry = followers.entry(prev.as_ref().map(Link::to_bytes)).or_insert_with(|| (prev.clone(), 0));
        entry.1 = entry.1.saturating_add(1);
    }
    followers.into_values().filter(|(_, n)| *n > 1).map(|(prev, _)| prev).collect()
}

/// How long a block an account put here stays in its repo with nothing
/// of its keeping it: collecting's grace period.
pub const HOLDING: std::time::Duration = std::time::Duration::from_hours(24 * 7);

/// The time from which a block put here is still in its putter's repo.
fn held_since() -> i64 {
    i64::try_from(now().saturating_sub(HOLDING.as_secs())).unwrap_or(i64::MAX)
}

/// Seconds since the epoch.
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

fn path_from(bytes: &[u8]) -> PathBuf {
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

impl Catalog {
    /// Open a repo directory with the standard stores, attach whichever
    /// other volumes are where they were last seen, and catch up with
    /// them.
    pub fn open_repo(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("blocks.db");
        let db = Db::open(&path)?;
        let shards = ShardStore::open(db.clone(), &dir.join("shards"))?;
        let mut catalog = Self::with_shards(db, Some(shards))?;
        catalog.locate(0, &path)?;
        catalog.attach_known()?;
        catalog.catch_up_if_free()?;
        catalog.sign_as(dir)?;
        Ok(catalog)
    }

    /// Act for the user running this, signing with this node's key, made
    /// if there's none yet. Until the account makes or joins a mesh, its
    /// device key is its user; once it has one, what this node signed
    /// counts once the user certifies it.
    fn sign_as(&mut self, dir: &Path) -> Result<()> {
        let key = crate::keys::Key::load_or_make(&dir.join(crate::keys::NODE_KEY))?;
        self.act_for(rustix::process::getuid().as_raw(), key)
    }

    /// Act for one of the host's users, signing with its key here: what
    /// it says is signed with it, and what's seen is what counts for its
    /// user.
    pub fn act_for(&mut self, uid: u32, key: crate::keys::Key) -> Result<()> {
        self.uid = uid;
        if let Some(claims) = &self.claims {
            claims.set_device(uid, &key.id())?;
        }
        self.signer = Some(key);
        self.refresh_acting()
    }

    /// Sign claims with this key from now on, as this account's.
    pub fn set_signer(&mut self, key: crate::keys::Key) -> Result<()> {
        self.act_for(self.uid, key)
    }

    /// The key claims made here are signed with, if any.
    pub const fn signer(&self) -> Option<&crate::keys::Key> {
        self.signer.as_ref()
    }

    /// Limit the bytes the account this acts for may have here.
    pub const fn set_quota(&mut self, quota: Option<u64>) {
        self.quota = quota;
    }

    /// The bytes of the blocks here that the account this acts for put
    /// here: its tally, against its quota.
    pub fn used(&self) -> Result<u64> {
        let used: i64 = self.db.conn()
            .prepare_cached(
                "SELECT coalesce(sum(size), 0) FROM holdings
                 WHERE uid = ?1 AND block IN (SELECT block FROM blocks)",
            )?
            .query_row([self.uid], |row| row.get(0))?;
        Ok(u64::try_from(used).unwrap_or_default())
    }

    /// Every block here the account this acts for put here, whenever it
    /// did, by CID.
    pub fn held(&self) -> Result<Vec<Link>> {
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(
                "SELECT m.multihash FROM holdings h JOIN multihashes m ON m.id = h.block
                 WHERE h.uid = ?1 AND h.block IN (SELECT block FROM blocks) ORDER BY h.block",
            )?
            .query_map([self.uid], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut held = Vec::new();
        for bytes in rows {
            let key = decode_key("router", &bytes)?;
            if let Some(cid) = self.cid_of(key.as_ref())? {
                held.push(cid);
            }
        }
        Ok(held)
    }

    /// The quota, and how much of it's left, if there is one.
    pub fn quota_left(&self) -> Result<Option<(u64, u64)>> {
        self.quota.map(|quota| Ok((quota, quota.saturating_sub(self.used()?)))).transpose()
    }

    /// The uid of the account this acts for.
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The account this acts for, if it's said anything yet.
    pub fn account(&self) -> Result<Option<claims::Account>> {
        self.claims.as_ref().map_or(Ok(None), |claims| claims.account(self.uid))
    }

    /// Whether a block is a claim another of the host's accounts made
    /// here, which isn't for this account's mesh to hear of.
    pub fn withheld(&self, cid: &Link) -> Result<bool> {
        self.claims.as_ref().map_or(Ok(false), |claims| claims.withheld(cid.multihash(), self.uid))
    }

    /// The root key of the user this acts for, if its account is in a mesh.
    pub fn user(&self) -> Result<Option<Link>> {
        Ok(self.account()?.and_then(|account| account.user))
    }

    /// Make `root` the user of the account this acts for, in place of any
    /// other: joining a user's mesh.
    pub fn set_user(&self, root: &Link) -> Result<()> {
        self.claims.as_ref().ok_or(Error::NoClaims)?.set_user(self.uid, root)?;
        self.refresh_acting()
    }

    /// Make `root` the user of the account this acts for, joining its
    /// mesh, with what the repo named before beside what the user names: a
    /// head of the user's root anchor of its own, merged with the rest.
    pub fn join_user(&self, root: &Link) -> Result<()> {
        let before = self.root_anchor()?;
        let named = before.as_ref().map(|anchor| self.anchor_value(anchor)).transpose()?.flatten();
        self.set_user(root)?;
        if let (Some(value), Some(anchor)) = (named, self.root_anchor()?)
            && Some(&anchor) != before.as_ref()
        {
            self.set_anchor_beside(&anchor, &value)?;
        }
        Ok(())
    }

    /// The root anchor of who this acts for, the top of what they've
    /// named: their user's, or until there's one, their device's.
    pub fn root_anchor(&self) -> Result<Option<Link>> {
        let key = match self.account()?.and_then(|account| account.acts_for().cloned()) {
            Some(key) => key,
            None => match &self.signer {
                Some(signer) => signer.id(),
                None => return Ok(None),
            },
        };
        Ok(Some(crate::claim::root_anchor(&key)?))
    }

    /// See what counts for the account's user.
    fn refresh_acting(&self) -> Result<()> {
        if let Some(claims) = &self.claims {
            let account = claims.account(self.uid)?;
            claims.act_as(account.as_ref().and_then(claims::Account::acts_for));
        }
        Ok(())
    }

    /// Put a claim, signed with this device's key if it has one: at once,
    /// or in a batch, with the rest of the batch's claims when it ends.
    /// Returns the claim's CID.
    pub fn put_claim(&self, claim: &Claim) -> Result<Link> {
        self.put_block(&claim.block(), CidVersion::V1)?;
        let cid = claim.cid();
        if let Some(key) = &self.signer {
            if self.batching > 0 {
                self.unsigned.borrow_mut().push(cid.clone());
            } else {
                self.sign_with(key, [cid.clone()])?;
            }
        }
        Ok(cid)
    }

    /// Sign claims with a key, those it hasn't already, in one sign which
    /// follows the key's last. Returns the sign's CID, if there was
    /// anything to sign.
    ///
    /// The key's last sign is read and the next written in one
    /// transaction, so two writers can't both follow it: the second
    /// fails, rather than forking the chain.
    fn sign_with(&self, key: &crate::keys::Key, claims: impl IntoIterator<Item = Link>) -> Result<Option<Link>> {
        let store = self.claims.as_ref().ok_or(Error::NoClaims)?;
        let mut fresh = Vec::new();
        for claim in claims {
            if !store.signed_by(&claim, &key.id())? {
                fresh.push(claim);
            }
        }
        if fresh.is_empty() {
            return Ok(None);
        }
        self.db.atomically(|| {
            // Take the write lock before reading the head
            self.db.conn().execute("DELETE FROM sign_claims WHERE 0", [])?;
            let prev = store.head(&key.id())?;
            let Some(sign) = crate::claim::Sign::new(key, fresh, prev, now()) else {
                return Ok(None);
            };
            let sign = Claim::Sign(sign);
            self.put_block(&sign.block(), CidVersion::V1)?;
            Ok(Some(sign.cid()))
        })
    }

    /// Sign what a batch has said so far.
    fn sign_batch(&self) -> Result<()> {
        let unsigned = std::mem::take(&mut *self.unsigned.borrow_mut());
        if let Some(key) = &self.signer {
            self.sign_with(key, unsigned)?;
        }
        Ok(())
    }

    /// Where to cut a device's chain of signs, revoking it, to trust what
    /// it signed as of a time: its last sign then, following the chain
    /// from its first. Nothing, if its first came after. Only for a chain
    /// that doesn't fork: once a copy of the key has signed, when isn't
    /// to be trusted, and only a sign is.
    pub fn cutoff_at(&self, device: &Link, until: u64) -> Result<Option<Link>> {
        let signs = self.claims.as_ref().ok_or(Error::NoClaims)?.signs_by(device)?;
        if let Some(fork) = forks(&signs).first() {
            let at = fork.as_ref().map_or_else(|| "its start".to_owned(), ToString::to_string);
            return Err(Error::User(format!("{} has more than one chain of signs, forking at {at}: its key was copied, so revoke it up to a sign rather than a time", crate::keys::peer_id(device))));
        }
        let mut cutoff = None;
        let mut next = signs.iter().find(|signed| signed.prev.is_none());
        while let Some(signed) = next.filter(|signed| signed.at <= until) {
            cutoff = Some(signed.sign.clone());
            next = signs.iter().find(|other| other.prev.as_ref() == Some(&signed.sign));
        }
        Ok(cutoff)
    }

    /// Where a device's signs fork: each sign followed by more than one,
    /// or `None` for more than one first sign.
    pub fn forks(&self, device: &Link) -> Result<Vec<Option<Link>>> {
        Ok(forks(&self.claims.as_ref().ok_or(Error::NoClaims)?.signs_by(device)?))
    }

    /// Make a user for this repo, as a mesh is made: a new root key, which
    /// certifies this device, sealed with a passphrase. Returns the root,
    /// which is nowhere else unsealed.
    ///
    /// What the repo's root anchor was, the new user's is: what it named
    /// before it was in a mesh, it still names. (A repo joining a mesh
    /// can't do the same, the user's root being whatever the mesh says.)
    pub fn found_user(&self, passphrase: &[u8], cost: crate::keys::Cost) -> Result<crate::keys::Key> {
        let device = self.signer.as_ref().ok_or_else(|| Error::User("this repo has no key to sign with".into()))?.id();
        if self.user()?.is_some() {
            return Err(Error::User("this repo has a user already".into()));
        }
        let named = self.root_anchor()?.map(|anchor| self.anchor_value(&anchor)).transpose()?.flatten();
        let root = crate::keys::Key::generate()?;
        self.set_user(&root.id())?;
        self.certify(&root, &device)?;
        if let (Some(value), Some(anchor)) = (named, self.root_anchor()?) {
            self.set_anchor(&anchor, &value)?;
        }
        self.keep_root()?;
        self.seal(&root, passphrase, cost)?;
        Ok(root)
    }

    /// Seal the user's root key with a passphrase, as a block this repo
    /// keeps, and so wherever the mesh keeps what it keeps. Returns its
    /// CID.
    pub fn seal(&self, root: &crate::keys::Key, passphrase: &[u8], cost: crate::keys::Cost) -> Result<Link> {
        let block = crate::keys::Sealed::seal(root, passphrase, cost)?.block();
        self.put_block(&block, CidVersion::V1)?;
        let cid = crate::cid::AnyCid::V1(block.cid().clone());
        self.keep(&cid)?;
        Ok(cid)
    }

    /// The user's root key, sealed, wherever it's here, by CID.
    pub fn seals(&self) -> Result<Vec<(Link, crate::keys::Sealed)>> {
        let Some(user) = self.user()? else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for source in self.backrefs(user.multihash())? {
            if let Some(cid) = self.cid_of(source.as_ref())?
                && let Some(block) = self.get_block(&cid)?
                && let Some(sealed) = crate::keys::Sealed::parse(block.data())
                && *sealed.key() == user
            {
                found.push((cid, sealed));
            }
        }
        Ok(found)
    }

    /// The user's root key, unsealed with its passphrase.
    pub fn root(&self, passphrase: &[u8]) -> Result<crate::keys::Key> {
        let seals = self.seals()?;
        if seals.is_empty() {
            return Err(Error::User("this repo has no sealed root key for its user".into()));
        }
        seals.iter()
            .find_map(|(_, sealed)| sealed.open(passphrase))
            .ok_or_else(|| Error::User("that's not the passphrase of the user's root key".into()))
    }

    /// Certify a device's key with the user's root key: a device claim the
    /// root signs. Returns the claim's CID.
    pub fn certify(&self, root: &crate::keys::Key, device: &Link) -> Result<Link> {
        let claim = Claim::Device(crate::claim::Device::new([device.clone()]).ok_or(Error::NoClaims)?);
        self.put_block(&claim.block(), CidVersion::V1)?;
        self.sign_with(root, [claim.cid()])?;
        Ok(claim.cid())
    }

    /// Revoke a device with the user's root key: a tomb of its certificate,
    /// which the root signs. What it signed in its sign `cutoff` or before
    /// it in its chain, and nothing else authorized has, is signed again,
    /// with this device's key, so it still counts; nothing else it signed
    /// does, whenever it says it was, and with no cutoff nothing it signed
    /// does. Returns how many were signed again.
    pub fn revoke(&self, root: &crate::keys::Key, device: &Link, cutoff: Option<&Link>) -> Result<usize> {
        let claims = self.claims.as_ref().ok_or(Error::NoClaims)?;
        let key = self.signer.as_ref().filter(|key| key.id() != *device).ok_or(Error::NoClaims)?;
        let orphans = cutoff.map(|cutoff| claims.signed_only_by(device, cutoff)).transpose()?.unwrap_or_default();
        let certificate = Claim::Device(crate::claim::Device::new([device.clone()]).ok_or(Error::NoClaims)?);
        let tomb = Claim::Tomb(Tomb::new([certificate.cid()]).ok_or(Error::NoClaims)?);
        self.put_block(&tomb.block(), CidVersion::V1)?;
        self.sign_with(root, [tomb.cid()])?;
        let count = orphans.len();
        self.sign_with(key, orphans)?;
        Ok(count)
    }

    /// Every device a certificate names, and whether it counts now.
    pub fn devices(&self) -> Result<Vec<(Link, bool)>> {
        self.claims.as_ref().map_or(Ok(Vec::new()), |claims| claims.devices())
    }

    /// The standard stores in one database, with no shards.
    pub fn standard(db: Db) -> Result<Self> {
        Self::with_shards(db, None)
    }

    /// The standard stores: in the catalog's database, ranges of files
    /// when that's where blocks came from, UnixFS nodes as rows, claims as
    /// rows, dag-cbor and dag-json as JSONB, git objects and deltas
    /// compressed; large blocks in the shards if
    /// there are any; and everything else as raw bytes in the database.
    pub fn with_shards(db: Db, shards: Option<ShardStore>) -> Result<Self> {
        let shards = shards.map(Rc::new);
        let offsets = Rc::new(OffsetStore::open(db.clone(), shards.clone())?);
        let claims = Rc::new(ClaimStore::open(db.clone())?);
        let stores: Vec<Box<dyn Store>> = vec![
            Box::new(Rc::clone(&offsets)),
            Box::new(UnixfsStore::open(db.clone())?),
            Box::new(Rc::clone(&claims)),
            Box::new(IpldStore::open(db.clone())?),
            Box::new(DeltaStore::open(db.clone())?),
            Box::new(RawStore::open(db.clone())?),
        ];
        let raw = stores.len().saturating_sub(1);
        let mut volumes = vec![Volume::sqlite("db", db.clone(), stores)?];
        let mut placement: Vec<_> = (0..raw).map(|store| (0, store)).collect();
        if let Some(shards) = &shards {
            volumes.push(Volume::flatfs("shards", Rc::clone(shards)));
            placement.push((1, 0));
        }
        placement.push((0, raw));
        let mut catalog = Self::with_volumes(db, volumes, placement)?;
        catalog.db.conn().execute_batch(
            "-- Every link in the repo, by the multihashes of the block it's in
             -- and the block it's to.
             CREATE VIEW IF NOT EXISTS links (source, target) AS
                 SELECT node, target FROM unixfs_links
                 UNION SELECT block, target FROM ipld_links
                 UNION SELECT c.claim, t.target FROM claim_targets t JOIN claims c ON c.id = t.claim
                     WHERE c.claim IS NOT NULL
                 UNION SELECT c.claim, g.into_ FROM group_claims g JOIN claims c ON c.id = g.id
                     WHERE c.claim IS NOT NULL
                 UNION SELECT source, target FROM refs;
             -- Changes made once to what's in a repo, by name, as made.
             CREATE TABLE IF NOT EXISTS migrations (
                 name TEXT PRIMARY KEY,
                 at INTEGER NOT NULL
             );",
        )?;
        catalog.migrate("mount points link to their anchors", Self::index_mount_points)?;
        catalog.db.conn().execute_batch(
            "-- Files and directories imported in place, by the anchor each is
             -- mounted on, and how they were imported, to import them again
             -- the same way when they change. Known only here: a path never
             -- enters the soup.
             CREATE TABLE IF NOT EXISTS mounts (
                 anchor BLOB PRIMARY KEY,
                 path BLOB UNIQUE NOT NULL,
                 chunk_size INTEGER NOT NULL,
                 width INTEGER NOT NULL,
                 hidden INTEGER NOT NULL,
                 overlay INTEGER NOT NULL DEFAULT 0
             );
             -- What an overlay mount says of paths beyond its work directory:
             -- that what's there is gone (cid NULL), or is a block already in
             -- the soup, as a rename leaves it, with the size its link says.
             CREATE TABLE IF NOT EXISTS overlay_marks (
                 anchor BLOB NOT NULL,
                 path BLOB NOT NULL,
                 cid BLOB,
                 tsize INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (anchor, path)
             ) WITHOUT ROWID;
             -- Files of overlays being copied from what the anchor had as
             -- they're read and written, rather than all at once: the block
             -- each is from, how much of it's wanted, and which of its
             -- chunks are filled, a bit each. A chunk's marked filled before
             -- anything's written to it, so one that isn't is the anchor's
             -- still.
             CREATE TABLE IF NOT EXISTS overlay_partials (
                 anchor BLOB NOT NULL,
                 path BLOB NOT NULL,
                 base BLOB NOT NULL,
                 len INTEGER NOT NULL,
                 filled BLOB NOT NULL,
                 PRIMARY KEY (anchor, path)
             ) WITHOUT ROWID;",
        )?;
        let has_overlay: bool = catalog.db.conn().query_row(
            "SELECT count(*) FROM pragma_table_info('mounts') WHERE name = 'overlay'",
            [],
            |row| row.get::<_, i64>(0),
        )? > 0;
        if !has_overlay {
            catalog.db.conn().execute_batch("ALTER TABLE mounts ADD COLUMN overlay INTEGER NOT NULL DEFAULT 0")?;
        }
        catalog.offsets = Some(offsets);
        catalog.claims = Some(claims);
        catalog.shards = shards;
        Ok(catalog)
    }

    /// A catalog whose only volume is its own database, holding these
    /// stores, offered blocks in order.
    pub fn new(db: Db, stores: Vec<Box<dyn Store>>) -> Result<Self> {
        let placement = (0..stores.len()).map(|store| (0, store)).collect();
        let volume = Volume::new("db", volume::db_label(&db)?, stores);
        Self::with_volumes(db, vec![volume], placement)
    }

    /// A catalog of volumes, offering blocks to their stores in the order
    /// given.
    pub fn with_volumes(db: Db, volumes: Vec<Volume>, placement: Vec<(usize, usize)>) -> Result<Self> {
        Self::schema(&db)?;
        if let Some(&(v, s)) = placement.iter().find(|&&(v, s)| volumes.get(v).is_none_or(|volume| volume.stores().get(s).is_none())) {
            return Err(Error::UnknownStore(format!("volume {v}, store {s}")));
        }
        let mut catalog = Self { db, volumes: Vec::new(), ids: Vec::new(), placement, offsets: None, shards: None, claims: None, signer: None, uid: rustix::process::getuid().as_raw(), quota: None, unsigned: std::cell::RefCell::default(), batching: 0, breathing: std::cell::Cell::new(None), lost_asked: std::cell::RefCell::default(), merges: std::cell::RefCell::default(), fetcher: None, missed: std::cell::RefCell::default(), commits: std::cell::RefCell::default() };
        for volume in volumes {
            catalog.attach(volume)?;
        }
        Ok(catalog)
    }

    fn schema(db: &Db) -> Result<()> {
        db.conn().execute_batch(
            "-- Every volume the catalog knows of, attached or not, by the
             -- label it carries: how to open it again, where it was last
             -- seen, and for a database, the latest of its generations
             -- caught up with.
             CREATE TABLE IF NOT EXISTS volumes (
                 id INTEGER PRIMARY KEY,
                 label BLOB UNIQUE NOT NULL,
                 name TEXT UNIQUE NOT NULL,
                 kind TEXT NOT NULL,
                 path BLOB,
                 cursor INTEGER NOT NULL DEFAULT 0
             );
             -- What each volume shares with others which could fail, taking
             -- them all: a disk, a machine, a building. Some are found where
             -- the volume was last seen, the rest said. Every volume also
             -- risks itself, which isn't written down.
             CREATE TABLE IF NOT EXISTS risks (
                 volume INTEGER NOT NULL REFERENCES volumes (id),
                 risk TEXT NOT NULL,
                 found INTEGER NOT NULL,
                 PRIMARY KEY (volume, risk)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS forms (
                 id INTEGER PRIMARY KEY,
                 name TEXT UNIQUE NOT NULL
             );
             -- Where each block that's present is: which volumes, and in
             -- which form in each.
             CREATE TABLE IF NOT EXISTS blocks (
                 block INTEGER NOT NULL REFERENCES multihashes (id),
                 volume INTEGER NOT NULL REFERENCES volumes (id),
                 form INTEGER NOT NULL REFERENCES forms (id),
                 PRIMARY KEY (block, volume)
             ) WITHOUT ROWID;
             -- The links of blocks in stores which don't index their own,
             -- read from their bytes by codec. With the stores' own link
             -- tables, every link in the repo, for backreferences.
             CREATE TABLE IF NOT EXISTS refs (
                 source INTEGER NOT NULL REFERENCES multihashes (id),
                 target INTEGER NOT NULL REFERENCES multihashes (id),
                 PRIMARY KEY (source, target)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS refs_target ON refs (target);",
        )?;
        db.conn().execute_batch(volume::BLOCK_CIDS)?;
        let fresh = !db.conn().prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'holdings'")?.exists([])?;
        db.conn().execute_batch(
            "-- Which of the host's accounts put each block here, by uid, and
             -- when last: added, fetched, or had from its mesh. A block is in
             -- an account's repo while it put it here within the grace
             -- period, or a keep that counts for its user reaches it.
             CREATE TABLE IF NOT EXISTS holdings (
                 uid INTEGER NOT NULL,
                 block INTEGER NOT NULL REFERENCES multihashes (id) ON DELETE CASCADE,
                 since INTEGER NOT NULL,
                 size INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (uid, block)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS holdings_block ON holdings (block);",
        )?;
        if !db.conn().prepare("SELECT 1 FROM pragma_table_info('holdings') WHERE name = 'size'")?.exists([])? {
            db.conn().execute_batch("ALTER TABLE holdings ADD COLUMN size INTEGER NOT NULL DEFAULT 0")?;
        }
        // From before holdings: everything here is its owner's
        if fresh {
            db.conn().execute(
                "INSERT OR IGNORE INTO holdings (uid, block, since) SELECT DISTINCT ?1, block, ?2 FROM blocks",
                params![rustix::process::getuid().as_raw(), i64::try_from(now()).unwrap_or(i64::MAX)],
            )?;
        }
        Ok(())
    }

    /// Record a volume as attached, as of where it's mounted now.
    fn attach(&mut self, volume: Volume) -> Result<usize> {
        let path = volume.path().map(path_bytes);
        // Only what's changed is written: opening a repo as it was leaves
        // it to whoever's writing, and doesn't wait for them
        let known: Option<(Id, String, String, Option<Vec<u8>>)> = self.db.conn()
            .prepare_cached("SELECT id, name, kind, path FROM volumes WHERE label = ?1")?
            .query_row([volume.label().as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .optional()?;
        let id: Id = match known {
            Some((id, name, kind, was)) if name == volume.name && kind == volume.kind() && (path.is_none() || path == was.as_deref()) => id,
            _ => self.db.conn()
                .prepare_cached(
                    "INSERT INTO volumes (label, name, kind, path) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (label) DO UPDATE SET
                         name = excluded.name, kind = excluded.kind, path = coalesce(excluded.path, path)
                     RETURNING id",
                )?
                .query_row(params![volume.label().as_slice(), volume.name, volume.kind(), path], |row| row.get(0))?,
        };
        self.found_risks(id, &volume)?;
        for store in volume.stores() {
            if !self.db.conn().prepare_cached("SELECT 1 FROM forms WHERE name = ?1")?.exists([store.name()])? {
                self.db.conn().execute("INSERT OR IGNORE INTO forms (name) VALUES (?1)", [store.name()])?;
            }
        }
        self.ids.push(id);
        self.volumes.push(volume);
        Ok(self.volumes.len().saturating_sub(1))
    }

    /// Say where an attached volume is mounted.
    fn locate(&mut self, volume: usize, path: &Path) -> Result<()> {
        let (Some(v), Some(&id)) = (self.volumes.get_mut(volume), self.ids.get(volume)) else {
            return Ok(());
        };
        let taken = std::mem::replace(v, Volume::new("", [0; 16], Vec::new()));
        *v = taken.at(path);
        let was: Option<Vec<u8>> = self.db.conn().prepare_cached("SELECT path FROM volumes WHERE id = ?1")?.query_row([id], |row| row.get(0))?;
        if was.as_deref() != Some(path_bytes(path)) {
            self.db.conn()
                .prepare_cached("UPDATE volumes SET path = ?1 WHERE id = ?2")?
                .execute(params![path_bytes(path), id])?;
        }
        let Some(v) = self.volumes.get(volume) else {
            return Ok(());
        };
        self.found_risks(id, v)
    }

    /// Record the risks found of a volume where it's mounted now, in place
    /// of those found before. What's said stays.
    fn found_risks(&self, id: Id, volume: &Volume) -> Result<()> {
        if volume.path().is_none() {
            return Ok(());
        }
        let conn = self.db.conn();
        let known: Vec<(String, bool)> = conn
            .prepare_cached("SELECT risk, found FROM risks WHERE volume = ?1")?
            .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let found_still = known.iter().all(|(risk, found)| !found || volume.risks().contains(risk));
        let all_known = volume.risks().iter().all(|risk| known.iter().any(|(known, _)| known == risk));
        if found_still && all_known {
            return Ok(());
        }
        conn.prepare_cached("DELETE FROM risks WHERE volume = ?1 AND found")?.execute([id])?;
        let mut insert = conn.prepare_cached("INSERT OR IGNORE INTO risks (volume, risk, found) VALUES (?1, ?2, 1)")?;
        for risk in volume.risks() {
            insert.execute(params![id, risk])?;
        }
        Ok(())
    }

    /// A volume's id by name, attached or not.
    fn volume_id(&self, name: &str) -> Result<Id> {
        self.db.conn()
            .prepare_cached("SELECT id FROM volumes WHERE name = ?1")?
            .query_row([name], |row| row.get(0))
            .optional()?
            .ok_or_else(|| Error::Volume(format!("no volume is called {name:?}")))
    }

    /// Say that a volume shares a risk with whichever others are said or
    /// found to, such as the building it's in.
    pub fn add_risk(&self, name: &str, risk: &str) -> Result<()> {
        self.db.conn()
            .prepare_cached("INSERT INTO risks (volume, risk, found) VALUES (?1, ?2, 0) ON CONFLICT DO UPDATE SET found = 0")?
            .execute(params![self.volume_id(name)?, risk])?;
        Ok(())
    }

    /// Unsay a risk. One that's found can't be, since it would be found
    /// again.
    pub fn remove_risk(&self, name: &str, risk: &str) -> Result<()> {
        let id = self.volume_id(name)?;
        let found: Option<bool> = self.db.conn()
            .prepare_cached("SELECT found FROM risks WHERE volume = ?1 AND risk = ?2")?
            .query_row(params![id, risk], |row| row.get(0))
            .optional()?;
        match found {
            None => Err(Error::Volume(format!("{name} isn't said to risk {risk}"))),
            Some(true) => Err(Error::Volume(format!("{name} is found to risk {risk} where it's mounted; it would be found again"))),
            Some(false) => {
                self.db.conn().prepare_cached("DELETE FROM risks WHERE volume = ?1 AND risk = ?2")?.execute(params![id, risk])?;
                Ok(())
            },
        }
    }

    /// Every volume's risks, by volume name, and whether each was found
    /// rather than said.
    pub fn risk_list(&self) -> Result<Vec<(String, String, bool)>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT v.name, r.risk, r.found FROM risks r JOIN volumes v ON v.id = r.volume ORDER BY v.id, r.risk",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// A volume's risks, itself included.
    fn risks(&self, id: Id) -> Result<Vec<String>> {
        let mut risks: Vec<String> = self.db.conn()
            .prepare_cached("SELECT risk FROM risks WHERE volume = ?1")?
            .query_map([id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let label: Vec<u8> = self.db.conn().prepare_cached("SELECT label FROM volumes WHERE id = ?1")?.query_row([id], |row| row.get(0))?;
        risks.push(volume_risk(&label));
        Ok(risks)
    }

    /// Attach every volume found where it was last seen, carrying its
    /// label. Those which aren't stay known, but unattached.
    fn attach_known(&mut self) -> Result<()> {
        type Known = (Id, Vec<u8>, String, String, Vec<u8>);
        let known: Vec<Known> = self.db.conn()
            .prepare("SELECT id, label, name, kind, path FROM volumes WHERE path IS NOT NULL")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, label, name, kind, path) in known {
            let Ok(label) = volume::Label::try_from(label) else {
                continue;
            };
            if self.ids.contains(&id) {
                continue;
            }
            let path = path_from(&path);
            let volume = match kind.as_str() {
                "flatfs" => ShardStore::attach(self.db.clone(), &path, label)?.map(|mut shards| {
                    shards.threshold = None;
                    Volume::flatfs(name, Rc::new(shards))
                }),
                "db" => Volume::open_sqlite(name, &path, Some(label))?,
                _ => None,
            };
            if let Some(volume) = volume {
                self.attach(volume)?;
            }
        }
        Ok(())
    }

    /// Add a flatfs directory as a volume, to keep copies of any block in.
    /// Returns the attached volumes it shares risks with, and which.
    pub fn add_volume(&mut self, name: &str, dir: &Path) -> Result<Vec<(String, Vec<String>)>> {
        let mut shards = ShardStore::open(self.db.clone(), dir)?;
        shards.threshold = None;
        self.add(name, Volume::flatfs(name, Rc::new(shards)))
    }

    /// Add a database file as a volume, made one if it isn't yet. It
    /// holds blocks in the forms the catalog's own database does, but for
    /// files kept in place, and another node may write to it too.
    pub fn add_sqlite_volume(&mut self, name: &str, path: &Path) -> Result<Vec<(String, Vec<String>)>> {
        let volume = Volume::open_sqlite(name, path, None)?.ok_or_else(|| Error::Volume(format!("can't open {}", path.display())))?;
        self.add(name, volume)
    }

    fn add(&mut self, name: &str, volume: Volume) -> Result<Vec<(String, Vec<String>)>> {
        if self.volumes.iter().any(|attached| attached.label() == volume.label()) {
            let path = volume.path().map(|path| path.display().to_string()).unwrap_or_default();
            return Err(Error::Volume(format!("{path} is already attached")));
        }
        let taken = self.db.conn()
            .prepare_cached("SELECT 1 FROM volumes WHERE name = ?1 AND label != ?2")?
            .exists(params![name, volume.label().as_slice()])?;
        if taken {
            return Err(Error::Volume(format!("a volume is already called {name:?}")));
        }
        let v = self.attach(volume)?;
        self.catch_up()?;
        let id = self.ids.get(v).copied().unwrap_or_default();
        let risks = self.risks(id)?;
        let mut shared = Vec::new();
        for (other, volume) in self.ids.iter().zip(&self.volumes) {
            let common: Vec<String> = self.risks(*other)?.into_iter().filter(|risk| *other != id && risks.contains(risk)).collect();
            if !common.is_empty() {
                shared.push((volume.name.clone(), common));
            }
        }
        Ok(shared)
    }

    /// Catch up, as a catalog's opened, unless it would mean waiting for
    /// a writer: what's missed is caught up with next time, and a writer
    /// that's long at it, keeping shards busy as it adds to them, mustn't
    /// keep anything from being read.
    fn catch_up_if_free(&self) -> Result<()> {
        self.db.conn().busy_timeout(CATCH_UP_WAIT)?;
        let caught_up = self.catch_up();
        self.db.conn().busy_timeout(WRITER_WAIT)?;
        match caught_up {
            Err(e) if e.is_busy() => Ok(()),
            other => other.map(drop),
        }
    }

    /// How long this catalog waits for other writers, from now on. What
    /// can't try again later would rather wait for longer.
    pub fn wait_for_writers(&self, wait: std::time::Duration) -> Result<()> {
        self.db.conn().busy_timeout(wait)?;
        for volume in 0..self.volumes.len() {
            if let Some(db) = self.foreign_db(volume) {
                db.conn().busy_timeout(wait)?;
            }
        }
        Ok(())
    }

    /// Whether a volume is a database other than the catalog's own, which
    /// others may write to.
    fn foreign_db(&self, volume: usize) -> Option<&Db> {
        self.volumes.get(volume)?.db().filter(|db| !Rc::ptr_eq(&db.0, &self.db.0))
    }

    /// The catalog's own volume, if it's one: its database.
    fn own(&self) -> Option<usize> {
        self.volumes.iter().position(|volume| volume.db().is_some_and(|db| Rc::ptr_eq(&db.0, &self.db.0)))
    }

    /// Every volume the catalog knows of.
    pub fn volume_list(&self) -> Result<Vec<VolumeInfo>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT v.id, v.name, v.kind, v.path, v.label, (SELECT count(*) FROM blocks b WHERE b.volume = v.id)
             FROM volumes v ORDER BY v.id",
        )?;
        let rows = stmt.query_map([], |row| Ok((
            row.get::<_, Id>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, i64>(5)?,
        )))?;
        rows.map(|row| {
            let (id, name, kind, path, label, blocks) = row?;
            Ok(VolumeInfo {
                name,
                kind,
                path: path.map(|path| path_from(&path)),
                label,
                attached: self.ids.contains(&id),
                blocks: u64::try_from(blocks).unwrap_or_default(),
            })
        })
        .collect()
    }

    /// Bring placement up to date with what attached volumes gained and
    /// lost without the catalog hearing of it, such as by another node
    /// writing to a shared one. Returns how many placements were added
    /// and removed.
    pub fn catch_up(&self) -> Result<(usize, usize)> {
        self.db.reading_first(|| {
            let (mut added, mut removed) = (0usize, 0usize);
            for (v, volume) in self.volumes.iter().enumerate() {
                if let Some(db) = self.foreign_db(v) {
                    let (more, fewer) = self.catch_up_db(v, db)?;
                    added = added.saturating_add(more);
                    removed = removed.saturating_add(fewer);
                    continue;
                }
                for store in volume.stores() {
                    let changes = store.catch_up()?;
                    for key in &changes.added {
                        let id = self.db.intern(key.as_ref())?;
                        if self.record(id, &(v, store.name().to_owned()))? {
                            added = added.saturating_add(1);
                            if store.refs().is_none() {
                                self.reindex_links(store.as_ref(), id, key.as_ref())?;
                            }
                        }
                    }
                    for key in &changes.removed {
                        if let Some(id) = self.db.lookup(key.as_ref())? {
                            removed = removed.saturating_add(self.unrecord(id, v)?);
                        }
                    }
                }
            }
            Ok((added, removed))
        })
    }

    /// Catch up with a database volume, from the generation after the
    /// last caught up with. Structure is also kept in the catalog's own
    /// database if it can be, so it's queried there, and so a tomb takes
    /// effect; it's what the catalog is for.
    fn catch_up_db(&self, v: usize, db: &Db) -> Result<(usize, usize)> {
        let Some(&volume) = self.ids.get(v) else {
            return Ok((0, 0));
        };
        let conn = self.db.conn();
        let cursor: i64 = conn.prepare_cached("SELECT cursor FROM volumes WHERE id = ?1")?.query_row([volume], |row| row.get(0))?;
        let changes: Vec<(String, Vec<u8>, bool, i64)> = db.conn()
            .prepare_cached(
                "SELECT g.form, m.multihash, g.present, g.generation FROM generations g
                 JOIN multihashes m ON m.id = g.block
                 WHERE g.generation > ?1 ORDER BY g.generation",
            )?
            .query_map([cursor], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let (mut added, mut removed, mut latest) = (0usize, 0usize, cursor);
        for (form, key, present, generation) in changes {
            latest = latest.max(generation);
            let key = decode_key("router", &key)?;
            let id = self.db.intern(key.as_ref())?;
            if !present {
                // Only if it's gone from the form it was known in, since it
                // may have moved
                let gone = conn
                    .prepare_cached("DELETE FROM blocks WHERE block = ?1 AND volume = ?2 AND form = (SELECT id FROM forms WHERE name = ?3)")?
                    .execute(params![id, volume, form])?;
                if gone > 0 {
                    removed = removed.saturating_add(gone);
                    self.forget_links(id)?;
                }
                continue;
            }
            if !self.record(id, &(v, form.clone()))? {
                continue;
            }
            added = added.saturating_add(1);
            let mut stmt = db.conn().prepare_cached(
                "SELECT c.prefix FROM block_cids c JOIN multihashes m ON m.id = c.block WHERE m.multihash = ?1",
            )?;
            let prefixes: Vec<Vec<u8>> = stmt.query_map([key.to_bytes()], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
            let mut insert = conn.prepare_cached("INSERT OR IGNORE INTO block_cids (block, prefix) VALUES (?1, ?2)")?;
            for prefix in &prefixes {
                insert.execute(params![id, prefix])?;
            }
            if !self.keep_structure(id, key.as_ref(), &form)? {
                self.reindex_links(self.named(&(v, form))?, id, key.as_ref())?;
            }
        }
        // Dissolved claims, stamped by row
        let rows: Vec<(Id, i64)> = db.conn()
            .prepare_cached("SELECT claim, generation FROM claim_generations WHERE generation > ?1 ORDER BY generation")?
            .query_map([cursor], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if let (Some(claims), false) = (&self.claims, rows.is_empty()) {
            let theirs = ClaimStore::open(db.clone())?;
            for (row, generation) in rows {
                latest = latest.max(generation);
                let Some(claim) = theirs.dissolved_row(row)? else {
                    continue;
                };
                if !claims.has_dissolved(&claim)? {
                    self.put_block(&claim.block(), CidVersion::V1)?;
                    added = added.saturating_add(1);
                }
            }
        }
        conn.prepare_cached("UPDATE volumes SET cursor = ?1 WHERE id = ?2")?.execute([latest, volume])?;
        Ok((added, removed))
    }

    /// Put dissolved claims in a database volume, returning how many it
    /// didn't have. They're small, and only a database keeps them.
    fn copy_dissolved(&self, v: usize, dissolved: &[Claim]) -> Result<usize> {
        let Some(db) = self.foreign_db(v) else {
            return Ok(0);
        };
        if self.volumes.get(v).and_then(|volume| volume.form("claims")).is_none() {
            return Ok(0);
        }
        let theirs = ClaimStore::open(db.clone())?;
        let mut copied = 0usize;
        for claim in dissolved {
            if !theirs.has_dissolved(claim)? && theirs.put(&claim.block())? == Put::Stored {
                copied = copied.saturating_add(1);
            }
        }
        Ok(copied)
    }

    /// The claims about a block, as multihashes: identities for dissolved
    /// ones.
    fn claims_about(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        self.claims.as_ref().map_or_else(|| Ok(Vec::new()), |claims| claims.backrefs(key))
    }

    /// Keep a copy of a block from another volume in the catalog's own,
    /// if the catalog keeps that form there and it isn't bulk. Returns
    /// whether it's there now, links indexed.
    fn keep_structure(&self, id: Id, key: Key<'_>, form: &str) -> Result<bool> {
        let Some(own) = self.own() else {
            return Ok(false);
        };
        let bulk = self.placement.last().and_then(|&(v, s)| self.volumes.get(v)?.stores().get(s)).map(|store| store.name());
        if bulk == Some(form) {
            return Ok(false);
        }
        let Some(store) = self.volumes.get(own).and_then(|volume| volume.form(form)) else {
            return Ok(false);
        };
        let Some(block) = self.readable(key)? else {
            return Ok(false);
        };
        if store.put(&block)? != Put::Stored {
            return Ok(false);
        }
        self.record(id, &(own, form.to_owned()))?;
        Ok(true)
    }

    /// Forget a block's placement in a volume, returning how many there
    /// were. Its links are forgotten with its last placement.
    fn unrecord(&self, id: Id, volume: usize) -> Result<usize> {
        let Some(&volume) = self.ids.get(volume) else {
            return Ok(0);
        };
        let removed = self.db.conn().prepare_cached("DELETE FROM blocks WHERE block = ?1 AND volume = ?2")?.execute([id, volume])?;
        self.forget_links(id)?;
        Ok(removed)
    }

    /// Forget the links read from a block, if it's nowhere any more.
    fn forget_links(&self, id: Id) -> Result<()> {
        let conn = self.db.conn();
        if !conn.prepare_cached("SELECT 1 FROM blocks WHERE block = ?1")?.exists([id])? {
            conn.prepare_cached("DELETE FROM refs WHERE source = ?1")?.execute([id])?;
        }
        Ok(())
    }

    /// The risks of each volume a block's copies are on.
    fn copy_risks(&self, id: Id) -> Result<Vec<Vec<String>>> {
        let volumes: Vec<Id> = self.db.conn()
            .prepare_cached("SELECT volume FROM blocks WHERE block = ?1")?
            .query_map([id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        volumes.into_iter().map(|volume| self.risks(volume)).collect()
    }

    /// The catalog's database, for others to keep what concerns its blocks
    /// beside them.
    pub const fn db(&self) -> &Db {
        &self.db
    }

    /// Structure which arrived in the catalog's own database after a
    /// generation, in the order it did: UnixFS nodes, IPLD and claims,
    /// dissolved claims included, up to `limit` of them. Returns their CIDs
    /// and the latest generation read, to read on from.
    pub fn structure_since(&self, generation: i64, limit: usize) -> Result<(Vec<Link>, i64)> {
        let conn = self.db.conn();
        if !conn.prepare_cached("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'generations'")?.exists([])? {
            return Ok((Vec::new(), generation));
        }
        let rows: Vec<(i64, bool, Id)> = conn
            .prepare_cached(
                "SELECT generation, 0, block FROM generations
                     WHERE generation > ?1 AND present AND form IN ('unixfs', 'claims', 'ipld')
                 UNION ALL SELECT generation, 1, claim FROM claim_generations WHERE generation > ?1
                 ORDER BY 1 LIMIT ?2",
            )?
            .query_map(params![generation, i64::try_from(limit).unwrap_or(i64::MAX)], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut latest = generation;
        let mut found = Vec::new();
        for (stamp, dissolved, id) in rows {
            latest = latest.max(stamp);
            if dissolved {
                if let Some(claim) = self.claims.as_ref().map(|claims| claims.dissolved_row(id)).transpose()?.flatten() {
                    found.push(claim.cid());
                }
                continue;
            }
            let bytes: Vec<u8> = conn.prepare_cached("SELECT multihash FROM multihashes WHERE id = ?1")?.query_row([id], |row| row.get(0))?;
            let key = decode_key("router", &bytes)?;
            found.extend(self.cids(key.as_ref())?.into_iter().next());
        }
        Ok((found, latest))
    }

    /// Blocks here whose multihashes were first known after `after`, by
    /// their ids, which only grow: what's arrived, mostly, since a block is
    /// usually known first when it's put. Up to `limit` of them, and the
    /// latest id read, to read on from.
    pub fn fresh_since(&self, after: Id, limit: usize) -> Result<(Vec<Multihash>, Id)> {
        let rows: Vec<(Id, Vec<u8>)> = self.db.conn()
            .prepare_cached(
                "SELECT DISTINCT b.block, m.multihash FROM blocks b JOIN multihashes m ON m.id = b.block
                 WHERE b.block > ?1 ORDER BY b.block LIMIT ?2",
            )?
            .query_map(params![after, i64::try_from(limit).unwrap_or(i64::MAX)], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let latest = rows.last().map_or(after, |&(id, _)| id);
        let keys = rows.into_iter().map(|(_, bytes)| decode_key("router", &bytes)).collect::<Result<_>>()?;
        Ok((keys, latest))
    }

    /// How many blocks are here.
    pub fn block_count(&self) -> Result<u64> {
        let count: i64 = self.db.conn().prepare_cached("SELECT count(DISTINCT block) FROM blocks")?.query_row([], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or_default())
    }

    /// Up to `k` blocks here, chosen at random: each the first at or after
    /// a random id, so a block after a gap in the ids is likelier, which is
    /// fine for sampling.
    pub fn sample(&self, k: usize) -> Result<Vec<Multihash>> {
        let conn = self.db.conn();
        let (lo, hi): (Option<Id>, Option<Id>) = conn.prepare_cached("SELECT min(block), max(block) FROM blocks")?.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let (Some(lo), Some(hi)) = (lo, hi) else {
            return Ok(Vec::new());
        };
        let span = u64::try_from(hi.saturating_sub(lo)).unwrap_or_default().saturating_add(1);
        let mut found = std::collections::BTreeMap::new();
        let mut stmt = conn.prepare_cached(
            "SELECT m.multihash FROM blocks b JOIN multihashes m ON m.id = b.block WHERE b.block >= ?1 ORDER BY b.block LIMIT 1",
        )?;
        // Twice as many tries as wanted, since some land on the same block
        for _ in 0..k.saturating_mul(2) {
            if found.len() >= k {
                break;
            }
            let mut bytes = [0u8; 8];
            getrandom::getrandom(&mut bytes).map_err(io::Error::from)?;
            let offset = u64::from_le_bytes(bytes).checked_rem(span).unwrap_or_default();
            let at = lo.saturating_add(i64::try_from(offset).unwrap_or_default());
            if let Some(bytes) = stmt.query_row([at], |row| row.get::<_, Vec<u8>>(0)).optional()? {
                let key = decode_key("router", &bytes)?;
                found.insert(bytes, key);
            }
        }
        Ok(found.into_values().collect())
    }

    /// The labels of the volumes new blocks are placed in, the repo's own:
    /// those whose copies this node can let go of.
    pub fn own_labels(&self) -> Vec<Vec<u8>> {
        let mut labels: Vec<Vec<u8>> = self.placement.iter().filter_map(|&(v, _)| Some(self.volumes.get(v)?.label().to_vec())).collect();
        labels.dedup();
        labels
    }

    /// Where a leaf is in the repo's own volumes, if every copy there can
    /// be let go of: a block with no links, under every CID it's had, in
    /// stores which can remove it, or as ranges only of files the repo
    /// keeps. Structure stays, being small and what's queried.
    fn droppable(&self, key: Key<'_>) -> Result<Option<Vec<Placement>>> {
        if key.code() == IDENTITY || self.cids(key)?.iter().any(|cid| cid.codec() != crate::cid::RAW_CODEC) {
            return Ok(None);
        }
        let own: Vec<usize> = self.placement.iter().map(|&(v, _)| v).collect();
        let placed: Vec<Placement> = self.placements(key)?.into_iter().filter(|(v, _)| own.contains(v)).collect();
        if placed.is_empty() {
            return Ok(None);
        }
        if placed.iter().any(|(_, form)| form == "offset") && !self.offsets.as_ref().is_some_and(|offsets| offsets.only_kept(key).unwrap_or(false)) {
            return Ok(None);
        }
        Ok(Some(placed))
    }

    /// Whether this node could let go of its own copies of a block.
    pub fn can_drop(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.droppable(key)?.is_some())
    }

    /// Let go of a leaf's copies in the repo's own volumes, returning the
    /// bytes freed, or None if they can't all be let go of. See
    /// `drop_all`.
    pub fn drop_copies(&self, key: Key<'_>) -> Result<Option<u64>> {
        let dropping = self.drop_all(&[owned(key)?])?;
        Ok((!dropping.dropped.is_empty()).then_some(dropping.freed))
    }

    /// Let go of the copies in the repo's own volumes of whichever of
    /// these leaves can all be let go of. Copies on other volumes stay.
    /// Whether the mesh can spare them is for the caller to know.
    ///
    /// A kept file exists for the file it was imported as, which a leaf
    /// going means is gone: so the kept file goes, and what's left of it,
    /// which other DAGs share, becomes blocks of their own first. Leaves
    /// let go of together cost nothing to move.
    pub fn drop_all(&self, keys: &[Multihash]) -> Result<Dropping> {
        self.let_go(keys, Self::droppable)
    }

    /// Where a block is in the repo's own volumes, if it's one garbage
    /// collection could let go of: anything but claims, which hold the
    /// history of what's kept, in stores which can remove it.
    fn collectable(&self, key: Key<'_>) -> Result<Option<Vec<Placement>>> {
        if key.code() == IDENTITY {
            return Ok(None);
        }
        let own: Vec<usize> = self.placement.iter().map(|&(v, _)| v).collect();
        let placed: Vec<Placement> = self.placements(key)?.into_iter().filter(|(v, _)| own.contains(v)).collect();
        if placed.is_empty() || placed.iter().any(|(_, form)| form == "claims") {
            return Ok(None);
        }
        if placed.iter().any(|(_, form)| form == "offset") && !self.offsets.as_ref().is_some_and(|offsets| offsets.only_kept(key).unwrap_or(false)) {
            return Ok(None);
        }
        Ok(Some(placed))
    }

    pub fn can_collect(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.collectable(key)?.is_some())
    }

    /// Whether anything here references a block: structure linking to it,
    /// a keep that counts, or a kept anchor being it now. Tags don't keep what they tag, and a tomb's
    /// link to what it retracts is the opposite of a reference.
    pub fn referenced(&self, key: Key<'_>) -> Result<bool> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(false);
        };
        let conn = self.db.conn();
        let mut sources = vec!["SELECT 1 FROM refs WHERE target = ?1".to_owned()];
        for table in ["unixfs_links", "ipld_links"] {
            if conn.prepare_cached("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1")?.exists([table])? {
                sources.push(format!("SELECT 1 FROM {table} WHERE target = ?1"));
            }
        }
        if self.claims.is_some() {
            sources.push(format!(
                "SELECT 1 FROM claim_targets t JOIN claims c ON c.id = t.claim WHERE t.target = ?1 AND c.kind = 'keep' AND {}",
                claims::LIVE_ANY,
            ));
            // What a kept anchor is now; what it was isn't referenced
            sources.push(format!(
                "SELECT 1 FROM anchor_values_any a JOIN claim_targets t ON t.target = a.anchor JOIN claims c ON c.id = t.claim
                 WHERE a.value = ?1 AND c.kind = 'keep' AND {}",
                claims::LIVE_ANY,
            ));
            // What a linked anchor is now: a block here linking to the
            // anchor, as an IPLD link or a mount point, references it.
            // Claims don't: a set links to its own anchor
            for table in ["refs", "unixfs_links", "ipld_links"] {
                let (source, target) = match table {
                    "unixfs_links" => ("node", "target"),
                    "ipld_links" => ("block", "target"),
                    _ => ("source", "target"),
                };
                if table == "refs" || conn.prepare_cached("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1")?.exists([table])? {
                    sources.push(format!(
                        "SELECT 1 FROM anchor_values_any a JOIN {table} l ON l.{target} = a.anchor
                         WHERE a.value = ?1 AND EXISTS (SELECT 1 FROM blocks b WHERE b.block = l.{source})"
                    ));
                }
            }
        }
        let query = sources.iter().map(|source| format!("EXISTS ({source})")).collect::<Vec<_>>().join(" OR ");
        Ok(conn.prepare_cached(&format!("SELECT {query}"))?.query_row([id], |row| row.get(0))?)
    }

    /// Let go of these blocks' copies in the repo's own volumes, structure
    /// too, as garbage collection does: whichever can be. Returns what went,
    /// with what the blocks that went linked to.
    pub fn collect_all(&self, keys: &[Multihash]) -> Result<(Dropping, Vec<Multihash>)> {
        let mut children = std::collections::BTreeMap::new();
        for key in keys {
            if self.collectable(key.as_ref())?.is_none() {
                continue;
            }
            let Some(block) = self.readable(key.as_ref())? else {
                continue;
            };
            // A linked anchor's child is what the anchor is now, linked by an
            // IPLD link or a mount point
            let links = crate::links::links(block.cid().codec(), block.data()).unwrap_or_default();
            let mounted = mount_point(block.cid().codec(), block.data());
            for link in links.iter().chain(mounted.as_ref()) {
                let child = owned(link.multihash())?;
                children.insert(child.to_bytes(), child);
                if crate::claim::is_anchor(link)
                    && let Some(value) = self.anchor_value(link)?
                {
                    let child = owned(value.multihash())?;
                    children.insert(child.to_bytes(), child);
                }
            }
        }
        let dropping = self.let_go(keys, Self::collectable)?;
        // What's gone from here is no one's
        let mut forget = self.db.conn().prepare_cached(
            "DELETE FROM holdings WHERE block = (SELECT id FROM multihashes WHERE multihash = ?1)
                 AND block NOT IN (SELECT block FROM blocks)",
        )?;
        for key in keys {
            forget.execute([key.to_bytes()])?;
        }
        Ok((dropping, children.into_values().collect()))
    }

    /// Let go of the copies in the repo's own volumes of whichever of these
    /// blocks `pick` says where to let go of. See `drop_all`.
    fn let_go(&self, keys: &[Multihash], pick: impl Fn(&Self, Key<'_>) -> Result<Option<Vec<Placement>>>) -> Result<Dropping> {
        let mut going: std::collections::BTreeMap<Vec<u8>, (&Multihash, Vec<Placement>)> = std::collections::BTreeMap::new();
        for key in keys {
            if let Some(placed) = pick(self, key.as_ref())? {
                going.insert(key.to_bytes(), (key, placed));
            }
        }
        self.db.atomically(|| {
            let mut freed = 0u64;
            let mut kept: std::collections::BTreeMap<Vec<u8>, Multihash> = std::collections::BTreeMap::new();
            for &(key, ref placed) in going.values() {
                let id = self.db.lookup(key.as_ref())?.ok_or_else(|| Error::Volume(format!("{key:?} isn't here")))?;
                for placement in placed {
                    if placement.1 == "offset" {
                        for blob in self.offsets.as_ref().map(|offsets| offsets.kept_blobs(key.as_ref())).transpose()?.unwrap_or_default() {
                            kept.insert(blob.to_bytes(), blob);
                        }
                        continue;
                    }
                    let Some(bytes) = self.named(placement)?.remove(key.as_ref())? else {
                        return Err(Error::Volume(format!("{} can't let {key:?} go", placement.1)));
                    };
                    freed = freed.saturating_add(bytes);
                    self.unrecord(id, placement.0)?;
                }
            }
            if let Some(offsets) = &self.offsets {
                for blob in kept.values() {
                    let mut moved = 0u64;
                    for (block, elsewhere) in offsets.ranges_of(blob.as_ref())? {
                        if !elsewhere && !going.contains_key(&block.to_bytes()) {
                            moved = moved.saturating_add(self.move_out(block.as_ref(), Provenance::Unknown)?);
                        }
                    }
                    freed = freed.saturating_add(offsets.unkeep(blob.as_ref())?.saturating_sub(moved));
                }
                for &(key, ref placed) in going.values() {
                    if let Some((volume, _)) = placed.iter().find(|(_, form)| form == "offset")
                        && !offsets.ranged(key.as_ref())?
                        && let Some(id) = self.db.lookup(key.as_ref())?
                    {
                        self.unrecord(id, *volume)?;
                    }
                }
            }
            Ok(Dropping { dropped: going.values().map(|&(key, _)| key.clone()).collect(), freed })
        })
    }

    /// Files imported in place, a random sample of them or all.
    pub fn external_files(&self, sample: Option<usize>) -> Result<Vec<ExternalFile>> {
        self.offsets.as_ref().map_or_else(|| Ok(Vec::new()), |offsets| offsets.external_files(sample))
    }

    /// The files imported in place from a path, one for each version
    /// recorded.
    pub fn external_at(&self, path: &Path) -> Result<Vec<ExternalFile>> {
        self.offsets.as_ref().map_or_else(|| Ok(Vec::new()), |offsets| offsets.external_at(path))
    }

    /// Forget whichever of these files imported in place have gone or
    /// changed since, returning the blocks that leaves no longer here.
    pub fn forget_changed(&self, files: &[ExternalFile]) -> Result<Vec<Multihash>> {
        let Some(offsets) = &self.offsets else {
            return Ok(Vec::new());
        };
        self.db.reading_first(|| {
            let mut lost = Vec::new();
            for file in files.iter().filter(|file| file.changed()) {
                for key in offsets.forget_external(file)? {
                    let Some(id) = self.db.lookup(key.as_ref())? else {
                        continue;
                    };
                    for (volume, _) in self.placements(key.as_ref())?.into_iter().filter(|(_, form)| form == "offset") {
                        self.unrecord(id, volume)?;
                    }
                    if !self.has(key.as_ref())? {
                        lost.push(key);
                    }
                }
            }
            Ok(lost)
        })
    }

    /// Before files at or under `path` imported in place are changed,
    /// moved or removed, keep what they were imported as, as blocks of
    /// their own, so the DAGs they're of stay whole, and forget them as
    /// imported in place. An overlay mount's work files are imported in
    /// place as it's committed, and written to again after. Returns how
    /// many blocks were moved out.
    pub fn preserve_in_place(&self, path: &Path) -> Result<usize> {
        let Some(offsets) = &self.offsets else {
            return Ok(0);
        };
        let files = offsets.external_under(path)?;
        if files.is_empty() {
            return Ok(0);
        }
        self.db.atomically(|| {
            // What's changed already is gone, and goes first, so what's
            // left elsewhere is somewhere it can be read
            let (gone, here): (Vec<&ExternalFile>, Vec<&ExternalFile>) = files.iter().partition(|file| file.changed());
            let mut moved = 0usize;
            for file in gone.into_iter().chain(here.iter().copied()) {
                if !file.changed() {
                    for (block, elsewhere) in offsets.ranges_of(file.blob.as_ref())? {
                        if !elsewhere && self.placements(block.as_ref())?.iter().any(|(_, form)| form == "offset") {
                            self.move_out(block.as_ref(), Provenance::Superseded)?;
                            moved = moved.saturating_add(1);
                        }
                    }
                }
                for key in offsets.forget_external(file)? {
                    let Some(id) = self.db.lookup(key.as_ref())? else {
                        continue;
                    };
                    for (volume, _) in self.placements(key.as_ref())?.into_iter().filter(|(_, form)| form == "offset") {
                        self.unrecord(id, volume)?;
                    }
                }
            }
            Ok(moved)
        })
    }

    /// Move a block out of the kept file it's a range of, to be a block of
    /// its own, placed as its provenance says, returning its size.
    fn move_out(&self, key: Key<'_>, provenance: Provenance<'_>) -> Result<u64> {
        let (Some(block), Some(id)) = (self.readable(key)?, self.db.lookup(key)?) else {
            return Err(Error::Volume(format!("{key:?} can't be read out of its kept file")));
        };
        for (volume, _) in self.placements(key)?.into_iter().filter(|(_, form)| form == "offset") {
            let &volume = self.ids.get(volume).ok_or_else(|| Error::UnknownStore("offset".into()))?;
            self.db.conn().prepare_cached("DELETE FROM blocks WHERE block = ?1 AND volume = ?2")?.execute([id, volume])?;
        }
        let placed = self.place(&block, provenance)?;
        self.record(id, &placed)?;
        Ok(crate::dag::len64(block.data()))
    }

    /// Keep `older` as a delta on `newer`, if both are kept in one volume's
    /// delta store and the delta's shorter: a version of part of a file on
    /// the version written over it, so the newest is whole. Returns
    /// whether it made it one; one already a delta is left as it is.
    pub fn revise(&self, older: &Link, newer: &Link) -> Result<bool> {
        if older.multihash() == newer.multihash() {
            return Ok(false);
        }
        let in_deltas = |cid: &Link| -> Result<Vec<usize>> {
            Ok(self.placements(cid.multihash())?.into_iter().filter(|(_, form)| form == "delta").map(|(volume, _)| volume).collect())
        };
        let newer_in = in_deltas(newer)?;
        let Some(volume) = in_deltas(older)?.into_iter().find(|volume| newer_in.contains(volume)) else {
            return Ok(false);
        };
        let store = self.named(&(volume, "delta".to_owned()))?;
        if store.is_delta(older.multihash())? {
            return Ok(false);
        }
        let (Some(old), Some(new)) = (self.get_block(older)?, self.get_block(newer)?) else {
            return Ok(false);
        };
        let delta = crate::delta::encode(new.data(), old.data()).map_err(|e| Error::Volume(e.to_string()))?;
        self.db.atomically(|| {
            store.put_from(&old, Provenance::Delta { base: newer.multihash(), delta: &delta })?;
            store.is_delta(older.multihash())
        })
    }

    /// Whether a block is here: as `has`, but a dissolved claim's identity
    /// is here only if the claim is.
    pub fn holds(&self, cid: &Link) -> Result<bool> {
        if cid.hashcode() != IDENTITY {
            return self.has(cid.multihash());
        }
        match (crate::claim::dissolved(cid), &self.claims) {
            (Some(claim), Some(claims)) => claims.has_dissolved(&claim),
            (Some(_), None) => Ok(false),
            (None, _) => Ok(true),
        }
    }

    /// A CID for a block by its multihash: the first it was put with, or a
    /// dissolved claim's.
    pub fn cid_of(&self, key: Key<'_>) -> Result<Option<Link>> {
        if key.code() == IDENTITY {
            return Ok(crate::claim::dissolved_cid(key.digest_ref()));
        }
        Ok(self.cids(key)?.into_iter().next())
    }

    /// The copies of a block the catalog knows of, on its volumes attached
    /// or not.
    pub fn replicas(&self, key: Key<'_>) -> Result<Vec<Replica>> {
        let Some(id) = self.db.lookup(key)? else {
            return Ok(Vec::new());
        };
        let volumes: Vec<(Id, Vec<u8>)> = self.db.conn()
            .prepare_cached("SELECT v.id, v.label FROM blocks b JOIN volumes v ON v.id = b.volume WHERE b.block = ?1 ORDER BY v.id")?
            .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        volumes.into_iter().map(|(volume, label)| Ok(Replica { label, risks: self.risks(volume)? })).collect()
    }

    /// Where this catalog would keep a block another node sends it: its own
    /// volume, or failing that its first.
    pub fn offer(&self) -> Result<Offer> {
        let v = self.own().unwrap_or_default();
        let (Some(&id), Some(volume)) = (self.ids.get(v), self.volumes.get(v)) else {
            return Ok(Offer { risks: Vec::new(), free: None });
        };
        Ok(Offer { risks: self.risks(id)?, free: volume.path().and_then(free_space) })
    }

    /// A block as it can be read now, verified, under the first CID it was
    /// put with; or None if no copy can be read.
    pub fn read_block(&self, key: Key<'_>) -> Result<Option<Block>> {
        self.readable(key)
    }

    /// Copy every block until it would take at least `copies` failures to
    /// lose it, as if it had that many copies sharing no risks, where
    /// attached volumes allow. Each copy goes wherever adds most. Returns
    /// how many copies were made, and the blocks still short of that.
    pub fn replicate(&self, copies: usize) -> Result<Replication> {
        let mut report = Replication::default();
        for key in self.keys()? {
            let Some(id) = self.db.lookup(key.as_ref())? else {
                continue;
            };
            let mut held = self.copy_risks(id)?;
            let mut tolerance = volume::tolerance(&held, copies);
            if tolerance >= copies {
                continue;
            }
            let Some(block) = self.readable(key.as_ref())? else {
                report.short.push(key);
                continue;
            };
            let mut tried: Vec<usize> = self.placements(key.as_ref())?.into_iter().map(|(v, _)| v).collect();
            while tolerance < copies {
                let mut best = None;
                for (v, &volume) in self.ids.iter().enumerate() {
                    if tried.contains(&v) {
                        continue;
                    }
                    let risks = self.risks(volume)?;
                    let with = volume::tolerance(&[held.as_slice(), std::slice::from_ref(&risks)].concat(), copies);
                    if with > best.as_ref().map_or(tolerance, |&(_, t, _)| t) {
                        best = Some((v, with, risks));
                    }
                }
                let Some((v, with, risks)) = best else {
                    break;
                };
                tried.push(v);
                if self.copy_into(v, id, &block)? {
                    held.push(risks);
                    tolerance = with;
                    report.copied = report.copied.saturating_add(1);
                }
            }
            if tolerance < copies {
                report.short.push(key);
            }
        }
        // Dissolved claims aren't blocks, so they've no copies to count;
        // they're small, so every database volume keeps them all
        let dissolved = self.claims.as_ref().map_or_else(|| Ok(Vec::new()), |claims| claims.dissolved())?;
        for v in 0..self.volumes.len() {
            report.claims = report.claims.saturating_add(self.copy_dissolved(v, &dissolved)?);
        }
        Ok(report)
    }

    /// Copy blocks to a volume, wherever it is: those under the roots, or
    /// every block if there are none. Claims about what's copied go too,
    /// and tombs retracting them, so tags go where what they tag does.
    /// Returns how many were copied, and the blocks which couldn't be read
    /// to be.
    pub fn copy_to(&self, name: &str, roots: &[Link]) -> Result<CopyReport> {
        let v = self.volumes.iter().position(|volume| volume.name == name)
            .ok_or_else(|| Error::Volume(format!("no volume called {name:?} is attached")))?;
        let mut report = CopyReport::default();
        let mut copy = |key: Multihash| -> Result<Option<Block>> {
            let Some(id) = self.db.lookup(key.as_ref())? else {
                report.unreadable.push(key);
                return Ok(None);
            };
            let Some(block) = self.readable(key.as_ref())? else {
                report.unreadable.push(key);
                return Ok(None);
            };
            if !self.placements(key.as_ref())?.iter().any(|&(held, _)| held == v) && self.copy_into(v, id, &block)? {
                report.copied = report.copied.saturating_add(1);
            }
            Ok(Some(block))
        };
        if roots.is_empty() {
            for key in self.keys()? {
                copy(key)?;
            }
            let dissolved = self.claims.as_ref().map_or_else(|| Ok(Vec::new()), |claims| claims.dissolved())?;
            report.claims = self.copy_dissolved(v, &dissolved)?;
            return Ok(report);
        }
        let mut seen = std::collections::HashSet::new();
        let mut stack: Vec<Link> = roots.to_vec();
        let mut claims = Vec::new();
        while let Some(cid) = stack.pop() {
            if cid.hashcode() == IDENTITY || !seen.insert(cid.multihash().to_bytes()) {
                continue;
            }
            let key = owned(cid.multihash())?;
            claims.extend(self.claims_about(key.as_ref())?);
            if let Some(block) = copy(key)? {
                stack.extend(crate::links::links(cid.codec(), block.data()).unwrap_or_default());
            }
        }
        // A claim's own links are what it's about, not part of the DAG;
        // only what's about it, tombs, follows it
        let mut dissolved = Vec::new();
        while let Some(key) = claims.pop() {
            if !seen.insert(key.to_bytes()) {
                continue;
            }
            if key.code() == IDENTITY {
                dissolved.extend(crate::claim::dissolved_cid(key.digest_ref()).as_ref().and_then(crate::claim::dissolved));
                continue;
            }
            claims.extend(self.claims_about(key.as_ref())?);
            copy(key)?;
        }
        // A tombed dissolved claim is gone, leaving its tomb, which says
        // what it was
        if let Some(store) = &self.claims {
            for tomb in store.dissolved()? {
                let about = |claim: &Claim| claim.target().iter().any(|target| seen.contains(&target.multihash().to_bytes()));
                if tomb.target().iter().filter_map(crate::claim::dissolved).any(|claim| about(&claim)) {
                    dissolved.push(tomb);
                }
            }
        }
        report.claims = self.copy_dissolved(v, &dissolved)?;
        Ok(report)
    }

    /// Put a block in the first of a volume's stores which takes it.
    /// Returns whether one did.
    fn copy_into(&self, v: usize, id: Id, block: &Block) -> Result<bool> {
        let Some(volume) = self.volumes.get(v) else {
            return Ok(false);
        };
        for store in volume.stores() {
            if store.put(block)? == Put::Stored {
                self.record(id, &(v, store.name().to_owned()))?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A block as it can be read now, under the first CID it was put with,
    /// verified; or None if no copy can be read.
    fn readable(&self, key: Key<'_>) -> Result<Option<Block>> {
        let Ok(Some(data)) = self.get(key) else {
            return Ok(None);
        };
        let cid = match self.cids(key)?.into_iter().next() {
            Some(cid) => cid.into(),
            None => Cidv1::new(crate::cid::RAW_CODEC, decode_key("router", &key.to_bytes())?),
        };
        Ok(Block::verify(cid, data.into_boxed_slice()).ok())
    }

    /// Run `f` in one transaction, for speed and so that a failed import
    /// leaves nothing behind. Other databases written to get one each,
    /// committed first: if the catalog's then fails, what they gained is
    /// caught up with.
    pub fn batch<T, E: From<Error>>(&mut self, f: impl FnOnce(&mut Self) -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        let mut dbs: Vec<Db> = (0..self.volumes.len()).filter_map(|v| self.foreign_db(v).cloned()).collect();
        dbs.push(self.db.clone());
        for db in &dbs {
            db.begin()?;
        }
        self.batching = self.batching.saturating_add(1);
        let mut result = f(self);
        self.batching = self.batching.saturating_sub(1);
        if self.batching == 0 {
            let signed = if result.is_ok() { self.sign_batch() } else { self.unsigned.take().clear(); Ok(()) };
            if let (Ok(_), Err(e)) = (&result, signed) {
                result = Err(e.into());
            }
        }
        let end = if result.is_ok() { "COMMIT" } else { "ROLLBACK" };
        for db in &dbs {
            // None, if it failed for want of the lock after a breath
            if !db.conn().is_autocommit() {
                db.conn().execute_batch(end).map_err(Error::from)?;
            }
        }
        result
    }

    /// A batch for a big import, which lets others write as it goes: what
    /// it's done so far is committed every so often, wherever it says it
    /// can [`Self::breathe`]. So it may leave some behind if it fails, which
    /// is only blocks nothing refers to, there for it to skip when tried
    /// again, and collected if it isn't.
    pub fn batch_breathing<T, E: From<Error>>(&mut self, f: impl FnOnce(&mut Self) -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        self.batch_breathing_every(BREATHE_EVERY, f)
    }

    fn batch_breathing_every<T, E: From<Error>>(&mut self, every: std::time::Duration, f: impl FnOnce(&mut Self) -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        self.breathing.set(Some((every, std::time::Instant::now())));
        let result = self.batch(f);
        self.breathing.set(None);
        result
    }

    /// Let others write, if this is a batch that breathes and it's time.
    /// Only where nothing's half done but what a file's ranges wait on, for
    /// which it goes on holding its breath: a range's block is placed before
    /// its range is known, so its file must be settled first. So a big file
    /// holds the lock for as long as it takes to read.
    pub fn breathe(&self) -> Result<()> {
        let Some((every, last)) = self.breathing.get() else {
            return Ok(());
        };
        if self.batching != 1 || last.elapsed() < every || self.offsets.as_ref().is_some_and(|offsets| offsets.is_pending().unwrap_or(true)) {
            return Ok(());
        }
        self.sign_batch()?;
        let mut dbs: Vec<Db> = (0..self.volumes.len()).filter_map(|v| self.foreign_db(v).cloned()).collect();
        dbs.push(self.db.clone());
        for db in &dbs {
            db.conn().execute_batch("COMMIT")?;
        }
        std::thread::sleep(BREATH);
        self.wait_for_writers(BREATHING_WAIT)?;
        for db in &dbs {
            db.begin()?;
        }
        self.breathing.set(Some((every, std::time::Instant::now())));
        Ok(())
    }

    /// The claim store, if there is one.
    pub fn claims(&self) -> Option<&ClaimStore> {
        self.claims.as_deref()
    }

    /// Tag a block, with a claim of its own so it can be retracted alone.
    /// Returns the claim's CID.
    pub fn tag(&self, target: &Link, tag: &Link) -> Result<Link> {
        let claim = Claim::Group(Group::new([target.clone()], tag.clone()).ok_or(Error::NoClaims)?);
        self.put_claim(&claim)
    }

    /// Keep a block, and what it links to, with a claim of its own so it
    /// can be let go of alone. Returns the claim's CID.
    pub fn keep(&self, target: &Link) -> Result<Link> {
        self.keep_short_of(target, &[])
    }

    /// Keep a block and what it links to, asking for `copies` failures to
    /// lose what this is the nearest keep of, rather than what the mesh
    /// runs with. Returns the keep's CID.
    pub fn keep_copies(&self, target: &Link, copies: usize) -> Result<Link> {
        self.keep_as(target, &[], Some(u64::try_from(copies).unwrap_or(u64::MAX)))
    }

    /// Keep a block and what it links to, short of a frontier: links the
    /// keep's reach stops at. Returns the keep's CID.
    pub fn keep_short_of(&self, target: &Link, beyond: &[Link]) -> Result<Link> {
        self.keep_as(target, beyond, None)
    }

    /// Keep a block and what it links to, short of a frontier, asking for
    /// `copies` failures to lose what this is the nearest keep of, if it
    /// says. Returns the keep's CID.
    pub fn keep_as(&self, target: &Link, beyond: &[Link], copies: Option<u64>) -> Result<Link> {
        let claims = self.claims.as_ref().ok_or(Error::NoClaims)?;
        let keep = crate::claim::Keep::bounded([target.clone()], beyond.iter().cloned()).ok_or(Error::NoClaims)?.with_copies(copies);
        // A tomb is forever, so keeping again once a keep's been tombed takes
        // the next time that hasn't been
        let mut n = 0u64;
        let claim = loop {
            let claim = Claim::Keep(keep.clone().again(n));
            if !claims.retracted(&claim.cid())? {
                break claim;
            }
            n = n.saturating_add(1);
        };
        self.put_claim(&claim)
    }

    /// Whether a keep that counts for anyone reaches a block, by its
    /// backrefs: the block, or anything linking to it however indirectly,
    /// is a keep's target; an anchor links to what it is now. Without
    /// claims to keep, everything is kept.
    pub fn kept_under(&self, key: Key<'_>) -> Result<bool> {
        self.kept_under_by(key, claims::LIVE_ANY, "anchor_values_any")
    }

    /// Whether a keep that counts for the acting account's user reaches a
    /// block: whether its mesh keeps it, as far as this node can say.
    pub fn kept_for_acting(&self, key: Key<'_>) -> Result<bool> {
        self.kept_under_by(key, claims::LIVE, "anchor_values")
    }

    /// How many failures it should take to lose a block, for the acting
    /// account's user: along each path up from it, by links and from
    /// anchors' values, the nearest keep says, as its `copies` or else
    /// `default`; of every path, the most. None if no keep reaches it.
    pub fn copies_wanted(&self, key: Key<'_>, default: usize) -> Result<Option<usize>> {
        if self.claims.is_none() {
            return Ok(Some(default));
        }
        let live = claims::LIVE;
        let kept = format!(
            "EXISTS (SELECT 1 FROM claim_targets t JOIN claims c ON c.id = t.claim WHERE t.target = up.id AND c.kind = 'keep' AND {live})"
        );
        let most: Option<i64> = self.db.conn()
            .prepare_cached(&format!(
                "WITH RECURSIVE up (id) AS (
                     SELECT id FROM multihashes WHERE multihash = ?1
                     UNION SELECT l.source FROM links l JOIN up ON l.target = up.id WHERE NOT {kept}
                     UNION SELECT a.anchor FROM anchor_values a JOIN up ON a.value = up.id WHERE NOT {kept}
                 )
                 SELECT max(coalesce(k.copies, ?2)) FROM up
                 JOIN claim_targets t ON t.target = up.id
                 JOIN claims c ON c.id = t.claim
                 LEFT JOIN keep_copies k ON k.claim = c.id
                 WHERE c.kind = 'keep' AND {live}"
            ))?
            .query_row(params![key.to_bytes(), i64::try_from(default).unwrap_or(i64::MAX)], |row| row.get(0))?;
        Ok(most.map(|most| usize::try_from(most).unwrap_or(default)))
    }

    fn kept_under_by(&self, key: Key<'_>, live: &str, anchors: &str) -> Result<bool> {
        if self.claims.is_none() {
            return Ok(true);
        }
        Ok(self.db.conn()
            .prepare_cached(&format!(
                "WITH RECURSIVE up (id) AS (
                     SELECT id FROM multihashes WHERE multihash = ?1
                     UNION SELECT l.source FROM links l JOIN up ON l.target = up.id
                     UNION SELECT a.anchor FROM {anchors} a JOIN up ON a.value = up.id
                 )
                 SELECT 1 FROM up
                 JOIN claim_targets t ON t.target = up.id
                 JOIN claims c ON c.id = t.claim
                 WHERE c.kind = 'keep' AND {live} LIMIT 1"
            ))?
            .exists([key.to_bytes()])?)
    }

    /// Whether a block is in the repo of the account this acts for: it
    /// put it here within the grace period, a keep that counts for its
    /// user reaches it, or it's a claim no other account alone signed.
    /// Anything else here is another account's, which this one can't
    /// read, serve or hear of. Without claims, everything is anyone's.
    pub fn visible(&self, key: Key<'_>) -> Result<bool> {
        let Some(claims) = &self.claims else {
            return Ok(true);
        };
        // An identity block is its CID, so it hides nothing, but a
        // dissolved claim is still someone's to tell
        if key.code() == IDENTITY {
            return Ok(!claims.withheld(key, self.uid)?);
        }
        let held = self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM holdings h JOIN multihashes m ON m.id = h.block
                 WHERE m.multihash = ?1 AND h.uid = ?2 AND h.since >= ?3",
            )?
            .exists(params![key.to_bytes(), self.uid, held_since()])?;
        if held || self.kept_for_acting(key)? {
            return Ok(true);
        }
        Ok(claims.has(key)? && !claims.withheld(key, self.uid)?)
    }

    /// Whether a block is in any other account's repo: put here by it
    /// within the grace period, or reached by a keep that counts for
    /// another user. Copies the acting account's mesh can spare are only
    /// spare here if it isn't.
    pub fn visible_to_others(&self, key: Key<'_>) -> Result<bool> {
        let others = self.db.conn().prepare_cached("SELECT 1 FROM holdings WHERE uid != ?1 LIMIT 1")?.exists([self.uid])?
            || self.db.conn().prepare_cached("SELECT 1 FROM accounts WHERE uid != ?1 LIMIT 1").and_then(|mut stmt| stmt.exists([self.uid])).unwrap_or(false);
        if self.claims.is_none() || !others {
            return Ok(false);
        }
        let held = self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM holdings h JOIN multihashes m ON m.id = h.block
                 WHERE m.multihash = ?1 AND h.uid != ?2 AND h.since >= ?3",
            )?
            .exists(params![key.to_bytes(), self.uid, held_since()])?;
        Ok(held || self.kept_under_by(key, claims::LIVE_OTHERS, "anchor_values_any")?)
    }

    /// What isn't here of the DAG under a root: each block linked to,
    /// the root included, which isn't held or can't be read. What's
    /// missing isn't walked into, so it's only the edge of what's here;
    /// nor is what a keep walked through has beyond its frontier.
    ///
    /// A node only keeps what it holds all of: whatever else is
    /// collecting what a keep links to, the keeper's copy survives, and
    /// is replicated again from there.
    pub fn missing_under(&self, root: &Link) -> Result<Vec<Link>> {
        let mut seen = std::collections::BTreeSet::new();
        let mut queue = vec![root.clone()];
        let mut missing = Vec::new();
        while let Some(cid) = queue.pop() {
            if !seen.insert(cid.to_bytes()) {
                continue;
            }
            let data = if cid.hashcode() == IDENTITY {
                self.holds(&cid)?.then(|| cid.digest_ref().to_vec())
            }
            else {
                self.get_block(&cid).ok().flatten().map(|block| block.data().to_vec())
            };
            let Some(data) = data else {
                missing.push(cid);
                continue;
            };
            // An anchor is what it is now
            if crate::claim::is_anchor(&cid) {
                queue.extend(self.anchor_value(&cid)?);
                continue;
            }
            if cid.codec() == crate::cid::DAG_CBOR_CODEC
                && let Some(Claim::Keep(keep)) = Claim::parse(&data)
            {
                seen.extend(keep.beyond().iter().map(Link::to_bytes));
                queue.extend(keep.target().iter().cloned());
                continue;
            }
            queue.extend(crate::links::links(cid.codec(), &data).unwrap_or_default());
        }
        Ok(missing)
    }

    /// The mount at a path, if there's one.
    pub fn mount_at(&self, path: &Path) -> Result<Option<Mount>> {
        Ok(self.mounts()?.into_iter().find(|mount| mount.path == path))
    }

    /// The mounts a path is, or is under.
    pub fn mounts_over(&self, path: &Path) -> Result<Vec<Mount>> {
        Ok(self.mounts()?.into_iter().filter(|mount| path.starts_with(&mount.path)).collect())
    }

    pub fn mounts(&self) -> Result<Vec<Mount>> {
        let mut stmt = self.db.conn().prepare_cached("SELECT anchor, path, chunk_size, width, hidden, overlay FROM mounts ORDER BY path")?;
        let rows = stmt.query_map([], |row| Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, bool>(4)?,
            row.get::<_, bool>(5)?,
        )))?;
        rows.map(|row| {
            let (anchor, path, chunk_size, width, hidden, overlay) = row?;
            Ok(Mount {
                anchor: Link::decode(&anchor).map_err(|e| Error::Invalid { store: "router", reason: format!("anchor: {e:?}") })?,
                path: path_from(&path),
                chunk_size: usize::try_from(chunk_size).unwrap_or_default(),
                width: usize::try_from(width).unwrap_or_default(),
                hidden,
                overlay,
            })
        })
        .collect()
    }

    /// Record a mount, replacing whatever was at its path.
    pub fn mount(&self, mount: &Mount) -> Result<()> {
        self.db.conn()
            .prepare_cached("INSERT OR REPLACE INTO mounts (anchor, path, chunk_size, width, hidden, overlay) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
            .execute(params![
                mount.anchor.to_bytes(),
                path_bytes(&mount.path),
                i64::try_from(mount.chunk_size).unwrap_or(i64::MAX),
                i64::try_from(mount.width).unwrap_or(i64::MAX),
                mount.hidden,
                mount.overlay,
            ])?;
        Ok(())
    }

    /// Import a path in place, mounted on its anchor, or a new one: the
    /// anchor's set to what it's imported as, if that's new. Returns the
    /// mount and what it's now.
    pub fn import_mounted(&mut self, importer: &crate::import::Importer, path: &Path, report: &mut dyn FnMut(&Path, &crate::dag::DagLink)) -> Result<(Mount, Link)> {
        let path = std::fs::canonicalize(path)?;
        let root = importer
            .add_path(&path, &mut InPlace::new(self), &mut |p: &Path, link: &crate::dag::DagLink| report(p, link))?
            .ok_or_else(|| Error::Invalid { store: "router", reason: format!("unsupported file type: {}", path.display()) })?;
        let root: Link = root.cid.into();
        let anchor = match self.mount_at(&path)? {
            Some(mount) => mount.anchor,
            None => self.new_anchor()?,
        };
        let mount = Mount { anchor, path, chunk_size: importer.chunk_size, width: importer.layout.width, hidden: importer.hidden, overlay: false };
        self.mount(&mount)?;
        if self.anchor_value(&mount.anchor)?.as_ref() != Some(&root) {
            self.set_anchor(&mount.anchor, &root)?;
        }
        Ok((mount, root))
    }

    /// Import an overlay mount again as [`Self::remount`] does, setting
    /// its anchor only if `still()` says nothing was written to it while
    /// it was imported. Returns what it's now, or none if something was.
    pub fn remount_if(&mut self, mount: &Mount, still: &dyn Fn() -> bool) -> Result<Option<Link>> {
        self.batch(|catalog| catalog.import_overlay_if(mount, still))
    }

    /// Import a mount again, as it's changed. Returns what it's now.
    pub fn remount(&mut self, mount: &Mount) -> Result<Link> {
        if mount.overlay {
            return self.batch(|catalog| catalog.import_overlay(mount));
        }
        let importer = mount.importer();
        let path = mount.path.clone();
        self.batch(|catalog| catalog.import_mounted(&importer, &path, &mut |_, _| {}).map(|(_, root)| root))
    }

    /// A new anchor, an empty identity to hang claims on.
    pub fn new_anchor(&self) -> Result<Link> {
        Ok(crate::claim::anchor()?)
    }

    /// Say an anchor is `value` now, in place of every head it has,
    /// which merges a fork: returning the set's CID.
    pub fn set_anchor(&self, anchor: &Link, value: &Link) -> Result<Link> {
        let heads = self.claims.as_ref().ok_or(Error::NoClaims)?.heads(anchor.multihash())?;
        self.put_set(anchor, value, heads.into_iter().map(|(set, _, _)| set).collect())
    }

    /// Say an anchor is `value` too, beside whatever it is, replacing
    /// nothing: a fork, merged with what it is. What a repo named before
    /// joining a mesh joins what the mesh names so.
    pub fn set_anchor_beside(&self, anchor: &Link, value: &Link) -> Result<Link> {
        self.put_set(anchor, value, Vec::new())
    }

    fn put_set(&self, anchor: &Link, value: &Link, prev: Vec<Link>) -> Result<Link> {
        // After the latest, so it's what the anchor is even within a second
        let latest = self.anchor_history(anchor)?.last().map_or(0, |&(at, _)| at.saturating_add(1));
        let at = now().max(latest);
        let set = crate::claim::Set::new([anchor.clone()], value.clone(), at).ok_or(Error::NoClaims)?.after(Some(prev));
        self.put_claim(&Claim::Set(set))
    }

    /// What an anchor is now, if any set says: its head, or its heads,
    /// merged, where it's forked.
    pub fn anchor_value(&self, anchor: &Link) -> Result<Option<Link>> {
        let heads = self.claims.as_ref().ok_or(Error::NoClaims)?.heads(anchor.multihash())?;
        match heads.as_slice() {
            [] => Ok(None),
            [(_, value, _)] => Ok(Some(value.clone())),
            _ => {
                let key: Vec<u8> = heads.iter().flat_map(|(set, _, _)| set.to_bytes()).collect();
                if let Some(merged) = self.merges.borrow().get(&key) {
                    return Ok(Some(merged.clone()));
                }
                let merged = self.merge_heads(anchor, &heads)?;
                self.merges.borrow_mut().insert(key, merged.clone());
                Ok(Some(merged))
            },
        }
    }

    /// Every set of an anchor that counts, as (set, value, at, prev), by
    /// `at`: its history, as a graph.
    pub fn sets_of(&self, anchor: &Link) -> Result<Vec<SetOf>> {
        self.claims.as_ref().ok_or(Error::NoClaims)?.sets(anchor.multihash())
    }

    /// Fetch what isn't here through a running node, as read: as the mount
    /// does, whose overlays and forks are of what may be only elsewhere.
    pub fn fetch_through(&mut self, fetcher: Fetcher) {
        self.fetcher = Some(fetcher);
    }

    /// Ask the node for blocks that aren't here, if this fetches through
    /// one, saying whether it could ask. In a transaction, the node's
    /// writing them would wait on it, so they're noted instead, for
    /// whoever's in it to fetch once it's over (see `take_missed`).
    pub fn fetch_missing(&self, cids: &[Link]) -> bool {
        let Some(fetcher) = &self.fetcher else {
            return false;
        };
        if !self.db.conn().is_autocommit() {
            self.missed.borrow_mut().extend_from_slice(cids);
            return false;
        }
        let asking: Vec<Link> = cids.iter().filter(|cid| self.worth_asking_for(cid)).cloned().collect();
        !asking.is_empty() && fetcher(&asking)
    }

    /// Whether to ask members for a block that isn't here: yes, unless it's
    /// reported lost and has been asked for lately.
    pub fn worth_asking_for(&self, cid: &Link) -> bool {
        if !self.lost_at(cid).is_ok_and(|at| at.is_some()) {
            return true;
        }
        let mut asked = self.lost_asked.borrow_mut();
        let due = asked.get(&cid.to_bytes()).is_none_or(|when| when.elapsed() >= ASK_FOR_LOST);
        if due {
            asked.insert(cid.to_bytes(), std::time::Instant::now());
        }
        due
    }

    /// When a block that isn't here was reported lost, if it was. One that's
    /// here isn't, whatever was said: it's turned up.
    pub fn lost_at(&self, cid: &Link) -> Result<Option<u64>> {
        if self.has(cid.multihash())? {
            return Ok(None);
        }
        self.claims.as_ref().map_or(Ok(None), |claims| claims.lost(cid.multihash()))
    }

    /// What's reported lost and isn't here, as (block, when), by multihash.
    pub fn lost_blocks(&self) -> Result<Vec<(Link, u64)>> {
        let Some(claims) = &self.claims else {
            return Ok(Vec::new());
        };
        let mut lost = claims.all_lost()?;
        lost.retain(|(cid, _)| !self.has(cid.multihash()).unwrap_or(true));
        Ok(lost)
    }

    /// Report a block lost as of now, unless it's here or already said to be
    /// lost. Returns the claim.
    pub fn report_lost(&self, cid: &Link) -> Result<Option<Link>> {
        if self.lost_at(cid)?.is_some() || self.has(cid.multihash())? {
            return Ok(None);
        }
        let lost = crate::claim::Lost::new([cid.clone()], now()).ok_or(Error::NoClaims)?;
        self.put_claim(&Claim::Lost(lost)).map(Some)
    }

    /// Take back reports that a block's lost. Returns the tombs' CIDs.
    pub fn unreport_lost(&self, cid: &Link) -> Result<Vec<Link>> {
        let claims = self.claims.as_ref().ok_or(Error::NoClaims)?;
        let mut tombs = Vec::new();
        for lost in claims.losing(cid.multihash())? {
            tombs.push(self.put_claim(&Claim::Tomb(Tomb::new([lost]).ok_or(Error::NoClaims)?))?);
        }
        Ok(tombs)
    }

    /// A block's gone, without anyone having let go of it.
    #[cfg(all(test, feature = "net"))]
    pub(crate) fn lose(&self, key: Key<'_>) -> Result<usize> {
        Ok(self.db.conn().execute("DELETE FROM blocks WHERE block = (SELECT id FROM multihashes WHERE multihash = ?1)", [key.to_bytes()])?)
    }

    /// What's gone without anyone meaning it to, by what's known here, not
    /// yet reported lost: blocks once held here, which nothing has let go of,
    /// as collecting forgets they were, that something still refers to. A
    /// file imported in place changed, say, or a volume's copy gone. Whether
    /// it's lost is then for whoever else might have it to say.
    pub fn lost_candidates(&self) -> Result<Vec<Link>> {
        let rows: Vec<Vec<u8>> = self.db.conn()
            .prepare_cached(
                "SELECT DISTINCT m.multihash FROM holdings h JOIN multihashes m ON m.id = h.block
                 WHERE h.block NOT IN (SELECT block FROM blocks) ORDER BY m.multihash",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut found = Vec::new();
        for bytes in rows {
            let key = decode_key("router", &bytes)?;
            if self.has(key.as_ref())? || self.backrefs(key.as_ref())?.is_empty() {
                continue;
            }
            if let Some(cid) = self.cid_of(key.as_ref())?
                && self.lost_at(&cid)?.is_none()
            {
                found.push(cid);
            }
        }
        Ok(found)
    }

    /// What was found missing in a transaction since last asked, to fetch
    /// now it's over and try again.
    pub fn take_missed(&self) -> Vec<Link> {
        std::mem::take(&mut *self.missed.borrow_mut())
    }

    /// An anchor's heads, as (set, value, at), by `at`: more than one where
    /// it's forked.
    pub fn anchor_heads(&self, anchor: &Link) -> Result<Vec<(Link, Link, u64)>> {
        self.claims.as_ref().ok_or(Error::NoClaims)?.heads(anchor.multihash())
    }

    /// Every set of an anchor that counts, as (at, value), oldest first.
    pub fn anchor_history(&self, anchor: &Link) -> Result<Vec<(u64, Link)>> {
        self.claims.as_ref().ok_or(Error::NoClaims)?.history(anchor.multihash())
    }

    /// Stop keeping a block, tombing every keep of it. Returns the tombs'
    /// CIDs.
    pub fn unkeep(&self, target: &Link) -> Result<Vec<Link>> {
        let claims = self.claims.as_ref().ok_or(Error::NoClaims)?;
        let mut tombs = Vec::new();
        for keep in claims.keeping(target.multihash())? {
            let tomb = Claim::Tomb(Tomb::new([keep]).ok_or(Error::NoClaims)?);
            tombs.push(self.put_claim(&tomb)?);
        }
        Ok(tombs)
    }

    /// Untag a block, tombing every claim tagging it with the tag. A claim
    /// is retracted whole, so whatever else one tagged is tagged again on
    /// its own. Returns the tombs' CIDs.
    pub fn untag(&self, target: &Link, tag: &Link) -> Result<Vec<Link>> {
        let claims = self.claims.as_ref().ok_or(Error::NoClaims)?;
        let mut tombs = Vec::new();
        for (claim, group) in claims.tagging(target.multihash(), tag.multihash())? {
            let tomb = Claim::Tomb(Tomb::new([claim]).ok_or(Error::NoClaims)?);
            tombs.push(self.put_claim(&tomb)?);
            for other in group.target().iter().filter(|other| other.multihash() != target.multihash()) {
                self.tag(other, tag)?;
            }
        }
        Ok(tombs)
    }

    /// Where a block is, in attached volumes, in volume order.
    pub fn placements(&self, key: Key<'_>) -> Result<Vec<Placement>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT b.volume, f.name FROM multihashes m
             JOIN blocks b ON b.block = m.id
             JOIN forms f ON f.id = b.form
             WHERE m.multihash = ?1",
        )?;
        let rows = stmt.query_map([key.to_bytes()], |row| Ok((row.get::<_, Id>(0)?, row.get::<_, String>(1)?)))?;
        let mut found = Vec::new();
        for row in rows {
            let (id, form) = row?;
            if let Some(volume) = self.ids.iter().position(|&attached| attached == id) {
                found.push((volume, form));
            }
        }
        found.sort();
        Ok(found)
    }

    /// Which form a block is in, in the first attached volume that has it.
    pub fn store_of(&self, key: Key<'_>) -> Result<Option<String>> {
        Ok(self.placements(key)?.into_iter().next().map(|(_, form)| form))
    }

    fn named(&self, (volume, form): &Placement) -> Result<&dyn Store> {
        self.volumes
            .get(*volume)
            .and_then(|v| v.form(form))
            .ok_or_else(|| Error::UnknownStore(form.clone()))
    }

    /// Put a block, returning the name of the store it's in.
    pub fn put_block(&self, block: &Block, version: CidVersion) -> Result<String> {
        self.put_block_from(block, version, Provenance::Unknown)
    }

    /// Put a block along with where its bytes came from.
    ///
    /// A block already present stays where it is, but its store hears of
    /// the provenance too: an offset store can then keep a block as part
    /// of several files, and serve it while any of them is unchanged.
    pub fn put_block_from(&self, block: &Block, version: CidVersion, provenance: Provenance<'_>) -> Result<String> {
        let key = block.cid().multihash();
        // An identity block is its CID, so there's nothing to keep, unless
        // it's a dissolved claim, which the claim store keeps as rows
        if key.code() == IDENTITY {
            if let Some(claims) = &self.claims
                && claims.put(block)? == Put::Stored
            {
                return Ok(claims.name().to_owned());
            }
            return Ok("identity".to_owned());
        }
        let prefix = cid_prefix(block.cid(), version);
        self.db.atomically(|| {
            let id = self.db.intern(key)?;
            let new_cid = self.db.conn()
                .prepare_cached("INSERT OR IGNORE INTO block_cids (block, prefix) VALUES (?1, ?2)")?
                .execute(params![id, prefix])? > 0;
            let placed = if let Some(placed) = self.placements(key)?.into_iter().next() {
                if provenance != Provenance::Unknown {
                    self.named(&placed)?.put_from(block, provenance)?;
                }
                placed
            }
            else {
                let placed = self.place(block, provenance)?;
                self.record(id, &placed)?;
                self.commits.borrow_mut().arrived(block);
                placed
            };
            // Read under each codec it's put with, since that's what says
            // where its links are
            if new_cid && self.named(&placed)?.refs().is_none() {
                self.index_links(id, block.cid().codec(), block.data())?;
            }
            if new_cid && let Some(anchor) = mount_point(block.cid().codec(), block.data()) {
                self.index_mount_point(id, &anchor)?;
            }
            self.db.conn()
                .prepare_cached(
                    "INSERT INTO holdings (uid, block, since, size) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (uid, block) DO UPDATE SET since = excluded.since, size = excluded.size",
                )?
                .execute(params![self.uid, id, i64::try_from(now()).unwrap_or(i64::MAX), i64::try_from(block.data().len()).unwrap_or(i64::MAX)])?;
            Ok(placed.1)
        })
    }

    /// Index the links of a block in a store which doesn't. A block that
    /// can't be read under its codec has none.
    fn index_links(&self, id: Id, codec: u64, data: &[u8]) -> Result<()> {
        let Ok(links) = crate::links::links(codec, data) else {
            return Ok(());
        };
        let mut stmt = self.db.conn().prepare_cached("INSERT OR IGNORE INTO refs (source, target) VALUES (?1, ?2)")?;
        for link in links {
            stmt.execute(params![id, self.db.intern(link.multihash())?])?;
        }
        Ok(())
    }

    /// Make a change to what's in the repo once, if it hasn't been.
    fn migrate<T>(&self, name: &str, change: impl FnOnce(&Self) -> Result<T>) -> Result<()> {
        let done = self.db.conn().prepare_cached("SELECT 1 FROM migrations WHERE name = ?1")?.exists([name])?;
        if done {
            return Ok(());
        }
        self.db.atomically(|| {
            change(self)?;
            self.db.conn()
                .prepare_cached("INSERT INTO migrations (name, at) VALUES (?1, ?2)")?
                .execute(params![name, i64::try_from(now()).unwrap_or(i64::MAX)])?;
            Ok(())
        })
    }

    /// Note a mount point's link to the anchor it mounts, as a link: what
    /// keeps a directory keeps what it mounts.
    fn index_mount_point(&self, id: Id, anchor: &Link) -> Result<()> {
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO refs (source, target) VALUES (?1, ?2)")?
            .execute(params![id, self.db.intern(anchor.multihash())?])?;
        Ok(())
    }

    /// Note every mount point the UnixFS store holds, as a link to the
    /// anchor it mounts. Returns how many there are.
    fn index_mount_points(&self) -> Result<usize> {
        let found: Vec<(Id, Vec<u8>)> = self.db.conn()
            .prepare(&format!(
                "SELECT block, data FROM unixfs_nodes WHERE type = {} AND substr(data, 1, 9) = CAST('/anchors/' AS BLOB)",
                u64::from(crate::unixfs::DataType::Symlink)
            ))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut count = 0usize;
        for (id, target) in found {
            if let Some(anchor) = crate::claim::anchor_target(&target) {
                self.index_mount_point(id, &anchor)?;
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// Keep the root anchor of who this acts for, if it isn't kept: what it
    /// names, and what they mount, is kept through it. Returns the keep's
    /// CID, if it made one.
    pub fn keep_root(&self) -> Result<Option<Link>> {
        let (Some(root), Some(claims)) = (self.root_anchor()?, &self.claims) else {
            return Ok(None);
        };
        if claims.kept(root.multihash())? {
            return Ok(None);
        }
        self.keep(&root).map(Some)
    }

    /// Every CID a block was put under.
    pub fn cids(&self, key: Key<'_>) -> Result<Vec<Link>> {
        // An identity multihash with no codec on record: a dissolved claim,
        // if it's one
        if key.code() == IDENTITY {
            return Ok(crate::claim::dissolved_cid(key.digest_ref())
                .filter(|cid| crate::claim::dissolved(cid).is_some())
                .into_iter()
                .collect());
        }
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT c.prefix FROM multihashes m JOIN block_cids c ON c.block = m.id WHERE m.multihash = ?1 ORDER BY c.prefix",
        )?;
        let rows = stmt.query_map([key.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|prefix| {
            let cid = [prefix?, key.to_bytes()].concat();
            Link::decode(&cid).map_err(|e| Error::Invalid { store: "router", reason: format!("CID: {e:?}") })
        })
        .collect()
    }

    /// Index a block as being in a volume, returning whether it's new
    /// there.
    fn record(&self, id: Id, (volume, form): &Placement) -> Result<bool> {
        let v = *volume;
        let volume = self.ids.get(v).ok_or_else(|| Error::UnknownStore(form.clone()))?;
        let added = self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO blocks (block, volume, form) SELECT ?1, ?2, id FROM forms WHERE name = ?3")?
            .execute(params![id, volume, form])?;
        if added > 0 && let Some(db) = self.foreign_db(v) {
            self.share_cids(id, db)?;
        }
        Ok(added > 0)
    }

    /// Tell a database volume the CIDs a block was put with, so whoever
    /// catches up with it can read its links.
    fn share_cids(&self, id: Id, db: &Db) -> Result<()> {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = self.db.conn()
            .prepare_cached("SELECT m.multihash, c.prefix FROM block_cids c JOIN multihashes m ON m.id = c.block WHERE c.block = ?1")?
            .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (key, prefix) in rows {
            let theirs = db.intern(decode_key("router", &key)?.as_ref())?;
            db.conn()
                .prepare_cached("INSERT OR IGNORE INTO block_cids (block, prefix) VALUES (?1, ?2)")?
                .execute(params![theirs, prefix])?;
        }
        Ok(())
    }

    /// Offer a block to each store in turn.
    fn place(&self, block: &Block, provenance: Provenance<'_>) -> Result<Placement> {
        for &(volume, store) in &self.placement {
            let Some(store) = self.volumes.get(volume).and_then(|v| v.stores().get(store)) else {
                continue;
            };
            if store.put_from(block, provenance)? == Put::Stored {
                return Ok((volume, store.name().to_owned()));
            }
        }
        Err(Error::Unplaced(block.cid().to_string()))
    }

    /// Get a block, verifying its bytes against its CID.
    pub fn get_block(&self, cid: &Link) -> Result<Option<Block>> {
        let Some(data) = self.get(cid.multihash())? else {
            return Ok(None);
        };
        let cid: Cidv1 = cid.clone().into();
        Block::verify(cid.clone(), data.into_boxed_slice())
            .map(Some)
            .map_err(|_| Error::Corrupt(cid.to_string()))
    }

    /// Rebuild placement from the attached volumes, returning how many
    /// placements it found. Within a volume, earlier stores win if more
    /// than one has a block. What's known of volumes which aren't attached
    /// is kept.
    pub fn reindex(&self) -> Result<usize> {
        self.db.atomically(|| {
            for store in self.volumes.iter().flat_map(Volume::stores) {
                store.rescan()?;
            }
            let conn = self.db.conn();
            let mut forget = conn.prepare_cached("DELETE FROM blocks WHERE volume = ?1")?;
            for id in &self.ids {
                forget.execute([id])?;
            }
            // Links read from blocks only elsewhere can't be read again
            conn.execute_batch("DELETE FROM refs WHERE source NOT IN (SELECT block FROM blocks);")?;
            let mut count = 0usize;
            for (v, volume) in self.volumes.iter().enumerate() {
                // The catalog keeps the links of what's in other databases
                // too, so they're known while those are detached
                let foreign = self.foreign_db(v);
                if let (Some(db), Some(id)) = (foreign, self.ids.get(v)) {
                    conn.prepare_cached("UPDATE volumes SET cursor = ?1 WHERE id = ?2")?.execute([volume::generation(db)?, *id])?;
                }
                for store in volume.stores() {
                    for key in store.keys()? {
                        let id = self.db.intern(key.as_ref())?;
                        if !self.record(id, &(v, store.name().to_owned()))? {
                            continue;
                        }
                        count = count.saturating_add(1);
                        if store.refs().is_none() || foreign.is_some() {
                            self.reindex_links(store.as_ref(), id, key.as_ref())?;
                        }
                    }
                }
            }
            self.index_mount_points()?;
            Ok(count)
        })
    }

    /// Index a block's links again, under every codec it was put with.
    /// Raw blocks have none, so they're never read, which matters for
    /// offset blocks whose files may be gone.
    fn reindex_links(&self, store: &dyn Store, id: Id, key: Key<'_>) -> Result<()> {
        let codecs: Vec<u64> = self.cids(key)?.iter().map(BaseCid::codec).filter(|&c| c != crate::cid::RAW_CODEC).collect();
        if codecs.is_empty() {
            return Ok(());
        }
        let Some(data) = store.get(key)? else {
            return Ok(());
        };
        for codec in codecs {
            self.index_links(id, codec, &data)?;
        }
        Ok(())
    }

    /// How many blocks each volume holds in each form, by the index,
    /// attached or not.
    pub fn stats(&self) -> Result<Vec<(String, String, u64)>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT v.name, f.name, count(*) FROM blocks b
             JOIN volumes v ON v.id = b.volume JOIN forms f ON f.id = b.form
             GROUP BY v.id, f.id ORDER BY v.name, f.name",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)?)))?;
        rows.map(|row| {
            let (volume, form, count) = row?;
            Ok((volume, form, u64::try_from(count).unwrap_or_default()))
        })
        .collect()
    }
}

impl BlockIndex for Catalog {
    /// Identity blocks are always had: they're their CIDs.
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(key.code() == IDENTITY || self.db.conn()
            .prepare_cached("SELECT 1 FROM multihashes m JOIN blocks b ON b.block = m.id WHERE m.multihash = ?1")?
            .exists([key.to_bytes()])?)
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, "router", "SELECT m.multihash FROM multihashes m WHERE m.id IN (SELECT block FROM blocks)")
    }
}

impl BlockSource for Catalog {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        if key.code() == IDENTITY {
            return Ok(Some(key.digest_ref().to_vec()));
        }
        let placements = self.placements(key)?;
        if placements.is_empty() && self.has(key)? {
            return Err(Error::Unattached(format!("{key:?}")));
        }
        // Any copy will do; a failure is reported only if none can be read
        let mut failure = None;
        for placed in &placements {
            match self.named(placed)?.get(key) {
                Ok(Some(data)) => return Ok(Some(data)),
                Ok(None) => {},
                Err(e) => { failure.get_or_insert(e); },
            }
        }
        failure.map_or(Ok(None), Err)
    }
}

/// Every block in the repo with a link to a multihash, whichever store
/// holds it.
impl RefIndex for Catalog {
    fn backrefs(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        let mut found = std::collections::BTreeMap::new();
        for store in self.volumes.iter().flat_map(Volume::stores) {
            if let Some(refs) = store.refs() {
                found.extend(refs.backrefs(key)?.into_iter().map(|mh| (mh.to_bytes(), mh)));
            }
        }
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT s.multihash FROM multihashes t
             JOIN refs r ON r.target = t.id
             JOIN multihashes s ON s.id = r.source
             WHERE t.multihash = ?1",
        )?;
        for bytes in stmt.query_map([key.to_bytes()], |row| row.get::<_, Vec<u8>>(0))? {
            let mh = decode_key("router", &bytes?)?;
            found.insert(mh.to_bytes(), mh);
        }
        Ok(found.into_values().collect())
    }
}

/// Routing stores compose: one can be a store within another.
impl BlockStore for Catalog {
    fn put(&self, block: &Block) -> Result<Put> {
        self.put_from(block, Provenance::Unknown)
    }

    fn put_from(&self, block: &Block, provenance: Provenance<'_>) -> Result<Put> {
        match self.put_block_from(block, CidVersion::V1, provenance) {
            Ok(_) => Ok(Put::Stored),
            Err(Error::Unplaced(_)) => Ok(Put::Declined),
            Err(e) => Err(e),
        }
    }
}

/// For the importer, which only makes CIDv1. Blocks are copied in as
/// they come; see `Copying` and `InPlace` for sinks which keep files whole.
impl BlockSink for Catalog {
    fn put(&mut self, block: Block) -> io::Result<()> {
        self.put_block(&block, CidVersion::V1).map_err(io::Error::other)?;
        self.breathe().map_err(io::Error::other)
    }
}

/// Stores of a router may be shared with it.
impl<T: Store + ?Sized> Store for Rc<T> {
    fn name(&self) -> &'static str { (**self).name() }
    fn refs(&self) -> Option<&dyn RefIndex> { (**self).refs() }
    fn catch_up(&self) -> Result<Changes> { (**self).catch_up() }
    fn rescan(&self) -> Result<()> { (**self).rescan() }
    fn remove(&self, key: Key<'_>) -> Result<Option<u64>> { (**self).remove(key) }
}

impl<T: BlockIndex + ?Sized> BlockIndex for Rc<T> {
    fn has(&self, key: Key<'_>) -> Result<bool> { (**self).has(key) }
    fn keys(&self) -> Result<Vec<Multihash>> { (**self).keys() }
}

impl<T: BlockSource + ?Sized> BlockSource for Rc<T> {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> { (**self).get(key) }
}

impl<T: BlockStore + ?Sized> BlockStore for Rc<T> {
    fn put(&self, block: &Block) -> Result<Put> { (**self).put(block) }
    fn put_from(&self, block: &Block, provenance: Provenance<'_>) -> Result<Put> {
        (**self).put_from(block, provenance)
    }
}

/// The anchor a block mounts, if it's a mount point: a UnixFS symlink to
/// `/anchors/<anchor>`.
pub fn mount_point(codec: u64, data: &[u8]) -> Option<Link> {
    if codec != crate::cid::DAG_PB_CODEC {
        return None;
    }
    let node = crate::pb::PbNode::decode(data).ok()?;
    let unixfs = crate::unixfs::DataBuf::decode(node.data?).ok()?;
    if unixfs.data_type != crate::unixfs::DataType::Symlink {
        return None;
    }
    crate::claim::anchor_target(unixfs.data.as_deref()?)
}

fn io_error(e: Error) -> io::Error {
    io::Error::other(e)
}

/// Imports files in place, keeping their leaves as ranges of the files
/// themselves (`hk add --nocopy`). Each file is hashed whole as its leaves
/// go by, and must be unchanged by the end.
pub struct InPlace<'a> {
    router: &'a mut Catalog,
    file: Option<(Fingerprint, Whole)>,
}

impl<'a> InPlace<'a> {
    pub const fn new(router: &'a mut Catalog) -> Self {
        Self { router, file: None }
    }
}

impl BlockSink for InPlace<'_> {
    fn put(&mut self, block: Block) -> io::Result<()> {
        BlockSink::put(self.router, block)
    }

    fn put_from(&mut self, block: Block, provenance: Provenance<'_>) -> io::Result<()> {
        if let (Some((_, whole)), Provenance::FileRange { offset, .. }) = (&mut self.file, provenance) {
            whole.push(offset, block.data())?;
        }
        self.router.put_block_from(&block, CidVersion::V1, provenance).map(drop).map_err(io_error)
    }

    fn begin_file(&mut self, path: &Path) -> io::Result<()> {
        self.router.breathe().map_err(io_error)?;
        let fingerprint = Fingerprint::read(path)
            .ok_or_else(|| io::Error::other(format!("can't fingerprint {}", path.display())))?;
        self.file = Some((fingerprint, Whole::default()));
        Ok(())
    }

    fn end_file(&mut self, path: &Path, _root: &DagLink) -> io::Result<()> {
        let (Some((fingerprint, whole)), Some(offsets)) = (self.file.take(), &self.router.offsets) else {
            return Ok(());
        };
        if Fingerprint::read(path) != Some(fingerprint) {
            return Err(io::Error::other(format!("{} changed while it was being imported", path.display())));
        }
        let len = whole.len();
        let blob = whole.finish();
        offsets.settle(path, blob.as_ref(), len, &Location::External { path, fingerprint }).map(drop).map_err(io_error)
    }
}

/// Imports files as copies, so nothing is kept as part of the originals.
///
/// A file of more than one leaf and more than the shards' threshold is
/// kept whole in the shards, written as its leaves go by, and its leaves
/// become ranges of it; the rest are copied block by block.
pub struct Copying<'a> {
    router: &'a mut Catalog,
    file: Option<Keeping>,
}

/// A file being imported which may be kept whole.
struct Keeping {
    whole: Whole,
    /// Leaves held back until the file is known to be worth keeping, and
    /// their offsets.
    held: Vec<(Block, u64)>,
    /// The file being written, once it's worth keeping.
    temp: Option<tempfile::NamedTempFile>,
}

impl<'a> Copying<'a> {
    pub const fn new(router: &'a mut Catalog) -> Self {
        Self { router, file: None }
    }
}

impl BlockSink for Copying<'_> {
    fn put(&mut self, block: Block) -> io::Result<()> {
        BlockSink::put(self.router, block)
    }

    fn put_from(&mut self, block: Block, provenance: Provenance<'_>) -> io::Result<()> {
        let (Some(file), Some(shards), Provenance::FileRange { path, offset }) =
            (&mut self.file, &self.router.shards, provenance)
        else {
            return BlockSink::put(self.router, block);
        };
        file.whole.push(offset, block.data())?;
        if let Some(temp) = &mut file.temp {
            io::Write::write_all(temp, block.data())?;
            return self.router.put_block_from(&block, CidVersion::V1, provenance).map(drop).map_err(io_error);
        }
        file.held.push((block, offset));
        let threshold = shards.threshold.map_or(0, |threshold| u64::try_from(threshold).unwrap_or(u64::MAX));
        if file.held.len() < 2 || file.whole.len() <= threshold {
            return Ok(());
        }
        let mut temp = shards.temp().map_err(io_error)?;
        for (leaf, offset) in std::mem::take(&mut file.held) {
            io::Write::write_all(&mut temp, leaf.data())?;
            self.router.put_block_from(&leaf, CidVersion::V1, Provenance::FileRange { path, offset }).map_err(io_error)?;
        }
        file.temp = Some(temp);
        Ok(())
    }

    fn begin_file(&mut self, _path: &Path) -> io::Result<()> {
        self.router.breathe().map_err(io_error)?;
        self.file = Some(Keeping { whole: Whole::default(), held: Vec::new(), temp: None });
        Ok(())
    }

    fn end_file(&mut self, path: &Path, root: &DagLink) -> io::Result<()> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        let (Some(temp), Some(shards), Some(offsets)) = (file.temp, &self.router.shards, &self.router.offsets) else {
            // Not worth keeping whole
            for (leaf, _) in file.held {
                BlockSink::put(self.router, leaf)?;
            }
            return Ok(());
        };
        let len = file.whole.len();
        let blob = file.whole.finish();
        let keep = || {
            shards.persist(temp, blob.as_ref())?;
            let ranges = offsets.settle(path, blob.as_ref(), len, &Location::Kept)?;
            // Every leaf was already stored some other way
            if ranges == 0 && self.router.store_of(blob.as_ref())?.is_none() {
                return shards.forget(blob.as_ref());
            }
            shards.record_root(blob.as_ref(), root.cid.multihash())
        };
        keep().map_err(io_error)
    }
}

#[cfg(test)]
mod tests;
