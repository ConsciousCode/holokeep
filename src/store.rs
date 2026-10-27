//! Blockstores: where blocks are kept and how they're represented.
//!
//! Stores are specialized. Each may restrict which blocks it admits and
//! represent them however suits their structure, so long as it can
//! manifest every block it admits byte-for-byte. A generic store accepts
//! anything; a specialized one declines what it can't represent. The
//! `RoutingStore` offers each block to its stores from most to least
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
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::{Connection, OptionalExtension, params};

use crate::block::Block;
use crate::cid::{AnyCid, BaseCid, CidRef, CidVersion, Cidv1};
use crate::dag::{BlockSink, DagLink, Provenance, Source};
use crate::multihash::{Inline, Multihash};

mod ipld;
mod offset;
mod raw;
mod shards;
mod unixfs;

pub use ipld::IpldStore;
pub use offset::OffsetStore;
pub use raw::RawStore;
pub use shards::Shards;
pub use unixfs::UnixfsStore;

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

    /// A multihash too long to keep; see `MAX_DIGEST_LEN`.
    #[error("multihash digest of {0} bytes is too long to keep")]
    Oversized(usize),

    /// Data in a store which can't be right.
    #[error("invalid data in store {store}: {reason}")]
    Invalid { store: &'static str, reason: String },
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

/// A store a `RoutingStore` can place blocks in.
pub trait Store: BlockIndex + BlockSource + BlockStore {
    /// A stable name, recorded in the router's index.
    fn name(&self) -> &'static str;
}

//--------------//
//-[ Database ]-//
//--------------//

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
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        Ok(Self(Rc::new(conn)))
    }

    pub fn conn(&self) -> &Connection {
        &self.0
    }

    /// Run `f` atomically. Savepoints nest, so this works inside an
    /// enclosing transaction too.
    pub fn atomically<T, E: From<Error>>(&self, f: impl FnOnce() -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        let conn = self.conn();
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

/// Places each block in the most specialized store which admits it, and
/// indexes where everything went.
///
/// The index is derived data: if it's lost or out of date, `reindex`
/// rebuilds it from the stores themselves.
pub struct RoutingStore {
    db: Db,
    /// Most specialized first; the last should admit anything.
    stores: Vec<Box<dyn Store>>,
    /// Where files copied in are kept whole, if anywhere.
    shards: Option<Rc<Shards>>,
}

impl RoutingStore {
    /// Open a repo directory with the standard stores.
    pub fn open_repo(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let db = Db::open(&dir.join("blocks.db"))?;
        let shards = Shards::open(db.clone(), &dir.join("shards"))?;
        Self::with_shards(db, Some(shards))
    }

    /// The standard stores in one database, with no shards.
    pub fn standard(db: Db) -> Result<Self> {
        Self::with_shards(db, None)
    }

    /// The standard stores in one database: ranges of files on disk when
    /// that's where blocks came from, UnixFS nodes as rows, dag-cbor and
    /// dag-json as JSONB, and everything else as raw bytes. Large files
    /// copied in are kept whole in the shards, if there are any.
    pub fn with_shards(db: Db, shards: Option<Shards>) -> Result<Self> {
        let shards = shards.map(Rc::new);
        let stores: Vec<Box<dyn Store>> = vec![
            Box::new(OffsetStore::open(db.clone(), shards.clone())?),
            Box::new(UnixfsStore::open(db.clone())?),
            Box::new(IpldStore::open(db.clone())?),
            Box::new(RawStore::open(db.clone())?),
        ];
        let mut router = Self::new(db, stores)?;
        router.shards = shards;
        Ok(router)
    }

    pub fn new(db: Db, stores: Vec<Box<dyn Store>>) -> Result<Self> {
        db.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS stores (
                 id INTEGER PRIMARY KEY,
                 name TEXT UNIQUE NOT NULL
             );
             -- Which store holds each block that's present.
             CREATE TABLE IF NOT EXISTS blocks (
                 block INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 store INTEGER NOT NULL REFERENCES stores (id)
             );
             -- The CID prefixes (version and codec) each block was put with.
             -- Unlike `blocks` this isn't derivable from the stores, which
             -- needn't know how their bytes are meant to be read, so it
             -- survives a reindex.
             CREATE TABLE IF NOT EXISTS block_cids (
                 block INTEGER NOT NULL REFERENCES multihashes (id),
                 prefix BLOB NOT NULL,
                 PRIMARY KEY (block, prefix)
             ) WITHOUT ROWID;",
        )?;
        for store in &stores {
            db.conn().execute("INSERT OR IGNORE INTO stores (name) VALUES (?1)", [store.name()])?;
        }
        Ok(Self { db, stores, shards: None })
    }

    /// Run `f` in one transaction, for speed and so that a failed import
    /// leaves nothing behind.
    pub fn batch<T, E: From<Error>>(&mut self, f: impl FnOnce(&mut Self) -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        let db = self.db.clone();
        db.conn().execute_batch("BEGIN").map_err(Error::from)?;
        match f(self) {
            Ok(value) => {
                db.conn().execute_batch("COMMIT").map_err(Error::from)?;
                Ok(value)
            },
            Err(e) => {
                db.conn().execute_batch("ROLLBACK").map_err(Error::from)?;
                Err(e)
            },
        }
    }

    /// Which store holds a block.
    pub fn store_of(&self, key: Key<'_>) -> Result<Option<String>> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT s.name FROM multihashes m
                 JOIN blocks b ON b.block = m.id
                 JOIN stores s ON s.id = b.store
                 WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |row| row.get(0))
            .optional()?)
    }

    fn named(&self, name: &str) -> Result<&dyn Store> {
        self.stores
            .iter()
            .find(|store| store.name() == name)
            .map(AsRef::as_ref)
            .ok_or_else(|| Error::UnknownStore(name.to_owned()))
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
        let prefix = cid_prefix(block.cid(), version);
        self.db.atomically(|| {
            let store = if let Some(store) = self.store_of(key)? {
                if provenance != Provenance::Unknown {
                    self.named(&store)?.put_from(block, provenance)?;
                }
                store
            }
            else {
                let store = self.place(block, provenance)?;
                self.record(self.db.intern(key)?, store)?;
                store.to_owned()
            };
            self.db.conn()
                .prepare_cached("INSERT OR IGNORE INTO block_cids (block, prefix) VALUES (?1, ?2)")?
                .execute(params![self.db.intern(key)?, prefix])?;
            Ok(store)
        })
    }

    /// Index a block as being in a store, returning whether it's new.
    fn record(&self, id: Id, store: &str) -> Result<bool> {
        let added = self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO blocks (block, store) SELECT ?1, id FROM stores WHERE name = ?2")?
            .execute(params![id, store])?;
        Ok(added > 0)
    }

    /// Offer a block to each store in turn.
    fn place(&self, block: &Block, provenance: Provenance<'_>) -> Result<&'static str> {
        for store in &self.stores {
            if store.put_from(block, provenance)? == Put::Stored {
                return Ok(store.name());
            }
        }
        Err(Error::Unplaced(block.cid().to_string()))
    }

    /// Get a block, verifying its bytes against its CID.
    pub fn get_block(&self, cid: &AnyCid<Inline<64>>) -> Result<Option<Block>> {
        let Some(data) = self.get(cid.multihash())? else {
            return Ok(None);
        };
        let cid: Cidv1 = cid.clone().into();
        Block::verify(cid.clone(), data.into_boxed_slice())
            .map(Some)
            .map_err(|_| Error::Corrupt(cid.to_string()))
    }

    /// Rebuild the index from the stores, returning how many blocks it
    /// found. Earlier stores win if more than one has a block.
    pub fn reindex(&self) -> Result<usize> {
        self.db.atomically(|| {
            self.db.conn().execute("DELETE FROM blocks", [])?;
            let mut count = 0usize;
            for store in &self.stores {
                for key in store.keys()? {
                    if self.record(self.db.intern(key.as_ref())?, store.name())? {
                        count = count.saturating_add(1);
                    }
                }
            }
            Ok(count)
        })
    }

    /// How many blocks each store holds, by the index.
    pub fn stats(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT s.name, count(*) FROM blocks b JOIN stores s ON s.id = b.store GROUP BY s.name ORDER BY s.name",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get::<_, i64>(1)?)))?;
        rows.map(|row| {
            let (store, count) = row?;
            Ok((store, u64::try_from(count).unwrap_or_default()))
        })
        .collect()
    }
}

impl BlockIndex for RoutingStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.store_of(key)?.is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, "router", "SELECT m.multihash FROM blocks b JOIN multihashes m ON m.id = b.block")
    }
}

impl BlockSource for RoutingStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        match self.store_of(key)? {
            Some(store) => self.named(&store)?.get(key),
            None => Ok(None),
        }
    }
}

/// Routing stores compose: one can be a store within another.
impl BlockStore for RoutingStore {
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

/// For the importer, which only makes CIDv1.
impl BlockSink for RoutingStore {
    fn put(&mut self, block: Block) -> io::Result<()> {
        BlockSink::put_from(self, block, Provenance::Unknown)
    }

    fn put_from(&mut self, block: Block, provenance: Provenance<'_>) -> io::Result<()> {
        self.put_block_from(&block, CidVersion::V1, provenance).map(drop).map_err(io::Error::other)
    }
}

/// Puts blocks into a router as copies, so nothing is kept as part of the
/// original files. Large files are kept whole in the router's shards, and
/// their leaves as ranges of them; the rest are copied block by block.
pub struct Copying<'a>(pub &'a mut RoutingStore);

impl BlockSink for Copying<'_> {
    fn put(&mut self, block: Block) -> io::Result<()> {
        BlockSink::put(self.0, block)
    }

    /// Provenance only ever points into kept files: `source` reads the rest
    /// without any.
    fn put_from(&mut self, block: Block, provenance: Provenance<'_>) -> io::Result<()> {
        BlockSink::put_from(self.0, block, provenance)
    }

    fn source(&mut self, path: &Path) -> io::Result<Source> {
        match &self.0.shards {
            Some(shards) if std::fs::metadata(path)?.len() > shards.threshold => {
                shards.keep(path).map(Source::Kept).map_err(io::Error::other)
            },
            _ => Ok(Source::Copy),
        }
    }

    fn kept(&mut self, copy: &Path, root: &DagLink) -> io::Result<()> {
        let Some(shards) = &self.0.shards else {
            return Ok(());
        };
        shards.kept(copy, root.cid.multihash()).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests;
