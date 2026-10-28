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
use crate::cid::{AnyCid, BaseCid, Cid, CidRef, CidVersion, Cidv1};
use crate::dag::{BlockSink, DagLink, Provenance};
use crate::model::Link;
use crate::multihash::{Inline, Multihash};

mod ipld;
mod offset;
mod raw;
mod shards;
mod unixfs;

pub use ipld::IpldStore;
pub use offset::OffsetStore;
use offset::{Fingerprint, Location, Whole};
pub use raw::RawStore;
pub use shards::ShardStore;
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

    /// The store's own index of its blocks' links, if it keeps one. A
    /// router indexes the links of blocks in stores which don't.
    fn refs(&self) -> Option<&dyn RefIndex> {
        None
    }
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
    /// The offset store, for sinks to settle the ranges of files they
    /// import.
    offsets: Option<Rc<OffsetStore>>,
    /// Where large blocks and whole files are kept, if anywhere.
    shards: Option<Rc<ShardStore>>,
}

impl RoutingStore {
    /// Open a repo directory with the standard stores.
    pub fn open_repo(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let db = Db::open(&dir.join("blocks.db"))?;
        let shards = ShardStore::open(db.clone(), &dir.join("shards"))?;
        Self::with_shards(db, Some(shards))
    }

    /// The standard stores in one database, with no shards.
    pub fn standard(db: Db) -> Result<Self> {
        Self::with_shards(db, None)
    }

    /// The standard stores in one database: ranges of files when that's
    /// where blocks came from, UnixFS nodes as rows, dag-cbor and dag-json
    /// as JSONB, large blocks in the shards if there are any, and
    /// everything else as raw bytes.
    pub fn with_shards(db: Db, shards: Option<ShardStore>) -> Result<Self> {
        let shards = shards.map(Rc::new);
        let offsets = Rc::new(OffsetStore::open(db.clone(), shards.clone())?);
        let mut stores: Vec<Box<dyn Store>> = vec![
            Box::new(Rc::clone(&offsets)),
            Box::new(UnixfsStore::open(db.clone())?),
            Box::new(IpldStore::open(db.clone())?),
        ];
        if let Some(shards) = &shards {
            stores.push(Box::new(Rc::clone(shards)));
        }
        stores.push(Box::new(RawStore::open(db.clone())?));
        let mut router = Self::new(db, stores)?;
        router.db.conn().execute_batch(
            "-- Every link in the repo, by the multihashes of the block it's in
             -- and the block it's to.
             CREATE VIEW IF NOT EXISTS links (source, target) AS
                 SELECT node, target FROM unixfs_links
                 UNION SELECT block, target FROM ipld_links
                 UNION SELECT source, target FROM refs;",
        )?;
        router.offsets = Some(offsets);
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
        for store in &stores {
            db.conn().execute("INSERT OR IGNORE INTO stores (name) VALUES (?1)", [store.name()])?;
        }
        Ok(Self { db, stores, offsets: None, shards: None })
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
            let id = self.db.intern(key)?;
            let store = if let Some(store) = self.store_of(key)? {
                if provenance != Provenance::Unknown {
                    self.named(&store)?.put_from(block, provenance)?;
                }
                store
            }
            else {
                let store = self.place(block, provenance)?;
                self.record(id, store)?;
                store.to_owned()
            };
            let new_cid = self.db.conn()
                .prepare_cached("INSERT OR IGNORE INTO block_cids (block, prefix) VALUES (?1, ?2)")?
                .execute(params![id, prefix])? > 0;
            // Read under each codec it's put with, since that's what says
            // where its links are
            if new_cid && self.named(&store)?.refs().is_none() {
                self.index_links(id, block.cid().codec(), block.data())?;
            }
            Ok(store)
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

    /// Every CID a block was put under.
    pub fn cids(&self, key: Key<'_>) -> Result<Vec<Link>> {
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
            if let Some(shards) = &self.shards {
                shards.rescan()?;
            }
            self.db.conn().execute_batch("DELETE FROM blocks; DELETE FROM refs;")?;
            let mut count = 0usize;
            for store in &self.stores {
                for key in store.keys()? {
                    let id = self.db.intern(key.as_ref())?;
                    if !self.record(id, store.name())? {
                        continue;
                    }
                    count = count.saturating_add(1);
                    if store.refs().is_none() {
                        self.reindex_links(store.as_ref(), id, key.as_ref())?;
                    }
                }
            }
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

/// Every block in the repo with a link to a multihash, whichever store
/// holds it.
impl RefIndex for RoutingStore {
    fn backrefs(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        let mut found = std::collections::BTreeMap::new();
        for store in &self.stores {
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

/// For the importer, which only makes CIDv1. Blocks are copied in as
/// they come; see `Copying` and `InPlace` for sinks which keep files whole.
impl BlockSink for RoutingStore {
    fn put(&mut self, block: Block) -> io::Result<()> {
        self.put_block(&block, CidVersion::V1).map(drop).map_err(io::Error::other)
    }
}

/// Stores of a router may be shared with it.
impl<T: Store + ?Sized> Store for Rc<T> {
    fn name(&self) -> &'static str { (**self).name() }
    fn refs(&self) -> Option<&dyn RefIndex> { (**self).refs() }
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

fn io_error(e: Error) -> io::Error {
    io::Error::other(e)
}

/// Imports files in place, keeping their leaves as ranges of the files
/// themselves (`hk add --nocopy`). Each file is hashed whole as its leaves
/// go by, and must be unchanged by the end.
pub struct InPlace<'a> {
    router: &'a mut RoutingStore,
    file: Option<(Fingerprint, Whole)>,
}

impl<'a> InPlace<'a> {
    pub const fn new(router: &'a mut RoutingStore) -> Self {
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
/// A file of more than one leaf and more than the shards' threshold is
/// kept whole in the shards, written as its leaves go by, and its leaves
/// become ranges of it; the rest are copied block by block.
pub struct Copying<'a> {
    router: &'a mut RoutingStore,
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
    pub const fn new(router: &'a mut RoutingStore) -> Self {
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
        let threshold = u64::try_from(shards.threshold).unwrap_or(u64::MAX);
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
