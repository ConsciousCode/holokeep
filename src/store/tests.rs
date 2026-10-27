use super::*;
use crate::cid::{Cidv1Spec, DAG_CBOR_CODEC, DAG_PB_CODEC, RAW_CODEC};
use crate::dag::{BalancedLayout, DynamicDirectory};
use crate::hamt::Hamt;
use crate::import::Importer;
use crate::multihash::MultihashFunc;
use crate::testutil::Scratch;
use crate::unixfs;

fn router() -> RoutingStore {
    RoutingStore::standard(Db::memory().expect("db")).expect("router")
}

fn raw(data: &[u8]) -> Block {
    Block::hash(Cidv1Spec::default(), data.into())
}

fn block(codec: u64, data: &[u8]) -> Block {
    Block::hash(Cidv1Spec::new(codec, MultihashFunc::Sha2_256), data.into())
}

/// Put blocks into a router while keeping a copy of each.
struct Tee<'a> {
    router: &'a mut RoutingStore,
    blocks: Vec<Block>,
}

impl BlockSink for Tee<'_> {
    fn put(&mut self, block: Block) -> io::Result<()> {
        self.blocks.push(block.clone());
        BlockSink::put(self.router, block)
    }
}

/// Import a tree with every kind of UnixFS node: chunked files at several
/// depths, a basic and a HAMT directory, a symlink and an empty file.
fn import_everything(router: &mut RoutingStore) -> Vec<Block> {
    let scratch = Scratch::new("store-import");
    let t = scratch.path().join("t");
    let shard = t.join("shard");
    std::fs::create_dir_all(&shard).expect("mkdir");
    std::fs::write(t.join("small"), "hello world").expect("write");
    std::fs::write(t.join("big"), (0..5000u32).map(|i| i.to_le_bytes()[0]).collect::<Vec<_>>()).expect("write");
    std::fs::write(t.join("empty"), "").expect("write");
    std::os::unix::fs::symlink("small", t.join("link")).expect("symlink");
    for c in 'a'..='z' {
        std::fs::write(shard.join(c.to_string()), c.to_string()).expect("write");
    }
    // Small chunks and fanouts so a little data makes deep trees and nested shards
    let importer = Importer {
        chunk_size: 64,
        layout: BalancedLayout { width: 3 },
        directory: DynamicDirectory { threshold: 400, hamt: Hamt { fanout: 8 } },
        ..Importer::default()
    };
    let mut tee = Tee { router, blocks: Vec::new() };
    importer.add_path(&t, &mut tee, &mut |_, _| {}).expect("import").expect("root");
    tee.blocks
}

#[test]
fn sorts_blocks_by_structure() {
    let mut router = router();
    let blocks = import_everything(&mut router);
    assert!(blocks.len() > 50, "only {} blocks", blocks.len());

    for block in &blocks {
        let store = router.store_of(block.cid().multihash()).expect("index").expect("indexed");
        let expected = if block.cid().codec() == DAG_PB_CODEC { "unixfs" } else { "raw" };
        assert_eq!(store, expected, "{}", block.cid());

        // Rows or bytes, every block comes back exactly
        let cid = AnyCid::V1(block.cid().clone());
        assert_eq!(router.get_block(&cid).expect("get").as_ref(), Some(block));
    }
    let stats = router.stats().expect("stats");
    assert!(stats.iter().any(|(store, n)| store == "unixfs" && *n > 10), "{stats:?}");
}

#[test]
fn raw_store() {
    let store = RawStore::open(Db::memory().expect("db")).expect("store");
    let block = raw(b"hello");
    let key = block.cid().multihash();
    assert!(!store.has(key).expect("has"));
    assert_eq!(store.get(key).expect("get"), None);

    assert_eq!(store.put(&block).expect("put"), Put::Stored);
    assert_eq!(store.put(&block).expect("put again"), Put::Stored);
    assert!(store.has(key).expect("has"));
    assert_eq!(store.get(key).expect("get").as_deref(), Some(&b"hello"[..]));
    assert_eq!(store.keys().expect("keys"), [Multihash::from(block.cid().clone())]);
}

#[test]
fn unixfs_store_declines_what_it_cant_manifest() {
    let store = UnixfsStore::open(Db::memory().expect("db")).expect("store");
    let file = raw(b"hello");
    let link = unixfs::Link { hash: file.cid(), name: b"hello", tsize: 5 };
    let canonical = unixfs::node_block(&[link], &unixfs::Data::directory());
    assert_eq!(store.put(&canonical).expect("put"), Put::Stored);

    // The same node without a link name, as dag-pb allows
    let unnamed = PbNode {
        links: vec![crate::pb::PbLink { hash: file.cid().to_bytes().into(), name: None, tsize: Some(5) }],
        data: Some(b"\x08\x01"),
    };
    // With a mode, which this store doesn't keep
    let with_mode = PbNode { links: vec![], data: Some(b"\x08\x02\x38\xa4\x03") };
    // Not UnixFS at all
    let not_unixfs = PbNode { links: vec![], data: Some(b"\xff") };
    for (label, bytes) in [
        ("unnamed link", unnamed.encode()),
        ("mode", with_mode.encode()),
        ("not UnixFS", not_unixfs.encode()),
        ("no data", PbNode::default().encode()),
    ] {
        assert_eq!(store.put(&block(DAG_PB_CODEC, &bytes)).expect("put"), Put::Declined, "{label}");
    }
    // Right bytes, wrong codec
    assert_eq!(store.put(&block(RAW_CODEC, canonical.data())).expect("put"), Put::Declined);
    assert_eq!(store.put(&block(DAG_CBOR_CODEC, b"\xa0")).expect("put"), Put::Declined);
    assert_eq!(store.keys().expect("keys").len(), 1);
}

use crate::pb::PbNode;

#[test]
fn declined_blocks_fall_through() {
    let router = router();
    let odd = PbNode { links: vec![], data: Some(b"\x08\x02\x38\xa4\x03") }.encode();
    let block = block(DAG_PB_CODEC, &odd);
    assert_eq!(router.put_block(&block, CidVersion::V1).expect("put"), "raw");
    let cid = AnyCid::V1(block.cid().clone());
    assert_eq!(router.get_block(&cid).expect("get").map(|b| b.into_data().into_vec()), Some(odd));
}

#[test]
fn unplaced_blocks_are_declined() {
    let db = Db::memory().expect("db");
    let unixfs_only: Vec<Box<dyn Store>> = vec![Box::new(UnixfsStore::open(db.clone()).expect("store"))];
    let router = RoutingStore::new(db, unixfs_only).expect("router");
    let block = raw(b"hello");
    assert!(matches!(router.put_block(&block, CidVersion::V1), Err(Error::Unplaced(_))));
    assert_eq!(BlockStore::put(&router, &block).expect("put"), Put::Declined);
    assert!(!router.has(block.cid().multihash()).expect("has"));
}

/// A router is itself a store, so routers nest.
struct Nested(RoutingStore);
impl Store for Nested {
    fn name(&self) -> &'static str { "nested" }
}
impl BlockIndex for Nested {
    fn has(&self, key: Key<'_>) -> Result<bool> { self.0.has(key) }
    fn keys(&self) -> Result<Vec<Multihash>> { self.0.keys() }
}
impl BlockSource for Nested {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> { self.0.get(key) }
}
impl BlockStore for Nested {
    fn put(&self, block: &Block) -> Result<Put> { BlockStore::put(&self.0, block) }
}

#[test]
fn routers_compose() {
    let inner = router();
    let db = Db::memory().expect("db");
    let outer = RoutingStore::new(db, vec![Box::new(Nested(inner))]).expect("router");
    let block = raw(b"hello");
    assert_eq!(outer.put_block(&block, CidVersion::V1).expect("put"), "nested");
    let cid = AnyCid::V1(block.cid().clone());
    assert_eq!(outer.get_block(&cid).expect("get"), Some(block));
}

#[test]
fn reindex_rebuilds_from_stores() {
    let mut router = router();
    let blocks = import_everything(&mut router);
    let before = router.stats().expect("stats");

    router.db.conn().execute("DELETE FROM blocks", []).expect("lose the index");
    let first = AnyCid::V1(blocks[0].cid().clone());
    assert_eq!(router.get_block(&first).expect("get"), None);

    let distinct: std::collections::HashSet<_> = blocks.iter().map(|b| b.cid().multihash().to_bytes()).collect();
    assert_eq!(router.reindex().expect("reindex"), distinct.len());
    assert_eq!(router.stats().expect("stats"), before);
    for block in &blocks {
        let cid = AnyCid::V1(block.cid().clone());
        assert_eq!(router.get_block(&cid).expect("get").as_ref(), Some(block));
    }
    // CID prefixes aren't derivable, so they must have survived
    let prefixes: i64 = router.db.conn().query_row("SELECT count(*) FROM block_cids", [], |r| r.get(0)).expect("count");
    assert_eq!(usize::try_from(prefixes).expect("count"), distinct.len());
}

#[test]
fn records_each_cid_prefix() {
    let router = router();
    let dir = unixfs::node_block(&[], &unixfs::Data::directory());
    router.put_block(&dir, CidVersion::V1).expect("put v1");
    router.put_block(&dir, CidVersion::V0).expect("put v0");
    router.put_block(&dir, CidVersion::V1).expect("put v1 again");
    let prefixes: Vec<Vec<u8>> = router.db.conn()
        .prepare("SELECT prefix FROM block_cids ORDER BY prefix").expect("prepare")
        .query_map([], |r| r.get(0)).expect("query")
        .collect::<rusqlite::Result<_>>().expect("rows");
    assert_eq!(prefixes, [vec![], vec![0x01, 0x70]]);
}

#[test]
fn detects_corruption() {
    let router = router();
    let block = raw(b"hello");
    router.put_block(&block, CidVersion::V1).expect("put");
    router.db.conn().execute("UPDATE raw_blocks SET data = x'00'", []).expect("corrupt");
    let cid = AnyCid::V1(block.cid().clone());
    assert!(matches!(router.get_block(&cid), Err(Error::Corrupt(_))));
}

#[test]
fn backrefs_come_from_link_rows() {
    let store = UnixfsStore::open(Db::memory().expect("db")).expect("store");
    let file = raw(b"hello");
    let link = unixfs::Link { hash: file.cid(), name: b"hello", tsize: 5 };
    let one = unixfs::node_block(std::slice::from_ref(&link), &unixfs::Data::directory());
    let two = unixfs::node_block(&[unixfs::Link { name: b"again", ..link.clone() }, link], &unixfs::Data::directory());
    store.put(&one).expect("put");
    store.put(&two).expect("put");

    let mut refs = store.backrefs(file.cid().multihash()).expect("backrefs");
    refs.sort_by_key(Multihash::to_bytes);
    let mut expected = vec![Multihash::from(one.cid().clone()), Multihash::from(two.cid().clone())];
    expected.sort_by_key(Multihash::to_bytes);
    assert_eq!(refs, expected);
    assert!(store.backrefs(one.cid().multihash()).expect("backrefs").is_empty());
}

#[test]
fn backrefs_span_cid_versions() {
    let store = UnixfsStore::open(Db::memory().expect("db")).expect("store");
    let child = unixfs::node_block(&[], &unixfs::Data::directory());
    let v0 = crate::cid::Cidv0::new(<[u8; 32]>::try_from(child.cid().digest_ref()).expect("sha2-256"));
    let entry = |hash: Vec<u8>| crate::pb::PbLink { hash: hash.into(), name: Some(b"child"), tsize: Some(4) };
    let by_v0 = PbNode { links: vec![entry(v0.to_bytes())], data: Some(b"\x08\x01") }.encode();
    let by_v1 = PbNode { links: vec![entry(child.cid().to_bytes())], data: Some(b"\x08\x01") }.encode();
    let (by_v0, by_v1) = (block(DAG_PB_CODEC, &by_v0), block(DAG_PB_CODEC, &by_v1));
    assert_eq!(store.put(&by_v0).expect("put"), Put::Stored);
    assert_eq!(store.put(&by_v1).expect("put"), Put::Stored);

    let mut refs = store.backrefs(child.cid().multihash()).expect("backrefs");
    refs.sort_by_key(Multihash::to_bytes);
    let mut expected = vec![Multihash::from(by_v0.cid().clone()), Multihash::from(by_v1.cid().clone())];
    expected.sort_by_key(Multihash::to_bytes);
    assert_eq!(refs, expected);
    // Each link still manifests with the CID it was written with
    assert_eq!(store.get(by_v0.cid().multihash()).expect("get").as_deref(), Some(by_v0.data()));
    assert_eq!(store.get(by_v1.cid().multihash()).expect("get").as_deref(), Some(by_v1.data()));
}

fn count(db: &Db, table: &str) -> usize {
    let n: i64 = db.conn().query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)).expect("count");
    usize::try_from(n).expect("count")
}

#[test]
fn interns_each_multihash_once() {
    let mut router = router();
    let blocks = import_everything(&mut router);
    let distinct: std::collections::HashSet<_> = blocks.iter().map(|b| b.cid().multihash().to_bytes()).collect();
    // Every link target is a block of the import, so nothing else is known
    assert_eq!(count(&router.db, "multihashes"), distinct.len());
    assert_eq!(count(&router.db, "blocks"), distinct.len());
}

#[test]
fn links_to_absent_blocks_are_known() {
    let router = router();
    let absent = raw(b"never stored");
    let link = unixfs::Link { hash: absent.cid(), name: b"absent", tsize: 12 };
    let dir = unixfs::node_block(&[link], &unixfs::Data::directory());
    assert_eq!(router.put_block(&dir, CidVersion::V1).expect("put"), "unixfs");

    assert_eq!(count(&router.db, "multihashes"), 2);
    assert_eq!(count(&router.db, "blocks"), 1);
    assert!(router.db.lookup(absent.cid().multihash()).expect("lookup").is_some());
    assert!(!router.has(absent.cid().multihash()).expect("has"));
}

#[test]
fn referenced_multihashes_cant_be_deleted() {
    let router = router();
    let block = raw(b"hello");
    router.put_block(&block, CidVersion::V1).expect("put");
    assert!(router.db.conn().execute("DELETE FROM multihashes", []).is_err());
    // Once nothing refers to it, it can go
    router.db.conn().execute_batch("DELETE FROM raw_blocks; DELETE FROM blocks; DELETE FROM block_cids;").expect("clear");
    assert_eq!(router.db.conn().execute("DELETE FROM multihashes", []).expect("delete"), 1);
}

#[test]
fn caps_digest_length() {
    let db = Db::memory().expect("db");
    let identity = |len: usize| Multihash::<Vec<u8>>::new(0x00, vec![7; len]);
    db.intern(identity(MAX_DIGEST_LEN).as_ref()).expect("128 bytes is fine");
    assert!(matches!(db.intern(identity(MAX_DIGEST_LEN + 1).as_ref()), Err(Error::Oversized(129))));

    // A node linking to an oversized identity CID isn't kept as rows
    let store = UnixfsStore::open(db).expect("store");
    let node = |len: usize| {
        let cid = Cidv1::new(RAW_CODEC, identity(len)).to_bytes();
        let link = crate::pb::PbLink { hash: cid.into(), name: Some(b"inline"), tsize: Some(1) };
        block(DAG_PB_CODEC, &PbNode { links: vec![link], data: Some(b"\x08\x01") }.encode())
    };
    assert_eq!(store.put(&node(MAX_DIGEST_LEN)).expect("put"), Put::Stored);
    assert_eq!(store.put(&node(MAX_DIGEST_LEN + 1)).expect("put"), Put::Declined);
}

#[test]
fn splits_cids() {
    let v1 = raw(b"hello");
    let bytes = v1.cid().to_bytes();
    let (prefix, key) = split_cid(&bytes).expect("v1");
    assert_eq!(prefix, [0x01, 0x55]);
    assert_eq!(key, v1.cid().multihash());

    let dir = unixfs::node_block(&[], &unixfs::Data::directory());
    let v0 = crate::cid::Cidv0::new(<[u8; 32]>::try_from(dir.cid().digest_ref()).expect("sha2-256")).to_bytes();
    let (prefix, key) = split_cid(&v0).expect("v0");
    assert!(prefix.is_empty());
    assert_eq!(key, dir.cid().multihash());

    for (label, bad) in [
        ("empty", vec![]),
        ("truncated", bytes[..bytes.len() - 1].to_vec()),
        ("trailing", [&bytes[..], b"\0"].concat()),
        ("non-minimal codec", [&[0x01, 0xd5, 0x00][..], &bytes[2..]].concat()),
        ("v0 that isn't sha2-256", [&[0x13, 0x20][..], &[0; 32]].concat()),
        ("version 2", [&[0x02][..], &bytes[1..]].concat()),
    ] {
        assert!(split_cid(&bad).is_none(), "{label}");
    }
}

#[test]
fn batches_roll_back() {
    let mut router = router();
    let block = raw(b"hello");
    let result: std::result::Result<(), Error> = router.batch(|router| {
        router.put_block(&block, CidVersion::V1)?;
        Err(Error::Unplaced("deliberate".into()))
    });
    assert!(result.is_err());
    assert!(!router.has(block.cid().multihash()).expect("has"));
    assert!(!RawStore::open(router.db.clone()).expect("store").has(block.cid().multihash()).expect("has"));
}

#[test]
fn persists() {
    let scratch = Scratch::new("store-persist");
    let block = raw(b"hello");
    {
        let router = RoutingStore::open_repo(scratch.path()).expect("open");
        router.put_block(&block, CidVersion::V1).expect("put");
    }
    let router = RoutingStore::open_repo(scratch.path()).expect("reopen");
    let cid = AnyCid::V1(block.cid().clone());
    assert_eq!(router.get_block(&cid).expect("get"), Some(block));
}
