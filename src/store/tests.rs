use super::*;
use crate::cid::{AnyCid, Cidv1Spec, DAG_CBOR_CODEC, DAG_PB_CODEC, RAW_CODEC};
use crate::dag::{BalancedLayout, DynamicDirectory};
use crate::hamt::Hamt;
use crate::import::Importer;
use crate::multihash::MultihashFunc;
use crate::dag::Provenance;
use crate::testutil::Scratch;
use crate::unixfs;

fn router() -> Catalog {
    Catalog::standard(Db::memory().expect("db")).expect("router")
}

/// How many blocks are in each form, whichever volume.
fn forms(router: &Catalog) -> Vec<(String, u64)> {
    let mut forms = std::collections::BTreeMap::new();
    for (_, form, n) in router.stats().expect("stats") {
        let total: &mut u64 = forms.entry(form).or_default();
        *total = total.saturating_add(n);
    }
    forms.into_iter().collect()
}

fn raw(data: &[u8]) -> Block {
    Block::hash(Cidv1Spec::default(), data.into())
}

fn block(codec: u64, data: &[u8]) -> Block {
    Block::hash(Cidv1Spec::new(codec, MultihashFunc::Sha2_256), data.into())
}

/// Put blocks into a router while keeping a copy of each.
struct Tee<'a> {
    router: &'a mut Catalog,
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
fn import_everything(router: &mut Catalog) -> Vec<Block> {
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
fn lists_directory_entries_sharded_or_not() {
    let mut router = router();
    import_everything(&mut router);
    let conn = router.db.conn();
    let names = |dir: i64| -> Vec<String> {
        conn.prepare("SELECT name FROM unixfs_entries WHERE directory = ?1 ORDER BY name").expect("prepare")
            .query_map([dir], |r| r.get::<_, Vec<u8>>(0)).expect("query")
            .map(|name| String::from_utf8(name.expect("row")).expect("utf-8"))
            .collect()
    };
    let entries_named = |name: &str| -> Vec<(i64, i64)> {
        conn.prepare("SELECT directory, target FROM unixfs_entries WHERE name = ?1").expect("prepare")
            .query_map([name.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?))).expect("query")
            .collect::<rusqlite::Result<_>>().expect("rows")
    };

    let [(top, shard)] = entries_named("shard")[..] else { panic!("one entry named shard") };
    assert_eq!(names(top), ["big", "empty", "link", "shard", "small"]);
    // The HAMT's entries, through its sub-shards, with their buckets split off
    assert_eq!(names(shard), ('a'..='z').map(String::from).collect::<Vec<_>>());
    let subshards: i64 = conn
        .query_row("SELECT count(*) FROM unixfs_links WHERE bucket IS NOT NULL AND name = x''", [], |r| r.get(0))
        .expect("count");
    assert!(subshards > 0, "no nested shards to descend through");
    // So finding an entry by name is the same either way
    assert_eq!(entries_named("q").iter().map(|&(dir, _)| dir).collect::<Vec<_>>(), [shard]);
    assert_eq!(entries_named("small").iter().map(|&(dir, _)| dir).collect::<Vec<_>>(), [top]);
}

#[test]
fn hamt_names_must_be_canonical_to_split() {
    use crate::pb::{PbLink, PbNode};
    let target = raw(b"hello").cid().to_bytes();
    let shard = |name: &[u8]| {
        let data = unixfs::DataBuf {
            data_type: unixfs::DataType::HAMTShard,
            data: Some(vec![0x01]),
            filesize: None,
            blocksizes: Vec::new(),
            hash_type: Some(0x22),
            fanout: Some(256),
        }.encode();
        let node = PbNode { links: vec![PbLink { hash: target.as_slice().into(), name: Some(name), tsize: Some(5) }], data: Some(&data) };
        block(DAG_PB_CODEC, &node.encode())
    };
    let store = UnixfsStore::open(Db::memory().expect("db")).expect("store");
    assert_eq!(store.put(&shard(b"0Ahello")).expect("put"), Put::Stored);
    // Lowercase, too short, or not hex at all
    for name in [&b"0ahello"[..], b"A", b"ZZhello"] {
        assert_eq!(store.put(&shard(name)).expect("put"), Put::Declined, "{}", String::from_utf8_lossy(name));
    }
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
    let stats = forms(&router);
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
    let router = Catalog::new(db, unixfs_only).expect("router");
    let block = raw(b"hello");
    assert!(matches!(router.put_block(&block, CidVersion::V1), Err(Error::Unplaced(_))));
    assert_eq!(BlockStore::put(&router, &block).expect("put"), Put::Declined);
    assert!(!router.has(block.cid().multihash()).expect("has"));
}

/// A router is itself a store, so routers nest.
struct Nested(Catalog);
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
    let outer = Catalog::new(db, vec![Box::new(Nested(inner))]).expect("router");
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
        let router = Catalog::open_repo(scratch.path()).expect("open");
        router.put_block(&block, CidVersion::V1).expect("put");
    }
    let router = Catalog::open_repo(scratch.path()).expect("reopen");
    let cid = AnyCid::V1(block.cid().clone());
    assert_eq!(router.get_block(&cid).expect("get"), Some(block));
}

//--------------//
//-[ Backrefs ]-//
//--------------//

fn sorted(mut keys: Vec<Multihash>) -> Vec<Multihash> {
    keys.sort_by_key(Multihash::to_bytes);
    keys
}

fn mh(block: &Block) -> Multihash {
    Multihash::from(block.cid().clone())
}

#[test]
fn backrefs_span_every_store() {
    use crate::model::Ipld;
    let router = router();
    let target = raw(b"hello");
    let link = Ipld::Link(AnyCid::V1(target.cid().clone()));
    // UnixFS rows, JSONB, and raw bytes for what neither will take
    let dir = unixfs::node_block(&[unixfs::Link { hash: target.cid(), name: b"hello", tsize: 5 }], &unixfs::Data::directory());
    let cbor = ipld_block(DAG_CBOR_CODEC, &Ipld::List(vec![link.clone()]));
    let noncanonical = block(DAG_PB_CODEC, &PbNode {
        links: vec![crate::pb::PbLink { hash: target.cid().to_bytes().into(), name: None, tsize: None }],
        data: None,
    }.encode());
    let slash = Ipld::Map([("/".to_owned(), Ipld::String("x".into())), ("to".to_owned(), link)].into_iter().collect());
    let slashy = ipld_block(DAG_CBOR_CODEC, &Ipld::Map(std::iter::once(("/".to_owned(), slash)).collect()));
    for (block, store) in [(&dir, "unixfs"), (&cbor, "ipld"), (&noncanonical, "raw"), (&slashy, "raw")] {
        assert_eq!(router.put_block(block, CidVersion::V1).expect("put"), store, "{}", block.cid());
    }

    let expected = sorted(vec![mh(&dir), mh(&cbor), mh(&noncanonical), mh(&slashy)]);
    assert_eq!(sorted(router.backrefs(target.cid().multihash()).expect("backrefs")), expected);
    // Only what no store indexes itself is in refs
    assert_eq!(count(&router.db, "refs"), 2);
    let linked: i64 = router.db.conn()
        .query_row("SELECT count(*) FROM links l JOIN multihashes t ON t.id = l.target WHERE t.multihash = ?1",
            [target.cid().multihash().to_bytes()], |r| r.get(0))
        .expect("links");
    assert_eq!(linked, 4);
    // And sources come back under the CIDs they were put with
    assert_eq!(router.cids(noncanonical.cid().multihash()).expect("cids"), [AnyCid::V1(noncanonical.cid().clone())]);
}

#[test]
fn links_are_read_under_each_codec() {
    let router = router();
    let target = raw(b"hello");
    let json = format!(r#"[{{"/":"{}"}}]"#, target.cid());
    // The same bytes, as raw and then as dag-json
    let as_raw = block(RAW_CODEC, json.as_bytes());
    let as_json = block(crate::cid::DAG_JSON_CODEC, json.as_bytes());
    assert_eq!(router.put_block(&as_raw, CidVersion::V1).expect("put"), "raw");
    assert!(router.backrefs(target.cid().multihash()).expect("backrefs").is_empty());
    assert_eq!(router.put_block(&as_json, CidVersion::V1).expect("put"), "raw");
    assert_eq!(router.backrefs(target.cid().multihash()).expect("backrefs"), [mh(&as_raw)]);
    assert_eq!(router.cids(as_raw.cid().multihash()).expect("cids").len(), 2);
}

#[test]
fn reindex_rebuilds_refs() {
    let mut router = router();
    let blocks = import_everything(&mut router);
    let raw_pb = block(DAG_PB_CODEC, &PbNode {
        links: vec![crate::pb::PbLink { hash: blocks[0].cid().to_bytes().into(), name: None, tsize: None }],
        data: None,
    }.encode());
    router.put_block(&raw_pb, CidVersion::V1).expect("put");
    let before: Vec<_> = blocks.iter().map(|b| sorted(router.backrefs(b.cid().multihash()).expect("backrefs"))).collect();
    assert!(before.iter().filter(|refs| !refs.is_empty()).count() > 10);

    router.db.conn().execute("DELETE FROM refs", []).expect("forget");
    router.reindex().expect("reindex");
    let after: Vec<_> = blocks.iter().map(|b| sorted(router.backrefs(b.cid().multihash()).expect("backrefs"))).collect();
    assert_eq!(after, before);
    assert_eq!(count(&router.db, "refs"), 1);
}

//------------//
//-[ Claims ]-//
//------------//

use crate::claim::{Claim, Group, Tomb};

fn link(block: &Block) -> crate::model::Link {
    AnyCid::V1(block.cid().clone())
}

fn tag(name: &str) -> crate::model::Link {
    crate::claim::tag(name).expect("tag")
}

/// A claim tagging blocks: dissolved for one, hashed for more.
fn tagging(name: &str, targets: &[&Block]) -> Block {
    Claim::Group(Group::new(targets.iter().map(|b| link(b)), tag(name)).expect("group")).block()
}

fn tomb(claim: &Block) -> Block {
    Claim::Tomb(Tomb::new([link(claim)]).expect("tomb")).block()
}

fn tagged(router: &Catalog, name: &str) -> Vec<crate::model::Link> {
    router.claims().expect("claims").tagged(tag(name).multihash()).expect("tagged")
}

fn by_multihash(mut links: Vec<crate::model::Link>) -> Vec<crate::model::Link> {
    links.sort_by_key(|cid| cid.multihash().to_bytes());
    links
}

#[test]
fn tags_are_rows() {
    let router = router();
    let (a, b, c) = (raw(b"a"), raw(b"b"), raw(b"c"));
    let claims = [tagging("music", &[&a, &b]), tagging("music", &[&c]), tagging("jazz", &[&b])];
    for claim in &claims {
        assert_eq!(router.put_block(claim, CidVersion::V1).expect("put"), "claims");
        assert!(router.has(claim.cid().multihash()).expect("has"));
        // Manifested from rows exactly, or the CID itself
        assert_eq!(router.get_block(&link(claim)).expect("get").as_ref(), Some(claim));
    }
    assert_eq!(count(&router.db, "ipld_blocks"), 0);
    // Only the pair was hashed: the dissolved claims have no multihash
    assert_eq!(claims.iter().filter(|c| c.cid().hashcode() == 0x12).count(), 1);
    assert_eq!(count(&router.db, "multihashes"), 3 + 2 + 1);

    // Claims with the same tag combine their targets
    assert_eq!(tagged(&router, "music"), by_multihash(vec![link(&a), link(&b), link(&c)]));
    assert_eq!(tagged(&router, "jazz"), [link(&b)]);
    assert!(tagged(&router, "unheard").is_empty());
    let names: Vec<_> = router.claims().expect("claims").tags(b.cid().multihash()).expect("tags").iter()
        .map(|tag| crate::claim::tag_name(tag).expect("simple").to_owned())
        .collect();
    assert_eq!(names, ["jazz", "music"]);

    // And in SQL, by name
    let names: Vec<String> = router.db.conn()
        .prepare("SELECT DISTINCT name FROM tags ORDER BY name").expect("prepare")
        .query_map([], |r| r.get(0)).expect("query")
        .collect::<rusqlite::Result<_>>().expect("rows");
    assert_eq!(names, ["jazz", "music"]);

    // Claims are backrefs of what they tag and what they tag it with,
    // dissolved ones under their identity CIDs
    assert_eq!(sorted(router.backrefs(b.cid().multihash()).expect("backrefs")), sorted(vec![mh(&claims[0]), mh(&claims[2])]));
    assert_eq!(sorted(router.backrefs(tag("music").multihash()).expect("backrefs")), sorted(vec![mh(&claims[0]), mh(&claims[1])]));
    assert_eq!(router.cids(claims[1].cid().multihash()).expect("cids"), [link(&claims[1])]);
}

#[test]
fn long_tag_names_fit() {
    let router = router();
    let name = "x".repeat(crate::claim::MAX_NAME);
    let a = raw(b"a");
    let claim = tagging(&name, &[&a]);
    // Too big to dissolve, so hashed
    assert_eq!(claim.cid().hashcode(), 0x12);
    router.put_block(&claim, CidVersion::V1).expect("put");
    assert_eq!(tagged(&router, &name), [link(&a)]);
    let names: Vec<String> = router.db.conn()
        .prepare("SELECT name FROM tags").expect("prepare")
        .query_map([], |r| r.get(0)).expect("query")
        .collect::<rusqlite::Result<_>>().expect("rows");
    assert_eq!(names, [name]);
}

#[test]
fn tombs_retract_claims() {
    let router = router();
    let (a, b, c) = (raw(b"a"), raw(b"b"), raw(b"c"));
    let single = tagging("music", &[&a]);
    let pair = tagging("music", &[&b, &c]);
    for claim in [&single, &pair] {
        router.put_block(claim, CidVersion::V1).expect("put");
    }
    assert_eq!(tagged(&router, "music").len(), 3);

    // A dissolved claim is gone at once, and stays gone
    let buried = tomb(&single);
    assert_eq!(buried.cid().hashcode(), 0x00, "a tomb for a dissolved claim dissolves");
    assert_eq!(router.put_block(&buried, CidVersion::V1).expect("put"), "claims");
    assert_eq!(tagged(&router, "music"), by_multihash(vec![link(&b), link(&c)]));
    router.put_block(&single, CidVersion::V1).expect("put again");
    assert_eq!(tagged(&router, "music"), by_multihash(vec![link(&b), link(&c)]));
    assert_eq!(router.backrefs(single.cid().multihash()).expect("backrefs"), [mh(&buried)]);

    // A hashed one stops counting, all of it, but is still a block
    router.put_block(&tomb(&pair), CidVersion::V1).expect("put");
    assert!(tagged(&router, "music").is_empty());
    assert_eq!(router.get_block(&link(&pair)).expect("get").as_ref(), Some(&pair));
    let names: i64 = router.db.conn().query_row("SELECT count(*) FROM tags", [], |r| r.get(0)).expect("count");
    assert_eq!(names, 0);
}

#[test]
fn untagging_retags_the_rest() {
    let router = router();
    let (a, b, c) = (raw(b"a"), raw(b"b"), raw(b"c"));
    // Tagged by one claim, as if imported, and by one of its own
    router.put_block(&tagging("music", &[&a, &b, &c]), CidVersion::V1).expect("put");
    router.tag(&link(&a), &tag("music")).expect("tag");

    let tombs = router.untag(&link(&a), &tag("music")).expect("untag");
    assert_eq!(tombs.len(), 2);
    assert_eq!(tagged(&router, "music"), by_multihash(vec![link(&b), link(&c)]));
    // The others are tagged on their own now, so untagging one leaves the other
    router.untag(&link(&b), &tag("music")).expect("untag");
    assert_eq!(tagged(&router, "music"), [link(&c)]);
    assert!(router.untag(&link(&b), &tag("music")).expect("untag").is_empty());
}

#[test]
fn tags_keep_target_cids() {
    let router = router();
    let dir = unixfs::node_block(&[], &unixfs::Data::directory());
    let v0 = crate::model::Link::decode(&dir.cid().multihash().to_bytes()).expect("cidv0");
    let claim = Claim::Group(Group::new([v0.clone(), link(&dir)], tag("empty")).expect("group")).block();
    router.put_block(&claim, CidVersion::V1).expect("put");
    assert_eq!(router.get_block(&link(&claim)).expect("get"), Some(claim));
    let tagged = tagged(&router, "empty");
    assert_eq!(tagged.len(), 2);
    assert!(tagged.contains(&v0));
}

#[test]
fn claims_store_declines_what_isnt_a_claim() {
    use crate::model::Ipld;
    let store = ClaimStore::open(Db::memory().expect("db")).expect("store");
    let claim = tagging("t", &[&raw(b"a")]);
    // The same bytes under another codec, and dag-cbor that isn't a claim
    assert_eq!(store.put(&block(RAW_CODEC, claim.data())).expect("put"), Put::Declined);
    assert_eq!(store.put(&ipld_block(DAG_CBOR_CODEC, &sample())).expect("put"), Put::Declined);
    let other = Ipld::Map(std::iter::once(("claim".to_owned(), Ipld::String("same".into()))).collect());
    assert_eq!(store.put(&ipld_block(DAG_CBOR_CODEC, &other)).expect("put"), Put::Declined);
    // An identity CID for a claim that should be hashed
    let pair = tagging("t", &[&raw(b"a"), &raw(b"b")]);
    let identity: Block = Block::identity(DAG_CBOR_CODEC, pair.data().into()).expect("fits");
    assert_eq!(store.put(&identity).expect("put"), Put::Declined);
    assert_eq!(store.put(&claim).expect("put"), Put::Stored);
}

#[test]
fn identity_blocks_are_never_kept() {
    let router = router();
    let block: Block = Block::identity(RAW_CODEC, b"hello"[..].into()).expect("fits");
    assert_eq!(router.put_block(&block, CidVersion::V1).expect("put"), "identity");
    assert!(router.has(block.cid().multihash()).expect("has"));
    assert_eq!(router.get_block(&link(&block)).expect("get"), Some(block));
    assert_eq!(count(&router.db, "multihashes"), 0);
}

//------------//
//-[ Offset ]-//
//------------//

/// Import with provenance, as `hk add --nocopy` does.
fn import_in_place(router: &mut Catalog, path: &std::path::Path) -> crate::dag::DagLink {
    let importer = Importer { chunk_size: 64, ..Importer::default() };
    importer.add_path(path, &mut InPlace::new(router), &mut |_, _| {}).expect("import").expect("root")
}

fn content(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).expect("byte") ^ seed).collect()
}

#[test]
fn keeps_leaves_in_place() {
    let scratch = Scratch::new("offset-in-place");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = router();
    let root = import_in_place(&mut router, &file);

    // 16 leaves in the file, one node as rows, and no copies
    assert_eq!(forms(&router), [("offset".to_owned(), 16), ("unixfs".to_owned(), 1)]);
    assert_eq!(count(&router.db, "raw_blocks"), 0);

    let mut out = Vec::new();
    crate::export::cat(&router, &AnyCid::V1(root.cid), &mut out).expect("cat");
    assert_eq!(out, content(1000, 0));
}

#[test]
fn changed_files_are_stale() {
    let scratch = Scratch::new("offset-stale");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(200, 0)).expect("write");
    let mut router = router();
    let root = import_in_place(&mut router, &file);
    let cid = AnyCid::V1(root.cid);

    // Same size, different bytes
    std::fs::write(&file, content(200, 1)).expect("rewrite");
    let mut out = Vec::new();
    let err = crate::export::cat(&router, &cid, &mut out).expect_err("stale");
    assert!(err.to_string().contains("changed since it was added"), "{err}");

    // Importing it again keeps the new leaves, and the old ones stay stale
    let new = import_in_place(&mut router, &file);
    let mut out = Vec::new();
    crate::export::cat(&router, &AnyCid::V1(new.cid), &mut out).expect("cat");
    assert_eq!(out, content(200, 1));
    std::fs::remove_file(&file).expect("remove");
    assert!(crate::export::cat(&router, &cid, &mut Vec::new()).is_err());
}

#[test]
fn blocks_are_served_from_any_unchanged_file() {
    let scratch = Scratch::new("offset-copies");
    let (a, b) = (scratch.path().join("a"), scratch.path().join("b"));
    std::fs::write(&a, content(300, 0)).expect("write");
    std::fs::write(&b, content(300, 0)).expect("write");
    let mut router = router();
    let root = import_in_place(&mut router, &a);
    assert_eq!(import_in_place(&mut router, &b).cid, root.cid);
    // Five leaves, each a range of one blob found at both paths
    assert_eq!((count(&router.db, "offset_ranges"), count(&router.db, "external_files")), (5, 2));

    std::fs::write(&b, content(300, 9)).expect("change b");
    let mut out = Vec::new();
    crate::export::cat(&router, &AnyCid::V1(root.cid.clone()), &mut out).expect("from a");
    assert_eq!(out, content(300, 0));
    std::fs::remove_file(&a).expect("remove a");
    assert!(crate::export::cat(&router, &AnyCid::V1(root.cid), &mut Vec::new()).is_err());
}

#[test]
fn offset_store_needs_provenance() {
    let scratch = Scratch::new("offset-provenance");
    let file = scratch.path().join("file");
    std::fs::write(&file, b"hello world").expect("write");
    let fingerprint = Fingerprint::read(&file).expect("fingerprint");
    let store = OffsetStore::open(Db::memory().expect("db"), None).expect("store");
    let hello = raw(b"hello");
    let at = |offset| Provenance::FileRange { path: &file, offset };
    let blob = raw(b"hello world");
    let settle = |len| store.settle(&file, blob.cid().multihash(), len, &Location::External { path: &file, fingerprint });

    assert_eq!(store.put(&hello).expect("put"), Put::Declined);
    assert_eq!(store.put_from(&hello, Provenance::Unknown).expect("put"), Put::Declined);
    // Not a raw block
    assert_eq!(store.put_from(&block(DAG_PB_CODEC, b"hello"), at(0)).expect("put"), Put::Declined);

    // Pending until settled, and past the end of the file it won't settle
    assert_eq!(store.put_from(&hello, at(7)).expect("put"), Put::Stored);
    assert!(settle(11).is_err());
    assert_eq!(store.get(hello.cid().multihash()).expect("get"), None);
    assert_eq!(store.put_from(&hello, at(0)).expect("put"), Put::Stored);
    assert_eq!(settle(11).expect("settle"), 1);
    assert_eq!(store.get(hello.cid().multihash()).expect("get").as_deref(), Some(&b"hello"[..]));

    // Provenance is trusted, and the router's re-hash is what catches a lie
    let world = raw(b"world");
    assert_eq!(store.put_from(&world, at(0)).expect("put"), Put::Stored);
    assert_eq!(settle(11).expect("settle"), 2);
    assert_eq!(store.get(world.cid().multihash()).expect("get").as_deref(), Some(&b"hello"[..]));
}

#[test]
fn leaves_must_be_the_whole_file_in_order() {
    let mut whole = Whole::default();
    whole.push(0, b"hello ").expect("first");
    assert!(whole.push(0, b"world").is_err());
    assert!(whole.push(7, b"world").is_err());
    whole.push(6, b"world").expect("next");
    assert_eq!(whole.finish(), Multihash::from(raw(b"hello world").cid().clone()));
}

#[test]
fn copying_forgets_provenance() {
    let scratch = Scratch::new("offset-copying");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(100, 0)).expect("write");
    let mut router = router();
    let importer = Importer { chunk_size: 64, ..Importer::default() };
    importer.add_path(&file, &mut Copying::new(&mut router), &mut |_, _| {}).expect("import");
    assert_eq!(forms(&router), [("raw".to_owned(), 2), ("unixfs".to_owned(), 1)]);
}

//------------//
//-[ Shards ]-//
//------------//

/// A router whose shards keep files over 100 bytes.
fn sharded(scratch: &Scratch) -> Catalog {
    let db = Db::memory().expect("db");
    let mut shards = ShardStore::open(db.clone(), &scratch.path().join("shards")).expect("shards");
    shards.threshold = 100;
    Catalog::with_shards(db, Some(shards)).expect("router")
}

/// Import as `hk add` does, copying.
fn import_copying(router: &mut Catalog, path: &std::path::Path) -> crate::dag::DagLink {
    let importer = Importer { chunk_size: 64, ..Importer::default() };
    importer.add_path(path, &mut Copying::new(router), &mut |_, _| {}).expect("import").expect("root")
}

/// Every file kept in the shards.
fn kept_files(scratch: &Scratch) -> Vec<std::path::PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(scratch.path().join("shards")).expect("shards")
        .map(|entry| entry.expect("entry").path())
        .filter(|dir| dir.is_dir() && dir.file_name() != Some(".temp".as_ref()))
        .flat_map(|dir| std::fs::read_dir(dir).expect("shard").map(|entry| entry.expect("entry").path()))
        .collect();
    files.sort();
    files
}

/// Where flatfs would keep a blob: base32upper, next-to-last/2.
fn shard_path(scratch: &Scratch, data: &[u8]) -> std::path::PathBuf {
    let key = multibase::Base::Base32Upper.encode(raw(data).cid().multihash().to_bytes());
    let shard = key.get(key.len().saturating_sub(3)..key.len().saturating_sub(1)).expect("shard");
    scratch.path().join("shards").canonicalize().expect("dir").join(shard).join(format!("{key}.data"))
}

#[test]
fn keeps_large_files_whole() {
    let scratch = Scratch::new("shards-whole");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = sharded(&scratch);
    let root = import_copying(&mut router, &file);

    // Leaves as ranges of the kept file, the node as rows, and no copies
    assert_eq!(forms(&router), [("offset".to_owned(), 16), ("unixfs".to_owned(), 1)]);
    assert_eq!(count(&router.db, "raw_blocks"), 0);
    assert_eq!(count(&router.db, "shard_roots"), 1);

    // Named by its multihash as flatfs would, and read-only
    let kept = kept_files(&scratch);
    assert_eq!(kept, [shard_path(&scratch, &content(1000, 0))]);
    assert!(std::fs::metadata(&kept[0]).expect("metadata").permissions().readonly());
    assert_eq!(std::fs::read(&kept[0]).expect("read"), content(1000, 0));

    // The original is the user's to change
    std::fs::remove_file(&file).expect("remove");
    let mut out = Vec::new();
    crate::export::cat(&router, &AnyCid::V1(root.cid), &mut out).expect("cat");
    assert_eq!(out, content(1000, 0));
}

#[test]
fn small_files_are_copied_as_blocks() {
    let scratch = Scratch::new("shards-small");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(100, 0)).expect("write");
    let mut router = sharded(&scratch);
    import_copying(&mut router, &file);
    assert_eq!(forms(&router), [("raw".to_owned(), 2), ("unixfs".to_owned(), 1)]);
    assert!(kept_files(&scratch).is_empty());
}

#[test]
fn identical_files_are_kept_once() {
    let scratch = Scratch::new("shards-dedup");
    let (a, b) = (scratch.path().join("a"), scratch.path().join("b"));
    std::fs::write(&a, content(300, 0)).expect("write");
    std::fs::write(&b, content(300, 0)).expect("write");
    let mut router = sharded(&scratch);
    let root = import_copying(&mut router, &a);
    assert_eq!(import_copying(&mut router, &b).cid, root.cid);
    assert_eq!(kept_files(&scratch).len(), 1);
    assert_eq!((count(&router.db, "offset_ranges"), count(&router.db, "shard_files")), (5, 1));
    assert_eq!(count(&router.db, "shard_roots"), 1);
}

#[test]
fn kept_files_arent_blocks() {
    let scratch = Scratch::new("shards-not-blocks");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(300, 0)).expect("write");
    let mut router = sharded(&scratch);
    import_copying(&mut router, &file);
    let whole = raw(&content(300, 0));
    let before = router.stats().expect("stats");
    assert!(!router.has(whole.cid().multihash()).expect("has"));
    router.reindex().expect("reindex");
    assert!(!router.has(whole.cid().multihash()).expect("has"));
    assert_eq!(router.stats().expect("stats"), before);
}

#[test]
fn large_blocks_are_kept_as_files() {
    let scratch = Scratch::new("shards-blocks");
    let router = sharded(&scratch);
    let (small, large) = (raw(&content(100, 0)), raw(&content(101, 0)));
    assert_eq!(router.put_block(&small, CidVersion::V1).expect("put"), "raw");
    assert_eq!(router.put_block(&large, CidVersion::V1).expect("put"), "flatfs");
    assert_eq!(kept_files(&scratch), [shard_path(&scratch, &content(101, 0))]);
    assert_eq!(router.get_block(&AnyCid::V1(large.cid().clone())).expect("get"), Some(large.clone()));

    // The cache is rebuilt from the directory, ignoring what isn't a blob
    std::fs::write(scratch.path().join("shards").join("stray"), b"").expect("stray");
    router.db.conn().execute("DELETE FROM shard_files", []).expect("forget");
    router.reindex().expect("reindex");
    assert_eq!(router.store_of(large.cid().multihash()).expect("store"), Some("flatfs".to_owned()));
    assert_eq!(count(&router.db, "shard_files"), 1);
}

#[test]
fn kept_files_nothing_uses_are_let_go() {
    let scratch = Scratch::new("shards-unused");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(300, 0)).expect("write");
    let mut router = sharded(&scratch);
    // Its leaves are already blocks of their own...
    let shards = router.shards.take();
    import_copying(&mut router, &file);
    router.shards = shards;
    // ...so a kept copy would be served by nothing
    import_copying(&mut router, &file);
    assert!(kept_files(&scratch).is_empty());
    assert_eq!(count(&router.db, "shard_files"), 0);
}

#[test]
fn missing_kept_files_are_reported() {
    let scratch = Scratch::new("shards-missing");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(300, 0)).expect("write");
    let mut router = sharded(&scratch);
    let root = import_copying(&mut router, &file);
    for kept in kept_files(&scratch) {
        std::fs::remove_file(kept).expect("remove");
    }
    let err = crate::export::cat(&router, &AnyCid::V1(root.cid), &mut Vec::new()).expect_err("missing");
    assert!(err.to_string().contains("which is missing"), "{err}");
}

//----------//
//-[ IPLD ]-//
//----------//

fn ipld_block(codec: u64, value: &crate::model::Ipld) -> Block {
    let data = match codec {
        DAG_CBOR_CODEC => crate::dagcbor::to_vec(value).expect("encode"),
        _ => crate::dagjson::to_vec(value).expect("encode"),
    };
    block(codec, &data)
}

fn sample() -> crate::model::Ipld {
    use crate::model::Ipld;
    let link = raw(b"hello");
    Ipld::Map([
        ("name".to_owned(), Ipld::String("holokeep".into())),
        ("size".to_owned(), Ipld::Integer(-(1 << 64))),
        ("ratio".to_owned(), Ipld::Float(1.0)),
        ("bytes".to_owned(), Ipld::Bytes(vec![0, 1, 2])),
        ("target".to_owned(), Ipld::Link(AnyCid::V1(link.cid().clone()))),
        ("list".to_owned(), Ipld::List(vec![Ipld::Null, Ipld::Bool(true)])),
    ].into_iter().collect())
}

#[test]
fn ipld_as_jsonb() {
    let router = router();
    for codec in [DAG_CBOR_CODEC, crate::cid::DAG_JSON_CODEC] {
        let block = ipld_block(codec, &sample());
        assert_eq!(router.put_block(&block, CidVersion::V1).expect("put"), "ipld");
        let cid = AnyCid::V1(block.cid().clone());
        assert_eq!(router.get_block(&cid).expect("get"), Some(block));
    }
    // Queryable in place
    let names: Vec<String> = router.db.conn()
        .prepare("SELECT data ->> '$.name' FROM ipld_blocks WHERE data ->> '$.ratio' = 1.0").expect("prepare")
        .query_map([], |r| r.get(0)).expect("query")
        .collect::<rusqlite::Result<_>>().expect("rows");
    assert_eq!(names, ["holokeep", "holokeep"]);
}

#[test]
fn ipld_store_declines_what_it_cant_manifest() {
    use crate::model::Ipld;
    let store = IpldStore::open(Db::memory().expect("db")).expect("store");
    // A map dag-json would read back as a link
    let slash = Ipld::Map(std::iter::once(("/".to_owned(), Ipld::String("bafy".into()))).collect());
    // Deeper than the decoder allows
    let deep = [&vec![0x81; crate::serde::MAX_DEPTH + 1][..], b"\xf6"].concat();
    for (label, block) in [
        ("slash map", ipld_block(DAG_CBOR_CODEC, &slash)),
        ("too deep", block(DAG_CBOR_CODEC, &deep)),
        // A map with its keys out of order
        ("non-canonical", block(DAG_CBOR_CODEC, b"\xa2\x61b\x01\x61a\x02")),
        ("not dag-cbor", block(DAG_CBOR_CODEC, b"\xff")),
        ("dag-json with whitespace", block(crate::cid::DAG_JSON_CODEC, b"{ }")),
        ("wrong codec", block(RAW_CODEC, &crate::dagcbor::to_vec(&sample()).expect("encode"))),
    ] {
        assert_eq!(store.put(&block).expect("put"), Put::Declined, "{label}");
    }
    assert!(store.keys().expect("keys").is_empty());
}

#[test]
fn ipld_backrefs() {
    let store = IpldStore::open(Db::memory().expect("db")).expect("store");
    let block = ipld_block(DAG_CBOR_CODEC, &sample());
    store.put(&block).expect("put");
    assert_eq!(store.backrefs(raw(b"hello").cid().multihash()).expect("backrefs"), [Multihash::from(block.cid().clone())]);
}


//-------------//
//-[ Volumes ]-//
//-------------//

fn labels(router: &Catalog) -> Vec<volume::Label> {
    router.volumes.iter().map(Volume::label).collect()
}

#[test]
fn volumes_keep_their_labels() {
    let scratch = Scratch::new("volumes-labels");
    let first = labels(&Catalog::open_repo(scratch.path()).expect("open"));
    assert_eq!(first.len(), 2);
    assert_ne!(first.first(), first.get(1));
    assert!(scratch.path().join("shards").join("VOLUME").exists());
    assert_eq!(labels(&Catalog::open_repo(scratch.path()).expect("reopen")), first);

    // A label is the volume's, wherever it's opened from
    let shards = ShardStore::open(Db::memory().expect("db"), &scratch.path().join("shards")).expect("shards");
    assert_eq!(shards.label(), *first.get(1).expect("shards"));
}

#[test]
fn any_copy_serves_a_block() {
    let scratch = Scratch::new("volumes-copies");
    let router = sharded(&scratch);
    let large = raw(&content(101, 0));
    router.put_block(&large, CidVersion::V1).expect("put");
    // A second copy, in the database's raw store
    let db = router.volumes.first().expect("db");
    db.form("raw").expect("raw").put(&large).expect("copy");
    router.reindex().expect("reindex");
    assert_eq!(router.placements(large.cid().multihash()).expect("placements").len(), 2);

    // One copy lost, the other serves it
    std::fs::remove_file(shard_path(&scratch, &content(101, 0))).expect("lose");
    let cid = AnyCid::V1(large.cid().clone());
    assert_eq!(router.get_block(&cid).expect("get"), Some(large));
}

#[test]
fn blocks_on_detached_volumes_are_known() {
    let scratch = Scratch::new("volumes-detached");
    let db = Db::open(&scratch.path().join("blocks.db")).expect("db");
    let (large, parent) = {
        let mut shards = ShardStore::open(db.clone(), &scratch.path().join("shards")).expect("shards");
        shards.threshold = 100;
        let router = Catalog::with_shards(db.clone(), Some(shards)).expect("router");
        let large = raw(&content(101, 0));
        let parent = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::Link(link(&large)));
        router.put_block(&large, CidVersion::V1).expect("put");
        router.put_block(&parent, CidVersion::V1).expect("put");
        (large, parent)
    };

    // Without the shards, the block is still in the repo, and linked to,
    // and a reindex doesn't forget it
    let router = Catalog::standard(db).expect("router");
    router.reindex().expect("reindex");
    let key = large.cid().multihash();
    assert!(router.has(key).expect("has"));
    assert_eq!(router.backrefs(key).expect("backrefs"), [mh(&parent)]);
    assert!(matches!(router.get(key), Err(Error::Unattached(_))));
    assert_eq!(router.stats().expect("stats"), [
        ("db".to_owned(), "ipld".to_owned(), 1),
        ("shards".to_owned(), "flatfs".to_owned(), 1),
    ]);
}
