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
    // Once nothing refers to it, it can go, including the generation it
    // left in
    router.db.conn().execute_batch("DELETE FROM raw_blocks; DELETE FROM blocks; DELETE FROM block_cids;").expect("clear");
    assert!(router.db.conn().execute("DELETE FROM multihashes", []).is_err());
    router.db.conn().execute_batch("DELETE FROM generations;").expect("clear");
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
    // Only the pair was hashed: the dissolved claims have no multihash but
    // their identities, which is what claims about them target
    assert_eq!(claims.iter().filter(|c| c.cid().hashcode() == 0x12).count(), 1);
    assert_eq!(count(&router.db, "multihashes"), 3 + 2 + 1 + 2);

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
fn keeps_are_claims_and_can_be_let_go_of() {
    let router = router();
    let (a, b) = (raw(b"kept"), raw(b"also kept"));
    let claims = router.claims().expect("claims");
    let keep = router.keep(&link(&a)).expect("keep");
    // One target: dissolved, its own CID
    assert_eq!(keep.hashcode(), crate::block::IDENTITY);
    assert!(router.holds(&keep).expect("holds"));
    router.keep(&link(&b)).expect("keep");
    assert!(claims.kept(a.cid().multihash()).expect("kept"));
    assert_eq!(claims.keeps().expect("keeps"), by_multihash(vec![link(&a), link(&b)]));
    // Keeps are backrefs, so holders of what's kept hear of them
    assert!(router.backrefs(a.cid().multihash()).expect("backrefs").iter().any(|source| source.code() == crate::block::IDENTITY));

    let tombs = router.unkeep(&link(&a)).expect("unkeep");
    assert_eq!(tombs.len(), 1);
    assert!(!claims.kept(a.cid().multihash()).expect("kept"));
    // Its rows stay, in case the tomb stops counting, but it doesn't count
    assert!(router.holds(&keep).expect("holds"));
    assert_eq!(claims.keeps().expect("keeps"), [link(&b)]);
    assert!(router.unkeep(&link(&a)).expect("unkeep").is_empty());
    // And it isn't brought back
    router.put_block(&crate::claim::dissolved(&keep).expect("claim").block(), CidVersion::V1).expect("put");
    assert!(!claims.kept(a.cid().multihash()).expect("kept"));
}

#[test]
fn whats_missing_under_a_root_is_the_edge_of_whats_here() {
    let router = router();
    let (a, b, c) = (raw(b"a"), raw(b"b"), raw(b"c"));
    let inner = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::List(vec![crate::model::Ipld::Link(link(&b)), crate::model::Ipld::Link(link(&c))]));
    let root = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::List(vec![crate::model::Ipld::Link(link(&a)), crate::model::Ipld::Link(link(&inner))]));
    assert_eq!(router.missing_under(&link(&root)).expect("missing"), [link(&root)]);
    for block in [&root, &a, &b] {
        router.put_block(block, CidVersion::V1).expect("put");
    }
    // What's under what's missing isn't known to be missing
    assert_eq!(router.missing_under(&link(&root)).expect("missing"), [link(&inner)]);
    router.put_block(&inner, CidVersion::V1).expect("put");
    assert_eq!(router.missing_under(&link(&root)).expect("missing"), [link(&c)]);
    router.put_block(&c, CidVersion::V1).expect("put");
    assert!(router.missing_under(&link(&root)).expect("missing").is_empty());
    // A keep is a dissolved claim, walked into from its own CID
    let keep = router.keep(&link(&root)).expect("keep");
    assert!(router.missing_under(&keep).expect("missing").is_empty());
}

#[test]
fn keeps_stop_at_their_frontier() {
    let router = router();
    let (a, far) = (raw(b"a"), raw(b"far away"));
    let root = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::List(vec![crate::model::Ipld::Link(link(&a)), crate::model::Ipld::Link(link(&far))]));
    for block in [&root, &a] {
        router.put_block(block, CidVersion::V1).expect("put");
    }
    let beyond = router.missing_under(&link(&root)).expect("missing");
    assert_eq!(beyond, [link(&far)]);
    let keep = router.keep_short_of(&link(&root), &beyond).expect("keep");
    assert!(router.missing_under(&keep).expect("missing").is_empty(), "nothing short of the frontier is missing");
    assert!(router.missing_under(&router.keep(&link(&root)).expect("keep")).expect("missing").contains(&link(&far)));
    // Rows, and back out as the same block
    assert_eq!(count(&router.db, "keep_beyond"), 1);
    assert_eq!(router.get_block(&keep).expect("get").map(|block| link(&block)), Some(keep.clone()));
    assert!(router.claims().expect("claims").kept(root.cid().multihash()).expect("kept"));
}

#[test]
fn whats_let_go_of_can_be_kept_again() {
    let router = router();
    let a = raw(b"kept twice");
    let claims = router.claims().expect("claims");
    let first = router.keep(&link(&a)).expect("keep");
    router.unkeep(&link(&a)).expect("unkeep");
    assert!(!claims.kept(a.cid().multihash()).expect("kept"));
    // The same keep is tombed for good, so it's kept a second time
    let second = router.keep(&link(&a)).expect("keep");
    assert_ne!(second, first);
    assert!(claims.kept(a.cid().multihash()).expect("kept"));
    let Some(Claim::Keep(keep)) = crate::claim::dissolved(&second) else { panic!("a dissolved keep") };
    assert_eq!(keep.n(), 1);
    assert_eq!(claims.keeping(a.cid().multihash()).expect("keeping"), std::slice::from_ref(&second));
    // And again
    router.unkeep(&link(&a)).expect("unkeep");
    assert!(!claims.kept(a.cid().multihash()).expect("kept"));
    let third = router.keep(&link(&a)).expect("keep");
    assert!(claims.kept(a.cid().multihash()).expect("kept"));
    assert_eq!(claims.keeping(a.cid().multihash()).expect("keeping"), [third]);
}

#[test]
fn anchors_are_what_they_were_last_set_to() {
    let router = router();
    let anchor = router.new_anchor().expect("anchor");
    assert!(crate::claim::is_anchor(&anchor));
    assert!(!crate::claim::is_anchor(&crate::claim::tag("anchor").expect("tag")));
    assert_ne!(router.new_anchor().expect("anchor"), anchor, "each its own");
    assert_eq!(router.anchor_value(&anchor).expect("value"), None);

    let (leaf1, leaf2) = (raw(b"first leaf"), raw(b"second leaf"));
    let v1 = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::List(vec![crate::model::Ipld::Link(link(&leaf1))]));
    let v2 = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::List(vec![crate::model::Ipld::Link(link(&leaf2))]));
    for block in [&leaf1, &leaf2, &v1, &v2] {
        router.put_block(block, CidVersion::V1).expect("put");
    }
    router.set_anchor(&anchor, &link(&v1)).expect("set");
    router.keep(&anchor).expect("keep");
    assert_eq!(router.anchor_value(&anchor).expect("value"), Some(link(&v1)));
    assert!(router.referenced(v1.cid().multihash()).expect("referenced"), "what a kept anchor is");
    assert!(router.kept_under(leaf1.cid().multihash()).expect("kept"));
    assert!(router.missing_under(&anchor).expect("missing").is_empty());

    // Set again within the second, it's still the latest
    let second = router.set_anchor(&anchor, &link(&v2)).expect("set");
    assert_eq!(router.anchor_value(&anchor).expect("value"), Some(link(&v2)));
    assert!(!router.referenced(v1.cid().multihash()).expect("referenced"), "what it was isn't");
    assert!(!router.kept_under(leaf1.cid().multihash()).expect("kept"));
    assert!(router.kept_under(leaf2.cid().multihash()).expect("kept"));
    let history: Vec<Link> = router.anchor_history(&anchor).expect("history").into_iter().map(|(_, value)| value).collect();
    assert_eq!(history, [link(&v1), link(&v2)]);

    // Retracting the latest set makes it what it was
    let tomb = Claim::Tomb(Tomb::new([second]).expect("tomb"));
    router.put_block(&tomb.block(), CidVersion::V1).expect("tomb");
    assert_eq!(router.anchor_value(&anchor).expect("value"), Some(link(&v1)));

    // An anchor nothing keeps references nothing
    let loose = router.new_anchor().expect("anchor");
    router.set_anchor(&loose, &link(&v2)).expect("set");
    assert!(!router.referenced(v2.cid().multihash()).expect("referenced"));
}

#[test]
fn claims_tables_from_before_keeps_take_them() {
    let db = Db::memory().expect("db");
    db.conn()
        .execute_batch(
            "CREATE TABLE claims (
                 id INTEGER PRIMARY KEY,
                 claim INTEGER UNIQUE REFERENCES multihashes (id),
                 kind TEXT NOT NULL CHECK (kind IN ('group', 'tomb'))
             );
             INSERT INTO claims (kind) VALUES ('group');",
        )
        .expect("old schema");
    assert!(db.conn().execute("INSERT INTO claims (kind) VALUES ('keep')", []).is_err());
    let router = Catalog::standard(db.clone()).expect("open");
    router.keep(&link(&raw(b"kept"))).expect("keep");
    let kinds: Vec<String> = db.conn().prepare("SELECT kind FROM claims ORDER BY id").expect("prepare")
        .query_map([], |row| row.get(0)).expect("query").collect::<rusqlite::Result<_>>().expect("rows");
    assert_eq!(kinds, ["group", "keep"]);
    assert!(db.conn().execute("INSERT INTO claims (kind) VALUES ('neither')", []).is_err(), "still checked");
    let check: String = db.conn().query_row("PRAGMA integrity_check", [], |row| row.get(0)).expect("check");
    assert_eq!(check, "ok");
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
fn files_imported_in_place_which_change_are_forgotten() {
    let scratch = Scratch::new("offset-changed");
    let (file, other) = (scratch.path().join("file"), scratch.path().join("other"));
    std::fs::write(&file, content(1000, 0)).expect("write");
    std::fs::write(&other, content(1000, 7)).expect("write");
    let mut router = router();
    import_in_place(&mut router, &file);
    import_in_place(&mut router, &other);
    // Nothing's changed yet
    assert!(router.forget_changed(&router.external_files(None).expect("files")).expect("forget").is_empty());
    assert_eq!(router.external_files(Some(1)).expect("sample").len(), 1);

    std::fs::write(&file, content(1000, 1)).expect("change");
    let lost = router.forget_changed(&router.external_at(&file.canonicalize().expect("path")).expect("files")).expect("forget");
    assert_eq!(lost.len(), 16);
    assert!(lost.iter().all(|leaf| !router.has(leaf.as_ref()).expect("has")));
    assert_eq!(router.external_files(None).expect("files").len(), 1, "the other's unchanged");
    assert_eq!(count(&router.db, "offset_ranges"), 16);
}

#[test]
fn whats_kept_too_isnt_lost_with_the_original() {
    let scratch = Scratch::new("shards-changed");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = sharded(&scratch);
    import_copying(&mut router, &file);
    import_in_place(&mut router, &file);
    std::fs::remove_file(&file).expect("remove");
    assert!(router.forget_changed(&router.external_files(None).expect("files")).expect("forget").is_empty());
    assert!(router.external_files(None).expect("files").is_empty());
    assert_eq!(forms(&router), [("offset".to_owned(), 16), ("unixfs".to_owned(), 1)]);
}

#[test]
fn files_imported_in_place_are_mounted_on_anchors() {
    let scratch = Scratch::new("offset-mounted");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = router();
    let importer = Importer { chunk_size: 64, ..Importer::default() };
    let (mount, first) = router.import_mounted(&importer, &file, &mut |_, _| {}).expect("import");
    assert!(crate::claim::is_anchor(&mount.anchor));
    assert_eq!(mount.path, file.canonicalize().expect("path"));
    assert_eq!((mount.chunk_size, mount.hidden), (64, false));
    router.keep(&mount.anchor).expect("keep");
    assert_eq!(router.anchor_value(&mount.anchor).expect("value"), Some(first.clone()));
    assert!(router.referenced(first.multihash()).expect("referenced"));

    // Importing it again unchanged changes nothing
    assert_eq!(router.remount(&mount).expect("remount"), first);
    assert_eq!(router.anchor_history(&mount.anchor).expect("history").len(), 1);

    // Changed, it's mounted on the same anchor, which is the new version
    std::fs::write(&file, content(1000, 3)).expect("change");
    let second = router.remount(&mount).expect("remount");
    assert_ne!(second, first);
    assert_eq!(router.mounts().expect("mounts"), std::slice::from_ref(&mount));
    assert_eq!(router.anchor_value(&mount.anchor).expect("value"), Some(second.clone()));
    assert!(router.referenced(second.multihash()).expect("referenced"));
    assert!(!router.referenced(first.multihash()).expect("referenced"), "what it was is collectable");
    assert_eq!(router.mounts_over(&mount.path).expect("over"), std::slice::from_ref(&mount));
    assert!(router.mounts_over(scratch.path()).expect("over").is_empty(), "a parent isn't under it");
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
    shards.threshold = Some(100);
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

/// A kept file's leaves, in order.
fn kept_leaves(router: &Catalog, data: &[u8]) -> Vec<Multihash> {
    let offsets = router.offsets.as_ref().expect("offsets");
    offsets.ranges_of(raw(data).cid().multihash()).expect("ranges").into_iter().map(|(leaf, _)| leaf).collect()
}

#[test]
fn kept_files_go_whole_when_their_leaves_all_do() {
    let scratch = Scratch::new("shards-drop-whole");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = sharded(&scratch);
    import_copying(&mut router, &file);
    let leaves = kept_leaves(&router, &content(1000, 0));
    assert_eq!(leaves.len(), 16);
    assert!(leaves.iter().all(|leaf| router.can_drop(leaf.as_ref()).expect("can")));

    let dropping = router.drop_all(&leaves).expect("drop");
    assert_eq!((dropping.dropped.len(), dropping.freed), (16, 1000), "nothing moved");
    assert!(kept_files(&scratch).is_empty());
    assert_eq!((count(&router.db, "offset_ranges"), count(&router.db, "shard_roots"), count(&router.db, "raw_blocks")), (0, 0, 0));
    assert!(leaves.iter().all(|leaf| !router.has(leaf.as_ref()).expect("has")));
    assert_eq!(forms(&router), [("unixfs".to_owned(), 1)]);
}

#[test]
fn a_leaf_going_splits_its_kept_file() {
    let scratch = Scratch::new("shards-split");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = sharded(&scratch);
    import_copying(&mut router, &file);
    let leaves = kept_leaves(&router, &content(1000, 0));
    let (gone, rest) = leaves.split_first().expect("leaves");

    // The rest are 64 bytes but the last, and become raw blocks
    assert_eq!(router.drop_copies(gone.as_ref()).expect("drop"), Some(1000 - 936));
    assert!(kept_files(&scratch).is_empty(), "the kept file's gone");
    assert!(!router.has(gone.as_ref()).expect("has"));
    assert_eq!(forms(&router), [("raw".to_owned(), 15), ("unixfs".to_owned(), 1)]);
    for (leaf, start) in rest.iter().zip((64..).step_by(64)) {
        let cid = router.cid_of(leaf.as_ref()).expect("cid").expect("known");
        let block = router.get_block(&cid).expect("get").expect("still here");
        assert_eq!(block.data(), &content(1000, 0)[start..(start + 64).min(1000)]);
    }

    // And what's left survives a reopen of the shards
    router.reindex().expect("reindex");
    assert_eq!(forms(&router), [("raw".to_owned(), 15), ("unixfs".to_owned(), 1)]);
}

#[test]
fn collecting_a_file_takes_its_kept_file_along() {
    let scratch = Scratch::new("shards-collect");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = sharded(&scratch);
    let root = import_copying(&mut router, &file);
    let root = owned(root.cid.multihash()).expect("root");
    assert!(router.can_collect(root.as_ref()).expect("can") && !router.referenced(root.as_ref()).expect("referenced"));
    let (dropping, leaves) = router.collect_all(std::slice::from_ref(&root)).expect("collect");
    assert_eq!(dropping.dropped, [root]);
    assert_eq!(leaves.len(), 16);
    // Nothing references the leaves now, and they go together, moving nothing
    assert!(leaves.iter().all(|leaf| !router.referenced(leaf.as_ref()).expect("referenced")));
    let (dropping, _) = router.collect_all(&leaves).expect("collect");
    assert_eq!((dropping.dropped.len(), dropping.freed), (16, 1000));
    assert!(kept_files(&scratch).is_empty());
    assert!(forms(&router).is_empty());
}

#[test]
fn leaves_of_files_imported_in_place_stay() {
    let scratch = Scratch::new("shards-drop-in-place");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = sharded(&scratch);
    import_copying(&mut router, &file);
    import_in_place(&mut router, &file);
    let leaves = kept_leaves(&router, &content(1000, 0));
    assert!(leaves.iter().all(|leaf| !router.can_drop(leaf.as_ref()).expect("can")), "they're the user's");
    assert_eq!(router.drop_all(&leaves).expect("drop").dropped.len(), 0);
    assert_eq!(kept_files(&scratch).len(), 1);
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
        shards.threshold = Some(100);
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

#[test]
fn volumes_are_attached_where_they_were_seen() {
    let scratch = Scratch::new("volumes-attach");
    let (repo, backup) = (scratch.path().join("repo"), scratch.path().join("backup"));
    let block = raw(b"kept twice");
    {
        let mut router = Catalog::open_repo(&repo).expect("open");
        router.add_volume("backup", &backup).expect("add");
        router.put_block(&block, CidVersion::V1).expect("put");
        // Both are on the scratch directory's disk, so replicating won't
        // copy it there; another node's copy there is caught up with
        assert_eq!(router.replicate(2).expect("replicate").copied, 0);
        let mut other = ShardStore::open(Db::memory().expect("db"), &backup).expect("other");
        other.threshold = None;
        other.put(&block).expect("copy");
        assert_eq!(router.catch_up().expect("catch up"), (1, 0));
    }
    let attached = |router: &Catalog| -> Vec<(String, bool)> {
        router.volume_list().expect("list").into_iter().map(|v| (v.name, v.attached)).collect()
    };
    let router = Catalog::open_repo(&repo).expect("reopen");
    assert_eq!(attached(&router), [("db".to_owned(), true), ("shards".to_owned(), true), ("backup".to_owned(), true)]);
    assert_eq!(router.placements(block.cid().multihash()).expect("placements").len(), 2);
    drop(router);

    // Gone, or something else in its place, it's known but not attached
    std::fs::rename(&backup, scratch.path().join("elsewhere")).expect("unmount");
    let router = Catalog::open_repo(&repo).expect("reopen");
    assert_eq!(attached(&router).last(), Some(&("backup".to_owned(), false)));
    assert_eq!(router.placements(block.cid().multihash()).expect("placements").len(), 1);
    drop(router);
    ShardStore::open(Db::memory().expect("db"), &backup).expect("impostor");
    let router = Catalog::open_repo(&repo).expect("reopen");
    assert_eq!(attached(&router).last(), Some(&("backup".to_owned(), false)));
}

#[test]
fn volumes_on_one_disk_risk_it_together() {
    let scratch = Scratch::new("volumes-domains");
    let mut router = router();
    assert!(router.add_volume("a", &scratch.path().join("a")).expect("add").is_empty());
    // The database is in memory, so on no disk; both directories are on
    // the scratch directory's
    let shared = router.add_volume("b", &scratch.path().join("b")).expect("add");
    assert_eq!(shared.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["a"]);
    assert_eq!(shared.first().map(|(_, risks)| risks.clone()), Some(volume::risks_of(scratch.path())));
    assert!(router.add_volume("a", &scratch.path().join("c")).is_err());
    assert!(router.add_volume("again", &scratch.path().join("a")).is_err());

    let block = raw(b"precious");
    router.put_block(&block, CidVersion::V1).expect("put");
    let report = router.replicate(3).expect("replicate");
    assert_eq!((report.copied, report.short.len()), (1, 1));
    assert_eq!(router.placements(block.cid().multihash()).expect("placements").len(), 2);
    // It takes two failures to lose it already, nothing more to do
    assert_eq!(router.replicate(2).expect("replicate").copied, 0);
}

#[test]
fn shared_volumes_are_caught_up_with() {
    let scratch = Scratch::new("volumes-shared");
    let shared = scratch.path().join("shared");
    let (mut a, mut b) = (router(), router());
    a.add_volume("shared", &shared).expect("add");
    let (one, two) = (raw(b"one"), raw(b"two"));
    a.put_block(&one, CidVersion::V1).expect("put");
    a.replicate(2).expect("replicate");

    // Another node opening it learns what's there
    b.add_volume("shared", &shared).expect("add");
    assert!(b.has(one.cid().multihash()).expect("has"));
    assert_eq!(b.get(one.cid().multihash()).expect("get").as_deref(), Some(&b"one"[..]));

    // And what's added and removed since
    a.put_block(&two, CidVersion::V1).expect("put");
    a.replicate(2).expect("replicate");
    let shards = ShardStore::open(Db::memory().expect("db"), &shared).expect("shards");
    std::fs::remove_file(shards.path(one.cid().multihash())).expect("remove");
    assert_eq!(b.catch_up().expect("catch up"), (1, 1));
    assert!(b.has(two.cid().multihash()).expect("has"));
    assert!(!b.has(one.cid().multihash()).expect("has"));
    assert_eq!(b.catch_up().expect("catch up"), (0, 0));
}

#[test]
fn unreadable_blocks_are_short() {
    let scratch = Scratch::new("volumes-unreadable");
    let file = scratch.path().join("file");
    std::fs::write(&file, content(1000, 0)).expect("write");
    let mut router = router();
    router.add_volume("backup", &scratch.path().join("backup")).expect("add");
    import_in_place(&mut router, &file);
    std::fs::write(&file, content(1000, 1)).expect("change");
    // The node is copied; the leaves, whose file changed, can't be
    let report = router.replicate(2).expect("replicate");
    assert_eq!((report.copied, report.short.len()), (1, 16));
}

/// Set every shard directory's mtime, as if it was last written then.
fn backdate(dir: &std::path::Path, when: std::time::SystemTime) {
    for entry in std::fs::read_dir(dir).expect("dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            std::fs::File::open(&path).expect("shard").set_modified(when).expect("backdate");
        }
    }
}

#[test]
fn only_changed_shards_are_listed_again() {
    let scratch = Scratch::new("volumes-mtimes");
    let shared = scratch.path().join("shared");
    let mut router = router();
    router.add_volume("shared", &shared).expect("add");
    let mut other = ShardStore::open(Db::memory().expect("db"), &shared).expect("other");
    other.threshold = None;
    let one = raw(b"one");
    // Another block in the same shard
    let shard_of = |block: &Block| other.path(block.cid().multihash()).parent().map(std::path::Path::to_owned);
    let two = (0..u32::MAX).map(|i| raw(&i.to_le_bytes())).find(|block| shard_of(block) == shard_of(&one)).expect("a neighbour");
    other.put(&one).expect("put");
    let then = std::time::SystemTime::now() - std::time::Duration::from_mins(1);
    backdate(other.dir(), then);
    assert_eq!(router.catch_up().expect("catch up"), (1, 0));

    // A blob slipped in without its shard's mtime changing isn't seen,
    // which shows unchanged shards aren't listed...
    other.put(&two).expect("put");
    backdate(other.dir(), then);
    assert_eq!(router.catch_up().expect("catch up"), (0, 0));
    // ...and once its shard's mtime is anything else, it is
    backdate(other.dir(), then + std::time::Duration::from_secs(1));
    assert_eq!(router.catch_up().expect("catch up"), (1, 0));
    assert!(router.has(two.cid().multihash()).expect("has"));
}

#[test]
fn risks_are_found() {
    let scratch = Scratch::new("volumes-disks");
    let here = volume::risks_of(scratch.path());
    assert!(!here.is_empty());
    // Wherever in a filesystem, the same; and a filesystem with no disk is
    // named by its mount
    assert_eq!(volume::risks_of(&scratch.path().join("..")), here);
    if std::path::Path::new("/proc/self/mountinfo").exists() {
        assert_eq!(volume::risks_of(std::path::Path::new("/proc")), ["proc:proc"]);
    }
}

#[test]
fn tolerance_is_failures_to_lose_every_copy() {
    let copies = |sets: &[&[&str]]| -> Vec<Vec<String>> {
        sets.iter().map(|set| set.iter().map(|&risk| risk.to_owned()).collect()).collect()
    };
    let tolerance = |sets: &[&[&str]]| volume::tolerance(&copies(sets), 5);
    assert_eq!(tolerance(&[]), 0);
    assert_eq!(tolerance(&[&["a"]]), 1);
    assert_eq!(tolerance(&[&["a"], &["b"]]), 2);
    // Two volumes on one disk, or in one house
    assert_eq!(tolerance(&[&["a", "nvme"], &["b", "nvme"]]), 1);
    assert_eq!(tolerance(&[&["a", "nvme", "home"], &["b", "usb", "home"], &["c", "cloud"]]), 2);
    assert_eq!(volume::tolerance(&copies(&[&["a"], &["b"], &["c"]]), 2), 2, "counted only so far");
}

#[test]
fn said_risks_count() {
    let scratch = Scratch::new("volumes-said");
    let mut router = router();
    router.add_volume("a", &scratch.path().join("a")).expect("add");
    let block = raw(b"precious");
    router.put_block(&block, CidVersion::V1).expect("put");
    assert_eq!(router.replicate(2).expect("replicate").copied, 1);

    // The database and the copy are in one house after all, so one more
    // copy, even on a's disk, helps
    router.add_risk("db", "home").expect("risk");
    router.add_risk("a", "home").expect("risk");
    router.add_volume("b", &scratch.path().join("b")).expect("add");
    let report = router.replicate(2).expect("replicate");
    assert_eq!((report.copied, report.short.len()), (1, 0));

    // Said risks can be unsaid; found ones can't
    let found = volume::risks_of(scratch.path());
    let disk = found.first().expect("a risk");
    assert!(router.remove_risk("a", disk).is_err());
    assert!(router.remove_risk("a", "office").is_err());
    router.remove_risk("a", "home").expect("unsay");
    let list = router.risk_list().expect("list");
    assert!(list.contains(&("db".to_owned(), "home".to_owned(), false)));
    assert!(list.contains(&("a".to_owned(), disk.clone(), true)));
    assert!(!list.contains(&("a".to_owned(), "home".to_owned(), false)));
}

fn with_sqlite(scratch: &Scratch, file: &str) -> Catalog {
    let mut router = router();
    router.add_sqlite_volume("shared", &scratch.path().join(file)).expect("add");
    router
}

/// Which volumes and forms a block is in, by name.
fn placed(router: &Catalog, block: &Block) -> Vec<(String, String)> {
    router.placements(block.cid().multihash()).expect("placements").into_iter()
        .map(|(v, form)| (router.volumes.get(v).expect("volume").name.clone(), form))
        .collect()
}

fn pair(volume: &str, form: &str) -> (String, String) {
    (volume.to_owned(), form.to_owned())
}

#[test]
fn database_volumes_are_caught_up_with_by_generation() {
    let scratch = Scratch::new("volumes-generations");
    let (a, mut b) = (with_sqlite(&scratch, "shared.db"), router());
    let (leaf, other) = (raw(b"leaf"), raw(b"other"));
    let parent = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::Link(link(&leaf)));
    // Kept as raw bytes, so only the codec it was put with says it links
    let json = block(crate::cid::DAG_JSON_CODEC, format!(r#"[{{"/":"{}"}}]"#, leaf.cid()).as_bytes());
    for block in [&leaf, &parent, &json, &other] {
        a.put_block(block, CidVersion::V1).expect("put");
    }
    assert_eq!(a.copy_to("shared", &[link(&parent)]).expect("copy").copied, 2);
    assert_eq!(a.copy_to("shared", &[]).expect("copy").copied, 2);
    assert_eq!(a.copy_to("shared", &[]).expect("copy").copied, 0);

    // Another node opening it learns what's there, and what links to what
    b.add_sqlite_volume("shared", &scratch.path().join("shared.db")).expect("add");
    assert!(b.has(leaf.cid().multihash()).expect("has"));
    assert_eq!(sorted(b.backrefs(leaf.cid().multihash()).expect("backrefs")), sorted(vec![mh(&parent), mh(&json)]));
    // Structure is kept in the catalog too; bulk isn't
    assert_eq!(placed(&b, &parent), [pair("db", "ipld"), pair("shared", "ipld")]);
    assert_eq!(placed(&b, &leaf), [pair("shared", "raw")]);
    assert_eq!(b.catch_up().expect("catch up"), (0, 0));

    // What's added since, and what's removed, however it was
    let late = raw(b"late");
    a.put_block(&late, CidVersion::V1).expect("put");
    assert_eq!(a.copy_to("shared", &[link(&late)]).expect("copy").copied, 1);
    let shared = a.volumes.last().and_then(Volume::db).expect("shared");
    let id = shared.lookup(other.cid().multihash()).expect("lookup").expect("id");
    shared.conn().execute("DELETE FROM raw_blocks WHERE block = ?1", [id]).expect("remove");
    assert_eq!(b.catch_up().expect("catch up"), (1, 1));
    assert!(b.has(late.cid().multihash()).expect("has"));
    assert!(!b.has(other.cid().multihash()).expect("has"));
    assert_eq!(b.catch_up().expect("catch up"), (0, 0));

    // A reindex starts from the generation it saw
    b.reindex().expect("reindex");
    assert_eq!(b.catch_up().expect("catch up"), (0, 0));
}

#[test]
fn database_volumes_are_attached_where_they_were_seen() {
    let scratch = Scratch::new("volumes-attach-db");
    let (repo, usb) = (scratch.path().join("repo"), scratch.path().join("usb.db"));
    let block = raw(b"carried");
    {
        let mut router = Catalog::open_repo(&repo).expect("open");
        router.add_sqlite_volume("usb", &usb).expect("add");
        router.put_block(&block, CidVersion::V1).expect("put");
        assert_eq!(router.copy_to("usb", &[link(&block)]).expect("copy").copied, 1);
    }
    let router = Catalog::open_repo(&repo).expect("reopen");
    assert_eq!(placed(&router, &block), [pair("db", "raw"), pair("usb", "raw")]);
    drop(router);

    // Gone, or another database in its place, it's known but not attached
    std::fs::rename(&usb, scratch.path().join("elsewhere.db")).expect("unplug");
    let router = Catalog::open_repo(&repo).expect("reopen");
    assert_eq!(placed(&router, &block), [pair("db", "raw")]);
    drop(router);
    with_sqlite(&scratch, "usb.db");
    let router = Catalog::open_repo(&repo).expect("reopen");
    assert_eq!(placed(&router, &block), [pair("db", "raw")]);
    assert!(router.copy_to("usb", &[]).is_err());
}

#[test]
fn tags_go_where_what_they_tag_does() {
    let scratch = Scratch::new("volumes-tags");
    let (a, mut b) = (with_sqlite(&scratch, "shared.db"), router());
    let (leaf, elsewhere) = (raw(b"leaf"), raw(b"elsewhere"));
    let parent = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::Link(link(&leaf)));
    for block in [&leaf, &parent, &elsewhere] {
        a.put_block(block, CidVersion::V1).expect("put");
    }
    // A dissolved tag on the leaf, and a precipitated claim tagging it and
    // something not under the root
    a.tag(&link(&leaf), &tag("music")).expect("tag");
    let pair = Claim::Group(Group::new([link(&leaf), link(&elsewhere)], tag("pair")).expect("group"));
    a.put_block(&pair.block(), CidVersion::V1).expect("put");
    let report = a.copy_to("shared", &[link(&parent)]).expect("copy");
    assert_eq!((report.copied, report.claims), (3, 1));
    assert!(!a.placements(elsewhere.cid().multihash()).expect("placements").iter().any(|&(v, _)| v == a.volumes.len() - 1));

    b.add_sqlite_volume("shared", &scratch.path().join("shared.db")).expect("add");
    let claims = b.claims().expect("claims");
    assert_eq!(claims.tags(leaf.cid().multihash()).expect("tags"), [tag("pair"), tag("music")]);

    // Untagging follows them too, dissolved and precipitated
    a.untag(&link(&leaf), &tag("music")).expect("untag");
    a.untag(&link(&leaf), &tag("pair")).expect("untag");
    let report = a.copy_to("shared", &[link(&parent)]).expect("copy");
    assert!(report.claims >= 1, "the tombs: {report:?}");
    b.catch_up().expect("catch up");
    assert_eq!(b.claims().expect("claims").tags(leaf.cid().multihash()).expect("tags"), Vec::<crate::model::Link>::new());
    assert_eq!(b.catch_up().expect("catch up"), (0, 0));
}

#[test]
fn replicas_keep_dissolved_claims() {
    let scratch = Scratch::new("volumes-replica-claims");
    let (a, mut b) = (with_sqlite(&scratch, "shared.db"), router());
    let block = raw(b"tagged");
    a.put_block(&block, CidVersion::V1).expect("put");
    a.tag(&link(&block), &tag("kept")).expect("tag");
    let report = a.replicate(2).expect("replicate");
    assert_eq!((report.copied, report.claims), (1, 1));
    assert_eq!(a.replicate(2).expect("replicate").claims, 0);
    b.add_sqlite_volume("shared", &scratch.path().join("shared.db")).expect("add");
    assert_eq!(b.claims().expect("claims").tagged(tag("kept").multihash()).expect("tagged"), [link(&block)]);
}

/// A catalog whose user is `root`, signing as a device `root` certified.
fn signed_router(root: &crate::keys::Key) -> (Catalog, crate::keys::Key) {
    let mut router = router();
    let device = crate::keys::Key::generate().expect("key");
    router.set_user(&root.id()).expect("user");
    router.certify(root, &device.id()).expect("certify");
    router.set_signer(device.clone()).expect("signer");
    (router, device)
}

/// Sign a claim with a key, as another device would.
fn sign(router: &Catalog, key: &crate::keys::Key, claim: &crate::model::Link) {
    let sign = Claim::Sign(crate::claim::Sign::new(key, [claim.clone()], None, 1).expect("sign"));
    router.put_block(&sign.block(), CidVersion::V1).expect("put");
}

#[test]
fn a_repo_has_no_user_until_it_founds_one_with_a_sealed_root() {
    use crate::keys::Cost;
    let scratch = Scratch::new("found-user");
    let block = raw(b"kept");
    let repo = Catalog::open_repo(scratch.path()).expect("open");
    let device = repo.signer().expect("signer").id();
    assert!(repo.user().expect("user").is_none());
    assert!(repo.root(b"anything").is_err());
    let keep = repo.keep(&link(&block)).expect("keep");
    let claims = repo.claims().expect("claims");
    assert!(claims.signed_by(&keep, &device).expect("signed"));
    assert!(claims.kept(block.cid().multihash()).expect("kept"), "no user, so taken at its word");

    let root = repo.found_user(b"correct horse", Cost::NONE).expect("found");
    assert_eq!(repo.user().expect("user"), Some(root.id()));
    assert_eq!(repo.devices().expect("devices"), [(device.clone(), true)]);
    assert!(claims.kept(block.cid().multihash()).expect("kept"), "signed by a device the user certified");
    // The root is kept sealed, and only sealed
    let [(seal, _)] = <[_; 1]>::try_from(repo.seals().expect("seals")).expect("one seal");
    assert!(claims.kept(seal.multihash()).expect("kept"));
    assert_eq!(repo.root(b"correct horse").expect("root").id(), root.id());
    assert!(repo.root(b"battery staple").is_err());
    assert!(repo.found_user(b"again", Cost::NONE).is_err());
    assert!(!scratch.path().join(crate::keys::USER_KEY).exists());
    drop(repo);
    // The same user, and the same device, next time
    let repo = Catalog::open_repo(scratch.path()).expect("open");
    assert_eq!(repo.signer().expect("signer").id(), device);
    assert_eq!(repo.user().expect("user"), Some(root.id()));
    assert_eq!(repo.root(b"correct horse").expect("root").id(), root.id());
}

#[test]
fn claims_count_only_when_an_authorized_key_signs_them() {
    let root = crate::keys::Key::generate().expect("key");
    let (router, _) = signed_router(&root);
    let claims = router.claims().expect("claims");
    let block = raw(b"kept");
    let kept = || claims.kept(block.cid().multihash()).expect("kept");

    // Unsigned, as from a CAR or another user's mesh
    let keep = Claim::Keep(crate::claim::Keep::new([link(&block)]).expect("keep"));
    router.put_block(&keep.block(), CidVersion::V1).expect("put");
    assert!(!kept());
    // Signed by a key nobody certified
    let stranger = crate::keys::Key::generate().expect("key");
    sign(&router, &stranger, &keep.cid());
    assert!(!kept());
    // Until the root certifies it
    router.certify(&root, &stranger.id()).expect("certify");
    assert!(kept());

    // A device can't certify another
    let other = crate::keys::Key::generate().expect("key");
    let device = router.certify(&stranger, &other.id()).expect("certify");
    assert!(!claims.authorized(&other.id()).expect("authorized"));
    // Nor revoke one
    let tomb = Claim::Tomb(crate::claim::Tomb::new([device]).expect("tomb"));
    router.put_block(&tomb.block(), CidVersion::V1).expect("put");
    sign(&router, &stranger, &tomb.cid());
    assert!(claims.authorized(&stranger.id()).expect("authorized"));

    // A tomb nobody authorized signed doesn't retract
    let tomb = Claim::Tomb(crate::claim::Tomb::new([keep.cid()]).expect("tomb"));
    router.put_block(&tomb.block(), CidVersion::V1).expect("put");
    assert!(kept());
    sign(&router, &crate::keys::Key::generate().expect("key"), &tomb.cid());
    assert!(kept());
    sign(&router, &stranger, &tomb.cid());
    assert!(!kept());
}

#[test]
fn a_tampered_signature_is_no_claim() {
    let root = crate::keys::Key::generate().expect("key");
    let (router, device) = signed_router(&root);
    let keep = Claim::Keep(crate::claim::Keep::new([link(&raw(b"kept"))]).expect("keep"));
    let sign = crate::claim::Sign::new(&device, [keep.cid()], None, 1).expect("sign");
    let forged = crate::claim::Sign::from_parts([keep.cid()], device.id(), 2, None, sign.sig().to_vec()).expect("sign");
    let unlinked = crate::claim::Sign::from_parts([keep.cid()], device.id(), 1, Some(keep.cid()), sign.sig().to_vec()).expect("sign");
    assert!(!unlinked.verify(), "prev is signed too");
    assert!(sign.verify() && !forged.verify());
    // Just dag-cbor, to the claim store
    assert_eq!(router.put_block(&Claim::Sign(forged).block(), CidVersion::V1).expect("put"), "ipld");
    router.put_block(&keep.block(), CidVersion::V1).expect("put");
    assert!(!router.claims().expect("claims").kept(keep.target()[0].multihash()).expect("kept"));
}

#[test]
fn revoking_a_device_unsigns_what_it_alone_said_after_its_cutoff() {
    let root = crate::keys::Key::generate().expect("key");
    let (router, _) = signed_router(&root);
    let claims = router.claims().expect("claims");
    let lost = crate::keys::Key::generate().expect("key");
    router.certify(&root, &lost.id()).expect("certify");
    let (before, after, both, forged) = (raw(b"before"), raw(b"after"), raw(b"both"), raw(b"forged"));
    let keep = |block: &Block| Claim::Keep(crate::claim::Keep::new([link(block)]).expect("keep"));
    for block in [&before, &after, &both, &forged] {
        router.put_block(&keep(block).block(), CidVersion::V1).expect("put");
    }
    let sign = |blocks: &[&Block], prev: Option<Link>, at| {
        let sign = Claim::Sign(crate::claim::Sign::new(&lost, blocks.iter().map(|block| keep(block).cid()), prev, at).expect("sign"));
        router.put_block(&sign.block(), CidVersion::V1).expect("put");
        sign.cid()
    };
    // Its chain: before and both at 10, then after at 30
    let first = sign(&[&before, &both], None, 10);
    let second = sign(&[&after], Some(first.clone()), 30);
    assert_eq!(claims.head(&lost.id()).expect("head"), Some(second.clone()));
    router.put_claim(&keep(&both)).expect("signed here too");
    let kept = |block: &Block| claims.kept(block.cid().multihash()).expect("kept");
    assert!(kept(&before) && kept(&after) && kept(&both));
    assert_eq!(router.cutoff_at(&lost.id(), 20).expect("cutoff"), Some(first.clone()));
    assert_eq!(router.cutoff_at(&lost.id(), 5).expect("cutoff"), None);
    assert_eq!(router.cutoff_at(&lost.id(), 40).expect("cutoff"), Some(second));

    // A thief, with a copy of the key, backdates a sign to before then
    sign(&[&forged], Some(first.clone()), 15);
    assert!(kept(&forged));
    assert_eq!(router.forks(&lost.id()).expect("forks"), [Some(first.clone())]);
    assert!(router.cutoff_at(&lost.id(), 20).is_err(), "times aren't to be trusted once it forks");

    // Lost after its first sign: what that signed is signed again here,
    // and nothing after, backdated or not
    assert_eq!(router.revoke(&root, &lost.id(), Some(&first)).expect("revoke"), 1);
    assert!(!claims.authorized(&lost.id()).expect("authorized"));
    assert!(kept(&before) && !kept(&after) && kept(&both) && !kept(&forged));
    assert_eq!(router.devices().expect("devices").iter().filter(|(_, ok)| *ok).count(), 1);
}

#[test]
fn a_batch_says_what_it_says_in_one_sign_and_signs_follow_each_other() {
    let root = crate::keys::Key::generate().expect("key");
    let (mut router, device) = signed_router(&root);
    let (a, b, c) = (raw(b"a"), raw(b"b"), raw(b"c"));
    let claims = |router: &Catalog| router.claims().expect("claims").signs_by(&device.id()).expect("signs");
    router.keep(&link(&a)).expect("keep");
    let [first] = <[_; 1]>::try_from(claims(&router)).expect("one sign");
    assert_eq!((first.prev.as_ref(), first.claims), (None, 1));
    router.batch(|router| {
        router.keep(&link(&b))?;
        router.tag(&link(&b), &tag("bee"))?;
        router.keep(&link(&c))?;
        Ok::<_, Error>(())
    }).expect("batch");
    let signs = claims(&router);
    assert_eq!(signs.len(), 2);
    assert_eq!(signs.get(1).map(|signed| (signed.prev.clone(), signed.claims)), Some((Some(first.sign), 3)));
    let store = router.claims().expect("claims");
    assert!(store.kept(b.cid().multihash()).expect("kept") && store.kept(c.cid().multihash()).expect("kept"));
    assert_eq!(store.tags(b.cid().multihash()).expect("tags"), [tag("bee")]);
    // A batch that fails signs nothing
    let failed: Result<()> = router.batch(|router| {
        router.keep(&link(&raw(b"d")))?;
        Err(Error::NoClaims)
    });
    assert!(failed.is_err());
    assert_eq!(claims(&router).len(), 2);
    assert!(router.forks(&device.id()).expect("forks").is_empty());
}

#[test]
fn what_a_device_said_before_it_had_a_user_counts_once_the_user_certifies_it() {
    let mut router = router();
    let device = crate::keys::Key::generate().expect("key");
    router.set_signer(device.clone()).expect("signer");
    let block = raw(b"kept");
    router.keep(&link(&block)).expect("keep");
    let kept = |router: &Catalog| router.claims().expect("claims").kept(block.cid().multihash()).expect("kept");
    assert!(kept(&router));
    // Joining a user that hasn't certified it yet
    let root = crate::keys::Key::generate().expect("key");
    router.set_user(&root.id()).expect("user");
    assert!(!kept(&router));
    router.certify(&root, &device.id()).expect("certify");
    assert!(kept(&router));
    // Another user's, merging: certified by that one, it counts there too
    let other = crate::keys::Key::generate().expect("key");
    router.set_user(&other.id()).expect("user");
    assert!(!kept(&router));
    router.certify(&other, &device.id()).expect("certify");
    assert!(kept(&router));
}

#[test]
fn accounts_see_what_counts_for_them_and_collecting_respects_them_all() {
    use crate::keys::{Cost, Key};
    let scratch = Scratch::new("accounts");
    let mut repo = Catalog::open_repo(scratch.path()).expect("open");
    let (a, b) = (raw(b"alice's"), raw(b"bob's"));
    for block in [&a, &b] {
        repo.put_block(block, CidVersion::V1).expect("put");
    }
    let owner = repo.signer().expect("signer").clone();
    let me = repo.uid();
    let bob = me.wrapping_add(1);
    let bobs = Key::generate().expect("key");
    let tags = |repo: &Catalog, block: &Block| repo.claims().expect("claims").tags(block.cid().multihash()).expect("tags");
    let kept = |repo: &Catalog, block: &Block| repo.claims().expect("claims").kept(block.cid().multihash()).expect("kept");
    let referenced = |repo: &Catalog, block: &Block| repo.referenced(block.cid().multihash()).expect("referenced");

    let alices_keep = repo.keep(&link(&a)).expect("keep");
    repo.tag(&link(&a), &tag("alice")).expect("tag");
    repo.act_for(bob, bobs.clone()).expect("act");
    repo.keep(&link(&b)).expect("keep");
    repo.tag(&link(&a), &tag("bob")).expect("tag");
    // Bob sees his own
    assert_eq!(tags(&repo, &a), [tag("bob")]);
    assert!(kept(&repo, &b) && !kept(&repo, &a));
    // A tomb of Alice's keep, signed by Bob, retracts nothing of hers
    let tomb = Claim::Tomb(Tomb::new([alices_keep]).expect("tomb"));
    repo.put_claim(&tomb).expect("tomb");

    repo.act_for(me, owner.clone()).expect("act");
    assert_eq!(tags(&repo, &a), [tag("alice")]);
    assert!(kept(&repo, &a) && !kept(&repo, &b));
    // Collecting respects everyone's keeps, whoever's acting
    assert!(referenced(&repo, &a) && referenced(&repo, &b));
    let accounts = repo.claims().expect("claims").accounts().expect("accounts");
    assert_eq!(accounts.iter().map(|account| (account.uid, account.device.clone())).collect::<Vec<_>>(), [(me, Some(owner.id())), (bob, Some(bobs.id()))]);

    // Bob stops keeping his: nothing keeps it now
    repo.act_for(bob, bobs.clone()).expect("act");
    repo.unkeep(&link(&b)).expect("unkeep");
    assert!(!referenced(&repo, &b));
    // Bob makes a mesh of his own: what he said still counts for him
    let root = repo.found_user(b"bob's", Cost::NONE).expect("found");
    assert_eq!(repo.user().expect("user"), Some(root.id()));
    assert_eq!(tags(&repo, &a), [tag("bob")]);
    assert_eq!(repo.devices().expect("devices"), [(bobs.id(), true)]);
    repo.act_for(me, owner).expect("act");
    assert!(repo.user().expect("user").is_none());
    assert_eq!(tags(&repo, &a), [tag("alice")]);
    assert!(repo.devices().expect("devices").is_empty(), "Bob's user certified no device of Alice's");
}

#[test]
fn a_repo_from_when_there_was_one_user_keeps_it() {
    let scratch = Scratch::new("one-user");
    let root = crate::keys::Key::generate().expect("key");
    let db = Db::open(&scratch.path().join("blocks.db")).expect("db");
    let key = db.intern(root.id().multihash()).expect("intern");
    db.conn().execute_batch("CREATE TABLE users (key INTEGER PRIMARY KEY); CREATE TABLE authorized (key INTEGER PRIMARY KEY);").expect("old");
    db.conn().execute("INSERT INTO users (key) VALUES (?1)", [key]).expect("user");
    let repo = Catalog::standard(db).expect("open");
    assert_eq!(repo.user().expect("user"), Some(root.id()));
    assert!(repo.claims().expect("claims").authorized(&root.id()).expect("authorized"));
}

#[test]
fn what_another_account_says_isnt_for_this_ones_mesh() {
    let scratch = Scratch::new("withheld");
    let mut repo = Catalog::open_repo(scratch.path()).expect("open");
    let block = raw(b"both");
    repo.put_block(&block, CidVersion::V1).expect("put");
    let owner = repo.signer().expect("signer").clone();
    let me = repo.uid();
    let other = crate::keys::Key::generate().expect("key");
    repo.act_for(me.wrapping_add(1), other.clone()).expect("act");
    let theirs = repo.tag(&link(&block), &tag("theirs")).expect("tag");
    let shared = repo.keep(&link(&block)).expect("keep");
    repo.act_for(me, owner.clone()).expect("act");
    let mine = repo.tag(&link(&block), &tag("mine")).expect("tag");
    repo.keep(&link(&block)).expect("keep");

    let signs = |key: &crate::keys::Key| repo.claims().expect("claims").signs_by(&key.id()).expect("signs");
    assert!(repo.withheld(&theirs).expect("withheld"));
    assert!(signs(&other).iter().all(|signed| repo.withheld(&signed.sign).expect("withheld")));
    assert!(!repo.withheld(&mine).expect("withheld"));
    assert!(!repo.withheld(&shared).expect("withheld"), "this account signed it too");
    assert!(signs(&owner).iter().all(|signed| !repo.withheld(&signed.sign).expect("withheld")));
    assert!(!repo.withheld(&link(&block)).expect("withheld"), "blocks are anyone's");
    // And the other way about
    repo.act_for(me.wrapping_add(1), other).expect("act");
    assert!(repo.withheld(&mine).expect("withheld") && !repo.withheld(&theirs).expect("withheld"));
}
