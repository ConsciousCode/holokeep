use super::*;
use crate::cid::{AnyCid, Cidv1Spec, DAG_CBOR_CODEC, DAG_PB_CODEC, RAW_CODEC};
use crate::dag::{BalancedLayout, DynamicDirectory};
use crate::hamt::Hamt;
use crate::import::Importer;
use crate::multihash::MultihashFunc;
use crate::dag::Provenance;
use crate::testutil::Scratch;
use crate::unixfs;

mod converge;

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

/// What an anchor was stays referenced, and what's under it, till it's
/// forgotten; and forgetting never changes what it is.
#[test]
fn history_is_kept_till_its_forgotten() {
    let scratch = Scratch::new("history-kept");
    let catalog = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    let value = |data: &[u8]| -> (Block, Link) {
        let block = raw(data);
        catalog.put_block(&block, CidVersion::V1).expect("put");
        let cid = block.cid().clone().into();
        (block, cid)
    };
    let anchor = catalog.new_anchor().expect("anchor");
    catalog.keep(&anchor).expect("keep");
    let (old, older) = value(b"oldest");
    let (_, middle) = value(b"middle");
    let (_, now) = value(b"now");
    let first = catalog.set_anchor(&anchor, &older).expect("set");
    let second = catalog.set_anchor(&anchor, &middle).expect("set");
    let third = catalog.set_anchor(&anchor, &now).expect("set");
    assert!([&first, &second, &third].iter().all(|set| !set.to_bytes().is_empty()));
    assert!(catalog.referenced(old.cid().multihash()).expect("referenced"), "what it was");
    assert!(catalog.kept_under(old.cid().multihash()).expect("kept"));

    let everything = u64::MAX;
    let versions = catalog.versions_before(&anchor, everything).expect("versions");
    assert_eq!(versions.len(), 2, "all but what it is");
    assert_eq!(catalog.versions_before(&anchor, 0).expect("versions"), [], "nothing's before the start of time");
    catalog.forget_versions(&anchor, &versions).expect("forget").expect("a tomb");
    assert_eq!(catalog.anchor_value(&anchor).expect("value"), Some(now.clone()), "still what it is");
    assert_eq!(catalog.anchor_history(&anchor).expect("history").len(), 1);
    assert!(!catalog.referenced(old.cid().multihash()).expect("referenced"), "free to go");
    assert!(catalog.referenced(now.multihash()).expect("referenced"));
    assert_eq!(catalog.versions_before(&anchor, everything).expect("versions"), [], "nothing left to forget");
    assert_eq!(catalog.forget_versions(&anchor, &[]).expect("forget"), None);
}

/// Forgetting takes what's replaced too, whatever its clock said, or that
/// would be what the anchor is now.
#[test]
fn forgetting_a_version_takes_what_it_replaced() {
    let scratch = Scratch::new("history-skewed");
    let catalog = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    let anchor = catalog.new_anchor().expect("anchor");
    let at = |value: &Block, at: u64, prev: Vec<Link>| -> Link {
        catalog.put_block(value, CidVersion::V1).expect("put");
        let set = crate::claim::Set::new([anchor.clone()], value.cid().clone().into(), at).expect("set").after(Some(prev));
        catalog.put_claim(&Claim::Set(set)).expect("put")
    };
    // By its clock, the first's after the second, which replaced it
    let (first, second, third) = (raw(b"first"), raw(b"second"), raw(b"third"));
    let a = at(&first, 500, Vec::new());
    let b = at(&second, 100, vec![a]);
    at(&third, 900, vec![b]);
    let third_cid: Link = third.cid().clone().into();
    assert_eq!(catalog.anchor_value(&anchor).expect("value"), Some(third_cid.clone()));

    let versions = catalog.versions_before(&anchor, 200).expect("versions");
    assert_eq!(versions.len(), 2, "the second, and what it replaced, which it says is later");
    catalog.forget_versions(&anchor, &versions).expect("forget");
    assert_eq!(catalog.anchor_value(&anchor).expect("value"), Some(third_cid));
    assert_eq!(catalog.anchor_heads(&anchor).expect("heads").len(), 1);
}

/// Lost is only what's said of what isn't here: when it turns up, that's that.
#[test]
fn what_turns_up_is_not_lost() {
    let scratch = Scratch::new("lost");
    let repo = scratch.path().join("repo");
    let catalog = Catalog::open_repo(&repo).expect("catalog");
    let gone = raw(b"gone");
    let cid: Link = gone.cid().clone().into();
    assert_eq!(catalog.lost_at(&cid).expect("lost"), None);

    let claim = catalog.report_lost(&cid).expect("report").expect("a claim");
    assert!(claim.hashcode() == IDENTITY, "small enough to dissolve");
    let at = catalog.lost_at(&cid).expect("lost").expect("it's lost");
    assert_eq!(catalog.lost_blocks().expect("list"), [(cid.clone(), at)]);
    assert_eq!(catalog.report_lost(&cid).expect("again"), None, "once is enough");
    // Read back from its rows, it's the same claim
    assert!(catalog.claims().expect("claims").dissolved().expect("dissolved").iter().any(|c| c.cid() == claim));

    catalog.put_block(&gone, CidVersion::V1).expect("put");
    assert_eq!(catalog.lost_at(&cid).expect("lost"), None, "it's here");
    assert!(catalog.lost_blocks().expect("list").is_empty());
    assert_eq!(catalog.report_lost(&cid).expect("report"), None, "what's here can't be lost");

    let other: Link = raw(b"other").cid().clone().into();
    catalog.report_lost(&other).expect("report").expect("a claim");
    assert_eq!(catalog.unreport_lost(&other).expect("unreport").len(), 1);
    assert_eq!(catalog.lost_at(&other).expect("lost"), None, "taken back");
}

/// A stranger can't talk a repo out of looking for something.
#[test]
fn only_those_who_count_can_say_a_block_is_lost() {
    let scratch = Scratch::new("lost-stranger");
    let repo = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    repo.found_user(b"pass", crate::keys::Cost::NONE).expect("found");
    let cid: Link = raw(b"wanted").cid().clone().into();
    // Unsigned, as a stranger's would be
    let lost = Claim::Lost(crate::claim::Lost::new([cid.clone()], 5).expect("lost"));
    repo.put_block(&lost.block(), CidVersion::V1).expect("put");
    assert_eq!(repo.lost_at(&cid).expect("lost"), None);
    assert!(repo.lost_blocks().expect("list").is_empty());
    assert!(repo.worth_asking_for(&cid) && repo.worth_asking_for(&cid));
    // Its own key's does
    repo.report_lost(&cid).expect("report").expect("a claim");
    assert!(repo.lost_at(&cid).expect("lost").is_some());
}

/// Lost blocks are asked for now and then, not on every read.
#[test]
fn what_is_lost_is_not_asked_for_every_time() {
    let scratch = Scratch::new("lost-asked");
    let mut catalog = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    let asks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&asks);
    catalog.fetch_through(std::sync::Arc::new(move |_: &[Link]| {
        counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        false
    }));
    let (lost, unknown): (Link, Link) = (raw(b"lost").cid().clone().into(), raw(b"unknown").cid().clone().into());
    catalog.report_lost(&lost).expect("report");
    for _ in 0..5 {
        assert!(!catalog.fetch_missing(std::slice::from_ref(&lost)));
    }
    assert_eq!(asks.load(std::sync::atomic::Ordering::Relaxed), 1, "once, then not for a while");
    for _ in 0..5 {
        catalog.fetch_missing(std::slice::from_ref(&unknown));
    }
    assert_eq!(asks.load(std::sync::atomic::Ordering::Relaxed), 6, "what isn't reported lost, every time");
}

/// A scan finds what was held, wasn't let go of, and something refers to.
#[test]
fn a_scan_finds_what_went_without_being_let_go() {
    let scratch = Scratch::new("lost-scan");
    let repo = scratch.path().join("repo");
    let t = scratch.path().join("t");
    std::fs::create_dir_all(&t).expect("mkdir");
    std::fs::write(t.join("file"), "imported in place").expect("write");
    let mut catalog = Catalog::open_repo(&repo).expect("catalog");
    let (mount, root) = catalog.batch(|catalog| catalog.import_mounted(&Importer::default(), &t, &mut |_, _| {})).expect("import");
    assert!(catalog.lost_candidates().expect("scan").is_empty(), "nothing's gone");

    // Changed, what it was imported as is gone, though the anchor's value
    // still links to it
    std::fs::write(t.join("file"), "changed, as it may be").expect("write");
    let files = catalog.external_files(None).expect("files");
    assert_eq!(catalog.forget_changed(&files).expect("forget").len(), 1);
    let leaf: Link = raw(b"imported in place").cid().clone().into();
    assert_eq!(catalog.lost_candidates().expect("scan"), std::slice::from_ref(&leaf));
    assert_eq!(catalog.missing_under(&root).expect("missing"), std::slice::from_ref(&leaf));
    assert_eq!(catalog.anchor_value(&mount.anchor).expect("value"), Some(root));

    catalog.report_lost(&leaf).expect("report").expect("a claim");
    assert!(catalog.lost_candidates().expect("scan").is_empty(), "reported once");

    // Nothing refers to what was only ever put on its own
    let scratch2 = Scratch::new("lost-scan-alone");
    let alone = Catalog::open_repo(&scratch2.path().join("repo")).expect("catalog");
    let block = raw(b"alone");
    alone.put_block(&block, CidVersion::V1).expect("put");
    alone.db.conn().execute("DELETE FROM blocks", []).expect("gone");
    assert!(alone.lost_candidates().expect("scan").is_empty(), "nothing refers to it");
}

/// However claims arrive, what's authorized is what it'd be worked out afresh,
/// though it's only worked out when it might have changed: certificates and
/// revocations, before and after what signs them.
#[test]
fn whats_authorized_is_kept_up_however_claims_arrive() {
    let scratch = Scratch::new("claims-authorized");
    let here = Catalog::open_repo(&scratch.path().join("here")).expect("catalog");
    let root = here.found_user(b"pass", crate::keys::Cost::NONE).expect("found");
    let others: Vec<crate::keys::Key> = (0..3).map(|_| crate::keys::Key::generate().expect("key")).collect();
    for other in &others {
        here.certify(&root, &other.id()).expect("certify");
    }
    let revoked = crate::claim::Device::new([others[0].id()]).expect("device");
    let tomb = crate::claim::Claim::Tomb(crate::claim::Tomb::new([crate::claim::Claim::Device(revoked).cid()]).expect("tomb"));
    here.put_block(&tomb.block(), CidVersion::V1).expect("tomb");
    here.sign_with(&root, [tomb.cid()]).expect("sign");
    let claims = here.claims().expect("claims");
    assert!(!claims.authorized(&others[0].id()).expect("authorized"), "revoked");
    assert!(claims.authorized(&others[1].id()).expect("authorized"));

    let mut sections: Vec<Block> = Vec::new();
    for key in here.keys().expect("keys") {
        let cid = here.cid_of(key.as_ref()).expect("cid").expect("cid");
        sections.push(here.get_block(&cid).expect("get").expect("block"));
    }
    for claim in claims.dissolved().expect("dissolved") {
        sections.push(claim.block());
    }
    // Forwards, backwards, and each from the middle out
    let orders: Vec<Vec<&Block>> = vec![
        sections.iter().collect(),
        sections.iter().rev().collect(),
        sections.iter().step_by(2).chain(sections.iter().skip(1).step_by(2)).collect(),
        sections.iter().skip(1).step_by(2).rev().chain(sections.iter().step_by(2)).collect(),
    ];
    for (n, order) in orders.into_iter().enumerate() {
        let there = Catalog::open_repo(&scratch.path().join(format!("there-{n}"))).expect("catalog");
        there.set_user(&root.id()).expect("user");
        for block in order {
            there.put_block(block, CidVersion::V1).expect("put");
            assert!(there.claims().expect("claims").is_authorized_current().expect("current"), "order {n}");
        }
        let claims = there.claims().expect("claims");
        assert!(!claims.authorized(&others[0].id()).expect("authorized"), "order {n}");
        assert!(claims.authorized(&others[2].id()).expect("authorized"), "order {n}");
    }
}

/// A key whose chain forks at its start, as a key copied to a fresh repo's
/// would, signing what it alone keeps. What's trusted decides what stays, what
/// doesn't is said beforehand, and the sealed root isn't at stake either way.
#[test]
fn revoking_a_forked_key_keeps_what_its_told_and_says_what_it_wont() {
    let scratch = Scratch::new("revoke-forked");
    let repo = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    let root = repo.found_user(b"pass", crate::keys::Cost::NONE).expect("found");
    let (seal, _) = repo.seals().expect("seals").into_iter().next().expect("a seal");
    let root_anchor = repo.root_anchor().expect("root").expect("root");
    let old = crate::keys::Key::generate().expect("key");
    repo.certify(&root, &old.id()).expect("certify");
    let (first, second, third) = (raw(b"first"), raw(b"second"), raw(b"third"));
    let keep_of = |block: &Block| Claim::Keep(crate::claim::Keep::new([block.cid().clone().into()]).expect("keep"));
    let mut signs = Vec::new();
    for (n, block) in [&first, &second, &third].into_iter().enumerate() {
        repo.put_block(block, CidVersion::V1).expect("put");
        let claim = keep_of(block);
        repo.put_block(&claim.block(), CidVersion::V1).expect("put");
        let sign = Claim::Sign(crate::claim::Sign::new(&old, [claim.cid()], None, u64::try_from(n).expect("n")).expect("sign"));
        repo.put_block(&sign.block(), CidVersion::V1).expect("put");
        signs.push(sign.cid());
    }
    let claims = repo.claims().expect("claims");
    // The old key's all that keeps the sealed root and root anchor, too
    for target in [&seal, &root_anchor] {
        repo.unkeep(target).expect("unkeep");
        let again = Claim::Keep(crate::claim::Keep::new([target.clone()]).expect("keep").again(1));
        repo.put_block(&again.block(), CidVersion::V1).expect("put");
        let sign = Claim::Sign(crate::claim::Sign::new(&old, [again.cid()], None, 9).expect("sign"));
        repo.put_block(&sign.block(), CidVersion::V1).expect("put");
        assert!(claims.kept(target.multihash()).expect("kept"));
    }

    // What it says of itself
    let said = repo.signed_in(&old.id(), &signs[0]).expect("signed");
    assert_eq!(said.len(), 1);
    assert_eq!(said[0].claim, Some(keep_of(&first)));
    assert!(said[0].alone && !said[0].retracted);

    // Trusting no chain costs all it signed; each trusted, that much less. What
    // keeps the sealed root and root anchor isn't a cost
    assert_eq!(repo.revocation_costs(&old.id(), &[]).expect("costs").len(), 3);
    assert_eq!(repo.revocation_costs(&old.id(), &signs[..1]).expect("costs"), [keep_of(&second), keep_of(&third)]);
    assert!(repo.revocation_costs(&old.id(), &signs).expect("costs").is_empty());
    assert!(repo.cutoff_at(&old.id(), 100).is_err(), "a time can't say which chain");

    assert_eq!(repo.revoke_trusting(&root, &old.id(), &signs[..2]).expect("revoke"), 2);
    assert!(!claims.authorized(&old.id()).expect("authorized"));
    assert!(claims.kept(first.cid().multihash()).expect("kept") && claims.kept(second.cid().multihash()).expect("kept"));
    assert!(!claims.kept(third.cid().multihash()).expect("kept"), "as it said");
    assert!(claims.kept(seal.multihash()).expect("kept"), "kept regardless");
    assert!(claims.kept(root_anchor.multihash()).expect("kept"), "kept regardless");
    assert!(repo.root(b"pass").is_ok());
}

/// A claim another authorized key has signed doesn't depend on this one, and
/// a retraction's no loss.
#[test]
fn what_others_sign_or_was_retracted_is_no_cost_of_revoking() {
    let scratch = Scratch::new("revoke-shared");
    let repo = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    let root = repo.found_user(b"pass", crate::keys::Cost::NONE).expect("found");
    let old = crate::keys::Key::generate().expect("key");
    repo.certify(&root, &old.id()).expect("certify");
    let (shared, retracted) = (raw(b"shared"), raw(b"retracted"));
    for block in [&shared, &retracted] {
        repo.put_block(block, CidVersion::V1).expect("put");
    }
    let shared_keep = repo.keep(&shared.cid().clone().into()).expect("keep");
    let retracted_keep = repo.keep(&retracted.cid().clone().into()).expect("keep");
    let sign = Claim::Sign(crate::claim::Sign::new(&old, [shared_keep, retracted_keep], None, 1).expect("sign"));
    repo.put_block(&sign.block(), CidVersion::V1).expect("put");
    repo.unkeep(&retracted.cid().clone().into()).expect("unkeep");
    assert!(repo.revocation_costs(&old.id(), &[]).expect("costs").is_empty());
    let said = repo.signed_in(&old.id(), &sign.cid()).expect("signed");
    assert_eq!(said.iter().filter(|claim| claim.retracted).count(), 1);
    assert!(said.iter().all(|claim| !claim.alone));
}

/// Two devices settling a merge the same way and going on from it have no one
/// set in common that says what they had: that's the merge, worked out again,
/// or what one left alone looks changed, and undoes what the other did.
#[test]
fn going_on_from_a_merge_measures_from_the_merge() {
    let scratch = Scratch::new("merge-criss-cross");
    let mut repo = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    let anchor = repo.new_anchor().expect("anchor");
    let set = |files: &[(&str, &str)], at: u64, prev: Vec<Link>, repo: &mut Catalog| -> (Link, Link) {
        let value = tree(repo, &scratch, files);
        let claim = crate::claim::Set::new([anchor.clone()], value.clone(), at).expect("set").after(Some(prev));
        (repo.put_claim(&Claim::Set(claim)).expect("put"), value)
    };
    let (start, _) = set(&[("turns", "first")], 1, Vec::new(), &mut repo);
    // One edits it, then the other, not having seen that, adds something: so
    // the latest they have in common, by itself, is from before the edit
    let (edited, _) = set(&[("turns", "second")], 2, vec![start.clone()], &mut repo);
    let (added, _) = set(&[("turns", "first"), ("other", "other")], 3, vec![start], &mut repo);
    let merge = repo.anchor_value(&anchor).expect("value").expect("merged");
    assert_eq!(repo.anchor_heads(&anchor).expect("heads").len(), 2);
    let read = |name: &str, value: &Link, repo: &Catalog| -> Option<Vec<u8>> {
        let out = scratch.path().join("out");
        let _ = std::fs::remove_dir_all(&out);
        crate::export::get(repo, value, &out).expect("get");
        std::fs::read(out.join(name)).ok()
    };
    assert_eq!(read("turns", &merge, &repo), Some(b"second".to_vec()), "what changed on one side");

    // Each goes on from the merge: one removes the file, the other changes
    // something else
    let (_, _) = set(&[("other", "other")], 4, vec![edited.clone(), added.clone()], &mut repo);
    let (_, _) = set(&[("turns", "second"), ("other", "more")], 5, vec![edited, added], &mut repo);
    let settled = repo.anchor_value(&anchor).expect("value").expect("merged");
    assert_eq!(read("turns", &settled, &repo), None, "the removal stands: the other side left it as it was");
    assert_eq!(read("other", &settled, &repo), Some(b"more".to_vec()));
}

/// A batch that breathes commits as it goes, between files, ending whole.
#[test]
fn a_big_import_lets_others_write_as_it_goes() {
    let scratch = Scratch::new("breathing");
    let repo = scratch.path().join("repo");
    let t = scratch.path().join("t");
    std::fs::create_dir_all(&t).expect("mkdir");
    for n in 0..4 {
        std::fs::write(t.join(format!("small{n}")), format!("small {n}")).expect("write");
        // Kept whole, so its leaves wait on its being settled
        std::fs::write(t.join(format!("big{n}")), vec![u8::try_from(n).expect("n"); 2_000_000]).expect("write");
    }
    let mut catalog = Catalog::open_repo(&repo).expect("catalog");
    let other = Catalog::open_repo(&repo).expect("other");
    let root = catalog.batch_breathing_every(std::time::Duration::ZERO, |catalog| {
        let importer = Importer::default();
        let root = importer.add_path(&t, &mut Copying::new(catalog), &mut |_, _| {}).expect("import").expect("root");
        // Everything before the last file's committed
        assert!(other.has(raw(b"small 0").cid().multihash()).expect("has"), "seen before it's finished");
        Ok::<_, Error>(root)
    }).expect("batch");
    let out = scratch.path().join("out");
    crate::export::get(&catalog, &AnyCid::V1(root.cid), &out).expect("whole");
    assert_eq!(std::fs::read(out.join("big3")).expect("big"), vec![3u8; 2_000_000]);
}

/// A failed import leaves what it's committed, every block of it readable.
#[test]
fn a_big_import_that_fails_leaves_only_what_can_be_read() {
    let scratch = Scratch::new("breathing-fails");
    let repo = scratch.path().join("repo");
    let t = scratch.path().join("t");
    std::fs::create_dir_all(&t).expect("mkdir");
    std::fs::write(t.join("big"), vec![7u8; 2_000_000]).expect("write");
    let mut catalog = Catalog::open_repo(&repo).expect("catalog");
    let (kept, chunk) = (raw(b"kept"), raw(&vec![7u8; 1 << 18]));
    let failed: Result<()> = catalog.batch_breathing_every(std::time::Duration::ZERO, |catalog| {
        BlockSink::put(catalog, kept.clone()).expect("put");
        let mut sink = Copying::new(catalog);
        sink.begin_file(&t.join("big")).expect("begin");
        let mut offset = 0;
        for _ in 0..7 {
            sink.put_from(chunk.clone(), Provenance::FileRange { path: &t.join("big"), offset }).expect("put");
            offset += 1 << 18;
            // In the middle of a file, it doesn't breathe
            sink.router.breathe().expect("held");
        }
        Err(Error::NoClaims)
    });
    assert!(failed.is_err());
    drop(catalog);
    let again = Catalog::open_repo(&repo).expect("catalog");
    assert!(again.has(kept.cid().multihash()).expect("has"), "committed by the breath before it");
    assert!(!again.has(chunk.cid().multihash()).expect("has"), "said to be here, it couldn't be read");
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
    assert!(router.referenced(v1.cid().multihash()).expect("referenced"), "nor what it was");
    assert!(router.kept_under(leaf1.cid().multihash()).expect("kept"));
    assert!(router.kept_under(leaf2.cid().multihash()).expect("kept"));
    let history: Vec<Link> = router.anchor_history(&anchor).expect("history").into_iter().map(|(_, value)| value).collect();
    assert_eq!(history, [link(&v1), link(&v2)]);
    assert_eq!(router.claims().expect("claims").anchors().expect("anchors"), [(anchor.clone(), link(&v2))]);

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
    assert_eq!(router.claims().expect("claims").all_tags().expect("tags"), [tag("empty")]);
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
    assert!(router.referenced(first.multihash()).expect("referenced"), "what it was, till that's forgotten");
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


//------------//
//-[ Deltas ]-//
//------------//

/// A git blob of `text`, and a delta making it from `base`, as copying
/// all of `base` then adding the rest.
fn grown(base: &Block, text: &[u8]) -> (Block, Vec<u8>) {
    let block = crate::git::block(crate::git::Kind::Blob, text);
    let (_, base_text) = crate::git::parse(base.data()).expect("base");
    let header = block.data().len().saturating_sub(text.len());
    let base_header = base.data().len().saturating_sub(base_text.len());
    let mut delta = crate::delta::Writer::new(base.data().len(), block.data().len());
    delta.insert(block.data().get(..header).expect("header"));
    delta.copy(base_header, base_text.len()).expect("copy");
    delta.insert(text.get(base_text.len()..).expect("grown"));
    (block, delta.finish())
}

fn text(n: usize) -> Vec<u8> {
    (0..n).flat_map(|i| format!("line {i}\n").into_bytes()).collect()
}

fn on<'a>(base: &'a Block, delta: &'a [u8]) -> Provenance<'a> {
    Provenance::Delta { base: base.cid().multihash(), delta }
}

#[test]
fn git_objects_and_deltas_on_them_are_kept_compactly() {
    let router = router();
    let first = crate::git::block(crate::git::Kind::Blob, &text(1000));
    router.put_block(&first, CidVersion::V1).expect("put");
    let (second, delta) = grown(&first, &text(1010));
    router.put_block_from(&second, CidVersion::V1, on(&first, &delta)).expect("put");
    assert_eq!(forms(&router), [("delta".to_owned(), 2)]);
    let delta_store = DeltaStore::open(router.db().clone()).expect("store");
    assert_eq!(delta_store.counts().expect("counts"), (1, 1), "one delta on one whole");
    let second_link: Link = second.cid().clone().into();
    assert_eq!(router.get_block(&second_link).expect("get"), Some(second));

    // A delta that doesn't make the block is no delta, and isn't kept
    let (third, _) = grown(&first, &text(1020));
    router.put_block_from(&third, CidVersion::V1, on(&first, &delta)).expect("put");
    assert_eq!(delta_store.counts().expect("counts"), (1, 2));
    assert_eq!(router.get_block(&third.cid().clone().into()).expect("get"), Some(third));

    // Anything with a delta on what's here, any codec; without one, or on
    // what isn't here, elsewhere
    let other = raw(crate::git::block(crate::git::Kind::Blob, &text(1010)).data());
    let not_here = crate::git::block(crate::git::Kind::Blob, b"elsewhere");
    router.put_block_from(&other, CidVersion::V1, on(&first, &delta)).expect("put");
    router.put_block_from(&raw(b"plain"), CidVersion::V1, Provenance::Delta { base: not_here.cid().multihash(), delta: &delta }).expect("put");
    assert_eq!(forms(&router), [("delta".to_owned(), 4), ("raw".to_owned(), 1)]);
    assert_eq!(router.get_block(&other.cid().clone().into()).expect("get"), Some(other));
}

#[test]
fn a_whole_block_offered_as_a_delta_becomes_one_unless_that_loops() {
    let store = DeltaStore::open(Db::memory().expect("db")).expect("store");
    let first = crate::git::block(crate::git::Kind::Blob, &text(1000));
    let (second, delta) = grown(&first, &text(1010));
    store.put(&second).expect("put");
    store.put(&first).expect("put");
    assert_eq!(store.counts().expect("counts"), (0, 2));
    store.put_from(&second, Provenance::Delta { base: first.cid().multihash(), delta: &delta }).expect("put");
    assert_eq!(store.counts().expect("counts"), (1, 1));
    // The first on the second would loop, so it stays whole
    let back = crate::delta::Writer::new(second.data().len(), first.data().len());
    let mut back = back;
    back.copy(0, first.data().len()).expect("copy");
    store.put_from(&first, Provenance::Delta { base: second.cid().multihash(), delta: &back.finish() }).expect("put");
    assert_eq!(store.counts().expect("counts"), (1, 1));
    assert_eq!(store.get(first.cid().multihash()).expect("get").as_deref(), Some(first.data()));
    assert_eq!(store.get(second.cid().multihash()).expect("get").as_deref(), Some(second.data()));
}

#[test]
fn chains_of_deltas_stop_at_their_depth_and_outlive_their_bases() {
    let store = DeltaStore::open(Db::memory().expect("db")).expect("store");
    let mut chain = vec![crate::git::block(crate::git::Kind::Blob, &text(100))];
    store.put(&chain[0]).expect("put");
    for n in 1..=60 {
        let base = chain.last().expect("base").clone();
        let (next, delta) = grown(&base, &text(100 + n));
        store.put_from(&next, Provenance::Delta { base: base.cid().multihash(), delta: &delta }).expect("put");
        chain.push(next);
    }
    let (deltas, whole) = store.counts().expect("counts");
    assert_eq!((deltas, whole), (59, 2), "the 51st starts a chain of its own");
    let freed = store.remove(chain[0].cid().multihash()).expect("remove");
    assert!(freed.is_some());
    assert_eq!(store.counts().expect("counts"), (58, 2), "what was on it made whole");
    assert!(!store.has(chain[0].cid().multihash()).expect("has"));
    for block in chain.iter().skip(1) {
        assert_eq!(store.get(block.cid().multihash()).expect("get").as_deref(), Some(block.data()));
    }
}


/// Whether every delta row says how deep it is truly.
fn depths_true(db: &Db) -> bool {
    db.conn()
        .query_row(
            "WITH RECURSIVE chain (block, depth) AS (
                 SELECT block, 0 FROM delta_blocks WHERE base IS NULL
                 UNION ALL SELECT d.block, chain.depth + 1 FROM delta_blocks d JOIN chain ON d.base = chain.block
             )
             SELECT count(*) FROM delta_blocks d JOIN chain c ON c.block = d.block WHERE c.depth != d.depth",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("depths")
        == 0
}

#[test]
fn versions_written_over_are_deltas_on_the_versions_after_them() {
    let router = router();
    let versions: Vec<Block> = (0..60).map(|n| raw(&text(2000 + n * 3))).collect();
    // Not without being written over
    router.put_block(&versions[0], CidVersion::V1).expect("put");
    assert_eq!(router.store_of(versions[0].cid().multihash()).expect("store").as_deref(), Some("raw"));
    let router = self::router();
    for (n, version) in versions.iter().enumerate() {
        assert_eq!(router.put_block_from(version, CidVersion::V1, Provenance::Superseded).expect("put"), "delta");
        if let Some(older) = n.checked_sub(1).and_then(|n| versions.get(n)) {
            router.revise(&older.cid().clone().into(), &version.cid().clone().into()).expect("revise");
        }
        assert!(depths_true(&router.db), "after {n}");
    }
    let rows = |sql: &str| router.db.conn().query_row(sql, [], |row| row.get::<_, i64>(0)).expect("rows");
    // The oldest fifty on the next, then the one too deep for that, whole,
    // and those after on the next, but the newest
    assert_eq!(rows("SELECT count(*) FROM delta_blocks WHERE base IS NULL"), 2);
    assert_eq!(rows("SELECT max(depth) FROM delta_blocks"), 50);
    assert!(rows("SELECT sum(length(data)) FROM delta_blocks") < 3 * i64::try_from(versions[59].data().len()).expect("len"));
    for version in &versions {
        assert_eq!(router.get_block(&version.cid().clone().into()).expect("get").as_ref().map(Block::data), Some(version.data()));
    }

    // A base let go of makes what's on it whole, and shallower what's on that
    let store = DeltaStore::open(router.db.clone()).expect("store");
    store.remove(versions[50].cid().multihash()).expect("remove");
    assert!(depths_true(&router.db));
    assert_eq!(rows("SELECT max(depth) FROM delta_blocks"), 49);
    assert_eq!(store.get(versions[0].cid().multihash()).expect("get").as_deref(), Some(versions[0].data()));
}

#[test]
fn a_delta_no_shorter_than_its_block_is_not_kept() {
    let store = DeltaStore::open(Db::memory().expect("db")).expect("store");
    let base = raw(b"a base");
    store.put_from(&base, Provenance::Superseded).expect("put");
    let target = raw(b"tiny");
    let delta = crate::delta::encode(base.data(), target.data()).expect("encode");
    assert_eq!(store.put_from(&target, on(&base, &delta)).expect("put"), Put::Declined);
    assert_eq!(store.counts().expect("counts"), (0, 1));
}

/// A git tree of these entries, each (mode, name, object).
fn git_tree(entries: &[(&str, &str, &Block)]) -> Block {
    let mut content = Vec::new();
    for (mode, name, object) in entries {
        content.extend_from_slice(format!("{mode} {name}\0").as_bytes());
        content.extend_from_slice(&crate::git::sha1_of(&object.cid().clone().into()).expect("sha1"));
    }
    crate::git::block(crate::git::Kind::Tree, &content)
}

fn git_hex(object: &Block) -> String {
    crate::git::sha1_of(&object.cid().clone().into()).expect("sha1").iter().fold(String::new(), |mut hex, byte| {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("digit"));
        hex.push(char::from_digit(u32::from(byte & 15), 16).expect("digit"));
        hex
    })
}

#[test]
fn git_objects_that_come_whole_become_deltas_on_their_next_versions() {
    let router = router();
    let blob = |text: &[u8]| crate::git::block(crate::git::Kind::Blob, text);
    let same = blob(b"never changes\n");
    // Each commit: (commit, [a.txt, sub/b.txt, sub, root])
    let mut commits: Vec<(Block, Vec<Block>)> = Vec::new();
    for n in 0..3_usize {
        let a = blob(&text(300 + n * 10));
        let b = blob(&text(200 + n));
        let sub = git_tree(&[("100644", "b.txt", &b)]);
        let root = git_tree(&[("100644", "a.txt", &a), ("100644", "same.txt", &same), ("40000", "sub", &sub)]);
        let parent = commits.last().map(|(commit, _)| format!("parent {}\n", git_hex(commit))).unwrap_or_default();
        let commit = crate::git::block(crate::git::Kind::Commit, format!("tree {}\n{parent}author t <t@t> 0 +0000\n\ncommit {n}\n", git_hex(&root)).as_bytes());
        commits.push((commit, vec![a, b, sub, root]));
    }
    let put = |block: &Block| router.put_block(block, CidVersion::V1).expect("put");
    put(&same);
    // Newest first, and the newest a.txt not yet
    for (n, (commit, objects)) in commits.iter().enumerate().rev() {
        put(commit);
        for (i, object) in objects.iter().enumerate() {
            if (n, i) != (2, 0) {
                put(object);
            }
        }
    }
    assert!(router.git_arriving() && !router.git_arriving(), "said once");
    let first = router.git_deltas().expect("deltas");
    assert_eq!(first.waiting, 1, "the newest commit waits on its a.txt");
    put(&commits[2].1[0]);
    let second = router.git_deltas().expect("deltas");
    assert_eq!(second.waiting, 0);
    assert_eq!(first.deltas + second.deltas, 8, "four objects of each of the older two");
    assert!(!router.git_waiting());
    let is_delta = |block: &Block| {
        router.db.conn()
            .query_row("SELECT base IS NOT NULL FROM delta_blocks d JOIN multihashes m ON m.id = d.block WHERE m.multihash = ?1", [block.cid().multihash().to_bytes()], |row| row.get::<_, bool>(0))
            .expect("row")
    };
    for (n, (_, objects)) in commits.iter().enumerate() {
        for object in objects {
            assert_eq!(is_delta(object), n < 2, "commit {n}");
            assert_eq!(router.get_block(&object.cid().clone().into()).expect("get").as_ref().map(Block::data), Some(object.data()));
        }
    }
    assert!(!is_delta(&same));
}

/// A transaction that reads, then writes, while another process has the
/// write lock for a moment: if it held a read first, `SQLite` wouldn't wait,
/// and it'd fail at once however long writers are told to wait.
#[test]
fn transactions_wait_for_a_writer_rather_than_failing_at_once() {
    let scratch = Scratch::new("write-lock");
    let path = scratch.path().join("db");
    let db = Db::open(&path).expect("open");
    db.conn().execute_batch("CREATE TABLE t (n INTEGER)").expect("table");
    let hold = |ms: u64| {
        let other = rusqlite::Connection::open(&path).expect("open");
        other.execute_batch("BEGIN IMMEDIATE").expect("lock");
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            other.execute_batch("COMMIT").expect("unlock");
        })
    };
    let read_then_write = |db: &Db| -> Result<()> {
        let n: i64 = db.conn().query_row("SELECT count(*) FROM t", [], |row| row.get(0))?;
        db.conn().execute("INSERT INTO t VALUES (?1)", [n])?;
        Ok(())
    };
    let holder = hold(300);
    db.atomically(|| read_then_write(&db)).expect("atomically");
    holder.join().expect("holder");

    let mut router = Catalog::open_repo(&scratch.path().join("repo")).expect("repo");
    let holder = {
        let other = rusqlite::Connection::open(scratch.path().join("repo").join("blocks.db")).expect("open");
        other.execute_batch("BEGIN IMMEDIATE").expect("lock");
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            other.execute_batch("COMMIT").expect("unlock");
        })
    };
    router.batch(|router| router.put_block(&raw(b"in a batch"), CidVersion::V1).map(|_| ())).expect("batch");
    holder.join().expect("holder");

    // What only reads doesn't wait for a writer at all, while what turns
    // out to need to write does
    let other = rusqlite::Connection::open(&path).expect("open");
    other.execute_batch("BEGIN IMMEDIATE").expect("lock");
    let quick = std::time::Instant::now();
    db.reading_first(|| Ok(db.conn().query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))?)).expect("read");
    assert!(quick.elapsed() < std::time::Duration::from_secs(5), "{:?}", quick.elapsed());
    assert!(db.conn().is_autocommit());
    let holder = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        other.execute_batch("COMMIT").expect("unlock");
    });
    db.reading_first(|| read_then_write(&db)).expect("write");
    holder.join().expect("holder");
    assert!(db.conn().is_autocommit());
    let failed: Result<()> = db.reading_first(|| Err(Error::Volume("nothing to undo".to_owned())));
    assert!(failed.is_err());
    assert!(db.conn().is_autocommit());

    // Nested, and rolled back only as far as it should be
    let count = || db.conn().query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0)).expect("count");
    let before = count();
    let outer = db.atomically(|| {
        read_then_write(&db)?;
        let inner: Result<()> = db.atomically(|| {
            read_then_write(&db)?;
            Err(Error::Volume("inner".to_owned()))
        });
        assert!(inner.is_err());
        Ok::<_, Error>(())
    });
    outer.expect("outer");
    assert_eq!(count(), before + 1, "the inner one undone");
    let failed: Result<()> = db.atomically(|| {
        read_then_write(&db)?;
        Err(Error::Volume("outer".to_owned()))
    });
    assert!(failed.is_err());
    assert_eq!(count(), before + 1, "the outer one undone");
    assert!(db.conn().is_autocommit(), "nothing left open");
}

/// Opening a repo that's already as it should be writes nothing, so what
/// only reads isn't held up by a writer, however long it takes.
#[test]
fn opening_a_repo_beside_a_writer_does_not_wait() {
    let scratch = Scratch::new("open-beside");
    let repo = scratch.path().join("repo");
    let mut catalog = Catalog::open_repo(&repo).expect("open");
    catalog.add_sqlite_volume("other", &scratch.path().join("other.db")).expect("volume");
    let block = raw(b"read beside a writer");
    catalog.put_block(&block, CidVersion::V1).expect("put");
    // In a shard so new it's not to be trusted, so catching up would write
    let big = raw(&vec![7_u8; 100_000]);
    assert_eq!(catalog.put_block(&big, CidVersion::V1).expect("put"), "flatfs");
    drop(catalog);
    Catalog::open_repo(&repo).expect("settle");

    let other = rusqlite::Connection::open(repo.join("blocks.db")).expect("db");
    other.execute_batch("BEGIN IMMEDIATE").expect("lock");
    let start = std::time::Instant::now();
    let catalog = Catalog::open_repo(&repo).expect("open beside a writer");
    for block in [&block, &big] {
        assert_eq!(catalog.get_block(&block.cid().clone().into()).expect("get").as_ref().map(Block::data), Some(block.data()));
    }
    assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
    other.execute_batch("COMMIT").expect("unlock");
    assert!(catalog.db.conn().is_autocommit(), "left nothing open");
    drop(catalog);
    Catalog::open_repo(&repo).expect("and once it's free");
}

/// Opening writes nothing that's as it should be, but still puts right
/// what isn't.
#[test]
fn opening_a_repo_puts_right_what_has_changed() {
    let scratch = Scratch::new("open-right");
    let repo = scratch.path().join("repo");
    drop(Catalog::open_repo(&repo).expect("open"));
    let db = rusqlite::Connection::open(repo.join("blocks.db")).expect("db");
    let version = |db: &rusqlite::Connection| db.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0)).expect("version");
    let before = version(&db);
    drop(Catalog::open_repo(&repo).expect("open"));
    assert_eq!(version(&db), before, "the schema's left alone");

    let keys = |db: &rusqlite::Connection| db.query_row("SELECT count(*) FROM authorized", [], |row| row.get::<_, i64>(0)).expect("keys");
    let authorized = keys(&db);
    assert!(authorized > 0);
    db.execute_batch(
        "DELETE FROM authorized;
         DROP VIEW tags;
         DROP VIEW anchor_values;
         DROP VIEW anchor_values_any;
         CREATE VIEW anchor_values_any (anchor, value, prefix, claim, at) AS SELECT 1, 2, 3, 4, 5;",
    ).expect("change");
    let catalog = Catalog::open_repo(&repo).expect("open");
    assert_eq!(keys(&db), authorized, "what's authorized worked out again");
    let view = |name: &str| db.query_row("SELECT sql FROM sqlite_schema WHERE type = 'view' AND name = ?1", [name], |row| row.get::<_, String>(0)).expect("view");
    assert!(view("tags").contains("CREATE VIEW tags"));
    assert!(view("anchor_values").contains("CREATE VIEW anchor_values"));
    assert!(view("anchor_values_any").len() > 100, "what's out of date made again");
    assert!(catalog.new_anchor().is_ok());
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

/// A dissolved claim copied to a volume takes its signature, or it says
/// nothing when that's all there is of it.
#[test]
fn a_dissolved_claim_copied_takes_its_signature() {
    let scratch = Scratch::new("volumes-signed");
    let a = with_sqlite(&scratch, "shared.db");
    let key = crate::keys::Key::generate().expect("key");
    let leaf = raw(b"leaf");
    a.put_block(&leaf, CidVersion::V1).expect("put");
    let claim = Claim::Keep(crate::claim::Keep::new([link(&leaf)]).expect("keep"));
    a.put_block(&claim.block(), CidVersion::V1).expect("put");
    let sign = a.sign_with(&key, [claim.cid()]).expect("sign").expect("a sign");
    a.copy_to("shared", &[link(&leaf)]).expect("copy");
    let shared = rusqlite::Connection::open(scratch.path().join("shared.db")).expect("db");
    let signs: i64 = shared.query_row("SELECT count(*) FROM claims WHERE kind = 'sign'", [], |row| row.get(0)).expect("signs");
    assert_eq!(signs, 1, "{sign} left behind");
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
fn a_root_anchor_is_the_devices_then_the_users_naming_the_same() {
    let scratch = Scratch::new("root-anchor");
    let repo = Catalog::open_repo(scratch.path()).expect("open");
    let device = repo.signer().expect("signer").id();
    let before = repo.root_anchor().expect("root").expect("a key, so a root");
    assert!(crate::claim::is_anchor(&before));
    assert_eq!(before, crate::claim::root_anchor(&device).expect("root"), "found from the key alone");
    let named = link(&raw(b"named"));
    repo.set_anchor(&before, &named).expect("set");

    let user = repo.found_user(b"pass", crate::keys::Cost::NONE).expect("found");
    let after = repo.root_anchor().expect("root").expect("root");
    assert_eq!(after, crate::claim::root_anchor(&user.id()).expect("root"), "the user's, so every device's");
    assert_ne!(after, before);
    assert_eq!(repo.anchor_value(&after).expect("value"), Some(named), "naming what the repo named");
}

#[test]
fn what_the_root_names_is_kept_through_mount_points() {
    let scratch = Scratch::new("root-kept");
    let mut repo = Catalog::open_repo(&scratch.path().join("repo")).expect("open");
    let (inside, elsewhere) = (raw(b"inside"), raw(b"elsewhere"));
    let (mounted, other) = (repo.new_anchor().expect("anchor"), repo.new_anchor().expect("anchor"));
    for (anchor, block) in [(&mounted, &inside), (&other, &elsewhere)] {
        repo.put_block(block, CidVersion::V1).expect("put");
        repo.set_anchor(anchor, &link(block)).expect("set");
    }
    let t = scratch.path().join("t");
    std::fs::create_dir_all(&t).expect("mkdir");
    std::os::unix::fs::symlink(format!("/anchors/{mounted}"), t.join("wiki")).expect("symlink");
    std::os::unix::fs::symlink(format!("/anchors/{other}/x"), t.join("into")).expect("symlink");
    let top = AnyCid::V1(Importer::default().add_path(&t, &mut repo, &mut |_, _| {}).expect("import").expect("top").cid);
    let root = repo.root_anchor().expect("root").expect("root");
    repo.set_anchor(&root, &top).expect("set");
    assert!(!repo.kept_under(inside.cid().multihash()).expect("kept"), "nothing keeps the root yet");
    assert!(repo.referenced(inside.cid().multihash()).expect("referenced"), "what a mount point here mounts isn't collected before it");
    assert!(!repo.referenced(elsewhere.cid().multihash()).expect("referenced"), "an anchor's own set doesn't reference what it is");
    // An IPLD document's link to an anchor is a link already
    let linked = raw(b"linked");
    let doc_anchor = repo.new_anchor().expect("anchor");
    repo.put_block(&linked, CidVersion::V1).expect("put");
    repo.set_anchor(&doc_anchor, &link(&linked)).expect("set");
    assert!(!repo.referenced(linked.cid().multihash()).expect("referenced"));
    let doc = ipld_block(DAG_CBOR_CODEC, &crate::model::Ipld::Map(std::iter::once(("notes".to_owned(), crate::model::Ipld::Link(doc_anchor))).collect()));
    repo.put_block(&doc, CidVersion::V1).expect("put");
    assert!(repo.referenced(linked.cid().multihash()).expect("referenced"), "what a document here links to is now");
    repo.keep(&link(&doc)).expect("keep");
    assert!(repo.kept_under(linked.cid().multihash()).expect("kept"), "and kept through it");

    assert!(repo.keep_root().expect("keep").is_some());
    assert!(repo.keep_root().expect("keep").is_none(), "kept already");
    assert!(repo.kept_under(top.multihash()).expect("kept"));
    assert!(repo.kept_under(inside.cid().multihash()).expect("kept"), "through the mount point");
    assert!(!repo.kept_under(elsewhere.cid().multihash()).expect("kept"), "a link into an anchor isn't a mount point");

    // Indexed again from what's stored, as an older repo is once
    repo.db().conn().execute("DELETE FROM refs", []).expect("forget");
    assert!(!repo.kept_under(inside.cid().multihash()).expect("kept"));
    assert!(!repo.referenced(inside.cid().multihash()).expect("referenced"));
    assert_eq!(repo.index_mount_points().expect("index"), 1);
    assert!(repo.kept_under(inside.cid().multihash()).expect("kept"));
}

#[test]
fn the_nearest_keep_says_how_many_copies_and_the_most_of_any_path() {
    use crate::model::Ipld;
    let scratch = Scratch::new("copies");
    let repo = Catalog::open_repo(scratch.path()).expect("open");
    let doc = |links: Vec<Link>| ipld_block(DAG_CBOR_CODEC, &Ipld::List(links.into_iter().map(Ipld::Link).collect()));
    let leaf = raw(b"leaf");
    let sub = doc(vec![link(&leaf)]);
    let top = doc(vec![link(&sub)]);
    for block in [&leaf, &sub, &top] {
        repo.put_block(block, CidVersion::V1).expect("put");
    }
    let wanted = |block: &Block| repo.copies_wanted(block.cid().multihash(), 2).expect("copies");
    assert_eq!(wanted(&leaf), None, "nothing keeps it");

    // Kept through an anchor: what the mesh runs with
    let anchor = repo.new_anchor().expect("anchor");
    repo.set_anchor(&anchor, &link(&top)).expect("set");
    repo.keep(&anchor).expect("keep");
    assert_eq!(wanted(&leaf), Some(2));

    // A nearer keep says otherwise for what's under it
    repo.keep_copies(&link(&sub), 1).expect("keep");
    assert_eq!(wanted(&leaf), Some(1));
    assert_eq!(wanted(&sub), Some(1));
    assert_eq!(wanted(&top), Some(2), "not above it");

    // What's under two keeps is as safe as the more careful
    let precious = doc(vec![link(&leaf), link(&leaf)]);
    repo.put_block(&precious, CidVersion::V1).expect("put");
    repo.keep_copies(&link(&precious), 3).expect("keep");
    assert_eq!(wanted(&leaf), Some(3));
    assert_eq!(wanted(&sub), Some(1));
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

#[test]
fn an_account_sees_only_the_blocks_in_its_repo() {
    let scratch = Scratch::new("visible");
    let mut repo = Catalog::open_repo(scratch.path()).expect("open");
    let (mine, theirs, both) = (raw(b"mine"), raw(b"theirs"), raw(b"both"));
    let owner = repo.signer().expect("signer").clone();
    let me = repo.uid();
    let bob = me.wrapping_add(1);
    let bobs = crate::keys::Key::generate().expect("key");
    let visible = |repo: &Catalog, block: &Block| repo.visible(block.cid().multihash()).expect("visible");
    let others = |repo: &Catalog, block: &Block| repo.visible_to_others(block.cid().multihash()).expect("others");

    repo.put_block(&mine, CidVersion::V1).expect("put");
    repo.put_block(&both, CidVersion::V1).expect("put");
    repo.keep(&link(&both)).expect("keep");
    repo.act_for(bob, bobs.clone()).expect("act");
    repo.put_block(&theirs, CidVersion::V1).expect("put");
    assert!(visible(&repo, &theirs) && !visible(&repo, &mine) && !visible(&repo, &both));
    assert!(others(&repo, &mine) && others(&repo, &both) && !others(&repo, &theirs));

    repo.act_for(me, owner.clone()).expect("act");
    assert!(visible(&repo, &mine) && visible(&repo, &both) && !visible(&repo, &theirs));
    assert!(others(&repo, &theirs) && !others(&repo, &mine));

    // Past the grace period, only what a keep of one's own reaches
    repo.db.conn().execute("UPDATE holdings SET since = 0", []).expect("age");
    assert!(!visible(&repo, &mine) && visible(&repo, &both));
    repo.act_for(bob, bobs.clone()).expect("act");
    assert!(!visible(&repo, &theirs));
    repo.keep(&link(&theirs)).expect("keep");
    assert!(visible(&repo, &theirs) && !visible(&repo, &both));
    assert!(!visible(&repo, &raw(b"never put")));
    // Its signature of the keep is its own, and not another's; the keep,
    // dissolved, is its own CID, which hides nothing
    let signs = repo.claims().expect("claims").signs_by(&bobs.id()).expect("signs");
    let sign = &signs.last().expect("sign").sign;
    repo.db.conn().execute("UPDATE holdings SET since = 0", []).expect("age");
    assert!(repo.visible(sign.multihash()).expect("visible"));
    repo.act_for(me, owner).expect("act");
    assert!(!repo.visible(sign.multihash()).expect("visible"));
}

#[test]
fn another_accounts_dissolved_claims_are_withheld_too() {
    let scratch = Scratch::new("dissolved-withheld");
    let mut repo = Catalog::open_repo(scratch.path()).expect("open");
    let block = raw(b"tagged");
    repo.put_block(&block, CidVersion::V1).expect("put");
    let owner = repo.signer().expect("signer").clone();
    let me = repo.uid();
    let mine = repo.tag(&link(&block), &tag("mine")).expect("tag");
    assert_eq!(mine.hashcode(), crate::block::IDENTITY, "dissolved");
    repo.act_for(me.wrapping_add(1), crate::keys::Key::generate().expect("key")).expect("act");
    assert!(!repo.visible(mine.multihash()).expect("visible"), "the owner's, dissolved or not");
    // An identity block that isn't a claim hides nothing
    assert!(repo.visible(tag("mine").multihash()).expect("visible"));
    repo.act_for(me, owner).expect("act");
    assert!(repo.visible(mine.multihash()).expect("visible"));
}

/// Copy a directory tree, as a fixture is copied before opening, since
/// opening upgrades a repo in place.
fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read_dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// Every repo an earlier build made (`scripts/make-repo-fixture.sh`)
/// still opens, upgraded in place, with all it had.
#[test]
fn repos_earlier_builds_made_still_open() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/repos");
    let mut seen = 0;
    for fixture in std::fs::read_dir(&fixtures).expect("fixtures") {
        let fixture = fixture.expect("fixture").path();
        let name = fixture.file_name().expect("name").to_string_lossy().into_owned();
        let expect: std::collections::HashMap<String, crate::model::Link> = std::fs::read_to_string(fixture.join("expect.txt"))
            .expect("expect.txt")
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(key, cid)| (key.to_owned(), cid.parse().expect("cid")))
            .collect();
        let scratch = Scratch::new("old-repo");
        let dir = scratch.path().join(&name);
        copy_tree(&fixture, &dir);
        let mut repo = Catalog::open_repo(&dir).unwrap_or_else(|e| panic!("{name}: {e}"));

        let hello = repo.get_block(&expect["hello"]).expect("get").unwrap_or_else(|| panic!("{name}: hello"));
        assert!(String::from_utf8_lossy(hello.data()).starts_with("hello from "), "{name}");
        let big = repo.get_block(&expect["big"]).expect("get").unwrap_or_else(|| panic!("{name}: big, in the shards"));
        assert_eq!(big.data().len(), 100_000, "{name}");
        let tree = crate::export::list(&repo, &expect["tree"]).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(tree.iter().map(|entry| entry.name.as_slice()).collect::<Vec<_>>(), [b"hello.txt".as_slice(), b"sub"], "{name}");

        let claims = repo.claims().expect("claims");
        assert!(claims.kept(expect["tree"].multihash()).expect("kept"), "{name}: what hk add kept");
        let fixture_tag = crate::claim::tag("fixture").expect("tag");
        assert_eq!(claims.tagged(fixture_tag.multihash()).expect("tagged"), [expect["hello"].clone()], "{name}");
        assert_eq!(repo.anchor_value(&expect["anchor"]).expect("value").as_ref(), Some(&expect["tree"]), "{name}");
        assert_eq!(repo.root_anchor().expect("root").as_ref(), Some(&expect["root"]), "{name}: the same root, from the same key");
        assert_eq!(repo.anchor_value(&expect["root"]).expect("value").as_ref(), Some(&expect["top"]), "{name}");
        assert!(!repo.backrefs(expect["anchor"].multihash()).expect("backrefs").is_empty(), "{name}: the root's mount point links to the anchor it mounts");
        if let Some(copied) = expect.get("copied") {
            assert_eq!(repo.copies_wanted(copied.multihash(), 2).expect("copies"), Some(1), "{name}: as its nearest keep says");
        }
        if let Some(git) = expect.get("git") {
            // A commit, its tree and its parents' trees and blobs, some as deltas
            let mut stack = vec![git.clone()];
            let mut seen_objects = 0;
            while let Some(link) = stack.pop() {
                let block = repo.get_block(&link).expect("get").unwrap_or_else(|| panic!("{name}: git object {link}"));
                stack.extend(crate::git::links(block.data()).expect("links"));
                seen_objects += 1;
            }
            assert_eq!(seen_objects, 9, "{name}: three commits, trees and blobs");
            assert!(repo.claims().expect("claims").kept(git.multihash()).expect("kept"), "{name}: what the refs name");
        }

        if let Some(lost) = expect.get("lost") {
            assert!(repo.lost_at(lost).expect("lost").is_some(), "{name}: reported lost");
            assert_eq!(repo.lost_blocks().expect("list").len(), 1, "{name}");
        }
        // Older ones can say so now too
        let reported: Link = raw(name.as_bytes()).cid().clone().into();
        repo.report_lost(&reported).expect("report").expect("a claim");
        assert!(repo.lost_at(&reported).expect("lost").is_some(), "{name}");

        // And it takes more as ever
        let added = AnyCid::V1(Importer::default().add_path(&fixture.join("expect.txt"), &mut repo, &mut |_, _| {}).expect("add").expect("root").cid);
        assert!(repo.get_block(&added).expect("get").is_some(), "{name}");
        seen += 1;
    }
    assert!(seen > 0, "no fixtures in {}", fixtures.display());
}

/// A tree of files, imported, as an anchor might be.
fn tree(repo: &mut Catalog, scratch: &Scratch, files: &[(&str, &str)]) -> Link {
    let dir = scratch.path().join(format!("tree-{}", files.iter().map(|(path, data)| format!("{path}={data}")).collect::<Vec<_>>().join(",").replace('/', "_")));
    std::fs::create_dir_all(&dir).expect("mkdir");
    for (path, data) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, data).expect("write");
    }
    AnyCid::V1(Importer::default().add_path(&dir, repo, &mut |_, _| {}).expect("import").expect("root").cid)
}

/// What's in a tree, as (path, contents), in order.
fn files_of(repo: &Catalog, scratch: &Scratch, root: &Link) -> Vec<(String, String)> {
    let out = scratch.path().join(format!("out-{root}"));
    crate::export::get(repo, root, &out).expect("get");
    let mut found = Vec::new();
    let mut dirs = vec![out.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                found.push((path.strip_prefix(&out).expect("under").display().to_string(), std::fs::read_to_string(&path).expect("read")));
            }
        }
    }
    found.sort();
    found
}

/// A set of an anchor made elsewhere, replacing `prev`, as of `at`.
fn set_after(repo: &Catalog, anchor: &Link, value: &Link, at: u64, prev: Vec<Link>) -> Link {
    let set = crate::claim::Set::new([anchor.clone()], value.clone(), at).expect("set").after(Some(prev));
    repo.put_claim(&Claim::Set(set)).expect("put")
}

#[test]
fn a_forked_anchor_is_its_heads_merged_till_its_set_again() {
    let scratch = Scratch::new("fork");
    let mut repo = Catalog::open_repo(&scratch.path().join("repo")).expect("open");
    let files = |list: &[(&str, &str)]| list.iter().map(|(path, data)| ((*path).to_owned(), (*data).to_owned())).collect::<Vec<_>>();
    let anchor = repo.new_anchor().expect("anchor");
    let base = tree(&mut repo, &scratch, &[("a", "1"), ("b", "1"), ("gone", "1"), ("d/x", "1")]);
    let start = set_after(&repo, &anchor, &base, 100, Vec::new());

    // Two devices change it without seeing each other
    let one = tree(&mut repo, &scratch, &[("a", "2"), ("b", "1"), ("c", "new"), ("d/x", "1"), ("d/y", "1")]);
    let two = tree(&mut repo, &scratch, &[("a", "1"), ("b", "2"), ("gone", "changed"), ("d/x", "1"), ("d/z", "1")]);
    let first = set_after(&repo, &anchor, &one, 101, vec![start.clone()]);
    let second = set_after(&repo, &anchor, &two, 102, vec![start]);
    assert_eq!(repo.anchor_heads(&anchor).expect("heads").len(), 2, "forked");
    let merged = repo.anchor_value(&anchor).expect("value").expect("merged");
    assert_eq!(files_of(&repo, &scratch, &merged), files(&[
        ("a", "2"), ("b", "2"), ("c", "new"), ("d/x", "1"), ("d/y", "1"), ("d/z", "1"),
        ("gone", "changed"), // one removed it: a change wins over a removal
    ]), "each side's changes, directories merged within");

    // Changed both ways: the latest by its name, the other beside it,
    // tagged by its set
    let three = tree(&mut repo, &scratch, &[("a", "3"), ("b", "3"), ("gone", "1"), ("d/x", "1")]);
    set_after(&repo, &anchor, &three, 103, vec![first]);
    // What's stored holds the latest of each; each other version's shown
    let stored = repo.anchor_value(&anchor).expect("value").expect("merged");
    let merged = repo.anchor_view(&anchor).expect("view").expect("merged").value;
    assert!(!files_of(&repo, &scratch, &stored).iter().any(|(path, _)| path.contains("conflict")), "not stored");
    let second = second.to_string();
    let tag = second.get(second.len() - 6..).expect("tag");
    assert_eq!(files_of(&repo, &scratch, &merged), files(&[
        ("a", "3"), // unchanged on the other side: no conflict
        ("b", "3"),
        (&format!("b (conflict {tag})"), "2"),
        ("d/x", "1"), ("d/z", "1"),
        // Removed, then put back as it was: a change, even so, and so a
        // conflict with the other side's
        ("gone", "1"), (&format!("gone (conflict {tag})"), "changed"),
    ]));

    // Set again, by anyone, it's whatever that says
    repo.set_anchor(&anchor, &merged).expect("set");
    assert_eq!(repo.anchor_heads(&anchor).expect("heads").len(), 1, "merged");
    assert_eq!(repo.anchor_value(&anchor).expect("value"), Some(merged));
}

#[test]
fn heads_beside_each_other_and_older_builds_sets() {
    let scratch = Scratch::new("heads");
    let mut repo = Catalog::open_repo(&scratch.path().join("repo")).expect("open");
    let old = |repo: &Catalog, anchor: &Link, value: &Link, at: u64| {
        repo.put_claim(&Claim::Set(crate::claim::Set::new([anchor.clone()], value.clone(), at).expect("set"))).expect("put")
    };

    // An older build's sets are a line, by `at`
    let anchor = repo.new_anchor().expect("anchor");
    let (earlier, later) = (tree(&mut repo, &scratch, &[("x", "1")]), tree(&mut repo, &scratch, &[("y", "1")]));
    old(&repo, &anchor, &later, 200);
    old(&repo, &anchor, &earlier, 100);
    assert_eq!(repo.anchor_heads(&anchor).expect("heads").len(), 1);
    assert_eq!(repo.anchor_value(&anchor).expect("value"), Some(later));
    // ...which a set after it replaces, as it names the head
    repo.set_anchor(&anchor, &earlier).expect("set");
    assert_eq!(repo.anchor_value(&anchor).expect("value"), Some(earlier.clone()));

    // What a joining repo named, beside what the mesh names: no common
    // ancestor, so every name is a change, and the same name both ways a
    // conflict
    let root = repo.new_anchor().expect("anchor");
    let mesh = tree(&mut repo, &scratch, &[("wiki", "theirs"), ("photos", "1")]);
    let mine = tree(&mut repo, &scratch, &[("wiki", "mine"), ("notes", "1")]);
    repo.set_anchor(&root, &mesh).expect("set");
    let beside = repo.set_anchor_beside(&root, &mine).expect("set");
    assert_eq!(repo.anchor_heads(&root).expect("heads").len(), 2);
    let merged = repo.anchor_view(&root).expect("view").expect("merged").value;
    let got = files_of(&repo, &scratch, &merged);
    let (latest, other) = if repo.anchor_heads(&root).expect("heads").last().map(|(set, _, _)| set) == Some(&beside) { ("mine", "theirs") } else { ("theirs", "mine") };
    assert_eq!(got.len(), 4, "{got:?}");
    assert!(got.contains(&("notes".to_owned(), "1".to_owned())) && got.contains(&("photos".to_owned(), "1".to_owned())));
    assert!(got.contains(&("wiki".to_owned(), latest.to_owned())), "{got:?}");
    assert!(got.iter().any(|(path, data)| path.starts_with("wiki (conflict ") && data == other), "{got:?}");

    // An older build's set after a fork replaces it all, as it would have
    old(&repo, &root, &earlier, u64::MAX >> 2);
    assert_eq!(repo.anchor_value(&root).expect("value"), Some(earlier));

    // A file anchor forked: the latest change
    let file = repo.new_anchor().expect("anchor");
    let (first, second, third) = (raw(b"a"), raw(b"b"), raw(b"c"));
    for block in [&first, &second, &third] {
        repo.put_block(block, CidVersion::V1).expect("put");
    }
    let start = set_after(&repo, &file, &link(&first), 300, Vec::new());
    set_after(&repo, &file, &link(&third), 302, vec![start.clone()]);
    set_after(&repo, &file, &link(&second), 301, vec![start]);
    assert_eq!(repo.anchor_value(&file).expect("value"), Some(link(&third)));
}

#[test]
fn what_a_joining_repo_named_joins_what_its_user_names() {
    let scratch = Scratch::new("join-root");
    let mut repo = Catalog::open_repo(&scratch.path().join("repo")).expect("open");
    let device = repo.signer().expect("signer").id();
    let mine = tree(&mut repo, &scratch, &[("wiki", "mine")]);
    let theirs = tree(&mut repo, &scratch, &[("photos", "theirs")]);
    let before = repo.root_anchor().expect("root").expect("root");
    repo.set_anchor(&before, &mine).expect("set");

    // The user's root names photos already, as its other devices said
    let user = crate::keys::Key::generate().expect("key");
    let root = crate::claim::root_anchor(&user.id()).expect("root");
    repo.join_user(&user.id()).expect("join");
    repo.certify(&user, &device).expect("certify");
    repo.set_anchor_beside(&root, &theirs).expect("set");
    assert_eq!(repo.root_anchor().expect("root"), Some(root.clone()));
    let merged = repo.anchor_value(&root).expect("value").expect("merged");
    assert_eq!(
        files_of(&repo, &scratch, &merged),
        [("photos".to_owned(), "theirs".to_owned()), ("wiki".to_owned(), "mine".to_owned())],
        "both, neither replacing the other"
    );
}

/// A set's `wrote` is kept with it, so it's the same claim read back.
#[test]
fn what_a_set_wrote_is_kept_with_it() {
    let scratch = Scratch::new("set-wrote");
    let repo = Catalog::open_repo(&scratch.path().join("repo")).expect("open");
    let anchor = repo.new_anchor().expect("anchor");
    let value = link(&raw(b"v"));
    repo.put_block(&raw(b"v"), CidVersion::V1).expect("put");
    let set = repo.set_anchor_wrote(&anchor, &value, Vec::new(), &[vec![b"a".to_vec(), b"page".to_vec()]]).expect("set");
    let read = repo.claim_at(set.multihash()).expect("read").expect("there");
    assert_eq!(read.cid(), set, "the same claim");
    let Claim::Set(read) = read else { panic!("a set") };
    assert_eq!(read.written(), [b"a/page".to_vec()]);
}
