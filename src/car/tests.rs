use super::*;
use crate::cid::{Cidv1Spec, CidVersion};
use crate::dag::{BalancedLayout, DynamicDirectory};
use crate::hamt::Hamt;
use crate::import::Importer;
use crate::store::{BlockIndex, Db, RoutingStore};
use crate::testutil::Scratch;

fn router() -> RoutingStore {
    RoutingStore::standard(Db::memory().expect("db")).expect("router")
}

/// A tree with chunked files, a HAMT directory and a symlink, imported.
fn tree(router: &mut RoutingStore) -> Link {
    let scratch = Scratch::new("car-tree");
    let t = scratch.path().join("t");
    std::fs::create_dir_all(t.join("hamt")).expect("dirs");
    std::fs::write(t.join("big"), (0..5000u32).map(|i| u8::try_from(i % 7).expect("byte")).collect::<Vec<_>>()).expect("big");
    std::fs::write(t.join("same"), b"same").expect("same");
    std::fs::write(t.join("again"), b"same").expect("again");
    for i in 0..40 {
        std::fs::write(t.join("hamt").join(format!("f{i}")), format!("{i}")).expect("entry");
    }
    std::os::unix::fs::symlink("big", t.join("link")).expect("symlink");
    let importer = Importer {
        chunk_size: 256,
        layout: BalancedLayout { width: 4 },
        directory: DynamicDirectory { threshold: 200, hamt: Hamt::default() },
        hidden: false,
    };
    let root = importer.add_path(&t, router, &mut |_, _| {}).expect("import").expect("root");
    AnyCid::V1(root.cid)
}

fn export_bytes(router: &RoutingStore, root: &Link) -> Vec<u8> {
    let mut car = Vec::new();
    export(router, root, &mut car).expect("export");
    car
}

fn import_bytes(car: Vec<u8>, router: &mut RoutingStore) -> io::Result<(Vec<Link>, u64)> {
    import(io::Cursor::new(car), router)
}

use crate::cid::AnyCid;

#[test]
fn round_trips() {
    let mut from = router();
    let root = tree(&mut from);
    let car = export_bytes(&from, &root);

    let mut to = router();
    let (roots, blocks) = import_bytes(car.clone(), &mut to).expect("import");
    assert_eq!(roots, std::slice::from_ref(&root));
    // Each block once, though "same" and "again" share theirs
    assert_eq!(blocks, u64::try_from(from.keys().expect("keys").len()).expect("count"));
    assert_eq!(export_bytes(&to, &root), car);
    // And it's all there to read back
    let out = Scratch::new("car-out");
    crate::export::get(&to, &root, &out.path().join("t")).expect("get");
}

#[test]
fn exports_depth_first() {
    let router = router();
    let leaf = |data: &[u8]| {
        let block = Block::hash(Cidv1Spec::default(), data.into());
        router.put_block(&block, CidVersion::V1).expect("put");
        AnyCid::V1(block.cid().clone())
    };
    let node = |links: Vec<Link>| {
        let value = Ipld::List(links.into_iter().map(Ipld::Link).collect());
        let block = Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, crate::multihash::MultihashFunc::Sha2_256),
            dagcbor::to_vec(&value).expect("encode").into());
        router.put_block(&block, CidVersion::V1).expect("put");
        AnyCid::V1(block.cid().clone())
    };
    let (a, b, c) = (leaf(b"a"), leaf(b"b"), leaf(b"c"));
    let left = node(vec![a.clone(), b.clone()]);
    let root = node(vec![left.clone(), c.clone(), a.clone()]);

    let mut car = CarReader::new(io::Cursor::new(export_bytes(&router, &root))).expect("read");
    let mut order = Vec::new();
    while let Some((block, _)) = car.next_block().expect("block") {
        order.push(AnyCid::V1(block.cid().clone()));
    }
    assert_eq!(order, [root, left, a, b, c]);
}

/// A section: varint length, CID, bytes.
fn section(cid: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::varint::write(&mut out, crate::dag::len64(cid).saturating_add(crate::dag::len64(data)));
    out.extend(cid);
    out.extend(data);
    out
}

fn header(roots: &[Link]) -> Vec<u8> {
    let mut out = Vec::new();
    write_header(&mut out, roots).expect("header");
    out
}

#[test]
fn keeps_cidv0() {
    let block: Block = Block::hash(Cidv1Spec::new(DAG_PB_CODEC, crate::multihash::MultihashFunc::Sha2_256), b"".as_slice().into());
    // A CIDv0 is its bare multihash
    let v0 = Link::decode(&block.cid().multihash().to_bytes()).expect("cidv0");
    assert_eq!(v0.version(), CidVersion::V0);
    let car = [header(std::slice::from_ref(&v0)), section(&v0.to_bytes(), b"")].concat();
    let mut router = router();
    let (roots, blocks) = import_bytes(car.clone(), &mut router).expect("import");
    assert_eq!((roots, blocks), (vec![v0.clone()], 1));
    assert_eq!(export_bytes(&router, &v0), car);
}

#[test]
fn reads_carv2() {
    let mut from = router();
    let root = tree(&mut from);
    let v1 = export_bytes(&from, &root);
    // Pragma, header, some padding, the CARv1, then an index to ignore
    let padding = 13u64;
    let offset = 64u64;
    let mut car = V2_PRAGMA.to_vec();
    car.extend([0; 16]);
    car.extend(offset.to_le_bytes());
    car.extend(u64::try_from(v1.len()).expect("len").to_le_bytes());
    car.extend(offset.saturating_add(u64::try_from(v1.len()).expect("len")).to_le_bytes());
    car.extend(vec![0; usize::try_from(padding).expect("padding")]);
    car.extend(&v1);
    car.extend(b"index, not a section");

    let mut to = router();
    let (roots, _) = import_bytes(car, &mut to).expect("import");
    assert_eq!(roots, std::slice::from_ref(&root));
    assert_eq!(export_bytes(&to, &root), v1);
}

#[test]
fn rejects_what_it_cant_trust() {
    let block = Block::hash(Cidv1Spec::default(), b"hello".as_slice().into());
    let cid = block.cid().to_bytes();
    let root = AnyCid::V1(block.cid().clone());
    let mut big = Vec::new();
    crate::varint::write(&mut big, MAX_SECTION + 1);
    for (label, car) in [
        ("empty", Vec::new()),
        ("mismatched block", [header(std::slice::from_ref(&root)), section(&cid, b"world")].concat()),
        ("truncated section", [header(&[]), section(&cid, b"hello")[..10].to_vec()].concat()),
        ("truncated CID", [header(&[]), section(&cid[..10], b"")].concat()),
        ("oversized section", [header(&[]), big].concat()),
        ("not a CAR header", section(b"", b"\xa1\x67version\x03")),
        ("no roots", section(b"", b"\xa1\x67version\x01")),
    ] {
        assert!(import_bytes(car, &mut router()).is_err(), "{label}");
    }
}

#[test]
fn follows_links_in_known_codecs_only() {
    let cid = |codec| AnyCid::V1(Block::<crate::multihash::Inline<64>>::hash(Cidv1Spec::new(codec, crate::multihash::MultihashFunc::Sha2_256), b"".as_slice().into()).cid().clone());
    assert!(links(&cid(RAW_CODEC), b"anything").expect("raw").is_empty());
    assert_eq!(links(&cid(DAG_JSON_CODEC), br#"[{"/":"bafkqaaa"}]"#).expect("json").len(), 1);
    assert!(links(&cid(DAG_CBOR_CODEC), b"\xff").is_err());
    assert!(links(&cid(0x78), b"").is_err());
}
