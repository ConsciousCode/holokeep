use super::*;
use crate::cid::{Cidv1Spec, CidVersion, DAG_CBOR_CODEC, DAG_PB_CODEC};
use crate::dag::{BalancedLayout, DynamicDirectory};
use crate::hamt::Hamt;
use crate::import::Importer;
use crate::store::{BlockIndex, Db, Catalog};
use crate::testutil::Scratch;

fn router() -> Catalog {
    Catalog::standard(Db::memory().expect("db")).expect("router")
}

/// A tree with chunked files, a HAMT directory and a symlink, imported.
fn tree(router: &mut Catalog) -> Link {
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

fn export_bytes(router: &Catalog, root: &Link) -> Vec<u8> {
    let mut car = Vec::new();
    export(router, root, &mut car).expect("export");
    car
}

fn import_bytes(car: Vec<u8>, router: &mut Catalog) -> io::Result<(Vec<Link>, u64)> {
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

//------------//
//-[ Claims ]-//
//------------//

fn export_claims(repo: &Catalog, root: &Link, history: bool) -> (Vec<u8>, Exported) {
    let mut car = Vec::new();
    let exported = export_with_claims(repo, root, WithClaims { history, sealed_root: false }, &mut car).expect("export");
    (car, exported)
}

fn import_into(repo: &mut Catalog, car: Vec<u8>) {
    import_bytes(car, repo).expect("import");
}

/// A repo of its own, certified as a device of the same user, whenever: as
/// one that's joined the mesh, or been told by the user's ticket.
fn same_user(scratch: &Scratch, name: &str, here: &Catalog, root: &crate::keys::Key) -> Catalog {
    let there = Catalog::open_repo(&scratch.path().join(name)).expect("catalog");
    here.certify(root, &there.signer().expect("signer").id()).expect("certify");
    there
}

fn raw_block(data: &[u8]) -> Block {
    Block::hash(Cidv1Spec::default(), data.into())
}

fn link_of(block: &Block) -> Link {
    block.cid().clone().into()
}

/// What's said of a DAG goes with it, dissolved or not, retraction and all.
#[test]
fn whats_said_of_a_dag_goes_with_it() {
    let scratch = Scratch::new("car-claims");
    let mut here = Catalog::open_repo(&scratch.path().join("here")).expect("catalog");
    let user = here.found_user(b"pass", crate::keys::Cost::NONE).expect("found");
    let mut fresh = same_user(&scratch, "fresh", &here, &user);
    let root = tree(&mut here);
    let tag = crate::claim::tag("music").expect("tag");
    let other = crate::claim::tag("retracted").expect("tag");
    here.tag(&root, &tag).expect("tag");
    here.tag(&root, &other).expect("tag");
    here.untag(&root, &other).expect("untag");
    here.keep_as(&root, &[], Some(1)).expect("keep");
    let (plain, (car, exported)) = (export_bytes(&here, &root), export_claims(&here, &root, false));
    assert!(exported.claims > 0);
    assert!(car.starts_with(&plain), "the DAG as it always is, then the claims");

    import_into(&mut fresh, car.clone());
    fresh.join_user(&user.id()).expect("join");
    let claims = fresh.claims().expect("claims");
    assert_eq!(claims.tagged(tag.multihash()).expect("tagged"), std::slice::from_ref(&root));
    assert!(claims.tagged(other.multihash()).expect("tagged").is_empty(), "and what's retracted stays so");
    assert!(claims.kept(root.multihash()).expect("kept"));
    assert_eq!(fresh.copies_wanted(root.multihash(), 2).expect("copies"), Some(1));

    // Exported from there, it's what it was, so nothing's lost on the way
    let (again, _) = export_claims(&fresh, &root, false);
    assert_eq!(again, car);

    // To a repo of its own, or another user's, they're only data, as any
    // stranger's are, since a CAR may come from anyone
    let mut own = Catalog::open_repo(&scratch.path().join("own")).expect("catalog");
    let mut other_user = Catalog::open_repo(&scratch.path().join("other")).expect("catalog");
    other_user.found_user(b"other", crate::keys::Cost::NONE).expect("found");
    for stranger in [&mut own, &mut other_user] {
        import_into(stranger, car.clone());
        let claims = stranger.claims().expect("claims");
        assert!(claims.tagged(tag.multihash()).expect("tagged").is_empty());
        assert!(!claims.kept(root.multihash()).expect("kept"));
    }
}

/// A plain export says what it left out, and writes as it always has.
#[test]
fn a_plain_export_says_what_it_left_out() {
    let scratch = Scratch::new("car-left-out");
    let mut here = Catalog::open_repo(&scratch.path().join("here")).expect("catalog");
    let root = tree(&mut here);
    let plain = export_bytes(&here, &root);
    let mut noted = Vec::new();
    assert_eq!(export_noting(&here, &root, &mut noted).expect("export").left_out, 0);
    here.tag(&root, &crate::claim::tag("music").expect("tag")).expect("tag");
    noted.clear();
    assert_eq!(export_noting(&here, &root, &mut noted).expect("export").left_out, 2, "the tag, and its signature");
    assert_eq!(noted, plain);
}

/// A claim that merely says a block's what an anchor was belongs to the
/// anchor, which doesn't come along with its old value.
#[test]
fn an_anchors_claims_come_with_it_not_its_value() {
    let scratch = Scratch::new("car-anchor-value");
    let here = Catalog::open_repo(&scratch.path().join("here")).expect("catalog");
    let value = raw_block(b"value");
    here.put_block(&value, CidVersion::V1).expect("put");
    let anchor = here.new_anchor().expect("anchor");
    here.set_anchor(&anchor, &link_of(&value)).expect("set");
    let (_, exported) = export_claims(&here, &link_of(&value), false);
    assert_eq!(exported.claims, 0);
}

/// From an anchor, it's what it is, and what's named through mount points, the
/// way a whole soup's taken from its root; older versions only if asked for,
/// as far as they're here.
#[test]
fn anchors_are_followed_to_what_they_are_and_were() {
    let scratch = Scratch::new("car-anchors");
    let mut here = Catalog::open_repo(&scratch.path().join("here")).expect("catalog");
    let user = here.found_user(b"pass", crate::keys::Cost::NONE).expect("found");
    let mut fresh = same_user(&scratch, "fresh", &here, &user);
    let mut whole = same_user(&scratch, "whole", &here, &user);
    let named = here.new_anchor().expect("anchor");
    let (old, gone, now) = (raw_block(b"old"), raw_block(b"gone"), raw_block(b"now"));
    for block in [&old, &gone, &now] {
        here.put_block(block, CidVersion::V1).expect("put");
    }
    for value in [&gone, &old, &now] {
        here.set_anchor(&named, &link_of(value)).expect("set");
    }
    here.lose(gone.cid().multihash()).expect("lose");
    here.report_lost(&link_of(&gone)).expect("report").expect("a claim");
    let t = scratch.path().join("t");
    std::fs::create_dir_all(&t).expect("mkdir");
    std::os::unix::fs::symlink(format!("/anchors/{named}"), t.join("wiki")).expect("symlink");
    let top = AnyCid::V1(Importer::default().add_path(&t, &mut here, &mut |_, _| {}).expect("import").expect("top").cid);
    let root = here.new_anchor().expect("anchor");
    here.set_anchor(&root, &top).expect("set");
    here.keep(&root).expect("keep");

    let (car, exported) = export_claims(&here, &root, false);
    assert_eq!(exported.unreadable, 0);
    import_into(&mut fresh, car);
    fresh.join_user(&user.id()).expect("join");
    assert_eq!(fresh.anchor_value(&root).expect("value"), Some(top));
    assert_eq!(fresh.anchor_value(&named).expect("value"), Some(link_of(&now)));
    assert_eq!(fresh.anchor_history(&named).expect("history").len(), 3, "what it was is still said");
    assert!(fresh.has(now.cid().multihash()).expect("has"));
    assert!(!fresh.has(old.cid().multihash()).expect("has"), "but not there");
    assert!(fresh.claims().expect("claims").kept(root.multihash()).expect("kept"));

    let (car, exported) = export_claims(&here, &root, true);
    assert_eq!(exported.unreadable, 1, "what's gone, passed over");
    import_into(&mut whole, car);
    whole.join_user(&user.id()).expect("join");
    assert!(whole.has(old.cid().multihash()).expect("has"));
    assert!(whole.lost_at(&link_of(&gone)).expect("lost").is_some(), "and said to be lost");
    assert!(whole.missing_under(&root).expect("missing").is_empty());

    // What it is now is another matter, unless it's known to be lost, when
    // there's no having it
    here.lose(now.cid().multihash()).expect("lose");
    let with = WithClaims { history: true, sealed_root: false };
    assert!(export_with_claims(&here, &root, with, &mut Vec::new()).is_err());
    here.report_lost(&link_of(&now)).expect("report").expect("a claim");
    assert_eq!(export_with_claims(&here, &root, with, &mut Vec::new()).expect("export").unreadable, 2);
}

/// With the sealed root and its passphrase, a repo with nothing else can be
/// the user again, everything said counting; without the passphrase, it can't.
#[test]
fn a_user_is_restored_from_a_car_and_a_passphrase() {
    let scratch = Scratch::new("car-restore");
    let mut here = Catalog::open_repo(&scratch.path().join("here")).expect("catalog");
    let user = here.found_user(b"correct horse", crate::keys::Cost::NONE).expect("found").id();
    let root = tree(&mut here);
    let music = crate::claim::tag("music").expect("tag");
    here.tag(&root, &music).expect("tag");
    here.keep(&root).expect("keep");
    let plain = export_claims(&here, &root, false).0;

    let mut car = Vec::new();
    let exported = export_with_claims(&here, &root, WithClaims { history: false, sealed_root: true }, &mut car).expect("export");
    assert_eq!(exported.sealed, 1);
    assert!(car.len() > plain.len());

    let mut there = Catalog::open_repo(&scratch.path().join("there")).expect("catalog");
    import_into(&mut there, car);
    assert!(there.claims().expect("claims").tagged(music.multihash()).expect("tagged").is_empty(), "not yet");
    assert!(there.restore_user(b"wrong").is_err());
    assert_ne!(there.user().expect("user"), Some(user.clone()));
    assert_eq!(there.restore_user(b"correct horse").expect("restore"), user);
    assert_eq!(there.user().expect("user"), Some(user.clone()));
    let claims = there.claims().expect("claims");
    assert_eq!(claims.tagged(music.multihash()).expect("tagged"), std::slice::from_ref(&root));
    assert!(claims.kept(root.multihash()).expect("kept"));
    assert_eq!(there.seals().expect("seals").len(), 1, "and it can invite others, having the seal");
    assert!(there.root(b"correct horse").is_ok());

    // Again's no harm, and it says the same
    assert_eq!(there.restore_user(b"correct horse").expect("again"), user);

    // A repo with nothing to open
    let empty = Catalog::open_repo(&scratch.path().join("empty")).expect("catalog");
    assert!(empty.restore_user(b"correct horse").is_err());
    // Nor is a seal written for a repo that has none
    let none = Catalog::open_repo(&scratch.path().join("none")).expect("catalog");
    assert!(export_with_claims(&none, &root, WithClaims { history: false, sealed_root: true }, &mut Vec::new()).is_err());
}
