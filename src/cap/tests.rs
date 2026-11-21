use std::collections::HashSet;
use std::path::Path;

use super::*;
use crate::cid::Cid as _;
use crate::dag::DynamicDirectory;
use crate::hamt::Hamt;
use crate::import::Importer;
use crate::store::Catalog;
use crate::testutil::Scratch;

/// Import a directory as UnixFS, into a catalog in memory.
fn import(catalog: &mut Catalog, path: &Path, importer: &Importer) -> Link {
    AnyCid::V1(importer.add_path(path, catalog, &mut |_, _| {}).expect("import").expect("root").cid)
}

/// Small chunks, so a file's several blocks.
fn importer() -> Importer {
    Importer { chunk_size: 1024, ..Importer::default() }
}

/// A tree with a bit of everything: nested directories, a file of several
/// chunks, an empty file, a symlink, and the same file in two places.
fn tree(name: &str) -> Scratch {
    let t = Scratch::new(name);
    let p = t.path();
    std::fs::create_dir_all(p.join("docs/deep")).expect("mkdir");
    std::fs::write(p.join("docs/deep/secret.txt"), "the secret plans").expect("write");
    std::fs::write(p.join("docs/readme.md"), "read me").expect("write");
    std::fs::write(p.join("big.bin"), (0..5000u32).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect::<Vec<_>>()).expect("write");
    std::fs::write(p.join("empty"), "").expect("write");
    std::fs::write(p.join("again.txt"), "read me").expect("write");
    std::os::unix::fs::symlink("docs/readme.md", p.join("link")).expect("symlink");
    t
}

/// Every block of a plaintext DAG, by CID bytes.
fn dag(catalog: &Catalog, root: &Link) -> HashSet<Vec<u8>> {
    let mut seen = HashSet::new();
    let mut stack = vec![root.clone()];
    while let Some(cid) = stack.pop() {
        if cid.hashcode() == IDENTITY || !seen.insert(cid.to_bytes()) {
            continue;
        }
        let data = catalog.fetch(&cid).expect("fetch");
        stack.extend(crate::links::links(cid.codec(), &data).expect("links"));
    }
    seen
}

fn held(sealed: &Sealed) -> Held {
    let mut held = Held::default();
    for block in &sealed.blocks {
        held.insert(block.clone());
    }
    held
}

fn sealed_cids(sealed: &Sealed) -> HashSet<Vec<u8>> {
    sealed.blocks.iter().map(|block| AnyCid::V1(block.cid().clone()).to_bytes()).collect()
}

#[test]
fn a_sealed_tree_unseals_whole_with_its_capability_and_says_nothing_without() {
    let t = tree("cap-roundtrip");
    let repo = Scratch::new("cap-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let root = import(&mut catalog, t.path(), &importer());
    let read = fresh_key().expect("key");
    let sealed = seal(&catalog, &root, &read).expect("seal");
    let cap = Snapshot::new(sealed.root.clone(), root.clone(), read);

    let blocks = unseal(&held(&sealed), &cap).expect("unseal");
    let unsealed: HashSet<Vec<u8>> = blocks.iter().map(|block| AnyCid::V1(block.cid().clone()).to_bytes()).collect();
    let wanted: HashSet<Vec<u8>> = dag(&catalog, &root).into_iter().map(|cid| AnyCid::V1(Link::decode(&cid).expect("cid").into()).to_bytes()).collect();
    assert_eq!(unsealed, wanted, "every block, and only those");
    assert_eq!(AnyCid::V1(blocks.first().expect("root").cid().clone()).to_bytes(), AnyCid::V1(root.clone().into()).to_bytes(), "root first");

    // The same file in two places is sealed under two keys
    assert!(sealed.blocks.len() > wanted.len(), "{} sealed of {}", sealed.blocks.len(), wanted.len());
    for block in &sealed.blocks {
        assert!(!block.data().windows(6).any(|window| window == b"secret" || window == b"read m"), "plaintext in the ciphertext");
    }

    // Another key opens nothing, nor does the right one for another root
    let wrong = Snapshot::new(sealed.root.clone(), root, fresh_key().expect("key"));
    assert!(unseal(&held(&sealed), &wrong).is_err());
    let other = Snapshot::new(sealed.root.clone(), sealed.blocks.first().map(|block| AnyCid::V1(block.cid().clone())).expect("one"), Zeroizing::new(**cap.read()));
    assert!(unseal(&held(&sealed), &other).is_err());
}

#[test]
fn sealing_is_the_same_every_time_under_one_key_and_unrelated_under_another() {
    let t = tree("cap-deterministic");
    let repo = Scratch::new("cap-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let root = import(&mut catalog, t.path(), &importer());
    let read = Zeroizing::new([7u8; 32]);
    let (once, twice) = (seal(&catalog, &root, &read).expect("seal"), seal(&catalog, &root, &read).expect("seal"));
    assert_eq!(once.root, twice.root);
    assert_eq!(sealed_cids(&once), sealed_cids(&twice));
    let other = seal(&catalog, &root, &Zeroizing::new([8u8; 32])).expect("seal");
    assert!(sealed_cids(&once).is_disjoint(&sealed_cids(&other)));
}

#[test]
fn an_edit_seals_again_only_the_path_to_it() {
    let t = tree("cap-edit");
    let repo = Scratch::new("cap-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let read = Zeroizing::new([9u8; 32]);
    let first = import(&mut catalog, t.path(), &importer());
    let before = seal(&catalog, &first, &read).expect("seal");
    std::fs::write(t.path().join("docs/deep/secret.txt"), "the plans have changed").expect("write");
    let second = import(&mut catalog, t.path(), &importer());
    let after = seal(&catalog, &second, &read).expect("seal");
    let new: Vec<_> = sealed_cids(&after).difference(&sealed_cids(&before)).cloned().collect();
    // The file, deep, docs, and the root
    assert_eq!(new.len(), 4, "{} sealed again", new.len());
}

#[test]
fn a_hamts_entries_keep_their_keys_as_its_shape_changes() {
    let t = Scratch::new("cap-hamt");
    let p = t.path().join("dir");
    std::fs::create_dir_all(&p).expect("mkdir");
    for i in 0..12 {
        std::fs::write(p.join(format!("file{i}")), format!("contents of {i}")).expect("write");
    }
    // Sharded from the first entry, four ways, so a few levels deep
    let sharded = Importer { directory: DynamicDirectory { threshold: 0, hamt: Hamt { fanout: 4 } }, ..importer() };
    let repo = Scratch::new("cap-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let read = Zeroizing::new([3u8; 32]);
    let root = import(&mut catalog, &p, &sharded);
    let before = seal(&catalog, &root, &read).expect("seal");
    let cap = Snapshot::new(before.root.clone(), root.clone(), Zeroizing::new(*read));
    assert_eq!(unseal(&held(&before), &cap).expect("unseal").len(), dag(&catalog, &root).len());

    for i in 12..40 {
        std::fs::write(p.join(format!("file{i}")), format!("contents of {i}")).expect("write");
    }
    let grown = import(&mut catalog, &p, &sharded);
    let after = seal(&catalog, &grown, &read).expect("seal");
    // Every file sealed before is sealed the same after, wherever its
    // shard's gone: only shards are sealed again, and new files
    let files_before: HashSet<Vec<u8>> = before.blocks.iter().filter(|block| block.len() < 400).map(|block| AnyCid::V1(block.cid().clone()).to_bytes()).collect();
    let kept = files_before.intersection(&sealed_cids(&after)).count();
    assert!(kept >= 12, "only {kept} of the files kept their ciphertext");
}

#[test]
fn sealed_nodes_are_padded_to_their_size_class() {
    assert_eq!(padded(0), 256);
    assert_eq!(padded(256), 256);
    assert_eq!(padded(257), 512);
    assert_eq!(padded(4096), 4096);
    assert_eq!(padded(4097), 8192);
    assert_eq!(padded(1 << 20), 1 << 20);
    assert_eq!(padded((1 << 20) + 1), (1 << 20) + 4096);

    let t = tree("cap-padded");
    let repo = Scratch::new("cap-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let root = import(&mut catalog, t.path(), &importer());
    let sealed = seal(&catalog, &root, &Zeroizing::new([1u8; 32])).expect("seal");
    for block in &sealed.blocks {
        // The header, then the padded node, then the tag
        let node = block.len() - 43 - 16;
        assert_eq!(padded(node), node, "{node} isn't a size class");
    }
}

#[test]
fn a_sealed_node_has_one_form() {
    let link: Link = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".parse().expect("cid");
    let node = encode(b"block", std::slice::from_ref(&link)).expect("encode");
    assert_eq!(node.len(), 256);
    let opened = decode(&node).expect("decode");
    assert_eq!((opened.block.as_slice(), opened.links.as_slice()), (&b"block"[..], std::slice::from_ref(&link)));

    let mut dirty = node.clone();
    *dirty.last_mut().expect("byte") = 1;
    assert!(decode(&dirty).is_err(), "padding that isn't zeros");
    assert!(decode(&node[..200]).is_err(), "padded short");
    let mut long = node;
    long.resize(512, 0);
    assert!(decode(&long).is_err(), "padded past its class");
    let mut other = crate::dagcbor::to_vec(&Ipld::Map(BTreeMap::from([("block".to_owned(), Ipld::Bytes(b"block".to_vec())), ("what".to_owned(), Ipld::Null)]))).expect("encode");
    other.resize(256, 0);
    assert!(decode(&other).is_err(), "a field it doesn't know");
}

#[test]
fn a_capability_reads_back_as_written() {
    let root: Link = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".parse().expect("cid");
    let plain: Link = "bafkqaaa".parse().expect("cid");
    let cap = Capability::Snapshot(Snapshot::new(root.clone(), plain.clone(), Zeroizing::new([5u8; 32])));
    let text = cap.encode();
    assert!(text.starts_with("hkcapb"), "{text}");
    let Capability::Snapshot(back) = Capability::decode(&format!("  {text}\n")).expect("decode") else {
        panic!("not a snapshot");
    };
    assert_eq!((&back.root, &back.plain, **back.read()), (&root, &plain, [5u8; 32]));
    let view = crate::claim::view(&crate::claim::anchor().expect("anchor"), &crate::keys::Key::generate().expect("key").id()).expect("view");
    let live = Capability::Live(Live::new(view.clone(), Zeroizing::new([6u8; 32]))).encode();
    assert!(matches!(Capability::decode(&live).expect("decode"), Capability::Live(back) if back.view == view && **back.read() == [6u8; 32]));
    assert!(Capability::decode(&text.replacen("hkcap", "hkcop", 1)).is_err());
    assert!(Capability::decode("hkcapbaaaa").is_err());
}

/// Test vectors: a fixed DAG under a fixed read key seals to these, here
/// and in any other implementation.
#[test]
fn a_fixed_tree_seals_to_known_blocks() {
    let repo = Scratch::new("cap-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let file = importer().add_file(&b"hello, sealed world"[..], &mut catalog).expect("file");
    let dir = crate::unixfs::node_block(
        &[crate::unixfs::Link { hash: &file.cid, name: b"hello.txt", tsize: file.tsize }],
        &crate::unixfs::Data::directory(),
    );
    crate::dag::BlockSink::put(&mut catalog, dir.clone()).expect("put");
    let root = AnyCid::V1(dir.cid().clone());
    let sealed = seal(&catalog, &root, &Zeroizing::new([0x42u8; 32])).expect("seal");
    let cids: Vec<String> = sealed.blocks.iter().map(|block| block.cid().to_string()).collect();
    assert_eq!(root.to_string(), "bafybeig3b3oi7lruke4xl5rd6b5qsi6bmug2x6ltoqhf276doiiirzvcq4");
    assert_eq!(sealed.root.to_string(), "bafkreifhyh75rbh3ekfa64angthj2xfmlkd7yesd2vepbtbcemxrac5scy");
    // The file, then the directory naming it
    assert_eq!(cids, ["bafkreic2niwyy4jblogxyxnaov4iyrw625y7r6ai6zv3bhlsh2wovsrpxe", "bafkreifhyh75rbh3ekfa64angthj2xfmlkd7yesd2vepbtbcemxrac5scy"]);
}

//-----------------------//
//-[ Sealed anchors ]----//
//-----------------------//

fn held_of(blocks: &[Block]) -> Held {
    let mut held = Held::default();
    for block in blocks {
        held.insert(block.clone());
    }
    held
}

#[test]
fn a_sealed_anchor_is_its_own_and_unrelated_to_what_its_of() {
    let (secret, other) = ([1u8; 32], [2u8; 32]);
    let (a, b) = (crate::claim::anchor().expect("anchor"), crate::claim::anchor().expect("anchor"));
    let published = Published::of(&secret, &a).expect("published");
    assert_eq!(published.view, Published::of(&secret, &a).expect("again").view, "derived, not kept");
    assert_ne!(published.view, Published::of(&secret, &b).expect("b").view);
    assert_ne!(published.view, Published::of(&other, &a).expect("another's").view);
    let (sealed, owner) = crate::claim::viewed(&published.view).expect("a view");
    assert_eq!((&sealed, &owner), (&published.anchor, &published.owner.id()));
    assert_ne!(crate::claim::anchor_nonce(&sealed), crate::claim::anchor_nonce(&a));
    assert!(Published::of(&secret, &published.view).is_err(), "a view's published by its owner");
}

#[test]
fn a_sealed_anchor_reads_as_its_latest_head_whatever_else_is_held() {
    let t = tree("cap-live");
    let repo = Scratch::new("cap-live-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let anchor = crate::claim::anchor().expect("anchor");
    let published = Published::of(&[3u8; 32], &anchor).expect("published");
    let Capability::Live(live) = published.capability() else {
        panic!("not live");
    };

    let first = import(&mut catalog, t.path(), &importer());
    let one = publish(&mut catalog, &published, &first).expect("publish");
    assert_eq!(read_live(&held_of(&one.blocks), &live).expect("read").0, first);
    let again = publish(&mut catalog, &published, &first).expect("publish");
    assert_eq!(again.set, one.set, "nothing new to say");

    std::fs::write(t.path().join("docs/readme.md"), "read me again").expect("write");
    let second = import(&mut catalog, t.path(), &importer());
    let two = publish(&mut catalog, &published, &second).expect("publish");
    assert_ne!(two.set, one.set);
    // Both held, the later replaces the earlier
    let both: Vec<Block> = one.blocks.iter().chain(&two.blocks).cloned().collect();
    let (plain, blocks) = read_live(&held_of(&both), &live).expect("read");
    assert_eq!(plain, second);
    assert_eq!(blocks.len(), dag(&catalog, &second).len());

    // A later head signed by anyone else counts for nothing
    let forger = crate::keys::Key::generate().expect("key");
    let head = seal_head(live.read(), &first, &seal(&catalog, &first, live.read()).expect("seal").root).expect("head");
    let set = crate::claim::Claim::Set(crate::claim::Set::new([published.anchor.clone()], AnyCid::V1(head.cid().clone()), u64::MAX).expect("set").after(Some(Vec::new())));
    let sign = crate::claim::Claim::Sign(crate::claim::Sign::new(&forger, [set.cid()], None, u64::MAX).expect("sign"));
    let with_forgery: Vec<Block> = both.iter().cloned().chain([head, set.block(), sign.block()]).collect();
    assert_eq!(read_live(&held_of(&with_forgery), &live).expect("read").0, second);

    // Nor does the right capability with another read key read anything
    let wrong = Live::new(live.view, Zeroizing::new([9u8; 32]));
    assert!(read_live(&held_of(&both), &wrong).is_err());
}
