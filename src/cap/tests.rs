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
    // Sealed after the first, it's the same, and only what's new is made
    for block in &before.blocks {
        catalog.put_block(block, crate::cid::CidVersion::V1).expect("put");
    }
    let since = seal_since(&catalog, &grown, &read, Some((root, before.root))).expect("seal");
    assert_eq!(since.root, after.root);
    assert!(since.blocks.len() < after.blocks.len(), "{} of {}", since.blocks.len(), after.blocks.len());
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
    let node = encode(b"block", std::slice::from_ref(&link), &BTreeMap::new()).expect("encode");
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
fn sealing_again_after_an_edit_seals_only_whats_new() {
    let t = tree("cap-since");
    let repo = Scratch::new("cap-since-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let read = Zeroizing::new([4u8; 32]);
    let first = import(&mut catalog, t.path(), &importer());
    let before = seal(&catalog, &first, &read).expect("seal");
    for block in &before.blocks {
        catalog.put_block(block, crate::cid::CidVersion::V1).expect("put");
    }
    // Unchanged, nothing's new
    let same = seal_since(&catalog, &first, &read, Some((first.clone(), before.root.clone()))).expect("seal");
    assert_eq!((same.root.clone(), same.blocks.len()), (before.root.clone(), 0));

    std::fs::write(t.path().join("docs/deep/secret.txt"), "the plans have changed").expect("write");
    let second = import(&mut catalog, t.path(), &importer());
    let after = seal_since(&catalog, &second, &read, Some((first, before.root))).expect("seal");
    // The file, deep, docs and the root, as sealing it all again makes
    assert_eq!(after.blocks.len(), 4);
    let whole = seal(&catalog, &second, &read).expect("seal");
    assert_eq!(after.root, whole.root);
    assert!(sealed_cids(&after).is_subset(&sealed_cids(&whole)));
}

#[test]
fn a_sealed_anchor_reads_as_its_latest_head_whatever_else_is_held() {
    let t = tree("cap-live");
    let repo = Scratch::new("cap-live-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let vault = crate::vault::Vault::open(repo.path(), catalog.uid()).expect("vault");
    let anchor = crate::claim::anchor().expect("anchor");
    let published = Published::of(&secret(&vault), &anchor).expect("published");
    let Capability::Live(live) = published.capability() else {
        panic!("not live");
    };

    let first = import(&mut catalog, t.path(), &importer());
    let one = publish(&mut catalog, &vault, &published, &first).expect("publish");
    assert!(one.fresh);
    let held_one = held_of(&published_blocks(&catalog, &one.manifest).expect("blocks"));
    assert_eq!(read_live(&held_one, held_one.all(), &live).expect("read").0, first);
    let again = publish(&mut catalog, &vault, &published, &first).expect("publish");
    assert_eq!((again.set.clone(), again.manifest.clone(), again.fresh), (one.set.clone(), one.manifest.clone(), false), "nothing new to say");

    std::fs::write(t.path().join("docs/readme.md"), "read me again").expect("write");
    let second = import(&mut catalog, t.path(), &importer());
    let two = publish(&mut catalog, &vault, &published, &second).expect("publish");
    assert_ne!(two.set, one.set);
    // The vault keeps the latest manifest, which reaches every head
    assert_eq!(published_list(&mut catalog, &vault), vec![(anchor, two.manifest.clone())]);
    let everything = published_blocks(&catalog, &two.manifest).expect("blocks");
    let (plain, blocks) = read_held(&everything, &live).expect("read");
    assert_eq!(plain, second);
    assert_eq!(blocks.len(), dag(&catalog, &second).len());
    assert!(sealed_cids(&Sealed { root: one.set, blocks: everything.clone() }).is_superset(&held_one.0.keys().cloned().collect()), "every head's held");

    // A later head signed by anyone else counts for nothing
    let forger = crate::keys::Key::generate().expect("key");
    let head = seal_head(live.read(), &HeadBlock::new(first.clone(), seal(&catalog, &first, live.read()).expect("seal").root)).expect("head");
    let set = crate::claim::Claim::Set(crate::claim::Set::new([published.anchor.clone()], AnyCid::V1(head.cid().clone()), u64::MAX).expect("set").after(Some(Vec::new())));
    let sign = crate::claim::Claim::Sign(crate::claim::Sign::new(&forger, [set.cid()], None, u64::MAX).expect("sign"));
    let with_forgery: Vec<Block> = everything.iter().cloned().chain([head, set.block(), sign.block()]).collect();
    assert_eq!(read_held(&with_forgery, &live).expect("read").0, second);

    // Nor does the right capability with another read key read anything
    let wrong = Live::new(live.view, Zeroizing::new([9u8; 32]));
    assert!(read_held(&everything, &wrong).is_err());

    // Unpublished, the vault keeps none of it
    assert!(unpublish(&mut catalog, &vault, &published).expect("unpublish"));
    assert!(published_list(&mut catalog, &vault).is_empty());
    assert!(!unpublish(&mut catalog, &vault, &published).expect("unpublish"));
}

#[test]
fn a_reader_remembers_the_head_it_read_and_notices_an_older_one_offered() {
    let t = tree("cap-behind");
    let repo = Scratch::new("cap-behind-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let vault = crate::vault::Vault::open(repo.path(), catalog.uid()).expect("vault");
    let published = Published::of(&secret(&vault), &crate::claim::anchor().expect("anchor")).expect("published");
    let Capability::Live(live) = published.capability() else {
        panic!("not live");
    };
    let first = import(&mut catalog, t.path(), &importer());
    let one = publish(&mut catalog, &vault, &published, &first).expect("publish");
    let held_one = held_of(&published_blocks(&catalog, &one.manifest).expect("blocks"));

    let reader = Scratch::new("cap-behind-reader");
    let remembered = Remembered::of(reader.path(), 1000, &live.view);
    assert!(remembered.claims().expect("nothing yet").is_empty());
    let read = read_live_after(&held_one, held_one.all(), &[], &live).expect("read");
    assert_eq!(read.plain, first);
    remembered.remember(&read.head).expect("remember");
    assert_eq!(remembered.claims().expect("claims"), read.head);
    // The same head again, offered again, reads
    assert_eq!(read_live_after(&held_one, held_one.all(), &read.head, &live).expect("read").plain, first);

    std::fs::write(t.path().join("docs/readme.md"), "newer").expect("write");
    let second = import(&mut catalog, t.path(), &importer());
    let two = publish(&mut catalog, &vault, &published, &second).expect("publish");
    let held_two = held_of(&published_blocks(&catalog, &two.manifest).expect("blocks"));
    // A newer head replaces the one remembered
    let newer = read_live_after(&held_two, held_two.all(), &remembered.claims().expect("claims"), &live).expect("read");
    assert_eq!(newer.plain, second);
    remembered.remember(&newer.head).expect("remember");

    // Offered only the first now, what has it is behind
    let behind = read_live_after(&held_one, held_one.all(), &remembered.claims().expect("claims"), &live);
    assert!(matches!(behind, Err(Error::Behind)), "an older head's noticed");
    // Though one forgetting reads it as the latest it's shown
    assert_eq!(read_live_after(&held_one, held_one.all(), &[], &live).expect("read").plain, first);
    // And what's remembered is its reader's, by account and view
    assert!(Remembered::of(reader.path(), 1001, &live.view).claims().expect("claims").is_empty());
}

fn read_held(blocks: &[Block], live: &Live) -> Result<(Link, Vec<Block>)> {
    let held = held_of(blocks);
    read_live(&held, held.all(), live)
}

fn published_list(catalog: &mut Catalog, vault: &crate::vault::Vault) -> Vec<(Link, Link)> {
    published(catalog, vault).expect("published")
}

/// Every block published of each publication, held together.
fn held_all(catalog: &Catalog, publications: &[(Link, Publication)]) -> Held {
    let mut held = Held::default();
    for (_, publication) in publications {
        for block in published_blocks(catalog, &publication.manifest).expect("blocks") {
            held.insert(block);
        }
    }
    held
}

#[test]
fn a_mounted_anchor_is_published_with_what_mounts_it_and_read_through_it() {
    let repo = Scratch::new("cap-mounts-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let vault = crate::vault::Vault::open(repo.path(), catalog.uid()).expect("vault");
    let (outer, inner, empty) = (catalog.new_anchor().expect("anchor"), catalog.new_anchor().expect("anchor"), catalog.new_anchor().expect("anchor"));

    // The inner anchor mounts the outer, a loop, and is mounted in it
    let t = tree("cap-mounts-inner");
    std::os::unix::fs::symlink(format!("/anchors/{outer}"), t.path().join("up")).expect("symlink");
    let inner_value = import(&mut catalog, t.path(), &importer());
    catalog.set_anchor(&inner, &inner_value).expect("set");
    let top = Scratch::new("cap-mounts-outer");
    std::fs::create_dir_all(top.path().join("shared")).expect("mkdir");
    std::fs::write(top.path().join("note.txt"), "outside").expect("write");
    std::os::unix::fs::symlink(format!("/anchors/{inner}"), top.path().join("shared/inner")).expect("symlink");
    // One that's nothing yet, and a symlink that only looks like one
    std::os::unix::fs::symlink(format!("/anchors/{empty}"), top.path().join("nothing")).expect("symlink");
    std::os::unix::fs::symlink("/anchors/not-one", top.path().join("odd")).expect("symlink");
    let outer_value = import(&mut catalog, top.path(), &importer());
    catalog.set_anchor(&outer, &outer_value).expect("set");

    let publications = publish_mounted(&mut catalog, &vault, &outer, &outer_value).expect("publish");
    let anchors: Vec<&Link> = publications.iter().map(|(anchor, _)| anchor).collect();
    assert_eq!(anchors, vec![&outer, &inner], "the outer, then what's mounted in it, each once, and nothing for what's nothing");
    let mut listed: Vec<Link> = published_list(&mut catalog, &vault).into_iter().map(|(anchor, _)| anchor).collect();
    listed.sort_by_key(CidRef::to_bytes);
    let mut wanted = vec![outer.clone(), inner.clone()];
    wanted.sort_by_key(CidRef::to_bytes);
    assert_eq!(listed, wanted, "each is published on its own too");

    let held = held_all(&catalog, &publications);
    let Capability::Live(live) = Published::of(&secret(&vault), &outer).expect("published").capability() else {
        panic!("not live");
    };
    let reading = read(&held, &live, &|_| Vec::new()).expect("read");
    assert_eq!(reading.plain, outer_value);
    let mounts: Vec<(&str, std::result::Result<&Link, &String>)> = reading.mounts.iter().map(|mounted| (mounted.path.as_str(), mounted.read.as_ref())).collect();
    assert_eq!(mounts.len(), 2, "{mounts:?}");
    assert!(mounts.contains(&("shared/inner", Ok(&inner_value))), "{mounts:?}");
    assert!(mounts.iter().any(|(path, read)| *path == "nothing" && read.is_err()), "what's nothing yet is said so: {mounts:?}");
    // Every block of both trees, and a head of each to remember; the loop back up is read once
    let read_cids: HashSet<Vec<u8>> = reading.blocks.iter().map(|block| AnyCid::V1(block.cid().clone()).to_bytes()).collect();
    assert!(dag(&catalog, &inner_value).iter().all(|cid| read_cids.contains(&AnyCid::V1(Link::decode(cid).expect("cid").into()).to_bytes())));
    assert_eq!(reading.heads.len(), 2);

    // A capability on the mounted anchor reads it and nothing above
    let Capability::Live(inner_live) = Published::of(&secret(&vault), &inner).expect("published").capability() else {
        panic!("not live");
    };
    let below = read(&held, &inner_live, &|_| Vec::new()).expect("read");
    assert_eq!(below.plain, inner_value);
    assert_eq!(below.mounts.iter().map(|mounted| (mounted.path.as_str(), mounted.read.clone().ok())).collect::<Vec<_>>(), vec![("up", Some(outer_value.clone())), ("up/nothing", None)], "up is the outer, as mounted, and what it mounts");

    // A snapshot seals mount points as the symlinks they are
    let snapshot = seal_tree(&catalog, &outer_value, &[3u8; 32], None, MountKeys::None).expect("seal");
    assert!(snapshot.1.is_empty());
}

#[test]
fn a_sealed_nodes_mount_points_read_back_and_must_be_views() {
    let opened = encode(b"block", &[], &BTreeMap::from([("ghost".to_owned(), Mount { view: crate::claim::view(&crate::claim::anchor().expect("anchor"), &crate::keys::Key::generate().expect("key").id()).expect("view"), read: Zeroizing::new([1u8; 32]), of: None })])).expect("encode");
    let decoded = decode(&opened).expect("decode");
    assert_eq!(decoded.mounts.len(), 1);
    // The view must be one
    let bad = encode(b"block", &[], &BTreeMap::from([("bad".to_owned(), Mount { view: crate::claim::anchor().expect("anchor"), read: Zeroizing::new([1u8; 32]), of: None })])).expect("encode");
    assert!(decode(&bad).is_err());
}


/// The claims a catalog holds of a published anchor, judged: its heads,
/// latest first, as set CIDs.
fn heads_held(catalog: &Catalog, published: &Published) -> Vec<Link> {
    use crate::cid::Cid as _;
    let claims = claims_about(catalog, &published.view).expect("claims");
    let mut gathered = Gathered::default();
    for (_, data) in &claims {
        gathered.add(&published.anchor, data);
    }
    heads_among(&gathered, &published.owner.id(), &published.anchor, &std::collections::HashSet::new()).expect("heads").into_iter().map(|(cid, ..)| Link::decode(&cid).expect("cid")).collect()
}

#[test]
fn each_machine_writes_with_a_key_the_owner_key_lets_write_and_can_have_it_taken_away() {
    let t = tree("cap-writers");
    let repo = Scratch::new("cap-writers-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let vault = crate::vault::Vault::open(repo.path(), catalog.uid()).expect("vault");
    let anchor = catalog.new_anchor().expect("anchor");
    let published = Published::of(&secret(&vault), &anchor).expect("published");
    let Capability::Live(live) = published.capability() else {
        panic!("not live");
    };
    let first = import(&mut catalog, t.path(), &importer());
    catalog.set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    catalog.set_anchor(&anchor, &first).expect("set");
    let one = publish(&mut catalog, &vault, &published, &first).expect("publish");
    // The head says which plaintext sets it's of
    let latest = last_head(&catalog, &published).expect("head").expect("a head");
    assert_eq!(latest.block.sets, catalog.anchor_heads(&anchor).expect("heads").into_iter().map(|(set, ..)| set).collect::<Vec<_>>());
    assert!(!latest.block.sets.is_empty());

    // Another machine, another writer, after the first
    std::fs::write(t.path().join("docs/readme.md"), "from the other machine").expect("write");
    let second = import(&mut catalog, t.path(), &importer());
    catalog.set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    let two = publish(&mut catalog, &vault, &published, &second).expect("publish");
    assert_eq!(heads_held(&catalog, &published), vec![two.set.clone()]);
    let everything = |catalog: &Catalog| held_all(catalog, &[(anchor.clone(), Publication { set: two.set.clone(), manifest: two.manifest.clone(), fresh: true, mounted: Vec::new() })]);
    assert_eq!(read(&everything(&catalog), &live, &|_| Vec::new()).expect("read").plain, second);
    let writers: Vec<Link> = [&one.set, &two.set].iter().map(|set| {
        let held = everything(&catalog);
        held.0.values().find_map(|data| match crate::claim::Claim::parse(data) {
            Some(crate::claim::Claim::Sign(sign)) if sign.signs().contains(set) => Some(sign.by().clone()),
            _ => None,
        }).expect("signed")
    }).collect();
    assert_ne!(writers[0], writers[1], "each machine its own key");
    assert!(writers.iter().all(|writer| *writer != published.owner.id()), "not the owner key itself");

    // The second machine's write taken away, standing at the first's head:
    // its head counts no more, and the first's is the latest again
    let claims = claims_about(&catalog, &published.view).expect("claims");
    let mut gathered = Gathered::default();
    for (_, data) in &claims {
        gathered.add(&published.anchor, data);
    }
    let judge = Judge::of(&published.owner.id(), &published.anchor, gathered.signed_grants(), &BTreeMap::new()).expect("judge");
    let prev = judge.state.as_ref().expect("state").heads();
    let take = crate::claim::Claim::Grant(crate::claim::Grant::new([writers[1].clone()], Some(published.anchor.clone()), [], [crate::grants::WRITE.to_owned()], [], prev).expect("grant"));
    catalog.put_block(&take.block(), crate::cid::CidVersion::V1).expect("put");
    catalog.sign_with_key(&published.owner, [take.cid()]).expect("sign");
    assert_eq!(heads_held(&catalog, &published), vec![one.set.clone()]);

    // A set by a key never let write counts for nothing, however late
    let stranger = crate::keys::Key::generate().expect("key");
    let head = seal_head(live.read(), &HeadBlock::new(first.clone(), seal(&catalog, &first, live.read()).expect("seal").root)).expect("head");
    let later = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("now").as_secs() + 1_000_000;
    let set = crate::claim::Claim::Set(crate::claim::Set::new([published.anchor.clone()], AnyCid::V1(head.cid().clone()), later).expect("set").after(Some(vec![one.set.clone()])));
    catalog.put_block(&set.block(), crate::cid::CidVersion::V1).expect("put");
    catalog.sign_with_key(&stranger, [set.cid()]).expect("sign");
    assert_eq!(heads_held(&catalog, &published), vec![one.set]);
}

#[test]
fn a_write_capability_writes_a_head_its_readers_read_carrying_the_plaintext_set() {
    let t = tree("cap-write");
    let repo = Scratch::new("cap-write-repo");
    let mut catalog = Catalog::open_repo(repo.path()).expect("catalog");
    let vault = crate::vault::Vault::open(repo.path(), catalog.uid()).expect("vault");
    catalog.set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    let anchor = catalog.new_anchor().expect("anchor");
    let first = import(&mut catalog, t.path(), &importer());
    catalog.set_anchor(&anchor, &first).expect("set");
    let published = Published::of(&secret(&vault), &anchor).expect("published");
    // A repo of no mesh has no user: whatever's set counts
    let owner = catalog.user().expect("user");
    assert!(add_writer(&mut catalog, &vault, &published).is_err(), "not published yet");
    publish(&mut catalog, &vault, &published, &first).expect("publish");
    let seed = add_writer(&mut catalog, &vault, &published).expect("writer");
    let capability = published.write_capability(seed, owner.clone());
    let Capability::Write(write_cap) = Capability::decode(&capability.encode()).expect("decode") else {
        panic!("not a write capability");
    };
    assert_eq!((&write_cap.of, &write_cap.owner), (&anchor, &owner));
    let owners_held = |catalog: &mut Catalog| {
        let (_, manifest) = published_list(catalog, &vault).into_iter().next().expect("published");
        let mut held = Held::default();
        for block in published_blocks(catalog, &manifest).expect("blocks") {
            held.insert(block);
        }
        held
    };

    // The writer reads, edits, and writes, in a repo of its own
    let elsewhere = Scratch::new("cap-write-writer");
    let mut theirs = Catalog::open_repo(elsewhere.path()).expect("catalog");
    let mut held = owners_held(&mut catalog);
    let reading = read(&held, &write_cap.live, &|_| Vec::new()).expect("read");
    assert_eq!(reading.plain, first);
    std::fs::write(t.path().join("docs/readme.md"), "written by a writer").expect("write");
    let edited = import(&mut theirs, t.path(), &importer());
    let base = reading.base.expect("a base");
    let written = write(&mut theirs, &write_cap, &base, &edited).expect("write");
    for block in written.blocks.clone() {
        held.insert(block);
    }

    // A reader reads what the writer wrote, as the latest head
    let Capability::Live(live) = published.capability() else {
        panic!("not live");
    };
    let after = read(&held, &live, &|_| Vec::new()).expect("read");
    assert_eq!(after.plain, edited);
    assert_eq!(after.base.as_ref().map(|base| &base.set), Some(&written.set));
    // Its head carries the plaintext set, after the owner's, for the owner's view, signed by the writer
    let block = after.base.expect("base").block;
    let Some(crate::claim::Claim::Set(inner)) = block.set.as_deref().and_then(crate::claim::Claim::parse) else {
        panic!("no plaintext set");
    };
    assert_eq!((inner.target(), inner.value(), inner.owner()), ([anchor.clone()].as_slice(), &edited, owner.as_ref()));
    assert_eq!(inner.prev().map(<[Link]>::to_vec), Some(catalog.anchor_heads(&anchor).expect("heads").into_iter().map(|(set, ..)| set).collect()));
    let Some(crate::claim::Claim::Sign(sign)) = block.sign.as_deref().and_then(crate::claim::Claim::parse) else {
        panic!("no sign");
    };
    assert!(sign.verify() && sign.signs().contains(&crate::claim::Claim::Set(inner).cid()) && *sign.by() == write_cap.writer().id());

    // The owner takes it in, once: the plaintext anchor is what was written,
    // after what it was, and it's published again as that
    for block in &written.blocks {
        catalog.put_block(block, crate::cid::CidVersion::V1).expect("put");
    }
    let taken = take_in(&mut catalog, &vault).expect("take in");
    assert_eq!(taken.iter().map(|taken| &taken.anchor).collect::<Vec<_>>(), vec![&anchor]);
    assert_eq!(catalog.anchor_value(&anchor).expect("value"), Some(edited.clone()));
    assert!(take_in(&mut catalog, &vault).expect("take in").is_empty(), "taken in once");
    let again = publish(&mut catalog, &vault, &published, &edited).expect("publish");
    assert!(again.fresh, "the owner's head follows the writer's");
    let held = owners_held(&mut catalog);
    let after = read(&held, &live, &|_| Vec::new()).expect("read");
    assert_eq!((after.plain, after.base.expect("base").set), (edited.clone(), again.set));

    // A writer the owner key never let write writes nothing anyone reads
    let forged = Write::new(Live::new(live.view.clone(), Zeroizing::new(**live.read())), fresh_key().expect("key"), anchor, None);
    let mut held = owners_held(&mut catalog);
    std::fs::write(t.path().join("docs/readme.md"), "forged").expect("write");
    let forgery = import(&mut theirs, t.path(), &importer());
    let stranger = write(&mut theirs, &forged, &base, &forgery).expect("write");
    for block in stranger.blocks {
        held.insert(block);
    }
    assert_eq!(read(&held, &live, &|_| Vec::new()).expect("read").plain, edited);
}
