use super::*;
use crate::cid::AnyCid;
use libp2p::core::transport::MemoryTransport;

/// A repo with an anchor published: its vault, what's published, and the
/// capability.
fn published(repo: &std::path::Path) -> (Catalog, crate::cap::Published, crate::cap::Live, Link) {
    let mut catalog = Catalog::open_repo(repo).expect("catalog");
    let vault = crate::vault::Vault::open(repo, catalog.uid()).expect("vault");
    let files = repo.join("files");
    std::fs::create_dir_all(files.join("docs")).expect("mkdir");
    std::fs::write(files.join("docs/a.md"), "behind the door").expect("write");
    std::fs::write(files.join("b.md"), "and this").expect("write");
    let value = AnyCid::V1(crate::import::Importer::default().add_path(&files, &mut catalog, &mut |_, _| {}).expect("import").expect("root").cid);
    let anchor = crate::claim::anchor().expect("anchor");
    let published = crate::cap::Published::of(&crate::cap::secret(&vault), &anchor).expect("published");
    crate::cap::publish(&mut catalog, &vault, &published, &value).expect("publish");
    let crate::cap::Capability::Live(live) = published.capability() else {
        panic!("not live");
    };
    (catalog, published, live, value)
}

#[test]
fn the_door_answers_only_what_a_capability_proves() {
    let scratch = crate::testutil::Scratch::new("door-answer");
    let (catalog, _, live, value) = published(scratch.path());
    let (asker, other) = (PeerId::random(), PeerId::random());
    let now = 1_000_000;
    let heads = |read: &[u8; 32], for_whom: &PeerId, at: u64| {
        let proof = crate::vault::prove(&crate::cap::head_bat(read), &live.view, &for_whom.to_bytes(), at);
        answer(&catalog, &asker, Asked::Heads { view: ByteBuf::from(live.view.to_bytes()), at, proof: ByteBuf::from(proof.to_vec()) }, now).expect("answer").blocks
    };
    // A set, its sign and the head
    let told = heads(live.read(), &asker, now);
    assert_eq!(told.len(), 3, "{told:?}");
    assert!(heads(&[0u8; 32], &asker, now).is_empty(), "another read key");
    assert!(heads(live.read(), &other, now).is_empty(), "a proof of someone else's");
    assert!(heads(live.read(), &asker, now - 3600).is_empty(), "a proof long since");

    // Blocks, each to a proof of its own token; plaintext never
    let set = told.iter().find_map(|(_, data)| match crate::claim::Claim::parse(data) {
        Some(crate::claim::Claim::Set(set)) => Some(set),
        _ => None,
    }).expect("a set");
    let head = set.value().clone();
    let bat = crate::cap::head_bat(live.read());
    let blocks = |cid: &Link, bat: &[u8; 32]| {
        let proof = crate::vault::prove(bat, cid, &asker.to_bytes(), now);
        answer(&catalog, &asker, Asked::Blocks { wanted: vec![(ByteBuf::from(cid.to_bytes()), ByteBuf::from(proof.to_vec()))], at: now }, now).expect("answer").blocks
    };
    assert_eq!(blocks(&head, &bat).len(), 1);
    assert!(blocks(&head, &[1u8; 32]).is_empty());
    assert!(blocks(&value, &bat).is_empty(), "the plaintext has no token to prove");
}

#[test]
fn a_reader_outside_reads_a_sealed_anchor_at_the_door() {
    let scratch = crate::testutil::Scratch::new("door-read");
    let (catalog, _, live, value) = published(scratch.path());
    let wanted = crate::car::export(&catalog, &value, &mut std::io::sink()).expect("count");
    drop(catalog);
    let port = rand_port();
    let door_key = Keypair::generate_ed25519();
    let door_peer = door_key.public().to_peer_id();
    let repo = scratch.path().to_path_buf();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        runtime.block_on(async {
            let transport = super::super::clients::client_transport(MemoryTransport::default(), &door_key).expect("transport");
            let mut door = Door::new(transport, &door_key, Catalog::open_repo(&repo).expect("catalog"));
            door.listen(format!("/memory/{port}").parse().expect("addr")).expect("listen");
            door.run().await;
        });
    });
    std::thread::sleep(Duration::from_millis(200));

    let key = Keypair::generate_ed25519();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let transport = {
        let _entered = runtime.enter();
        super::super::clients::client_transport(MemoryTransport::default(), &key).expect("transport")
    };
    let reader = Reader::over(runtime, transport, &key, &format!("/memory/{port}/p2p/{door_peer}").parse().expect("addr")).expect("connect");
    let claims = reader.heads(&live.view, live.read()).expect("heads");
    let (plain, blocks) = crate::cap::read_live(&reader, claims.iter().map(|(_, data)| data.as_slice()), &live).expect("read");
    assert_eq!(plain, value);
    assert_eq!(u64::try_from(blocks.len()).expect("len"), wanted);

    // With another read key, it's told nothing
    assert!(reader.heads(&live.view, &[7u8; 32]).expect("heads").is_empty());
}

fn rand_port() -> u64 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).expect("random");
    u64::from(u32::from_le_bytes(bytes)) | 1 << 40
}
