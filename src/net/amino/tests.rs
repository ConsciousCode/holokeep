use super::*;
use crate::cid::{AnyCid, CidVersion, Cidv1Spec};
use crate::model::Link;
use crate::testutil::Scratch;
use libp2p::core::transport::MemoryTransport;
use libp2p::multiaddr::Protocol;

fn raw(data: &[u8]) -> crate::block::Block {
    crate::block::Block::hash(Cidv1Spec::default(), data.into())
}

fn link(block: &crate::block::Block) -> Link {
    AnyCid::V1(block.cid().clone())
}

fn want(cid: &Link, want: WantType) -> Entry {
    Entry { cid: cid.clone(), priority: 1, cancel: false, want, send_dont_have: true }
}

/// A catalog holding a public block, a private one, and one fetched from
/// Amino to be shared.
fn holding(scratch: &Scratch, name: &str) -> (Catalog, Link, Link, Link) {
    let catalog = Catalog::open_repo(&scratch.path().join(name)).expect("catalog");
    let (public, private, fetched) = (raw(b"anyone's"), raw(b"mine alone"), raw(b"fetched from Amino"));
    for block in [&public, &private, &fetched] {
        catalog.put_block(block, CidVersion::V1).expect("put");
    }
    catalog.publish(&link(&public), crate::claim::Public::SERVE).expect("publish");
    catalog.share_fetched(&[link(&fetched)]).expect("share");
    (catalog, link(&public), link(&private), link(&fetched))
}

#[test]
fn whats_public_or_shared_is_served_and_the_rest_is_not_had_alike() {
    let scratch = Scratch::new("amino-answers");
    let (catalog, public, private, fetched) = holding(&scratch, "repo");
    let missing = link(&raw(b"never here"));
    let asked = Message {
        wants: vec![
            want(&public, WantType::Have),
            want(&public, WantType::Block),
            want(&fetched, WantType::Block),
            want(&private, WantType::Block),
            want(&private, WantType::Have),
            want(&missing, WantType::Block),
            Entry { cancel: true, ..want(&public, WantType::Block) },
            Entry { send_dont_have: false, ..want(&missing, WantType::Have) },
        ],
        ..Message::default()
    };
    let (now, later) = answers(&catalog, &asked);
    let blocks: Vec<Link> = now.iter().flat_map(|message| message.blocks.iter().map(|(cid, _)| cid.clone())).collect();
    let haves: Vec<_> = now.iter().flat_map(|message| message.presences.clone()).collect();
    assert_eq!(blocks, [public.clone(), fetched]);
    assert_eq!(haves, [(public, Presence::Have)]);
    // Private and missing alike, and only where it was asked to be said
    assert_eq!(later.presences, [(private.clone(), Presence::DontHave), (private, Presence::DontHave), (missing, Presence::DontHave)]);
}

/// A swarm over the in-memory transport, listening at a fresh address.
async fn swarm(catalog: Catalog) -> (Amino, Multiaddr) {
    use libp2p::Transport as _;
    let key = Keypair::generate_ed25519();
    let transport = MemoryTransport::default()
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(libp2p::noise::Config::new(&key).expect("noise"))
        .multiplex(libp2p::yamux::Config::default())
        .boxed();
    let mut amino = Amino::new(transport, &key, catalog, &[]).expect("amino");
    amino.listen(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    loop {
        if let Event::Listening(at) = amino.next().await.expect("event") {
            let peer = amino.peer_id();
            return (amino, at.with(Protocol::P2p(peer)));
        }
    }
}

/// Drive both till the second hears from the first, and say what.
async fn heard(a: &mut Amino, b: &mut Amino) -> Message {
    let from = a.peer_id();
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    loop {
        let event = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                event = a.next() => (false, event),
                event = b.next() => (true, event),
            }
        });
        if let (true, Ok(Event::Received(peer, message))) = event.await.expect("in time")
            && peer == from
        {
            return message;
        }
    }
}

#[tokio::test]
async fn a_peer_asking_over_bitswap_gets_whats_public_and_is_told_the_rest_isnt_had() {
    let scratch = Scratch::new("amino-swarm");
    let (catalog, public, private, _) = holding(&scratch, "serving");
    let (mut a, at) = swarm(catalog).await;
    let (mut b, _) = swarm(Catalog::open_repo(&scratch.path().join("asking")).expect("catalog")).await;
    b.dial(at).expect("dial");

    b.send(a.peer_id(), Message { wants: vec![want(&public, WantType::Block)], ..Message::default() });
    let told = heard(&mut a, &mut b).await;
    assert_eq!(told.blocks, [(public, b"anyone's".to_vec())]);

    let asked = std::time::Instant::now();
    b.send(a.peer_id(), Message { wants: vec![want(&private, WantType::Block)], ..Message::default() });
    let told = heard(&mut a, &mut b).await;
    assert_eq!((told.blocks.len(), told.presences), (0, vec![(private, Presence::DontHave)]));
    assert!(asked.elapsed() >= NOT_HAD, "not before the floor: {:?}", asked.elapsed());
}
