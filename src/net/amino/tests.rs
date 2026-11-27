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
    let mut amino = Amino::new(transport, &key, catalog, &[]);
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

/// Drive both till the fetch is done, and say what came of it.
async fn fetched(a: &mut Amino, b: &mut Amino, mut answer: tokio::sync::oneshot::Receiver<Fetched>) -> Fetched {
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(20)).expect("deadline");
    loop {
        let step = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                done = &mut answer => Some(done.expect("answered")),
                _ = a.next() => None,
                _ = b.next() => None,
            }
        });
        if let Some(done) = step.await.expect("in time") {
            return done;
        }
    }
}

#[tokio::test]
async fn a_dag_is_fetched_from_amino_and_shared_back_unless_not_to_be() {
    let scratch = Scratch::new("amino-fetch");
    let serving = Catalog::open_repo(&scratch.path().join("serving")).expect("catalog");
    let (leaf, deep) = (raw(b"a leaf"), raw(b"a deeper leaf"));
    let branch = crate::block::Block::hash(Cidv1Spec::new(crate::cid::DAG_CBOR_CODEC, crate::multihash::MultihashFunc::Sha2_256), crate::dagcbor::to_vec(&crate::model::Ipld::List(vec![crate::model::Ipld::Link(link(&deep))])).expect("cbor").into());
    let root = crate::block::Block::hash(Cidv1Spec::new(crate::cid::DAG_CBOR_CODEC, crate::multihash::MultihashFunc::Sha2_256), crate::dagcbor::to_vec(&crate::model::Ipld::List(vec![crate::model::Ipld::Link(link(&branch)), crate::model::Ipld::Link(link(&leaf))])).expect("cbor").into());
    let private = raw(b"not for Amino");
    for block in [&root, &branch, &leaf, &deep, &private] {
        serving.put_block(block, CidVersion::V1).expect("put");
    }
    serving.publish(&link(&root), crate::claim::Public::SERVE).expect("publish");
    let (mut a, at) = swarm(serving).await;
    let (mut b, _) = swarm(Catalog::open_repo(&scratch.path().join("fetching")).expect("catalog")).await;
    b.dial(at).expect("dial");
    let peer = a.peer_id();
    // What connects isn't an event, so look again every so often
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    while !b.is_connected(&peer) {
        assert!(tokio::time::Instant::now() < deadline, "connected in time");
        let _ = tokio::time::timeout(Duration::from_millis(50), async { tokio::select! { _ = a.next() => {}, _ = b.next() => {} } }).await;
    }
    let fetcher = b.fetcher();

    let done = fetched(&mut a, &mut b, fetcher.fetch(vec![link(&root)], true, true)).await;
    assert_eq!(done, Fetched { fetched: 4, missing: Vec::new() });
    for block in [&root, &branch, &leaf, &deep] {
        assert!(b.catalog().has(block.cid().multihash()).expect("has"));
        assert!(b.catalog().shared_fetch(&link(block)).expect("shared"), "shared back");
    }
    // Asked again, nothing's wanted
    assert_eq!(fetched(&mut a, &mut b, fetcher.fetch(vec![link(&root)], true, true)).await, Fetched::default());
    // What isn't served is missing, once nothing's come for a while
    let done = fetched(&mut a, &mut b, fetcher.fetch(vec![link(&private)], false, true)).await;
    assert_eq!(done, Fetched { fetched: 0, missing: vec![link(&private)] });
    // Fetched to be kept to oneself, it isn't shared
    let other = raw(b"public, fetched privately");
    a.catalog().put_block(&other, CidVersion::V1).expect("put");
    a.catalog().publish(&link(&other), crate::claim::Public::SERVE).expect("publish");
    assert_eq!(fetched(&mut a, &mut b, fetcher.fetch(vec![link(&other)], false, false)).await.fetched, 1);
    assert!(!b.catalog().shared_fetch(&link(&other)).expect("shared"));
}

/// A swarm as `swarm` makes, joining the DHT by these peers, a server of it.
async fn joining(catalog: Catalog, bootstrap: &[Multiaddr]) -> (Amino, Multiaddr) {
    use libp2p::Transport as _;
    let key = Keypair::generate_ed25519();
    let transport = MemoryTransport::default()
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(libp2p::noise::Config::new(&key).expect("noise"))
        .multiplex(libp2p::yamux::Config::default())
        .boxed();
    let mut amino = Amino::new(transport, &key, catalog, bootstrap);
    amino.listen(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    amino.serve_dht();
    loop {
        if let Event::Listening(at) = amino.next().await.expect("event") {
            let peer = amino.peer_id();
            return (amino, at.with(Protocol::P2p(peer)));
        }
    }
}

#[tokio::test]
async fn whats_announced_is_found_through_the_dht_by_whoever_wants_it() {
    let scratch = Scratch::new("amino-provide");
    let (mut server, at) = joining(Catalog::open_repo(&scratch.path().join("server")).expect("catalog"), &[]).await;
    let providing = Catalog::open_repo(&scratch.path().join("providing")).expect("catalog");
    let (announced, unannounced) = (raw(b"announced on Amino"), raw(b"served, not announced"));
    for block in [&announced, &unannounced] {
        providing.put_block(block, CidVersion::V1).expect("put");
    }
    providing.publish(&link(&announced), crate::claim::Public::ANNOUNCE).expect("publish");
    providing.publish(&link(&unannounced), crate::claim::Public::SERVE).expect("publish");
    assert_eq!(providing.announced().expect("announced"), [link(&announced)], "what's served alone isn't announced");
    let (mut provider, _) = joining(providing, std::slice::from_ref(&at)).await;
    let (mut fetcher, _) = joining(Catalog::open_repo(&scratch.path().join("fetching")).expect("catalog"), std::slice::from_ref(&at)).await;
    let fetch = fetcher.fetcher();
    // A moment for its record to reach the server
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! { _ = server.next() => {}, _ = provider.next() => {}, _ = fetcher.next() => {} }
        }
    }).await;

    // Its record reaches the server, and the fetcher, which knows only the
    // server, finds the provider by it
    let mut answer = fetch.fetch(vec![link(&announced)], false, true);
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(20)).expect("deadline");
    let done = loop {
        let step = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                done = &mut answer => Some(done.expect("answered")),
                _ = server.next() => None,
                _ = provider.next() => None,
                _ = fetcher.next() => None,
            }
        });
        if let Some(done) = step.await.expect("in time") {
            break done;
        }
    };
    assert_eq!(done.fetched, 1, "{done:?}");
    assert!(fetcher.catalog().has(announced.cid().multihash()).expect("has"));
    assert!(fetcher.is_connected(&provider.peer_id()), "found, and connected to");
    // Private again, it's announced no more
    provider.catalog().unpublish(&link(&announced)).expect("unpublish");
    assert!(provider.announce(), "what's announced changed");
    assert!(provider.providing.is_empty());
    assert!(!provider.announce(), "and stays so");
}

/// A server over HTTP on a port of its own, answering each path it's
/// asked with a status and body: where it is, and the paths it's been
/// asked.
fn serve(answer: impl Fn(&str) -> (u16, Vec<u8>) + Send + 'static) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{BufRead as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = asked.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = std::io::BufReader::new(stream);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let path = line.split(' ').nth(1).unwrap_or_default().to_owned();
            log.lock().expect("log").push(path.clone());
            while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                line.clear();
            }
            let (status, body) = answer(&path);
            let _ = write!(reader.get_mut(), "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            let _ = reader.get_mut().write_all(&body);
        }
    });
    (port, asked)
}

/// A router answering every ask with these providers, as JSON.
fn router(answer: String) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let (port, asked) = serve(move |_| (200, answer.clone().into_bytes()));
    (format!("http://127.0.0.1:{port}"), asked)
}

#[tokio::test]
async fn a_router_finds_what_nothing_else_does_and_isnt_asked_once_its_found() {
    let scratch = Scratch::new("amino-route");
    let serving = Catalog::open_repo(&scratch.path().join("serving")).expect("catalog");
    let (first, second) = (raw(b"found by a router"), raw(b"then of whoever's connected"));
    for block in [&first, &second] {
        serving.put_block(block, CidVersion::V1).expect("put");
        serving.publish(&link(block), crate::claim::Public::SERVE).expect("publish");
    }
    let (mut a, at) = swarm(serving).await;
    let (mut b, _) = swarm(Catalog::open_repo(&scratch.path().join("fetching")).expect("catalog")).await;
    let addr = at.iter().filter(|protocol| !matches!(protocol, Protocol::P2p(_))).collect::<Multiaddr>();
    let (url, asked) = router(format!(r#"{{"Providers":[{{"Schema":"peer","ID":"{}","Addrs":["{addr}"],"Protocols":["transport-bitswap"]}}]}}"#, a.peer_id()));
    b.route_by(vec![url]);
    let fetcher = b.fetcher();

    // Known to no one, the fetcher finds the provider by the router alone
    let done = fetched(&mut a, &mut b, fetcher.fetch(vec![link(&first)], false, true)).await;
    assert_eq!(done, Fetched { fetched: 1, missing: Vec::new() });
    assert_eq!(*asked.lock().expect("asked"), [format!("/routing/v1/providers/{}?filter-protocols=transport-bitswap,transport-ipfs-gateway-http,unknown&filter-addrs=tcp,!p2p-circuit", link(&first))]);
    // Connected to it now, it's found of whoever's connected, and the
    // router's asked nothing more
    let done = fetched(&mut a, &mut b, fetcher.fetch(vec![link(&second)], false, true)).await;
    assert_eq!(done, Fetched { fetched: 1, missing: Vec::new() });
    assert_eq!(asked.lock().expect("asked").len(), 1, "asked again");
    assert_eq!(b.status().routed, 1);
}

#[tokio::test]
async fn a_dag_is_had_of_a_gateway_a_router_finds_each_block_checked() {
    let scratch = Scratch::new("amino-gateway");
    let (leaf, deep) = (raw(b"a leaf over HTTP"), raw(b"a deeper leaf over HTTP"));
    let cbor = |links: Vec<&crate::block::Block>| crate::block::Block::hash(Cidv1Spec::new(crate::cid::DAG_CBOR_CODEC, crate::multihash::MultihashFunc::Sha2_256), crate::dagcbor::to_vec(&crate::model::Ipld::List(links.into_iter().map(|block| crate::model::Ipld::Link(link(block))).collect())).expect("cbor").into());
    let branch = cbor(vec![&deep]);
    let root = cbor(vec![&branch, &leaf]);
    let (lied, missing) = (raw(b"what the gateway lies about"), raw(b"what the gateway hasn't"));
    let mut blocks: HashMap<String, Vec<u8>> = [&root, &branch, &leaf, &deep].into_iter().map(|block| (link(block).to_string(), block.data().to_vec())).collect();
    blocks.insert(link(&lied).to_string(), b"not what it says".to_vec());
    let (port, asked) = serve(move |path| {
        let cid = path.strip_prefix("/ipfs/").and_then(|rest| rest.strip_suffix("?format=raw")).unwrap_or_default();
        blocks.get(cid).map_or((404, Vec::new()), |data| (200, data.clone()))
    });
    let (url, _) = router(format!(r#"{{"Providers":[{{"Schema":"peer","ID":"12D3KooWP9jPCTRwpRk7J7CknwqC3h14ujuvtBoN518YuiJ5MSFR","Addrs":["/dns4/localhost/tcp/{port}/http"],"Protocols":["transport-ipfs-gateway-http"]}}]}}"#));
    // Neither connected to nor known by the other: only the gateway has it
    let (mut a, _) = swarm(Catalog::open_repo(&scratch.path().join("idle")).expect("catalog")).await;
    let (mut b, _) = swarm(Catalog::open_repo(&scratch.path().join("fetching")).expect("catalog")).await;
    b.route_by(vec![url]);
    let fetcher = b.fetcher();

    let done = fetched(&mut a, &mut b, fetcher.fetch(vec![link(&root)], true, true)).await;
    assert_eq!(done, Fetched { fetched: 4, missing: Vec::new() });
    for block in [&root, &branch, &leaf, &deep] {
        assert!(b.catalog().has(block.cid().multihash()).expect("has"));
    }
    assert!(asked.lock().expect("asked").iter().all(|path| path.ends_with("?format=raw")));
    // What isn't what it says, or isn't there, is missing
    let done = fetched(&mut a, &mut b, fetcher.fetch(vec![link(&lied), link(&missing)], false, true)).await;
    assert_eq!(done.fetched, 0);
    assert!(!b.catalog().has(lied.cid().multihash()).expect("has"), "not kept as what it isn't");
}
