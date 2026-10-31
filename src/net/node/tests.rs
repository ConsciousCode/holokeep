use super::*;
use crate::net::mesh::{self, Ticket};
use crate::store::Db;
use libp2p::core::transport::MemoryTransport;
use libp2p::multiaddr::Protocol;

/// A node over the in-memory transport, listening at a fresh address.
async fn node(swarm_key: PreSharedKey) -> Node {
    let key = Keypair::generate_ed25519();
    let members = Members::open(Db::memory().expect("db")).expect("members");
    let transport = transport(MemoryTransport::default(), &key, swarm_key).expect("transport");
    let catalog = Catalog::standard(Db::memory().expect("db")).expect("catalog");
    let mut node = Node::new(transport, &key, catalog, members, false).expect("node");
    node.listen(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    loop {
        if let Event::Listening(_) = node.next().await.expect("event") {
            return node;
        }
    }
}

/// Invite one node to another's mesh, as `hk node invite` and `join` do.
fn invite(inviter: &Node, joiner: &Node, swarm_key: PreSharedKey) {
    inviter.members().add(&joiner.peer_id()).expect("add");
    let mut members = inviter.members().list().expect("list");
    members.insert(inviter.peer_id(), inviter.listeners());
    let ticket = Ticket { swarm_key, inviter: inviter.peer_id(), members };
    let ticket = Ticket::decode(&ticket.encode()).expect("round trip");
    joiner.members().merge(&ticket.members).expect("join");
}

/// Drive every node until `done` says so, or give up.
async fn until(nodes: &mut [&mut Node], done: impl FnMut(&[&mut Node]) -> bool) -> bool {
    within(Duration::from_secs(10), nodes, done).await
}

/// Drive every node until `done` says so, or the time's up.
async fn within(time: Duration, nodes: &mut [&mut Node], mut done: impl FnMut(&[&mut Node]) -> bool) -> bool {
    // What changes state needn't be an event `next` returns, so look again
    // every so often regardless
    let deadline = tokio::time::Instant::now().checked_add(time).expect("deadline");
    while !done(nodes) {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        let events = futures::future::select_all(nodes.iter_mut().map(|node| Box::pin(node.next())));
        let _ = tokio::time::timeout(Duration::from_millis(50), events).await;
    }
    true
}

fn connected(a: &Node, b: &Node) -> bool {
    a.connected().contains(&b.peer_id()) && b.connected().contains(&a.peer_id())
}

#[tokio::test]
async fn members_connect() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut b) = (node(swarm_key).await, node(swarm_key).await);
    invite(&a, &b, swarm_key);
    a.reload().expect("reload");
    b.reload().expect("reload");
    b.dial_members().expect("dial");
    // And the inviter learns where the joiner listens
    let listening = |a: &Node, b: &Node| a.members().list().expect("list").get(&b.peer_id()).is_some_and(|addrs| !addrs.is_empty());
    assert!(until(&mut [&mut a, &mut b], |n| connected(n[0], n[1]) && listening(n[0], n[1])).await);
}

#[tokio::test]
async fn outsiders_are_shut_out() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut a = node(swarm_key).await;
    let addr = a.listeners().first().cloned().expect("listening");

    // Without the key, nothing gets through
    let mut stranger = node(mesh::fresh_swarm_key().expect("key")).await;
    stranger.members().add(&a.peer_id()).expect("add");
    stranger.reload().expect("reload");
    stranger.dial(a.peer_id(), vec![addr.clone()]);
    assert!(!within(Duration::from_secs(2), &mut [&mut a, &mut stranger], |n| connected(n[0], n[1])).await);

    // With the key but not a member, a's allow list refuses it
    let mut intruder = node(swarm_key).await;
    intruder.members().add(&a.peer_id()).expect("add");
    intruder.reload().expect("reload");
    intruder.dial(a.peer_id(), vec![addr]);
    assert!(!within(Duration::from_secs(2), &mut [&mut a, &mut intruder], |n| connected(n[0], n[1])).await);
}

#[tokio::test]
async fn members_tell_each_other_of_members() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut b, mut c) = (node(swarm_key).await, node(swarm_key).await, node(swarm_key).await);
    // a invites b, then c; b has never heard of c
    invite(&a, &b, swarm_key);
    invite(&a, &c, swarm_key);
    assert!(!b.members().contains(&c.peer_id()).expect("contains"));
    a.reload().expect("reload");
    for joiner in [&mut b, &mut c] {
        joiner.reload().expect("reload");
        joiner.dial_members().expect("dial");
    }
    // Once both have spoken to a, b and c let each other in and connect
    assert!(until(&mut [&mut a, &mut b, &mut c], |n| connected(n[0], n[1]) && connected(n[0], n[2]) && connected(n[1], n[2])).await);
}

//--------------//
//-[ Fetching ]-//
//--------------//

use crate::block::Block;
use crate::cid::{AnyCid, CidVersion, Cidv1Spec, DAG_CBOR_CODEC};
use crate::model::Ipld;
use crate::multihash::MultihashFunc;
use crate::cid::CidRef;
use crate::store::BlockIndex;

fn raw(data: &[u8]) -> Block {
    Block::hash(Cidv1Spec::default(), data.into())
}

fn link(block: &Block) -> Link {
    AnyCid::V1(block.cid().clone())
}

fn cbor(value: &Ipld) -> Block {
    let data = crate::dagcbor::to_vec(value).expect("encode");
    Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), data.into())
}

/// Two members, connected, the first holding a small DAG: a root linking
/// to a branch and a leaf, the branch to another leaf. Returns the blocks,
/// root first.
async fn holding() -> (Node, Node, Vec<Block>) {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut b) = (node(swarm_key).await, node(swarm_key).await);
    invite(&a, &b, swarm_key);
    a.reload().expect("reload");
    b.reload().expect("reload");
    b.dial_members().expect("dial");
    assert!(until(&mut [&mut a, &mut b], |n| connected(n[0], n[1])).await);
    let (leaf, deep) = (raw(b"leaf"), raw(b"deep"));
    let branch = cbor(&Ipld::List(vec![Ipld::Link(link(&deep))]));
    let root = cbor(&Ipld::List(vec![Ipld::Link(link(&branch)), Ipld::Link(link(&leaf))]));
    let blocks = vec![root, branch, leaf, deep];
    for block in &blocks {
        a.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    (a, b, blocks)
}

/// Fetch a DAG with one node, while driving both, and say what came of it.
async fn fetch(a: &mut Node, b: &mut Node, root: Link) -> (usize, Vec<Link>) {
    let id = b.fetch(root).expect("fetch");
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    loop {
        let event = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                event = a.next() => event,
                event = b.next() => event,
            }
        });
        if let Event::Fetched { id: done, fetched, missing } = event.await.expect("in time").expect("event")
            && done == id
        {
            return (fetched, missing);
        }
    }
}

#[tokio::test]
async fn members_fetch_dags_from_each_other() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let root = link(blocks.first().expect("root"));
    assert_eq!(fetch(&mut a, &mut b, root.clone()).await, (4, vec![]));
    for block in &blocks {
        let got = b.catalog().get_block(&link(block)).expect("get");
        assert_eq!(got.as_ref(), Some(block));
    }
    // Now it's all here, nothing's asked
    assert_eq!(fetch(&mut a, &mut b, root).await, (0, vec![]));
}

#[tokio::test]
async fn only_whats_missing_is_fetched() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    // The branch is here already, its leaf isn't
    let branch = blocks.get(1).expect("branch");
    b.catalog().put_block(branch, CidVersion::V1).expect("put");
    assert_eq!(fetch(&mut a, &mut b, link(blocks.first().expect("root"))).await, (3, vec![]));
    assert!(b.catalog().has(blocks.get(3).expect("deep").cid().multihash()).expect("has"));
}

#[tokio::test]
async fn what_no_member_has_is_missing() {
    let (mut a, mut b, _) = Box::pin(holding()).await;
    let nowhere = raw(b"nowhere");
    assert_eq!(fetch(&mut a, &mut b, link(&nowhere)).await, (0, vec![link(&nowhere)]));
}

#[tokio::test]
async fn a_member_without_a_block_passes_it_on() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut b, mut c) = (node(swarm_key).await, node(swarm_key).await, node(swarm_key).await);
    invite(&a, &b, swarm_key);
    invite(&a, &c, swarm_key);
    a.reload().expect("reload");
    for joiner in [&mut b, &mut c] {
        joiner.reload().expect("reload");
        joiner.dial_members().expect("dial");
    }
    assert!(until(&mut [&mut a, &mut b, &mut c], |n| connected(n[0], n[1]) && connected(n[0], n[2]) && connected(n[1], n[2])).await);
    // Only b has them; for some, c asks a first, for some b
    let leaves: Vec<Block> = (0..16u8).map(|i| raw(&[i])).collect();
    let root = cbor(&Ipld::List(leaves.iter().map(|leaf| Ipld::Link(link(leaf))).collect()));
    for block in leaves.iter().chain([&root]) {
        b.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    let id = c.fetch(link(&root)).expect("fetch");
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    loop {
        let event = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                event = a.next() => event,
                event = b.next() => event,
                event = c.next() => event,
            }
        });
        if let Event::Fetched { id: done, fetched, missing } = event.await.expect("in time").expect("event")
            && done == id
        {
            assert_eq!((fetched, missing), (17, vec![]));
            break;
        }
    }
}
