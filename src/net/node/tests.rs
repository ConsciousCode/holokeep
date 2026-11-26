use super::*;
use crate::net::check::Asking;
use crate::net::mesh::{self, Ticket, unless_busy};
use crate::store::Db;
use libp2p::core::transport::MemoryTransport;
use libp2p::multiaddr::Protocol;

/// A node over the in-memory transport, listening at a fresh address.
async fn node(swarm_key: PreSharedKey) -> Node {
    let key = Keypair::generate_ed25519();
    let members = Members::open(Db::memory().expect("db"), crate::net::mesh::MAIN).expect("members");
    let ports = Ports::default();
    let transport = transport(MemoryTransport::default(), &key, swarm_key, ports.clone()).expect("transport");
    let catalog = Catalog::standard(Db::memory().expect("db")).expect("catalog");
    let mut node = Node::new(transport, &key, catalog, members, false, ports, Tunables::default()).expect("node");
    node.listen(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    loop {
        if let Event::Listening(_) = node.next().await.expect("event") {
            return node;
        }
    }
}

/// A node over the in-memory transport which may be reached through
/// relays, and relays itself if `relays`: listening directly only if
/// `listens`.
async fn relayed_node(swarm_key: PreSharedKey, relays: bool, listens: bool) -> Node {
    let key = Keypair::generate_ed25519();
    let members = Members::open(Db::memory().expect("db"), crate::net::mesh::MAIN).expect("members");
    let ports = Ports::default();
    let (relayed, client) = relay::client::new(key.public().to_peer_id());
    let transport = transport(relayed.or_transport(MemoryTransport::default()), &key, swarm_key, ports.clone()).expect("transport");
    let catalog = Catalog::standard(Db::memory().expect("db")).expect("catalog");
    let tunables = Tunables { relay: relays, ..Tunables::default() };
    let mut node = Node::relayed(transport, client, &key, catalog, members, false, ports, tunables).expect("node");
    if listens {
        node.listen(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
        while !matches!(node.next().await.expect("event"), Event::Listening(_)) {}
    }
    node
}

/// Invite one node to another's mesh, as `hk node invite` and `join` do.
fn invite(inviter: &Node, joiner: &Node, swarm_key: PreSharedKey) {
    inviter.members().add(&joiner.peer_id()).expect("add");
    let mut members = inviter.members().list().expect("list");
    members.insert(inviter.peer_id(), inviter.listeners());
    let ticket = Ticket { swarm_key: Some(swarm_key), client: false, inviter: inviter.peer_id(), members, user: None, protected: false, sealed: Vec::new(), held: Vec::new(), grants: None };
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

/// Connected, each knowing what the other hosts.
fn connected(a: &Node, b: &Node) -> bool {
    a.ready().contains(&b.peer_id()) && b.ready().contains(&a.peer_id())
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

/// Two members which listen nowhere the other can reach connect through
/// a member relaying, and fetch from each other over the circuit, which
/// is the private network and noise end to end.
#[tokio::test]
async fn members_which_cant_reach_each_other_connect_through_a_relay() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut relay = relayed_node(swarm_key, true, true).await;
    let (mut a, mut b) = (relayed_node(swarm_key, false, false).await, relayed_node(swarm_key, false, false).await);
    invite(&relay, &a, swarm_key);
    invite(&relay, &b, swarm_key);
    a.members().add(&b.peer_id()).expect("add");
    b.members().add(&a.peer_id()).expect("add");
    for node in [&mut relay, &mut a, &mut b] {
        node.reload().expect("reload");
    }
    a.dial_members().expect("dial");
    b.dial_members().expect("dial");
    // Each holds a reservation on the relay, and listens through it
    let reserved = |node: &Node| !node.relayed_listeners().is_empty();
    assert!(until(&mut [&mut relay, &mut a, &mut b], |n| reserved(n[1]) && reserved(n[2])).await, "reserved");
    a.dial_members().expect("dial");
    assert!(until(&mut [&mut relay, &mut a, &mut b], |n| connected(n[1], n[2])).await, "connected through the relay");
    // Where each is reached through the relay is worked out, not kept
    for node in [&relay, &a, &b] {
        let kept = node.members().list().expect("list");
        assert!(kept.values().flatten().all(|addr| !super::is_relayed(addr)), "{kept:?}");
    }
    assert!(a.members().add_addr(&b.peer_id(), b.relayed_listeners().first().expect("relayed")).is_ok());
    assert!(a.members().list().expect("list").values().flatten().all(|addr| !super::is_relayed(addr)), "a relayed address said is let go of");
    let block = raw(b"over the circuit");
    a.catalog().put_block(&block, CidVersion::V1).expect("put");
    b.fetch(link(&block)).expect("fetch");
    assert!(until(&mut [&mut relay, &mut a, &mut b], |n| has(n[2], &block)).await, "fetched over the circuit");
    assert!(!has(&relay, &block), "the relay passed it on, and kept nothing");
    // Once they're connected directly, the circuit's let go of
    assert!(!a.circuits.is_empty() && !b.circuits.is_empty(), "connected through the relay");
    b.listen(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut relay, &mut a, &mut b], |n| !n[2].listeners().is_empty()).await);
    let direct = b.listeners().first().cloned().expect("listening");
    a.dial(b.peer_id(), vec![direct]);
    assert!(until(&mut [&mut relay, &mut a, &mut b], |n| n[1].circuits.is_empty() && n[2].circuits.is_empty() && connected(n[1], n[2])).await, "connected directly, and only so");
}

/// A relay relays for none but members, which alone reach it, and to
/// none who wouldn't let them in directly.
#[tokio::test]
async fn a_relay_relays_only_for_members() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut relay = relayed_node(swarm_key, true, true).await;
    let mut member = relayed_node(swarm_key, false, false).await;
    invite(&relay, &member, swarm_key);
    relay.reload().expect("reload");
    member.reload().expect("reload");
    member.dial_members().expect("dial");
    let reserved = |node: &Node| !node.relayed_listeners().is_empty();
    assert!(until(&mut [&mut relay, &mut member], |n| reserved(n[1])).await, "reserved");
    // With the key, knowing where the member listens, but no member
    let mut intruder = relayed_node(swarm_key, false, false).await;
    intruder.members().add(&member.peer_id()).expect("add");
    intruder.reload().expect("reload");
    let at = member.relayed_listeners().first().cloned().expect("relayed");
    intruder.dial(member.peer_id(), vec![at.clone()]);
    assert!(!within(Duration::from_secs(2), &mut [&mut relay, &mut member, &mut intruder], |n| connected(n[1], n[2])).await);
    // Nor through the relay to a member which doesn't let it in, though
    // the relay does
    relay.members().add(&intruder.peer_id()).expect("add");
    relay.reload().expect("reload");
    intruder.members().add(&relay.peer_id()).expect("add");
    intruder.reload().expect("reload");
    intruder.dial(member.peer_id(), vec![at]);
    assert!(!within(Duration::from_secs(2), &mut [&mut relay, &mut member, &mut intruder], |n| connected(n[1], n[2])).await);
    assert!(intruder.swarm.is_connected(&relay.peer_id()), "the relay let it in");
}

/// A member none can find by itself, told where it's reached on one
/// member, is dialled there, and the members connected are told too.
#[tokio::test]
async fn a_member_told_where_another_is_reached_dials_it_and_says_so() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut c, mut far) = (node(swarm_key).await, node(swarm_key).await, node(swarm_key).await);
    invite(&a, &c, swarm_key);
    for (one, other) in [(&a, &far), (&c, &far), (&far, &a), (&far, &c)] {
        one.members().add(&other.peer_id()).expect("add");
    }
    for node in [&mut a, &mut c, &mut far] {
        node.reload().expect("reload");
    }
    c.dial_members().expect("dial");
    assert!(until(&mut [&mut a, &mut c, &mut far], |n| connected(n[0], n[1])).await);
    let knows = |node: &Node, peer: &PeerId| node.members().list().expect("list").get(peer).is_some_and(|addrs| !addrs.is_empty());
    assert!(!knows(&a, &far.peer_id()) && !knows(&c, &far.peer_id()), "no one knows where it is");
    let at = far.listeners();
    assert!(a.reach_member(&PeerId::random(), &at).is_err(), "a stranger's no member to reach");
    a.reach_member(&far.peer_id(), &at).expect("reach");
    let far_peer = far.peer_id();
    assert!(until(&mut [&mut a, &mut c, &mut far], |n| connected(n[0], n[2]) && knows(n[1], &far_peer)).await, "dialled, and the others told");
}

#[test]
fn a_member_not_reached_is_dialled_less_often_till_it_is() {
    let (peer, start) = (PeerId::random(), std::time::Instant::now());
    let at = |secs| start + Duration::from_secs(secs);
    let mut redial = super::Redial::default();
    assert!(redial.due(&peer, start), "never dialled");
    // Each wait twice the last, from 2 s to a minute
    let mut now = 0;
    for wait in [2, 4, 8, 16, 32, 60, 60] {
        redial.dialled(peer, at(now));
        assert!(!redial.due(&peer, at(now + wait - 1)), "dialled again before {wait} s");
        assert!(redial.due(&peer, at(now + wait)), "not dialled again after {wait} s");
        now += wait;
    }
    // Reached, or lost, it's dialled at once again
    redial.reset(&peer);
    assert!(redial.due(&peer, at(now)));
    redial.dialled(peer, at(now));
    assert!(redial.due(&peer, at(now + 2)));
}

#[tokio::test]
async fn members_measure_each_others_clocks() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut b) = (node(swarm_key).await, node(swarm_key).await);
    invite(&a, &b, swarm_key);
    a.reload().expect("reload");
    b.reload().expect("reload");
    b.dial_members().expect("dial");
    assert!(until(&mut [&mut a, &mut b], |n| connected(n[0], n[1])).await);
    a.measure_clocks();
    b.measure_clocks();
    let (pa, pb) = (a.peer_id(), b.peer_id());
    assert!(until(&mut [&mut a, &mut b], |n| n[0].clocks().of(&pb).is_some() && n[1].clocks().of(&pa).is_some()).await);
    // One clock, so near none apart, and within the round trip
    let offset = a.clocks().of(&pb).expect("measured");
    assert!(offset.ahead.unsigned_abs() <= offset.trip.max(1000), "{offset:?}");
    assert_eq!(a.clocks().mesh().map(|(_, members)| members), Some(1));
}

//--------------//
//-[ Fetching ]-//
//--------------//

use crate::block::Block;
use crate::cid::{AnyCid, CidVersion, Cidv1Spec, DAG_CBOR_CODEC};
use crate::model::Ipld;
use crate::multihash::MultihashFunc;
use crate::cid::CidRef;
use crate::store::{BlockIndex, RefIndex};

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
    fetched(a, b, id).await
}

/// Drive both nodes until the second's fetch is done, and say what came
/// of it.
async fn fetched(a: &mut Node, b: &mut Node, id: FetchId) -> (usize, Vec<Link>) {
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

/// A block reported lost by one member, which another has, is lost no more.
#[tokio::test]
async fn what_one_reports_lost_another_makes_good() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = blocks.get(2).expect("leaf");
    b.catalog().report_lost(&link(leaf)).expect("report").expect("a claim");
    assert!(b.catalog().lost_at(&link(leaf)).expect("lost").is_some());
    // The claim travels as claims do, and the next audit there takes it up
    b.announce().expect("announce");
    let heard = |n: &[&mut Node]| n[0].catalog().claims().is_some_and(|claims| claims.lost(leaf.cid().multihash()).is_ok_and(|at| at.is_some()));
    assert!(within(Duration::from_secs(10), &mut [&mut a, &mut b], heard).await, "never heard of it");
    let id = a.trickle(2).expect("trickle");
    assert!(id.is_some());
    assert!(within(Duration::from_secs(10), &mut [&mut a, &mut b], |n| n[1].catalog().has(leaf.cid().multihash()).unwrap_or(false)).await, "it never came");
    assert_eq!(b.catalog().lost_at(&link(leaf)).expect("lost"), None);
    assert!(b.catalog().lost_blocks().expect("list").is_empty());
}

/// A member forgotten stays forgotten, whoever says it's a member, and one
/// that's there can't be.
#[tokio::test]
async fn a_member_forgotten_stays_so_till_its_invited() {
    let (mut a, b, _) = Box::pin(holding()).await;
    let ghost = PeerId::random();
    a.members().add(&ghost).expect("add");
    b.members().add(&ghost).expect("add");
    assert!(a.forget_member(&b.peer_id()).is_err(), "it's connected");
    assert!(a.forget_member(&PeerId::random()).is_err(), "not a member");
    a.forget_member(&ghost).expect("forget");
    assert!(!a.members().contains(&ghost).expect("contains"));
    let theirs = b.members().list().expect("list");
    assert!(!a.members().merge(&theirs).expect("merge").contains(&ghost));
    assert!(!a.members().contains(&ghost).expect("contains"), "not taken back");
    assert!(a.members().add(&ghost).expect("add"), "invited, it's let back in");
    assert!(a.members().contains(&ghost).expect("contains"));
}

/// A node's scan asks its members first, and only reports with all of them
/// there to ask.
#[tokio::test]
async fn a_scan_reports_only_what_no_member_has() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let root = blocks.first().expect("root");
    let (held, gone) = (blocks.get(1).expect("branch"), blocks.get(2).expect("leaf"));
    // Both blocks were here, linked to by the root, and went
    b.catalog().put_block(root, CidVersion::V1).expect("put");
    for block in [held, gone] {
        b.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    let forget = |node: &Node, block: &Block| assert_eq!(node.catalog().lose(block.cid().multihash()).expect("lose"), 1);
    forget(&b, held);
    forget(&b, gone);
    // The other has one of them
    forget(&a, gone);

    b.scan_lost().expect("scan");
    let lost_at = |node: &Node, block: &Block| node.catalog().lost_at(&link(block)).expect("lost");
    assert!(within(Duration::from_secs(10), &mut [&mut a, &mut b], |n| n[1].catalog().lost_at(&link(gone)).is_ok_and(|at| at.is_some())).await, "never reported");
    assert!(lost_at(&b, gone).is_some());
    assert_eq!(lost_at(&b, held), None, "fetched instead");
    assert!(has(&b, held));

    // With a member away, it might be with them, so nothing's even asked
    let deep = blocks.get(3).expect("deep");
    b.catalog().put_block(deep, CidVersion::V1).expect("put");
    forget(&b, deep);
    forget(&a, deep);
    b.members().add(&PeerId::random()).expect("add");
    b.scan_lost().expect("scan");
    let _ = within(Duration::from_secs(1), &mut [&mut a, &mut b], |_| false).await;
    assert_eq!(lost_at(&b, deep), None, "not with a member away");
}

#[tokio::test]
async fn fetching_blocks_takes_only_them() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    // The root, and a leaf it doesn't link to directly
    let (root, deep) = (blocks.first().expect("root"), blocks.get(3).expect("deep"));
    let id = b.fetch_blocks(vec![link(root), link(deep)]).expect("fetch");
    assert_eq!(fetched(&mut a, &mut b, id).await, (2, vec![]));
    assert!(has(&b, root) && has(&b, deep));
    assert!(!has(&b, blocks.get(1).expect("branch")) && !has(&b, blocks.get(2).expect("leaf")));
    let nowhere = raw(b"nowhere");
    let id = b.fetch_blocks(vec![link(root), link(&nowhere)]).expect("fetch");
    assert_eq!(fetched(&mut a, &mut b, id).await, (0, vec![link(&nowhere)]));
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

//----------------//
//-[ Durability ]-//
//----------------//

use crate::net::durability::Report;
use crate::multihash::Multihash;

/// Drive every node until each audit named, by node and id, reports.
async fn audited(nodes: &mut [&mut Node], audits: &[(usize, AuditId)]) -> Vec<Report> {
    let mut reports: Vec<Option<Report>> = vec![None; audits.len()];
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    while reports.iter().any(Option::is_none) {
        let events = futures::future::select_all(nodes.iter_mut().map(|node| Box::pin(node.next())));
        let (event, from, _) = tokio::time::timeout_at(deadline, events).await.expect("in time");
        if let Event::Audited { id, report } = event.expect("event")
            && let Some(i) = audits.iter().position(|&audit| audit == (from, id))
            && let Some(slot) = reports.get_mut(i)
        {
            *slot = Some(report);
        }
    }
    reports.into_iter().flatten().collect()
}

fn report(advertised: usize, copied: usize, short: usize) -> Report {
    Report { advertised, copied, short }
}

/// Three members, all connected.
async fn three() -> (Node, Node, Node) {
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
    (a, b, c)
}

/// Sixteen leaves and a root linking them.
fn wide() -> Vec<Block> {
    let leaves: Vec<Block> = (0..16u8).map(|i| raw(&[i, 0xd0])).collect();
    let root = cbor(&Ipld::List(leaves.iter().map(|leaf| Ipld::Link(link(leaf))).collect()));
    leaves.into_iter().chain([root]).collect()
}

fn has(node: &Node, block: &Block) -> bool {
    node.catalog().has(block.cid().multihash()).expect("has")
}

#[tokio::test]
async fn short_blocks_are_copied_to_a_member() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let id = a.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(0, id)]).await, [report(4, 4, 0)]);
    for block in &blocks {
        assert!(has(&b, block));
        // And a knows b has it
        let sighted = a.sightings().of(block.cid().multihash()).expect("sightings");
        assert_eq!(sighted.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(), [b.peer_id()]);
    }
    // Now nothing's short
    let id = a.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(0, id)]).await, [report(0, 0, 0)]);
}

#[tokio::test]
async fn whole_chunks_are_copied_and_fetched() {
    // A megabyte apiece, as `hk add` chunks files: more than one message
    // of libp2p's would carry
    let (mut a, mut b, _) = Box::pin(holding()).await;
    let chunks: Vec<Block> = (0..3u8).map(|i| raw(&vec![i; 1 << 20])).collect();
    for chunk in &chunks {
        a.catalog().put_block(chunk, CidVersion::V1).expect("put");
    }
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert!(chunks.iter().all(|chunk| has(&b, chunk)));
    let big = raw(&vec![9; 3 << 20]);
    b.catalog().put_block(&big, CidVersion::V1).expect("put");
    assert_eq!(fetch(&mut b, &mut a, link(&big)).await, (1, vec![]));
}

#[tokio::test]
async fn a_copy_a_member_has_is_sighted_not_sent() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let branch = blocks.get(1).expect("branch");
    b.catalog().put_block(branch, CidVersion::V1).expect("put");
    let id = a.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(0, id)]).await, [report(4, 3, 0)]);
    assert_eq!(a.sightings().of(branch.cid().multihash()).expect("sightings").len(), 1);
}

#[tokio::test]
async fn a_lone_node_reports_whats_short() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut a = node(swarm_key).await;
    for block in wide() {
        a.catalog().put_block(&block, CidVersion::V1).expect("put");
    }
    let id = a.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut a], &[(0, id)]).await, [report(17, 0, 17)]);
    // One copy is all it takes failing to lose one
    let id = a.audit(1).expect("audit");
    assert_eq!(audited(&mut [&mut a], &[(0, id)]).await, [report(0, 0, 0)]);
}

#[tokio::test]
async fn each_block_goes_to_one_member() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let blocks = wide();
    for block in &blocks {
        a.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    let id = a.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut a, &mut b, &mut c], &[(0, id)]).await, [report(17, 17, 0)]);
    let on_b = blocks.iter().filter(|block| has(&b, block)).count();
    let on_c = blocks.iter().filter(|block| has(&c, block)).count();
    assert_eq!(on_b + on_c, 17, "one copy each, not two");
    assert!(on_b > 0 && on_c > 0, "spread: {on_b} on b, {on_c} on c");
    // Three copies takes all three; a sees to those it's responsible for
    // among the two holders, the other holder to the rest
    let audits = [(0, a.audit(3).expect("audit")), (1, b.audit(3).expect("audit")), (2, c.audit(3).expect("audit"))];
    let reports = audited(&mut [&mut a, &mut b, &mut c], &audits).await;
    assert_eq!(reports.iter().map(|report| report.copied).sum::<usize>(), 17, "{reports:?}");
    assert!(blocks.iter().all(|block| has(&b, block) && has(&c, block)));
}

#[tokio::test]
async fn holders_auditing_at_once_send_each_block_once() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let blocks = wide();
    for block in &blocks {
        a.catalog().put_block(block, CidVersion::V1).expect("put");
        b.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    // Neither knows the other holds them, so both advertise everything;
    // the answers tell each which of them is responsible for which
    let (on_a, on_b) = (a.audit(3).expect("audit"), b.audit(3).expect("audit"));
    let reports = audited(&mut [&mut a, &mut b, &mut c], &[(0, on_a), (1, on_b)]).await;
    assert_eq!(reports.iter().map(|report| report.advertised).collect::<Vec<_>>(), [17, 17]);
    assert_eq!(reports.iter().map(|report| report.copied).sum::<usize>(), 17, "{reports:?}");
    assert!(reports.iter().all(|report| report.copied > 0), "{reports:?}");
    assert!(blocks.iter().all(|block| has(&c, block)));
    // And now each knows, only the one responsible advertises
    let (on_a, on_b) = (a.audit(3).expect("audit"), b.audit(3).expect("audit"));
    let reports = audited(&mut [&mut a, &mut b, &mut c], &[(0, on_a), (1, on_b)]).await;
    assert_eq!(reports, [report(0, 0, 0), report(0, 0, 0)]);
}

//---------------//
//-[ Structure ]-//
//---------------//

fn holds(node: &Node, cid: &Link) -> bool {
    node.catalog().holds(cid).expect("holds")
}

fn tags(node: &Node, target: &Block) -> Vec<Link> {
    node.catalog().claims().expect("claims").tags(target.cid().multihash()).expect("tags")
}

#[tokio::test]
async fn structure_reaches_holders_of_what_it_links_to() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let target = raw(b"held by a and b");
    for node in [&a, &b] {
        node.catalog().put_block(&target, CidVersion::V1).expect("put");
    }
    let linking = cbor(&Ipld::List(vec![Ipld::Link(link(&target))]));
    a.catalog().put_block(&linking, CidVersion::V1).expect("put");
    a.announce().expect("announce");
    let cid = link(&linking);
    assert!(until(&mut [&mut a, &mut b, &mut c], |n| holds(n[1], &cid)).await);
    let backrefs = b.catalog().backrefs(target.cid().multihash()).expect("backrefs");
    assert_eq!(backrefs, [linking.cid().multihash()]);
    // c holds nothing it links to, so it isn't sent it
    assert!(!within(Duration::from_millis(500), &mut [&mut a, &mut b, &mut c], |n| holds(n[2], &cid)).await);
}

#[tokio::test]
async fn tags_reach_holders_of_what_they_tag() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = blocks.get(2).expect("leaf");
    b.catalog().put_block(leaf, CidVersion::V1).expect("put");
    let tag = raw(b"favourite");
    a.catalog().put_block(&tag, CidVersion::V1).expect("put");
    a.catalog().tag(&link(leaf), &link(&tag)).expect("tag");
    a.announce().expect("announce");
    assert!(until(&mut [&mut a, &mut b], |n| tags(n[1], leaf) == [link(&tag)]).await);
}

#[tokio::test]
async fn a_member_hears_of_what_it_missed_when_it_connects() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut b) = (node(swarm_key).await, node(swarm_key).await);
    let target = raw(b"held by both");
    let linking = cbor(&Ipld::List(vec![Ipld::Link(link(&target))]));
    for block in [&target, &linking] {
        a.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    b.catalog().put_block(&target, CidVersion::V1).expect("put");
    invite(&a, &b, swarm_key);
    a.reload().expect("reload");
    b.reload().expect("reload");
    b.dial_members().expect("dial");
    let cid = link(&linking);
    assert!(until(&mut [&mut a, &mut b], |n| holds(n[1], &cid)).await);
}

#[tokio::test]
async fn copies_take_what_links_to_them_along() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let blocks = wide();
    let (root, leaves) = blocks.split_last().expect("root");
    for block in &blocks {
        a.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    // Only what's copied, not what's noticed from a's cursor
    for (peer, node) in [(b.peer_id(), &a), (c.peer_id(), &a)] {
        let latest = node.catalog().structure_since(0, usize::MAX).expect("latest").1;
        node.cursors.set(&peer, None, latest).expect("cursor");
    }
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b, &mut c], &[(0, id)]).await;
    let root = link(root);
    let holding_a_leaf = |node: &Node| leaves.iter().any(|leaf| has(node, leaf));
    assert!(holding_a_leaf(&b) && holding_a_leaf(&c));
    assert!(until(&mut [&mut a, &mut b, &mut c], |n| holds(n[1], &root) && holds(n[2], &root)).await);
}

#[tokio::test]
async fn fetching_takes_tags_along() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = blocks.get(2).expect("leaf");
    let tag = raw(b"fetched with it");
    a.catalog().put_block(&tag, CidVersion::V1).expect("put");
    a.catalog().tag(&link(leaf), &link(&tag)).expect("tag");
    assert_eq!(fetch(&mut a, &mut b, link(leaf)).await, (1, vec![]));
    assert!(until(&mut [&mut a, &mut b], |n| tags(n[1], leaf) == [link(&tag)]).await);
}

#[tokio::test]
async fn fetching_takes_tombs_along() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = blocks.get(2).expect("leaf");
    let tag = raw(b"retracted");
    a.catalog().put_block(&tag, CidVersion::V1).expect("put");
    a.catalog().tag(&link(leaf), &link(&tag)).expect("tag");
    let tombs = a.catalog().untag(&link(leaf), &link(&tag)).expect("untag");
    assert_eq!(fetch(&mut a, &mut b, link(leaf)).await, (1, vec![]));
    let tomb = tombs.first().expect("tomb").clone();
    assert!(until(&mut [&mut a, &mut b], |n| holds(n[1], &tomb)).await);
    assert!(tags(&b, leaf).is_empty());
}

#[tokio::test]
async fn fetching_takes_keeps_along() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    one_user(&mut [&mut a, &mut b]);
    let leaf = blocks.get(2).expect("leaf");
    let keep = a.catalog().keep(&link(leaf)).expect("keep");
    assert!(a.catalog().kept_under(leaf.cid().multihash()).expect("kept"));
    assert_eq!(fetch(&mut a, &mut b, link(leaf)).await, (1, vec![]));
    assert!(until(&mut [&mut a, &mut b], |n| holds(n[1], &keep)).await, "the keep");
    assert!(
        until(&mut [&mut a, &mut b], |n| n[1].catalog().kept_under(leaf.cid().multihash()).expect("kept")).await,
        "and what makes it count",
    );
}

#[tokio::test]
async fn a_vaults_keeps_reach_a_friend_holding_it() {
    use crate::store::RefIndex as _;
    let scratch = crate::testutil::Scratch::new("node-vault-keeps");
    let (mut a, mut b, _) = Box::pin(holding()).await;
    a.catalog_mut().set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    assert!(crate::vault::seal(a.catalog_mut(), scratch.path(), b"pass", crate::keys::Cost::NONE).expect("seal"));
    let vault = crate::vault::Vault::open(scratch.path(), a.catalog().uid()).expect("vault");
    a.catalog_mut().act_for(vault.uid(), vault.key().clone()).expect("act");
    let kept = a.catalog().claims().expect("claims").keeps().expect("keeps");
    let sealed = kept.first().expect("sealed").clone();
    let keep = a.catalog().backrefs(sealed.multihash()).expect("backrefs").first().and_then(|key| a.catalog().cid_of(key.as_ref()).expect("cid")).expect("keep");
    // A friend's account, the vault its user
    let friend = 0xC000_0000;
    b.catalog_mut().act_for(friend, crate::keys::Key::generate().expect("key")).expect("act");
    b.catalog().claims().expect("claims").set_user(friend, &vault.key().id()).expect("user");
    b.catalog_mut().act_for(friend, crate::keys::Key::generate().expect("key")).expect("act");
    assert_eq!(fetch(&mut a, &mut b, sealed.clone()).await, (1, vec![]));
    assert!(until(&mut [&mut a, &mut b], |n| holds(n[1], &keep)).await, "the keep");
    assert!(until(&mut [&mut a, &mut b], |n| n[1].catalog().kept_for_acting(sealed.multihash()).expect("kept")).await, "counting");
}

#[tokio::test]
async fn a_friend_holding_the_vault_holds_what_its_published_and_it_reads_from_that() {
    let scratch = crate::testutil::Scratch::new("node-published");
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    a.catalog_mut().set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    let vault = crate::vault::Vault::open(scratch.path(), a.catalog().uid()).expect("vault");
    // A friend's account, the vault its user
    let friend = 0xC000_0000;
    b.catalog_mut().act_for(friend, crate::keys::Key::generate().expect("key")).expect("act");
    b.catalog().claims().expect("claims").set_user(friend, &vault.key().id()).expect("user");
    b.catalog_mut().act_for(friend, crate::keys::Key::generate().expect("key")).expect("act");

    let anchor = crate::claim::anchor().expect("anchor");
    let published = crate::cap::Published::of(&crate::cap::secret(&vault), &anchor).expect("published");
    let publication = crate::cap::publish(a.catalog_mut(), &vault, &published, &link(&blocks[0])).expect("publish");
    let everything = crate::cap::published_blocks(a.catalog(), &publication.manifest).expect("blocks");
    // As the node of a protected mesh, holding the vault, acts for it
    a.catalog_mut().act_for(vault.uid(), vault.key().clone()).expect("act");
    a.reload().expect("reload");
    // Holding the vault, it holds what's published, every block of it,
    // once it's heard what this hosts now
    a.announce().expect("announce");
    let friend_peer = b.peer_id();
    assert!(until(&mut [&mut a, &mut b], |n| n[0].heard.contains(&friend_peer)).await, "heard");
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert!(until(&mut [&mut a, &mut b], |n| everything.iter().all(|block| holds(n[1], &AnyCid::V1(block.cid().clone())))).await, "every published block");
    assert!(until(&mut [&mut a, &mut b], |n| n[1].catalog().kept_for_acting(publication.manifest.multihash()).expect("kept")).await, "the manifest kept");

    // And whoever has the capability reads it from what the friend holds
    let crate::cap::Capability::Live(live) = published.capability() else {
        panic!("not live");
    };
    let claims = crate::cap::claims_about(b.catalog(), &live.view).expect("claims");
    let (plain, read) = crate::cap::read_live(b.catalog(), claims.iter().map(|(_, data)| data.as_slice()), &live).expect("read");
    assert_eq!(plain, link(&blocks[0]));
    assert_eq!(read.len(), blocks.len());
}

#[tokio::test]
async fn a_write_a_friend_keeps_reaches_the_owner_which_takes_it_in() {
    use crate::cap::{self, Capability};
    let scratch = crate::testutil::Scratch::new("node-friend-write");
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let owner_key = crate::keys::Key::generate().expect("key");
    a.catalog_mut().set_signer(owner_key.clone()).expect("signer");
    let owner_uid = a.catalog().uid();
    let vault = crate::vault::Vault::open(scratch.path(), owner_uid).expect("vault");
    let friend = 0xC000_0000;
    b.catalog_mut().act_for(friend, crate::keys::Key::generate().expect("key")).expect("act");
    b.catalog().claims().expect("claims").set_user(friend, &vault.key().id()).expect("user");
    b.catalog_mut().act_for(friend, crate::keys::Key::generate().expect("key")).expect("act");

    // The owner publishes a directory and lets a writer write it
    let anchor = a.catalog_mut().new_anchor().expect("anchor");
    let dir = crate::testutil::Scratch::new("node-friend-write-files");
    std::fs::write(dir.path().join("a.txt"), "as published").expect("write");
    let importer = crate::import::Importer::default();
    let first = AnyCid::V1(importer.add_path(dir.path(), a.catalog_mut(), &mut |_, _| {}).expect("import").expect("root").cid);
    a.catalog_mut().set_anchor(&anchor, &first).expect("set");
    let published = cap::Published::of(&cap::secret(&vault), &anchor).expect("published");
    cap::publish(a.catalog_mut(), &vault, &published, &first).expect("publish");
    let seed = cap::add_writer(a.catalog_mut(), &vault, &published).expect("writer");
    let Capability::Write(write) = published.write_capability(seed, None) else {
        panic!("not a write capability");
    };
    let _ = blocks;
    // The friend holds what the vault keeps
    a.catalog_mut().act_for(vault.uid(), vault.key().clone()).expect("act");
    a.reload().expect("reload");
    a.announce().expect("announce");
    let friend_peer = b.peer_id();
    assert!(until(&mut [&mut a, &mut b], |n| n[0].heard.contains(&friend_peer)).await, "heard");
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(0, id)]).await;
    let view = published.view.clone();
    assert!(until(&mut [&mut a, &mut b], |n| !cap::claims_about(n[1].catalog(), &view).expect("claims").is_empty()).await, "the friend holds the sealed view");

    // The writer writes at the friend's, which keeps it as the vault's
    let base = cap::read(b.catalog(), &write.live, &|_| Vec::new()).expect("read").base.expect("base");
    let mut theirs = Catalog::open_repo(&scratch.path().join("writer")).expect("catalog");
    std::fs::write(dir.path().join("a.txt"), "written while the owner's away").expect("write");
    let edited = AnyCid::V1(importer.add_path(dir.path(), &mut theirs, &mut |_, _| {}).expect("import").expect("root").cid);
    let written = cap::write(&mut theirs, &write, &base, &edited).expect("write");
    for block in written.all() {
        b.catalog().put_block(&block, crate::cid::CidVersion::V1).expect("put");
    }
    assert!(cap::keep_written(b.catalog(), &view, &written.all().iter().map(|block| AnyCid::V1(block.cid().clone())).collect::<Vec<_>>()).expect("keep"), "kept as the vault's");

    // It reaches the owner's machine, which takes it in
    b.reload().expect("reload");
    let id = b.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(1, id)]).await;
    assert!(until(&mut [&mut a, &mut b], |n| written.all().iter().all(|block| holds(n[0], &AnyCid::V1(block.cid().clone())))).await, "every block written");
    a.catalog_mut().act_for(owner_uid, owner_key).expect("act");
    assert_eq!(cap::take_in(a.catalog_mut(), &vault).expect("take in").len(), 1);
    assert_eq!(a.catalog().anchor_value(&anchor).expect("value"), Some(edited));
}

#[tokio::test]
async fn a_keep_noticed_with_its_target_goes_with_it() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    one_user(&mut [&mut a, &mut b]);
    let leaf = blocks.get(2).expect("leaf");
    b.catalog().put_block(leaf, CidVersion::V1).expect("put");
    // New structure over what b holds, and a keep of it, in one notice
    let over = cbor(&Ipld::List(vec![Ipld::Link(link(leaf))]));
    a.catalog().put_block(&over, CidVersion::V1).expect("put");
    let keep = a.catalog().keep(&link(&over)).expect("keep");
    a.announce().expect("announce");
    assert!(until(&mut [&mut a, &mut b], |n| holds(n[1], &link(&over))).await, "the structure");
    assert!(until(&mut [&mut a, &mut b], |n| holds(n[1], &keep)).await, "and its keep");
    assert!(until(&mut [&mut a, &mut b], |n| n[1].catalog().kept_under(over.cid().multihash()).expect("kept")).await, "counting");
}

#[tokio::test]
async fn signatures_over_what_a_member_lacks_stay_put() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    one_user(&mut [&mut a, &mut b]);
    let keep = a.catalog().keep(&link(&blocks[0])).expect("keep");
    let device = a.catalog().signer().expect("signer").id();
    a.announce().expect("announce");
    // b holds none of it, so neither the keep nor what signs it is b's. What
    // b does hold, such as the certificates, may yet be signed by others
    let heard = |n: &[&mut Node]| {
        let claims = n[1].catalog().claims().expect("claims");
        n[1].catalog().backrefs(blocks[0].cid().multihash()).is_ok_and(|about| !about.is_empty())
            || claims.signed_by(&keep, &device).unwrap_or(false)
    };
    assert!(!within(Duration::from_millis(500), &mut [&mut a, &mut b], heard).await);
}

/// Make nodes devices of one user, its root certifying each.
fn one_user(nodes: &mut [&mut Node]) -> crate::keys::Key {
    let root = crate::keys::Key::generate().expect("key");
    let devices: Vec<crate::keys::Key> = nodes.iter().map(|_| crate::keys::Key::generate().expect("key")).collect();
    for node in nodes.iter_mut() {
        node.catalog().set_user(&root.id()).expect("user");
        for device in &devices {
            node.catalog().certify(&root, &device.id()).expect("certify");
        }
    }
    for (node, device) in nodes.iter_mut().zip(devices) {
        node.catalog_mut().set_signer(device).expect("signer");
    }
    root
}

#[tokio::test]
async fn a_devices_claims_count_where_they_go_and_a_strangers_dont() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    one_user(&mut [&mut a, &mut b]);
    let (signed, unsigned) = (blocks.get(2).expect("leaf"), blocks.get(3).expect("leaf"));
    let (tag, other) = (raw(b"from a device"), raw(b"from a stranger"));
    for block in [&tag, &other] {
        a.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    a.catalog().tag(&link(signed), &link(&tag)).expect("tag");
    // A key the user never certified, as a stranger's; then the device's
    // again, or the machine couldn't say it hosts the user
    let device = a.catalog().signer().cloned().expect("device");
    a.catalog_mut().set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    a.catalog().tag(&link(unsigned), &link(&other)).expect("tag");
    a.catalog_mut().set_signer(device).expect("signer");
    assert!(tags(&a, unsigned).is_empty(), "not even where it was made");

    assert_eq!(fetch(&mut a, &mut b, link(signed)).await.0, 1);
    assert_eq!(fetch(&mut a, &mut b, link(unsigned)).await.0, 1);
    assert!(until(&mut [&mut a, &mut b], |n| tags(n[1], signed) == [link(&tag)]).await);
    // The stranger's tag arrives after its leaf, but doesn't count
    assert!(until(&mut [&mut a, &mut b], |n| !n[1].catalog().claims().expect("claims").backrefs(unsigned.cid().multihash()).expect("backrefs").is_empty()).await);
    assert!(tags(&b, unsigned).is_empty());
}

//-------------//
//-[ Trickle ]-//
//-------------//

#[tokio::test]
async fn the_trickle_copies_what_arrives() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let id = a.trickle(2).expect("trickle").expect("connected");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(0, id)]).await, [report(4, 4, 0)]);
    assert!(blocks.iter().all(|block| has(&b, block)));
    // b was told of a's copies with them, so it needn't ask
    let id = b.trickle(2).expect("trickle").expect("connected");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(1, id)]).await, [report(0, 0, 0)]);
    // And what a's seen arrive it doesn't audit again unless sampled,
    // when it finds nothing to do, and relaxes
    let before = a.trickle_interval();
    let id = a.trickle(2).expect("trickle").expect("connected");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(0, id)]).await, [report(0, 0, 0)]);
    assert!(a.trickle_interval() > before, "{:?} after {before:?}", a.trickle_interval());
    // Until something new arrives
    assert!(!a.arrived().expect("arrived"));
    a.catalog().put_block(&raw(b"new"), CidVersion::V1).expect("put");
    assert!(a.arrived().expect("arrived"));
    assert_eq!(a.trickle_interval(), durability::ALERT);
}

#[tokio::test]
async fn the_trickle_waits_for_someone_to_send_copies_to() {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut a = node(swarm_key).await;
    a.catalog().put_block(&raw(b"alone"), CidVersion::V1).expect("put");
    assert_eq!(a.trickle(2).expect("trickle"), None);
    // What arrived is still to be audited
    assert_eq!(a.sightings().fresh_cursor().expect("cursor"), 0);
}

//----------//
//-[ Trim ]-//
//----------//

/// Drive every node until each trim named, by node and id, reports.
async fn trimmed(nodes: &mut [&mut Node], trims: &[(usize, TrimId)]) -> Vec<trim::Report> {
    let mut reports: Vec<Option<trim::Report>> = vec![None; trims.len()];
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    while reports.iter().any(Option::is_none) {
        let events = futures::future::select_all(nodes.iter_mut().map(|node| Box::pin(node.next())));
        let (event, from, _) = tokio::time::timeout_at(deadline, events).await.expect("in time");
        if let Event::Trimmed { id, report } = event.expect("event")
            && let Some(i) = trims.iter().position(|&trim| trim == (from, id))
            && let Some(slot) = reports.get_mut(i)
        {
            *slot = Some(report);
        }
    }
    reports.into_iter().flatten().collect()
}

fn keys(blocks: &[Block]) -> Vec<Multihash> {
    blocks.iter().map(|block| Multihash::decode(&block.cid().multihash().to_bytes()).expect("key")).collect()
}

#[tokio::test]
async fn surplus_copies_are_let_go_of_once() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let blocks = wide();
    let (_, leaves) = blocks.split_last().expect("root");
    for node in [&a, &b, &c] {
        for block in &blocks {
            node.catalog().put_block(block, CidVersion::V1).expect("put");
        }
    }
    // Each learns the others hold everything
    let audits = [(0, a.audit(2).expect("audit")), (1, b.audit(2).expect("audit")), (2, c.audit(2).expect("audit"))];
    audited(&mut [&mut a, &mut b, &mut c], &audits).await;
    // Three copies of each where two will do: all three mean to let go of
    // every leaf at once, and for each the lowest-ranked does
    let trims = [
        (0, a.trim(2, &keys(&blocks), false).expect("trim")),
        (1, b.trim(2, &keys(&blocks), false).expect("trim")),
        (2, c.trim(2, &keys(&blocks), false).expect("trim")),
    ];
    let reports = trimmed(&mut [&mut a, &mut b, &mut c], &trims).await;
    assert!(reports.iter().all(|report| report.considered == 16), "the root is structure: {reports:?}");
    assert_eq!(reports.iter().map(|report| report.dropped).sum::<usize>(), 16, "{reports:?}");
    for leaf in leaves {
        let holders: Vec<&Node> = [&a, &b, &c].into_iter().filter(|node| has(node, leaf)).collect();
        assert_eq!(holders.len(), 2);
    }
    // And the others were told, so each holder counts only the other, and
    // whoever let go forgets
    assert!(until(&mut [&mut a, &mut b, &mut c], |n| {
        leaves.iter().all(|leaf| {
            n.iter().all(|node| node.sightings().of(leaf.cid().multihash()).expect("of").len() == usize::from(has(node, leaf)))
        })
    })
    .await);
    // Two copies left, none spare
    let trims = [(0, a.trim(2, &keys(&blocks), false).expect("trim")), (1, b.trim(2, &keys(&blocks), false).expect("trim"))];
    let reports = trimmed(&mut [&mut a, &mut b, &mut c], &trims).await;
    assert!(reports.iter().all(|report| report.dropped == 0), "{reports:?}");
}

#[tokio::test]
async fn sightings_arent_trusted_with_the_last_copies() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = blocks.get(2).expect("leaf");
    b.catalog().put_block(leaf, CidVersion::V1).expect("put");
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(0, id)]).await;
    // a believes b holds it, but b has let it go without saying
    b.catalog().drop_copies(leaf.cid().multihash()).expect("drop");
    // One copy will do, and a believes there'd be one left
    let id = a.trim(1, &keys(std::slice::from_ref(leaf)), false).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert_eq!(reports, [trim::Report { considered: 1, ..trim::Report::default() }]);
    assert!(has(&a, leaf));
}

#[tokio::test]
async fn whats_needed_here_is_handed_to_a_member_with_room() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let blocks = wide();
    let (_, leaves) = blocks.split_last().expect("root");
    for node in [&a, &b] {
        for block in &blocks {
            node.catalog().put_block(block, CidVersion::V1).expect("put");
        }
    }
    let audits = [(0, a.audit(2).expect("audit")), (1, b.audit(2).expect("audit"))];
    audited(&mut [&mut a, &mut b, &mut c], &audits).await;
    // Two copies of each where two are asked for: nothing's spare, so
    // without handing off nothing goes
    let id = a.trim(2, &keys(&blocks), false).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b, &mut c], &[(0, id)]).await;
    assert_eq!(reports[0].dropped, 0, "{reports:?}");
    // Handing off, c takes a copy of each leaf first, and a lets go of its
    let id = a.trim(2, &keys(&blocks), true).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b, &mut c], &[(0, id)]).await;
    assert_eq!((reports[0].dropped, reports[0].handed), (16, 16), "{reports:?}");
    assert!(reports[0].freed > 0);
    for leaf in leaves {
        assert!(!has(&a, leaf) && has(&b, leaf) && has(&c, leaf));
    }
    assert!(has(&a, blocks.last().expect("root")), "structure stays");
}

#[tokio::test]
async fn nothing_is_handed_off_without_a_member_to_make_up_for_it() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    for block in &blocks {
        b.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(0, id)]).await;
    // b holds them already, and there's no one else
    let id = a.trim(2, &keys(&blocks), true).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert_eq!(reports[0].dropped, 0, "{reports:?}");
    assert!(blocks.iter().all(|block| has(&a, block)));
}

#[tokio::test]
async fn a_member_without_room_isnt_handed_anything() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let blocks = wide();
    for node in [&a, &b] {
        for block in &blocks {
            node.catalog().put_block(block, CidVersion::V1).expect("put");
        }
    }
    // c keeps nothing more for others
    c.set_watermarks(trim::Watermarks::new(0, 0).with_target(Some(0)));
    let audits = [(0, a.audit(2).expect("audit")), (1, b.audit(2).expect("audit"))];
    audited(&mut [&mut a, &mut b, &mut c], &audits).await;
    let id = a.trim(2, &keys(&blocks), true).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b, &mut c], &[(0, id)]).await;
    assert_eq!(reports[0].dropped, 0, "{reports:?}");
    assert!(blocks.iter().all(|block| has(&a, block) && !has(&c, block)));
}

#[tokio::test]
async fn a_sole_copy_may_move_but_never_goes() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = &blocks[2];
    // Only a holds the leaf, and two copies are asked for: handed to b it's
    // no shorter, so it moves
    let id = a.trim(2, &keys(std::slice::from_ref(leaf)), true).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert_eq!(reports[0].handed, 1, "{reports:?}");
    assert!(!has(&a, leaf) && has(&b, leaf));
    // And b, with no one to hand it to, a being as full as it means to be,
    // keeps it
    a.set_watermarks(trim::Watermarks::new(0, 0).with_target(Some(0)));
    let id = b.trim(2, &keys(std::slice::from_ref(leaf)), true).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b], &[(1, id)]).await;
    assert_eq!(reports[0].dropped, 0, "{reports:?}");
    assert!(has(&b, leaf));
}

/// Collect everything on a node, and wait for members to answer for what it
/// condemned, and whatever that cascades to.
async fn condemn(nodes: &mut [&mut Node]) -> collect::Report {
    let report = nodes[0].collect(true).expect("collect");
    assert!(until(nodes, |n| !n[0].condemning()).await);
    report
}

#[tokio::test]
async fn garbage_goes_top_down_once_every_member_says_it_keeps_none() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    // Only the root has nothing referencing it; the rest follow it, a level
    // per round of answers
    let report = condemn(&mut [&mut a, &mut b]).await;
    assert_eq!(report.condemned, 1, "{report:?}");
    assert!(blocks.iter().all(|block| !has(&a, block)), "structure and all");
    assert_eq!(a.condemned().count().expect("count"), 0);
}

#[tokio::test]
async fn whats_kept_here_isnt_condemned() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    a.catalog().keep(&link(&blocks[0])).expect("keep");
    let report = condemn(&mut [&mut a, &mut b]).await;
    assert_eq!(report.condemned, 0);
    assert!(blocks.iter().all(|block| has(&a, block)));
}

#[tokio::test]
async fn whats_shared_with_something_kept_stays() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    // Another root, kept, shares the leaf
    let leaf = &blocks[2];
    let other = cbor(&Ipld::List(vec![Ipld::Link(link(leaf))]));
    a.catalog().put_block(&other, CidVersion::V1).expect("put");
    a.catalog().keep(&link(&other)).expect("keep");
    condemn(&mut [&mut a, &mut b]).await;
    assert!(has(&a, leaf) && has(&a, &other));
    assert!([&blocks[0], &blocks[1], &blocks[3]].iter().all(|block| !has(&a, block)));
}

#[tokio::test]
async fn a_member_keeping_it_pardons_it() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    // b keeps the DAG, holding all of it, and a's yet to hear of the keep
    for block in &blocks {
        b.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    b.catalog().keep(&link(&blocks[0])).expect("keep");
    let report = condemn(&mut [&mut a, &mut b]).await;
    assert_eq!(report.condemned, 1);
    assert_eq!(a.condemned().count().expect("count"), 0, "pardoned");
    assert!(blocks.iter().all(|block| has(&a, block)));
}

#[tokio::test]
async fn a_member_keeping_whats_under_it_stops_the_cascade() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    // b keeps only the branch, which a's yet to hear of
    let (branch, deep) = (&blocks[1], &blocks[3]);
    for block in [branch, deep] {
        b.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    b.catalog().keep(&link(branch)).expect("keep");
    condemn(&mut [&mut a, &mut b]).await;
    assert!(!has(&a, &blocks[0]) && !has(&a, &blocks[2]), "the root and the leaf go");
    assert!(has(&a, branch) && has(&a, deep), "what b keeps stays");
}

#[tokio::test]
async fn nothing_goes_before_its_grace() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    condemn(&mut [&mut a, &mut b]).await;
    assert_eq!(a.collect(true).expect("collect").collected, 0);
    assert_eq!(a.condemned().count().expect("count"), 1);
    assert!(blocks.iter().all(|block| has(&a, block)));
}

#[tokio::test]
async fn a_member_away_holds_collection_up() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    // A member which never connects, so never answers
    a.members().add(&PeerId::random()).expect("add");
    condemn(&mut [&mut a, &mut b]).await;
    assert_eq!(a.collect(true).expect("collect").collected, 0);
    assert!(blocks.iter().all(|block| has(&a, block)));
}

#[tokio::test]
async fn condemned_copies_dont_count_to_a_trimmer() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = &blocks[2];
    b.catalog().put_block(leaf, CidVersion::V1).expect("put");
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(0, id)]).await;
    // b means to collect its copy, so a mustn't let go of its own for it
    b.condemned().condemn(&keys(std::slice::from_ref(leaf)), None).expect("condemn");
    let id = a.trim(1, &keys(std::slice::from_ref(leaf)), false).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert_eq!(reports[0].dropped, 0, "{reports:?}");
    assert!(has(&a, leaf));
}

#[tokio::test]
async fn files_imported_in_place_which_change_are_let_go_of_and_said_so() {
    let (mut a, mut b, _) = Box::pin(holding()).await;
    let scratch = crate::testutil::Scratch::new("node-in-place");
    let file = scratch.path().join("file");
    std::fs::write(&file, vec![9u8; 3000]).expect("write");
    let importer = crate::import::Importer { chunk_size: 1000, ..crate::import::Importer::default() };
    importer.add_path(&file, &mut crate::store::InPlace::new(a.catalog_mut()), &mut |_, _| {}).expect("import");
    let leaf = raw(&[9u8; 1000]);
    assert!(has(&a, &leaf));
    // b has a copy, and knows a has one
    let id = a.audit(2).expect("audit");
    audited(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert!(has(&b, &leaf));
    assert_eq!(b.sightings().of(leaf.cid().multihash()).expect("of").len(), 1);

    // The user changes it, which the trickle notices
    std::fs::write(&file, vec![8u8; 3000]).expect("change");
    a.trickle(2).expect("trickle");
    assert!(!has(&a, &leaf));
    assert!(until(&mut [&mut a, &mut b], |n| n[1].sightings().of(leaf.cid().multihash()).expect("of").is_empty()).await, "b's told");
}

#[tokio::test]
async fn another_accounts_blocks_arent_this_meshs() {
    let (mut a, mut b, _) = Box::pin(holding()).await;
    let theirs = raw(b"another account's");
    let me = a.catalog().uid();
    a.catalog_mut().act_for(me.wrapping_add(1), crate::keys::Key::generate().expect("key")).expect("act");
    a.catalog().put_block(&theirs, CidVersion::V1).expect("put");
    a.catalog_mut().act_for(me, crate::keys::Key::generate().expect("key")).expect("act");
    assert_eq!(fetch(&mut a, &mut b, link(&theirs)).await, (0, vec![link(&theirs)]));
    // Once this account puts it here too, it's in its repo, and its mesh's
    a.catalog().put_block(&theirs, CidVersion::V1).expect("put");
    assert_eq!(fetch(&mut a, &mut b, link(&theirs)).await, (1, vec![]));
}

#[tokio::test]
async fn what_a_kept_root_mounts_stays_till_its_mount_point_goes() {
    use crate::cid::BaseCid as _;
    use crate::store::Catalog;
    let (mut a, mut b, _) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    let inside = raw(b"inside");
    a.catalog().put_block(&inside, CidVersion::V1).expect("put");
    let anchor = a.catalog().new_anchor().expect("anchor");
    a.catalog().set_anchor(&anchor, &link(&inside)).expect("set");
    // The root names the anchor by a mount point, imported elsewhere and
    // put here block by block
    let scratch = crate::testutil::Scratch::new("node-mounted");
    let t = scratch.path().join("t");
    std::fs::create_dir_all(&t).expect("mkdir");
    std::os::unix::fs::symlink(format!("/anchors/{anchor}"), t.join("wiki")).expect("symlink");
    let mut there = Catalog::open_repo(&scratch.path().join("there")).expect("open");
    let top = AnyCid::V1(crate::import::Importer::default().add_path(&t, &mut there, &mut |_, _| {}).expect("import").expect("top").cid);
    for key in there.keys().expect("keys") {
        let cid = there.cid_of(key.as_ref()).expect("cid").expect("cid");
        if cid.codec() == crate::cid::DAG_PB_CODEC {
            a.catalog().put_block(&there.get_block(&cid).expect("get").expect("block"), CidVersion::V1).expect("put");
        }
    }
    // A kept anchor naming it, as a root is
    let root = a.catalog().new_anchor().expect("anchor");
    a.catalog().set_anchor(&root, &top).expect("set");
    a.catalog().keep(&root).expect("keep");
    let top_block = a.catalog().get_block(&top).expect("get").expect("top");
    condemn(&mut [&mut a, &mut b]).await;
    assert!(has(&a, &inside) && has(&a, &top_block), "kept through the root and its mount point");

    // The root naming nothing now, it did: that's history
    let empty = raw(b"");
    a.catalog().set_anchor(&root, &link(&empty)).expect("set");
    condemn(&mut [&mut a, &mut b]).await;
    assert!(has(&a, &top_block) && has(&a, &inside), "what the root named, and what that mounted");

    // Forgotten, the mount point goes, and what it mounted after it
    let versions = a.catalog().versions_before(&root, u64::MAX).expect("versions");
    a.catalog().forget_versions(&root, &versions).expect("forget");
    condemn(&mut [&mut a, &mut b]).await;
    assert!(!has(&a, &top_block), "what the root named");
    assert!(!has(&a, &inside), "and what that mounted, in the same cascade");
}

#[tokio::test]
async fn what_a_document_links_to_by_anchor_goes_after_it() {
    let (mut a, mut b, _) = Box::pin(holding()).await;
    a.set_grace(Duration::ZERO).expect("grace");
    let linked = raw(b"linked");
    a.catalog().put_block(&linked, CidVersion::V1).expect("put");
    let anchor = a.catalog().new_anchor().expect("anchor");
    a.catalog().set_anchor(&anchor, &link(&linked)).expect("set");
    let doc = cbor(&Ipld::List(vec![Ipld::Link(anchor)]));
    a.catalog().put_block(&doc, CidVersion::V1).expect("put");
    a.catalog().keep(&link(&doc)).expect("keep");
    condemn(&mut [&mut a, &mut b]).await;
    assert!(has(&a, &doc) && has(&a, &linked), "kept through the document");
    a.catalog().unkeep(&link(&doc)).expect("unkeep");
    condemn(&mut [&mut a, &mut b]).await;
    assert!(!has(&a, &doc));
    assert!(!has(&a, &linked), "in the same cascade");
}

#[tokio::test]
async fn what_a_keep_asks_one_copy_of_isnt_copied() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let [root, branch, leaf, deep] = &blocks[..] else {
        panic!("{blocks:?}");
    };
    a.catalog().keep(&link(root)).expect("keep");
    // What's made again easily: the branch and what's under it
    a.catalog().keep_copies(&link(branch), 1).expect("keep");
    let id = a.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(0, id)]).await, [report(2, 2, 0)]);
    assert!(has(&b, root) && has(&b, leaf), "kept as the mesh runs");
    assert!(!has(&b, branch) && !has(&b, deep), "one copy, here");
}

/// A node with a catalog in a file, that gives up on other writers quickly,
/// and a connection to hold its write lock with.
async fn node_in_file(swarm_key: PreSharedKey, path: &std::path::Path) -> (Node, rusqlite::Connection) {
    let key = Keypair::generate_ed25519();
    let members = Members::open(Db::memory().expect("db"), crate::net::mesh::MAIN).expect("members");
    let transport = transport(MemoryTransport::default(), &key, swarm_key, Ports::default()).expect("transport");
    let catalog = Catalog::standard(Db::open(path).expect("db")).expect("catalog");
    catalog.wait_for_writers(Duration::from_millis(20)).expect("wait");
    let mut node = Node::new(transport, &key, catalog, members, false, Ports::default(), Tunables::default()).expect("node");
    node.listen(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    loop {
        if let Event::Listening(_) = node.next().await.expect("event") {
            return (node, rusqlite::Connection::open(path).expect("open"));
        }
    }
}

async fn beside_one_in_a_file(path: &std::path::Path) -> (Node, Node, rusqlite::Connection) {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut a = node(swarm_key).await;
    let (mut b, writer) = node_in_file(swarm_key, path).await;
    invite(&a, &b, swarm_key);
    a.reload().expect("reload");
    b.reload().expect("reload");
    b.dial_members().expect("dial");
    assert!(until(&mut [&mut a, &mut b], |n| connected(n[0], n[1])).await);
    (a, b, writer)
}

/// A fetch goes on, and finishes, though for a while something else is
/// writing, so nothing can be kept.
#[tokio::test]
async fn a_fetch_outlasts_another_writer() {
    let scratch = crate::testutil::Scratch::new("busy-fetch");
    let (mut a, mut b, writer) = Box::pin(beside_one_in_a_file(&scratch.path().join("b.db"))).await;
    let blocks = [raw(b"kept once the writer's done"), raw(b"and so is this")];
    let root = cbor(&Ipld::List(blocks.iter().map(|block| Ipld::Link(link(block))).collect()));
    a.catalog().put_block(&root, CidVersion::V1).expect("put");
    for block in &blocks {
        a.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    writer.execute_batch("BEGIN IMMEDIATE").expect("lock");
    let id = b.fetch(link(&root)).expect("fetch");
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        writer.execute_batch("COMMIT").expect("unlock");
    });
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    let (fetched, missing) = loop {
        assert!(tokio::time::Instant::now() < deadline, "the fetch never finished");
        let event = tokio::time::timeout(Duration::from_millis(50), async {
            tokio::select! {
                event = a.next() => event,
                event = b.next() => event,
            }
        });
        match event.await {
            Ok(event) => {
                if let Event::Fetched { id: done, fetched, missing } = event.expect("event")
                    && done == id
                {
                    break (fetched, missing);
                }
            },
            // As the daemon does every so often
            Err(_) => unless_busy(b.redrive(), "the test").expect("redrive"),
        }
    };
    release.join().expect("release");
    assert!(missing.is_empty(), "{missing:?}");
    assert_eq!(fetched, 3);
    for block in &blocks {
        assert!(has(&b, block));
    }
}

/// An audit finishes, though what it's learned can't be noted for something
/// else writing: stranded, a node would never audit again.
#[tokio::test]
async fn an_audit_finishes_beside_another_writer() {
    let scratch = crate::testutil::Scratch::new("busy-audit");
    let (mut a, mut b, writer) = Box::pin(beside_one_in_a_file(&scratch.path().join("b.db"))).await;
    let blocks = wide();
    for block in &blocks {
        b.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    let id = b.audit(2).expect("audit");
    writer.execute_batch("BEGIN IMMEDIATE").expect("lock");
    let reports = audited(&mut [&mut a, &mut b], &[(1, id)]).await;
    assert_eq!(reports, [report(17, 17, 0)]);
    assert!(!b.auditing());
    for block in &blocks {
        assert!(has(&a, block));
    }
    // Still busy throughout, and fine after
    writer.execute_batch("COMMIT").expect("unlock");
    let id = b.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut a, &mut b], &[(1, id)]).await.len(), 1);
}

//------------------------//
//-[ Users sharing nodes ]-//
//------------------------//

/// A server hosting two users, an account for each, and a laptop of each,
/// all members of one mesh. Returns the server, the laptops, and the
/// server's account for the second user, by uid.
async fn shared() -> (Node, Node, Node, u32) {
    let (server, mine, theirs, other, _) = Box::pin(shared_by()).await;
    (server, mine, theirs, other)
}

/// As `shared`, with the two users' root keys, mine first.
async fn shared_by() -> (Node, Node, Node, u32, (crate::keys::Key, crate::keys::Key)) {
    use crate::keys::Key;
    let (mut server, mut mine, mut theirs) = Box::pin(three()).await;
    let (me, them) = (Key::generate().expect("key"), Key::generate().expect("key"));
    let (server_mine, server_theirs) = (Key::generate().expect("key"), Key::generate().expect("key"));
    let (laptop_mine, laptop_theirs) = (Key::generate().expect("key"), Key::generate().expect("key"));
    let other = server.catalog().uid().wrapping_add(1);
    for node in [&server, &mine, &theirs] {
        for device in [&server_mine, &laptop_mine] {
            node.catalog().certify(&me, &device.id()).expect("certify");
        }
        for device in [&server_theirs, &laptop_theirs] {
            node.catalog().certify(&them, &device.id()).expect("certify");
        }
    }
    let claims = server.catalog().claims().expect("claims");
    claims.set_device(other, &server_theirs.id()).expect("device");
    claims.set_user(other, &them.id()).expect("user");
    server.catalog().set_user(&me.id()).expect("user");
    server.catalog_mut().set_signer(server_mine).expect("signer");
    server.serve(vec![(other, server_theirs)]).expect("serve");
    mine.catalog().set_user(&me.id()).expect("user");
    mine.catalog_mut().set_signer(laptop_mine).expect("signer");
    theirs.catalog().set_user(&them.id()).expect("user");
    theirs.catalog_mut().set_signer(laptop_theirs).expect("signer");
    for node in [&mut server, &mut mine, &mut theirs] {
        node.announce().expect("announce");
    }
    // Each laptop knows the server hosts its user, and the server both
    let hosting = |n: &[&mut Node]| {
        let (server, mine, theirs) = (&n[0], &n[1], &n[2]);
        [(server, mine), (server, theirs), (mine, server), (theirs, server)].iter().all(|(a, b)| a.ready().contains(&b.peer_id()))
    };
    assert!(until(&mut [&mut server, &mut mine, &mut theirs], hosting).await);
    (server, mine, theirs, other, (me, them))
}

/// Whether a node's account by uid has a block in its repo.
fn sees(node: &mut Node, uid: u32, block: &Block) -> bool {
    node.catalog_mut().viewing(uid, |catalog| catalog.visible(block.cid().multihash()).expect("visible")).expect("view")
}

#[tokio::test]
async fn a_users_blocks_go_only_to_machines_hosting_them() {
    let (mut server, mut mine, mut theirs, other) = Box::pin(shared()).await;
    let home = server.catalog().uid();
    let (ours, yours) = (raw(b"mine"), raw(b"theirs"));
    mine.catalog().put_block(&ours, CidVersion::V1).expect("put");
    theirs.catalog().put_block(&yours, CidVersion::V1).expect("put");

    // Each laptop's copies go to the server, for the account of its user,
    // with what certifies its devices
    let audits = [(1, mine.audit(2).expect("audit")), (2, theirs.audit(2).expect("audit"))];
    let reports = audited(&mut [&mut server, &mut mine, &mut theirs], &audits).await;
    assert!(reports.iter().all(|report| report.copied >= 1), "{reports:?}");
    assert!(has(&server, &ours) && has(&server, &yours));
    assert!(!has(&theirs, &ours) && !has(&mine, &yours), "never to the other user's laptop");
    assert!(sees(&mut server, home, &ours) && !sees(&mut server, home, &yours));
    assert!(sees(&mut server, other, &yours) && !sees(&mut server, other, &ours));

    // Nor can either fetch the other's from the server
    assert_eq!(fetch(&mut server, &mut theirs, link(&ours)).await, (0, vec![link(&ours)]));
    assert_eq!(fetch(&mut server, &mut mine, link(&yours)).await, (0, vec![link(&yours)]));
    // But each its own user's
    let more = raw(b"more of theirs");
    server.catalog_mut().viewing(other, |catalog| catalog.put_block(&more, CidVersion::V1)).expect("view").expect("put");
    assert_eq!(fetch(&mut server, &mut theirs, link(&more)).await, (1, vec![]));
    assert_eq!(fetch(&mut server, &mut mine, link(&more)).await, (0, vec![link(&more)]));
}

#[tokio::test]
async fn a_machine_says_it_hosts_only_users_whose_device_it_has() {
    let (mut server, mut mine, mut theirs, _) = Box::pin(shared()).await;
    // A key the second user never certified, as a thief's machine might
    // claim to host them with
    theirs.catalog_mut().set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    let yours = raw(b"theirs");
    server.catalog().put_block(&yours, CidVersion::V1).expect("put");
    theirs.announce().expect("announce");
    assert!(until(&mut [&mut server, &mut mine, &mut theirs], |n| n[0].ready().contains(&n[2].peer_id()) && n[2].ready().contains(&n[0].peer_id())).await);
    assert_eq!(fetch(&mut server, &mut theirs, link(&yours)).await.0, 0);
}

//------------//
//-[ Grants ]-//
//------------//

use crate::grants::{MACHINE, USER};

fn key_of(node: &Node) -> Link {
    crate::keys::from_peer_id(&node.peer_id().to_string()).expect("key")
}

/// Whether a node's worked out grants saying someone holds a command.
fn says(node: &Node, who: &Link, command: &str) -> bool {
    node.granted.as_ref().is_some_and(|(_, state)| state.holds(who, command))
}

/// Give a mesh grants, founded by a root key, on the first node, which
/// gives each node /mesh/machine; the others know only its first grant,
/// as a ticket would tell them, and ask for the rest.
fn found(nodes: &mut [&mut Node], root: &crate::keys::Key) -> Link {
    let first = nodes.first().expect("a node");
    let genesis = first.catalog().found_grants(root).expect("found");
    let machines: Vec<Link> = nodes.iter().map(|node| key_of(node)).collect();
    first.catalog().grant(&genesis, &machines, &[MACHINE.to_owned()], &[]).expect("grant");
    for node in nodes.iter_mut() {
        node.members().set_genesis(&genesis).expect("genesis");
        node.reload().expect("reload");
    }
    genesis
}

#[tokio::test]
async fn grants_say_which_machines_are_let_in() {
    let (mut a, mut b, mut c) = Box::pin(three()).await;
    let root = one_user(&mut [&mut a, &mut b, &mut c]);
    let genesis = found(&mut [&mut a, &mut b, &mut c], &root);
    let (kc, peer_c) = (key_of(&c), c.peer_id());
    // The others learn the grants from the first
    assert!(until(&mut [&mut a, &mut b, &mut c], |n| says(n[1], &kc, MACHINE) && says(n[2], &kc, MACHINE)).await);

    // Taken away on one, every machine shuts it out
    a.catalog().grant(&genesis, std::slice::from_ref(&kc), &[], &[MACHINE.to_owned()]).expect("grant");
    a.reload().expect("reload");
    let shut = |n: &[&mut Node]| {
        !n[0].connected().contains(&peer_c) && !n[1].connected().contains(&peer_c) && !n[1].members().contains(&peer_c).expect("contains")
    };
    assert!(until(&mut [&mut a, &mut b, &mut c], shut).await);
    assert!(a.forget_member(&b.peer_id()).is_err(), "a machine the grants say is in isn't forgotten");
    // Nor is it let back in by a roster that lists it
    c.dial_members().expect("dial");
    assert!(!within(Duration::from_secs(2), &mut [&mut a, &mut b, &mut c], |n| connected(n[0], n[2]) || connected(n[1], n[2])).await);
}

#[tokio::test]
async fn only_users_the_grants_recognize_are_hosted() {
    let (mut server, mut mine, mut theirs, other, (me, them)) = Box::pin(shared_by()).await;
    let genesis = found(&mut [&mut server, &mut mine, &mut theirs], &me);
    let ks = key_of(&server);
    assert!(until(&mut [&mut server, &mut mine, &mut theirs], |n| says(n[1], &ks, MACHINE) && says(n[2], &ks, MACHINE)).await);
    let yours = raw(b"theirs");
    server.catalog_mut().viewing(other, |catalog| catalog.put_block(&yours, CidVersion::V1)).expect("view").expect("put");
    assert_eq!(fetch(&mut server, &mut theirs, link(&yours)).await.0, 0, "their user isn't one of the mesh's");

    server.catalog().grant(&genesis, &[them.id()], &[USER.to_owned()], &[]).expect("grant");
    server.reload().expect("reload");
    assert!(until(&mut [&mut server, &mut mine, &mut theirs], |n| says(n[2], &them.id(), USER)).await);
    assert_eq!(fetch(&mut server, &mut theirs, link(&yours)).await.0, 1);
}

//-------------//
//-[ Clients ]-//
//-------------//

/// A client of a member, its device key its peer ID, told where the
/// member listens for clients, or `at`.
fn client_of(member: &Node, device: &crate::keys::Key, at: Option<Vec<Multiaddr>>) -> Node {
    let key = Keypair::from_protobuf_encoding(&device.to_protobuf()).expect("keypair");
    let members = Members::open(Db::memory().expect("db"), mesh::MAIN).expect("members");
    let at = at.unwrap_or_else(|| member.client_listeners());
    members.merge(&BTreeMap::from([(member.peer_id(), at)])).expect("merge");
    members.set_client_of(&member.peer_id()).expect("client of");
    let transport = crate::net::clients::client_transport(MemoryTransport::default(), &key).expect("transport");
    let catalog = Catalog::standard(Db::memory().expect("db")).expect("catalog");
    let mut client = Node::new(transport, &key, catalog, members, false, Ports::default(), Tunables::default()).expect("node");
    client.catalog_mut().set_signer(device.clone()).expect("signer");
    client
}

/// A member listening for clients too, and a client of it, devices of
/// one user, connected. Returns the user's root key.
async fn with_client() -> (Node, Node, crate::keys::Key) {
    use crate::keys::Key;
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut member = node(swarm_key).await;
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    assert!(member.listeners().iter().all(|addr| !member.client_listeners().contains(addr)));
    let (root, laptop, device) = (Key::generate().expect("key"), Key::generate().expect("key"), Key::generate().expect("key"));
    let mut client = client_of(&member, &device, None);
    for node in [&member, &client] {
        node.catalog().set_user(&root.id()).expect("user");
        for key in [&laptop, &device] {
            node.catalog().certify(&root, &key.id()).expect("certify");
        }
    }
    member.catalog_mut().set_signer(laptop).expect("signer");
    member.members().add_client(&client.peer_id(), member.catalog().uid()).expect("client");
    member.reload().expect("reload");
    client.reload().expect("reload");
    client.dial_members().expect("dial");
    assert!(until(&mut [&mut member, &mut client], |n| connected(n[0], n[1])).await);
    (member, client, root)
}

#[tokio::test]
async fn a_client_reads_and_writes_through_its_member() {
    let (mut member, mut client, _) = Box::pin(with_client()).await;
    assert!(member.is_client(&client.peer_id()) && client.client_of() == Some(member.peer_id()));
    assert!(!client.is_client(&member.peer_id()));
    // What the member holds, the client fetches
    let held = raw(b"on the member");
    member.catalog().put_block(&held, CidVersion::V1).expect("put");
    assert_eq!(fetch(&mut member, &mut client, link(&held)).await, (1, vec![]));
    // What the client says reaches the member, and counts there
    let tag = raw(b"from the client");
    client.catalog().put_block(&tag, CidVersion::V1).expect("put");
    client.catalog().tag(&link(&held), &link(&tag)).expect("tag");
    client.announce().expect("announce");
    assert!(until(&mut [&mut member, &mut client], |n| tags(n[0], &held) == [link(&tag)]).await);
    // What the client makes, its audit copies to the member
    let made = raw(b"made on the client");
    client.catalog().put_block(&made, CidVersion::V1).expect("put");
    let id = client.audit(2).expect("audit");
    let reports = audited(&mut [&mut member, &mut client], &[(1, id)]).await;
    assert_eq!(reports.first().map(|report| report.short), Some(0), "{reports:?}");
    assert!(has(&member, &made));
    // The member's roster isn't the client's to know, nor the client's
    // the member's
    assert!(!member.members().contains(&client.peer_id()).expect("contains"));
    assert_eq!(client.members().list().expect("list").len(), 1);
}

#[tokio::test]
async fn a_clients_copies_count_for_nothing() {
    let (mut member, mut client, _) = Box::pin(with_client()).await;
    let held = raw(b"on the member");
    member.catalog().put_block(&held, CidVersion::V1).expect("put");
    assert_eq!(fetch(&mut member, &mut client, link(&held)).await.0, 1);
    // The client says it holds a copy, which the member doesn't believe in
    let id = client.audit(3).expect("audit");
    audited(&mut [&mut member, &mut client], &[(1, id)]).await;
    assert!(member.sightings().of(held.cid().multihash()).expect("sightings").is_empty());
    // Nor copies anything to it
    let id = member.audit(2).expect("audit");
    let reports = audited(&mut [&mut member, &mut client], &[(0, id)]).await;
    assert!(reports.iter().all(|report| report.copied == 0 && report.short > 0), "{reports:?}");
}

#[tokio::test]
async fn only_clients_let_in_get_in_and_only_where_clients_do() {
    let (mut member, mut client, root) = Box::pin(with_client()).await;
    // A device of the user's, but never let in as a client
    let device = crate::keys::Key::generate().expect("key");
    member.catalog().certify(&root, &device.id()).expect("certify");
    let mut stranger = client_of(&member, &device, None);
    stranger.reload().expect("reload");
    stranger.dial_members().expect("dial");
    assert!(!within(Duration::from_secs(2), &mut [&mut member, &mut stranger], |n| connected(n[0], n[1])).await);

    // One let in, dialing where members connect, without the mesh's key
    let device = crate::keys::Key::generate().expect("key");
    member.catalog().certify(&root, &device.id()).expect("certify");
    let mut astray = client_of(&member, &device, Some(member.listeners()));
    member.members().add_client(&astray.peer_id(), member.catalog().uid()).expect("client");
    member.reload().expect("reload");
    assert!(member.is_client(&astray.peer_id()));
    astray.reload().expect("reload");
    astray.dial_members().expect("dial");
    assert!(!within(Duration::from_secs(2), &mut [&mut member, &mut astray], |n| connected(n[0], n[1])).await);

    // A member, with the key, dialing where clients connect
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let mut other = node(swarm_key).await;
    other.members().merge(&BTreeMap::from([(member.peer_id(), member.client_listeners())])).expect("merge");
    member.members().add(&other.peer_id()).expect("add");
    member.reload().expect("reload");
    other.reload().expect("reload");
    other.dial_members().expect("dial");
    assert!(!within(Duration::from_secs(2), &mut [&mut member, &mut other], |n| connected(n[0], n[1])).await);

    // And a client forgotten is shut out at once
    member.forget_member(&client.peer_id()).expect("forget");
    assert!(until(&mut [&mut member, &mut client], |n| !n[0].connected().contains(&n[1].peer_id())).await);
    assert!(!member.is_client(&client.peer_id()));
}

#[tokio::test]
async fn what_a_client_makes_goes_to_its_member_whatever_they_share() {
    let (mut member, mut client, _) = Box::pin(with_client()).await;
    // On one disk, as a sandbox on its member's machine: a copy there
    // raises nothing, but the client's own counts for nothing
    for node in [&member, &client] {
        for volume in node.catalog().volume_list().expect("volumes") {
            node.catalog().add_risk(&volume.name, "disk:shared").expect("risk");
        }
    }
    let made = raw(b"made on a shared disk");
    client.catalog().put_block(&made, CidVersion::V1).expect("put");
    let id = client.audit(2).expect("audit");
    let reports = audited(&mut [&mut member, &mut client], &[(1, id)]).await;
    assert!(has(&member, &made), "{reports:?}");
    // And once it's there, nothing's short
    let id = client.audit(2).expect("audit");
    assert_eq!(audited(&mut [&mut member, &mut client], &[(1, id)]).await.first().map(|report| report.advertised), Some(0));
}

#[tokio::test]
async fn what_its_member_lacks_a_client_has_next_time() {
    use crate::keys::Key;
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut member, mut other) = (node(swarm_key).await, node(swarm_key).await);
    invite(&member, &other, swarm_key);
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    let (root, mine, theirs, device) = (Key::generate().expect("key"), Key::generate().expect("key"), Key::generate().expect("key"), Key::generate().expect("key"));
    let mut client = client_of(&member, &device, None);
    for node in [&member, &other, &client] {
        node.catalog().set_user(&root.id()).expect("user");
        for key in [&mine, &theirs, &device] {
            node.catalog().certify(&root, &key.id()).expect("certify");
        }
    }
    member.catalog_mut().set_signer(mine).expect("signer");
    other.catalog_mut().set_signer(theirs).expect("signer");
    member.members().add_client(&client.peer_id(), member.catalog().uid()).expect("client");
    for node in [&mut member, &mut other, &mut client] {
        node.reload().expect("reload");
        node.dial_members().expect("dial");
    }
    assert!(until(&mut [&mut member, &mut other, &mut client], |n| connected(n[0], n[1]) && connected(n[0], n[2])).await);
    assert!(!other.connected().contains(&client.peer_id()));
    // Only the other member has it: the first ask finds it missing, and
    // has the member fetch it
    let elsewhere = raw(b"on the other member");
    other.catalog().put_block(&elsewhere, CidVersion::V1).expect("put");
    let id = client.fetch_blocks(vec![link(&elsewhere)]).expect("fetch");
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    loop {
        let events = futures::future::select_all([&mut member, &mut other, &mut client].map(|node| Box::pin(node.next())));
        let (event, from, _) = tokio::time::timeout_at(deadline, events).await.expect("in time");
        if let Event::Fetched { id: done, missing, .. } = event.expect("event")
            && (from, done) == (2, id)
        {
            assert_eq!(missing, [link(&elsewhere)]);
            break;
        }
    }
    assert!(until(&mut [&mut member, &mut other, &mut client], |n| has(n[0], &elsewhere)).await);
    let id = client.fetch_blocks(vec![link(&elsewhere)]).expect("fetch");
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    loop {
        let events = futures::future::select_all([&mut member, &mut other, &mut client].map(|node| Box::pin(node.next())));
        let (event, from, _) = tokio::time::timeout_at(deadline, events).await.expect("in time");
        if let Event::Fetched { id: done, fetched, .. } = event.expect("event")
            && (from, done) == (2, id)
        {
            assert_eq!(fetched, 1);
            break;
        }
    }
}

//------------------//
//-[ Thin clients ]-//
//------------------//

use crate::net::thin::Thin;

/// Drive nodes while some work's done, or give up.
async fn serving<T>(nodes: &mut [&mut Node], work: impl Future<Output = T>) -> T {
    let mut work = std::pin::pin!(work);
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(30)).expect("deadline");
    loop {
        assert!(tokio::time::Instant::now() < deadline, "out of time");
        let events = futures::future::select_all(nodes.iter_mut().map(|node| Box::pin(node.next())));
        tokio::select! {
            out = &mut work => return out,
            _ = tokio::time::timeout(Duration::from_millis(50), events) => {},
        }
    }
}

/// A thin client of a member, its device key its peer ID, for a user.
fn thin_of(member: &Node, device: &crate::keys::Key, user: &Link) -> Thin {
    let key = Keypair::from_protobuf_encoding(&device.to_protobuf()).expect("keypair");
    let transport = crate::net::clients::client_transport(MemoryTransport::default(), &key).expect("transport");
    Thin::new(transport, &key, vec![(member.peer_id(), member.client_listeners())], user)
}

/// A member listening for clients, and a thin client of it let in,
/// devices of one user, whose root key it returns.
async fn with_thin() -> (Node, Thin, crate::keys::Key) {
    use crate::keys::Key;
    let mut member = node(mesh::fresh_swarm_key().expect("key")).await;
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    let (root, laptop, device) = (Key::generate().expect("key"), Key::generate().expect("key"), Key::generate().expect("key"));
    member.catalog().set_user(&root.id()).expect("user");
    for key in [&laptop, &device] {
        member.catalog().certify(&root, &key.id()).expect("certify");
    }
    member.catalog_mut().set_signer(laptop).expect("signer");
    let thin = thin_of(&member, &device, &root.id());
    member.members().add_client(&thin.peer_id(), member.catalog().uid()).expect("client");
    member.reload().expect("reload");
    (member, thin, root)
}

#[tokio::test]
async fn a_thin_client_reads_writes_and_says_through_its_member() {
    let (mut member, mut thin, _) = Box::pin(with_thin()).await;
    serving(&mut [&mut member], thin.connect()).await.expect("connect");
    // What the member holds, the thin client reads
    let held = raw(b"on the member");
    member.catalog().put_block(&held, CidVersion::V1).expect("put");
    let got = serving(&mut [&mut member], thin.get(&[link(&held)])).await.expect("get");
    assert_eq!(got.iter().map(|block| block.data().to_vec()).collect::<Vec<_>>(), [b"on the member".to_vec()]);
    // What it writes, whole chunks among them, the member holds for it
    let chunks: Vec<Block> = (0..3u8).map(|i| raw(&vec![i; 1 << 20])).collect();
    let root = cbor(&Ipld::List(chunks.iter().map(|chunk| Ipld::Link(link(chunk))).collect()));
    let written: Vec<Block> = chunks.iter().cloned().chain([root.clone()]).collect();
    serving(&mut [&mut member], thin.push(written.clone())).await.expect("push");
    assert!(written.iter().all(|block| has(&member, block)));
    // And what it says, the member says as its account
    let words = |words: &[&str]| words.iter().map(|word| (*word).to_owned()).collect::<Vec<_>>();
    let kept = serving(&mut [&mut member], thin.ask(words(&["keep", "add", &link(&root).to_string()]))).await.expect("keep");
    assert_eq!(kept.len(), 1);
    assert!(member.catalog().claims().expect("claims").keeps().expect("keeps").contains(&link(&root)));
    let tag = serving(&mut [&mut member], thin.ask(words(&["tag", "add", "from afar", &link(&held).to_string()]))).await.expect("tag");
    assert_eq!(tag.len(), 1);
    assert_eq!(serving(&mut [&mut member], thin.ask(words(&["tag", "ls", &link(&held).to_string()]))).await.expect("tags"), ["from afar"]);
    let anchor = serving(&mut [&mut member], thin.ask(words(&["anchor", "new"]))).await.expect("anchor").remove(0);
    serving(&mut [&mut member], thin.ask(words(&["anchor", "set", &anchor, &link(&root).to_string()]))).await.expect("set");
    assert_eq!(member.catalog().anchor_value(&anchor.parse().expect("anchor")).expect("value"), Some(link(&root)));
    // What it can't, it's told
    let refused = serving(&mut [&mut member], thin.ask(words(&["collect"]))).await;
    assert!(refused.is_err_and(|e| e.to_string().starts_with("not something an account can ask")));
}

#[tokio::test]
async fn what_its_member_lacks_a_thin_client_reads_and_keeps_all_the_same() {
    use crate::keys::Key;
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut member, mut other) = (node(swarm_key).await, node(swarm_key).await);
    invite(&member, &other, swarm_key);
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    let (root, mine, theirs, device) = (Key::generate().expect("key"), Key::generate().expect("key"), Key::generate().expect("key"), Key::generate().expect("key"));
    for node in [&member, &other] {
        node.catalog().set_user(&root.id()).expect("user");
        for key in [&mine, &theirs, &device] {
            node.catalog().certify(&root, &key.id()).expect("certify");
        }
    }
    member.catalog_mut().set_signer(mine).expect("signer");
    other.catalog_mut().set_signer(theirs).expect("signer");
    let mut thin = thin_of(&member, &device, &root.id());
    member.members().add_client(&thin.peer_id(), member.catalog().uid()).expect("client");
    for node in [&mut member, &mut other] {
        node.reload().expect("reload");
        node.dial_members().expect("dial");
    }
    assert!(until(&mut [&mut member, &mut other], |n| connected(n[0], n[1])).await);
    // Only the other member has these: the member fetches them as asked
    let blocks = wide();
    for block in &blocks {
        other.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    let (first, top) = (blocks.first().expect("leaf").clone(), blocks.last().expect("root").clone());
    let got = serving(&mut [&mut member, &mut other], thin.get(&[link(&first)])).await.expect("get");
    assert_eq!(got.len(), 1);
    let words = vec!["keep".to_owned(), "add".to_owned(), link(&top).to_string()];
    serving(&mut [&mut member, &mut other], thin.ask(words)).await.expect("keep");
    assert!(blocks.iter().all(|block| has(&member, block)));
    assert!(member.catalog().claims().expect("claims").keeps().expect("keeps").contains(&link(&top)));
}

#[tokio::test]
async fn only_thin_clients_let_in_get_in() {
    let (mut member, _, root) = Box::pin(with_thin()).await;
    // A device of the user's, never let in
    let device = crate::keys::Key::generate().expect("key");
    member.catalog().certify(&root, &device.id()).expect("certify");
    let mut stranger = thin_of(&member, &device, &root.id());
    let refused = serving(&mut [&mut member], async {
        stranger.connect().await?;
        stranger.ask(vec!["whoami".to_owned()]).await
    }).await;
    assert!(refused.is_err());
}

//----------------------------//
//-[ Clients of the mesh's ]-//
//----------------------------//

/// Two members serving one user, both listening for clients, with grants;
/// and a device of the user's the first gives /mesh/client, which both
/// have heard of. Returns the device.
async fn granted_client() -> (Node, Node, crate::keys::Key, crate::keys::Key, Link) {
    let swarm_key = mesh::fresh_swarm_key().expect("key");
    let (mut a, mut b) = (node(swarm_key).await, node(swarm_key).await);
    for node in [&mut a, &mut b] {
        node.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    }
    assert!(until(&mut [&mut a, &mut b], |n| n.iter().all(|node| !node.client_listeners().is_empty())).await);
    invite(&a, &b, swarm_key);
    a.reload().expect("reload");
    b.reload().expect("reload");
    b.dial_members().expect("dial");
    assert!(until(&mut [&mut a, &mut b], |n| connected(n[0], n[1])).await);
    let root = one_user(&mut [&mut a, &mut b]);
    let device = crate::keys::Key::generate().expect("key");
    for node in [&a, &b] {
        node.catalog().certify(&root, &device.id()).expect("certify");
    }
    let genesis = found(&mut [&mut a, &mut b], &root);
    a.catalog().grant(&genesis, &[device.id()], &[crate::grants::CLIENT.to_owned()], &[]).expect("grant");
    a.reload().expect("reload");
    assert!(until(&mut [&mut a, &mut b], |n| says(n[1], &device.id(), crate::grants::CLIENT) && n[1].granted_clients().is_some_and(|clients| !clients.is_empty())).await);
    (a, b, root, device, genesis)
}

#[tokio::test]
async fn a_client_of_the_mesh_connects_to_every_member_serving_its_user() {
    let (mut a, mut b, root, device, genesis) = Box::pin(granted_client()).await;
    let mut client = client_of(&a, &device, None);
    client.catalog().set_user(&root.id()).expect("user");
    for key in [a.catalog().signer().expect("signer").id(), b.catalog().signer().expect("signer").id(), device.id()] {
        client.catalog().certify(&root, &key).expect("certify");
    }
    let peer = client.peer_id();
    assert!(a.is_client(&peer) && b.is_client(&peer), "each lets it in, as the grants say");
    client.reload().expect("reload");
    client.dial_members().expect("dial");
    // Told by the one it was invited by where the other listens, it
    // connects to both
    assert!(until(&mut [&mut a, &mut b, &mut client], |n| n[2].connected().contains(&n[0].peer_id()) && n[2].connected().contains(&n[1].peer_id())).await);
    assert!(!a.members().contains(&peer).expect("contains") && !b.members().contains(&peer).expect("contains"));
    // What only the other has, it reads from it, whichever it asks first,
    // so every node's driven
    let theirs = raw(b"only on b");
    b.catalog().put_block(&theirs, CidVersion::V1).expect("put");
    client.fetch(link(&theirs)).expect("fetch");
    assert!(until(&mut [&mut a, &mut b, &mut client], |n| has(n[2], &theirs)).await);
    // Forgetting it isn't enough; taking the grant away shuts it out of both
    assert!(a.forget_member(&peer).is_err());
    a.catalog().grant(&genesis, &[device.id()], &[], &[crate::grants::CLIENT.to_owned()]).expect("grant");
    a.reload().expect("reload");
    assert!(until(&mut [&mut a, &mut b, &mut client], |n| n[2].connected().is_empty() && !n[0].is_client(&peer) && !n[1].is_client(&peer)).await);
}

#[tokio::test]
async fn a_thin_client_reaches_whichever_member_is_there() {
    let (a, mut b, root, device, _) = Box::pin(granted_client()).await;
    let key = Keypair::from_protobuf_encoding(&device.to_protobuf()).expect("keypair");
    let transport = crate::net::clients::client_transport(MemoryTransport::default(), &key).expect("transport");
    let mut thin = Thin::new(transport, &key, vec![(a.peer_id(), a.client_listeners()), (b.peer_id(), b.client_listeners())], &root.id());
    // Its first member's gone
    let gone = a.peer_id();
    drop(a);
    let held = raw(b"on b");
    b.catalog().put_block(&held, CidVersion::V1).expect("put");
    let got = serving(&mut [&mut b], thin.get(&[link(&held)])).await.expect("get");
    assert_eq!(got.len(), 1);
    assert_ne!(thin.member(), gone);
}

//--------------//
//-[ Visitors ]-//
//--------------//

#[tokio::test]
async fn a_visitor_reads_only_what_is_shared_with_it() {
    use crate::grants::READ;
    let mut member = node(mesh::fresh_swarm_key().expect("key")).await;
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    let root = one_user(&mut [&mut member]);
    let genesis = found(&mut [&mut member], &root);
    // A folder on an anchor, shared; another not
    let blocks = wide();
    for block in &blocks {
        member.catalog().put_block(block, CidVersion::V1).expect("put");
    }
    let top = link(blocks.last().expect("root"));
    let (anchor, private) = (member.catalog().new_anchor().expect("anchor"), raw(b"not shared"));
    member.catalog().put_block(&private, CidVersion::V1).expect("put");
    let other = member.catalog().new_anchor().expect("anchor");
    member.catalog_mut().batch(|catalog| {
        catalog.set_anchor(&anchor, &top)?;
        catalog.set_anchor(&other, &link(&private))
    }).expect("set");
    let visitor = crate::keys::Key::generate().expect("key");
    member.catalog().grant_on(&genesis, &anchor, &[visitor.id()], &[READ.to_owned()], &[], &[]).expect("share");
    member.reload().expect("reload");
    let mut thin = thin_of(&member, &visitor, &root.id()).with_patience(Duration::from_millis(300));
    assert!(member.is_visitor(&thin.peer_id()) && !member.is_client(&thin.peer_id()));
    let words = |words: &[&str]| words.iter().map(|word| (*word).to_owned()).collect::<Vec<_>>();
    // It's told what's shared with it, and reads it
    let shared = serving(&mut [&mut member], thin.ask(words(&["shared"]))).await.expect("shared");
    let view = crate::claim::view(&anchor, &root.id()).expect("view");
    assert_eq!(shared.len(), 1);
    assert!(shared.first().is_some_and(|line| line.starts_with(&format!("{view}\t")) && line.ends_with(READ)));
    assert_eq!(serving(&mut [&mut member], thin.ask(words(&["anchor", "show", &view.to_string()]))).await.expect("show"), [top.to_string()]);
    let got = serving(&mut [&mut member], thin.get(&blocks.iter().map(link).collect::<Vec<_>>())).await.expect("get");
    assert_eq!(got.len(), blocks.len());
    // And nothing else
    assert!(serving(&mut [&mut member], thin.get(&[link(&private)])).await.is_err());
    let theirs = crate::claim::view(&other, &root.id()).expect("view");
    assert_eq!(serving(&mut [&mut member], thin.ask(words(&["anchor", "show", &theirs.to_string()]))).await.expect("show"), ["unset"]);
    assert!(serving(&mut [&mut member], thin.ask(words(&["keep", "ls"]))).await.is_err());
    assert!(serving(&mut [&mut member], thin.push(vec![raw(b"from a visitor")])).await.is_err());
    assert!(!member.catalog().has(raw(b"from a visitor").cid().multihash()).expect("has"));
    // Unshared, it's shut out
    member.catalog().grant_on(&genesis, &anchor, &[visitor.id()], &[], &[READ.to_owned()], &[]).expect("unshare");
    member.reload().expect("reload");
    assert!(!member.is_visitor(&thin.peer_id()));
    assert!(serving(&mut [&mut member], thin.ask(words(&["shared"]))).await.is_err());
}

/// A visitor let write a view sets it as itself: what it pushes is held
/// for the owner, its set, signed with its own key, counts in the owner's
/// view, and claims of other kinds aren't taken. Write taken away, it's
/// refused, and what stood stands.
#[tokio::test]
async fn a_visitor_let_write_sets_a_view_as_itself() {
    use crate::grants::{READ, WRITE};
    let mut member = node(mesh::fresh_swarm_key().expect("key")).await;
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    let root = one_user(&mut [&mut member]);
    let genesis = found(&mut [&mut member], &root);
    let (before, written, later) = (raw(b"before"), raw(b"from a visitor"), raw(b"too late"));
    member.catalog().put_block(&before, CidVersion::V1).expect("put");
    let anchor = member.catalog().new_anchor().expect("anchor");
    member.catalog().set_anchor(&anchor, &link(&before)).expect("set");
    let visitor = crate::keys::Key::generate().expect("key");
    member.catalog().grant_on(&genesis, &anchor, &[visitor.id()], &[READ.to_owned(), WRITE.to_owned()], &[], &[]).expect("share");
    member.reload().expect("reload");
    let mut thin = thin_of(&member, &visitor, &root.id()).with_patience(Duration::from_millis(300)).as_visitor(visitor.clone());
    let view = crate::claim::view(&anchor, &root.id()).expect("view");

    serving(&mut [&mut member], thin.push(vec![written.clone()])).await.expect("push");
    let set = serving(&mut [&mut member], thin.set_own(&view, &link(&written))).await.expect("set");
    assert_eq!(member.catalog().anchor_value(&anchor).expect("value"), Some(link(&written)), "it counts in the owner's view");
    assert!(member.catalog().has(written.cid().multihash()).expect("has"));
    assert_eq!(member.catalog().latest_sets_by(&anchor, &visitor.id()).expect("latest"), std::slice::from_ref(&set));
    // A keep of its own isn't taken (of two, so it's no inline CID)
    let keep = crate::claim::Claim::Keep(crate::claim::Keep::new([link(&written), link(&before)]).expect("keep"));
    let _ = serving(&mut [&mut member], thin.push(vec![keep.block()])).await;
    assert!(!member.catalog().has(keep.cid().multihash()).expect("has"));

    // Write taken away: refused, and what it set stands
    member.catalog().grant_on(&genesis, &anchor, &[visitor.id()], &[], &[WRITE.to_owned()], std::slice::from_ref(&set)).expect("unshare");
    member.reload().expect("reload");
    assert!(member.is_visitor(&thin.peer_id()), "it still reads");
    assert!(serving(&mut [&mut member], thin.set_own(&view, &link(&before))).await.is_err());
    assert!(serving(&mut [&mut member], thin.push(vec![later.clone()])).await.is_err());
    assert!(!member.catalog().has(later.cid().multihash()).expect("has"));
    assert_eq!(member.catalog().anchor_value(&anchor).expect("value"), Some(link(&written)));
}

/// A visitor let pass a view on does, as itself: a friend it shares with
/// is let in and reads it, and is shut out once the visitor takes it back.
/// One not let pass it on can't.
#[tokio::test]
async fn a_visitor_passes_a_view_on() {
    use crate::grants::{ANCHOR_GRANT, READ};
    let mut member = node(mesh::fresh_swarm_key().expect("key")).await;
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    let root = one_user(&mut [&mut member]);
    let genesis = found(&mut [&mut member], &root);
    let note = raw(b"passed on");
    member.catalog().put_block(&note, CidVersion::V1).expect("put");
    let anchor = member.catalog().new_anchor().expect("anchor");
    member.catalog().set_anchor(&anchor, &link(&note)).expect("set");
    let (visitor, friend, stranger) = (crate::keys::Key::generate().expect("key"), crate::keys::Key::generate().expect("key"), crate::keys::Key::generate().expect("key"));
    member.catalog().grant_on(&genesis, &anchor, &[visitor.id()], &[READ.to_owned(), ANCHOR_GRANT.to_owned()], &[], &[]).expect("share");
    member.catalog().grant_on(&genesis, &anchor, &[stranger.id()], &[READ.to_owned()], &[], &[]).expect("share");
    member.reload().expect("reload");
    let view = crate::claim::view(&anchor, &root.id()).expect("view");
    let read = [READ.to_owned()];

    // One let only read can't pass it on
    let mut theirs = thin_of(&member, &stranger, &root.id()).as_visitor(stranger.clone());
    assert!(serving(&mut [&mut member], theirs.share_own(&view, &friend.id(), &read, &[], None)).await.is_err());
    // Nor is a grant it signs and pushes itself taken
    let heads = member.catalog().grant_state(&genesis).expect("state").expect("a mesh").heads();
    let grant = crate::claim::Claim::Grant(crate::claim::Grant::new([friend.id()], Some(anchor.clone()), read.iter().cloned(), [], [], heads).expect("grant"));
    let sign = crate::claim::Claim::Sign(crate::claim::Sign::new(&stranger, [grant.cid()], None, 1).expect("sign"));
    let _ = serving(&mut [&mut member], theirs.push(vec![grant.block(), sign.block()])).await;
    assert!(!member.catalog().has(grant.cid().multihash()).expect("has"));
    assert!(!member.is_visitor(&PeerId::from_bytes(&friend.id().multihash().to_bytes()).expect("peer")));

    let mut thin = thin_of(&member, &visitor, &root.id()).as_visitor(visitor.clone());
    serving(&mut [&mut member], thin.share_own(&view, &friend.id(), &read, &[], None)).await.expect("passed on");
    let mut friends = thin_of(&member, &friend, &root.id()).with_patience(Duration::from_millis(300)).as_visitor(friend.clone());
    assert!(member.is_visitor(&friends.peer_id()), "the friend's let in");
    let words = vec!["anchor".to_owned(), "show".to_owned(), view.to_string()];
    assert_eq!(serving(&mut [&mut member], friends.ask(words)).await.expect("show"), [link(&note).to_string()]);
    assert_eq!(serving(&mut [&mut member], friends.get(&[link(&note)])).await.expect("get").len(), 1);

    // Taken back, the friend's shut out
    serving(&mut [&mut member], thin.share_own(&view, &friend.id(), &[], &read, None)).await.expect("taken back");
    assert!(!member.is_visitor(&friends.peer_id()));
    assert!(serving(&mut [&mut member], friends.ask(vec!["shared".to_owned()])).await.is_err());
}

/// What's shared till a time goes then: once it's passed, a visitor let
/// in for so long is shut out, and told nothing more.
#[tokio::test]
async fn a_visitor_let_in_for_a_while_is_shut_out_after() {
    use crate::grants::READ;
    let mut member = node(mesh::fresh_swarm_key().expect("key")).await;
    member.listen_for_clients(Multiaddr::empty().with(Protocol::Memory(0))).expect("listen");
    assert!(until(&mut [&mut member], |n| !n[0].client_listeners().is_empty()).await);
    let root = one_user(&mut [&mut member]);
    let genesis = found(&mut [&mut member], &root);
    let anchor = member.catalog().new_anchor().expect("anchor");
    let note = raw(b"for a while");
    member.catalog().put_block(&note, CidVersion::V1).expect("put");
    member.catalog().set_anchor(&anchor, &link(&note)).expect("set");
    let visitor = crate::keys::Key::generate().expect("key");
    let now = super::now_secs();
    member.catalog().grant_on_until(&genesis, &anchor, &[visitor.id()], &[READ.to_owned()], &[], &[], Some(now + 2)).expect("share");
    member.reload().expect("reload");
    let mut thin = thin_of(&member, &visitor, &root.id()).as_visitor(visitor.clone());
    assert!(member.is_visitor(&thin.peer_id()));
    let shared = serving(&mut [&mut member], thin.ask(vec!["shared".to_owned()])).await.expect("shared");
    assert!(shared.first().is_some_and(|line| line.ends_with(&format!("\tuntil {}", now + 2))), "{shared:?}");
    // Not yet, then gone, and what's shared with it as a guest
    member.expire().expect("expire");
    assert!(member.is_visitor(&thin.peer_id()));
    assert!(!member.catalog().guest_claims(&visitor.id()).expect("claims").is_empty());
    while super::now_secs() < now + 2 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    member.expire().expect("expire");
    assert!(!member.is_visitor(&thin.peer_id()));
    assert!(member.catalog().guest_claims(&visitor.id()).expect("claims").is_empty());
    assert!(serving(&mut [&mut member], thin.ask(vec!["shared".to_owned()])).await.is_err());
}

/// Drive both nodes until the first's check is done, and say what it
/// found.
async fn checked(a: &mut Node, b: &mut Node, id: CheckId) -> crate::health::Known {
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    loop {
        let event = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                event = a.next() => event,
                event = b.next() => event,
            }
        });
        if let Event::Checked { id: done, known } = event.await.expect("in time").expect("event")
            && done == id
        {
            return known;
        }
    }
}

/// Who a check found holding a block.
fn holders(known: &crate::health::Known, block: &Block) -> Vec<String> {
    known.elsewhere.get(&block.cid().multihash().to_bytes()).map(|copies| copies.iter().map(|copy| copy.peer.clone()).collect()).unwrap_or_default()
}

#[tokio::test]
async fn a_check_asks_members_only_of_what_it_hasnt_sighted_unless_told_to() {
    let (mut a, mut b, blocks) = Box::pin(holding()).await;
    let leaf = blocks.get(2).expect("leaf");
    b.catalog().put_block(leaf, CidVersion::V1).expect("put");
    let all = keys(&blocks);
    // Going by sightings alone, there are none yet, and no one's asked
    let id = a.check(&all, Asking::No).expect("check");
    let known = checked(&mut a, &mut b, id).await;
    assert!(known.node && known.asked.is_empty() && known.elsewhere.values().all(Vec::is_empty), "{known:?}");
    // Asked, b says it holds the leaf, and nothing else
    let id = a.check(&all, Asking::Unsighted).expect("check");
    let known = checked(&mut a, &mut b, id).await;
    assert_eq!(known.asked.iter().collect::<Vec<_>>(), [&b.peer_id().to_string()]);
    assert_eq!(holders(&known, leaf), [b.peer_id().to_string()]);
    assert!(blocks.iter().filter(|block| *block != leaf).all(|block| holders(&known, block).is_empty()));
    // Which is sighted now, so it's not asked about again, though b's let
    // it go without saying
    b.catalog().drop_copies(leaf.cid().multihash()).expect("drop");
    let id = a.check(&keys(std::slice::from_ref(leaf)), Asking::Unsighted).expect("check");
    let known = checked(&mut a, &mut b, id).await;
    assert!(known.asked.is_empty());
    assert_eq!(holders(&known, leaf), [b.peer_id().to_string()]);
    // Asking about everything finds it gone, and the sighting's forgotten
    let id = a.check(&all, Asking::All).expect("check");
    let known = checked(&mut a, &mut b, id).await;
    assert!(holders(&known, leaf).is_empty());
    assert!(a.sightings().of(leaf.cid().multihash()).expect("sighted").is_empty());
}

//-----------//
//-[ Serve ]-//
//-----------//

/// Drive both nodes until the first has an answer for a session.
async fn served_answer(nodes: &mut [&mut Node], session: u64) -> crate::ninep::Rmsg {
    let deadline = tokio::time::Instant::now().checked_add(Duration::from_secs(10)).expect("deadline");
    loop {
        let events = futures::future::select_all(nodes.iter_mut().map(|node| Box::pin(node.next())));
        let (event, from, _) = tokio::time::timeout_at(deadline, events).await.expect("in time");
        if let (0, Event::Served { session: of, message }) = (from, event.expect("event"))
            && of == session
        {
            return crate::ninep::Rmsg::decode(&message).expect("an answer").1;
        }
    }
}

/// A node serving an anchor from a filesystem in memory, on a socket its
/// config names.
fn serve_memfs(node: &mut Node, scratch: &crate::testutil::Scratch, fs: crate::ninep::memfs::MemFs) -> (Link, crate::ninep::memfs::Shared) {
    use std::os::unix::fs::PermissionsExt as _;
    let (run, repo) = (scratch.path().join("run"), scratch.path().join("repo"));
    for dir in [&run, &repo] {
        std::fs::create_dir_all(dir).expect("mkdir");
    }
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let socket = run.join("fs.9p");
    let shared = crate::ninep::memfs::Shared::new(fs);
    crate::ninep::memfs::listen(shared.clone(), &socket).expect("listen");
    std::fs::write(repo.join(crate::config::FILE), format!("[[serve]]\nname = \"notes\"\nsocket = {:?}\n", socket.display().to_string())).expect("config");
    std::fs::set_permissions(repo.join(crate::config::FILE), std::fs::Permissions::from_mode(0o644)).expect("chmod");
    node.set_repo(repo);
    let anchor = node.catalog().new_anchor().expect("anchor");
    node.catalog().serve_anchor(&anchor, &node.peer_id().to_bytes(), "notes", false).expect("serve");
    (anchor, shared)
}

#[tokio::test]
async fn a_member_reaches_an_anchor_another_serves_as_that_node_says() {
    use crate::ninep::{NOFID, Rmsg, Tmsg};
    let (mut a, mut b, _) = Box::pin(holding()).await;
    let scratch = crate::testutil::Scratch::new("node-served");
    let mut fs = crate::ninep::memfs::MemFs::new();
    fs.file("hello", b"hello from b");
    let (anchor, shared) = serve_memfs(&mut b, &scratch, fs);
    let peer = b.peer_id();

    // As root, of another tree, as a uid of b's: none of which b believes
    let attach = Tmsg::Attach { fid: 1, afid: NOFID, uname: b"root".to_vec(), aname: b"/".to_vec(), n_uname: 0 }.encode(1).expect("encode");
    a.ask_served(&peer, 7, &anchor, "notes", attach).expect("ask");
    assert!(matches!(served_answer(&mut [&mut a, &mut b], 7).await, Rmsg::Attach { .. }));
    let attached = shared.lock().attached.clone();
    let first = attached.first().expect("attached");
    assert_eq!((first.aname.clone(), first.n_uname), (anchor.to_string().into_bytes(), crate::ninep::NONUNAME));
    assert_ne!(first.uname, b"root");

    // Then whatever it serves
    let walk = Tmsg::Walk { fid: 1, newfid: 2, names: vec![b"hello".to_vec()] }.encode(2).expect("encode");
    a.ask_served(&peer, 7, &anchor, "notes", walk).expect("ask");
    assert!(matches!(served_answer(&mut [&mut a, &mut b], 7).await, Rmsg::Walk { .. }));
    a.ask_served(&peer, 7, &anchor, "notes", Tmsg::Lopen { fid: 2, flags: 0 }.encode(3).expect("encode")).expect("ask");
    served_answer(&mut [&mut a, &mut b], 7).await;
    a.ask_served(&peer, 7, &anchor, "notes", Tmsg::Read { fid: 2, offset: 0, count: 100 }.encode(4).expect("encode")).expect("ask");
    assert_eq!(served_answer(&mut [&mut a, &mut b], 7).await, Rmsg::Read { data: b"hello from b".to_vec() });

    // An anchor b doesn't serve so, or a service it hasn't, isn't reached
    let other = b.catalog().new_anchor().expect("anchor");
    let attach = Tmsg::Attach { fid: 1, afid: NOFID, uname: Vec::new(), aname: Vec::new(), n_uname: 0 }.encode(1).expect("encode");
    a.ask_served(&peer, 8, &other, "notes", attach.clone()).expect("ask");
    assert_eq!(served_answer(&mut [&mut a, &mut b], 8).await, Rmsg::Lerror { ecode: 13 });
    a.ask_served(&peer, 9, &anchor, "other", attach).expect("ask");
    assert_eq!(served_answer(&mut [&mut a, &mut b], 9).await, Rmsg::Lerror { ecode: 13 });
    assert_eq!(shared.lock().attached.len(), 1, "nothing connected to for either");

    // An ended session's fids are the service's no more
    a.end_served(&peer, 7, &anchor, "notes");
    a.ask_served(&peer, 7, &anchor, "notes", Tmsg::Read { fid: 2, offset: 0, count: 100 }.encode(5).expect("encode")).expect("ask");
    assert!(matches!(served_answer(&mut [&mut a, &mut b], 7).await, Rmsg::Lerror { .. }), "a new session, with no such fid");
}

#[tokio::test]
async fn only_machines_hosting_its_user_reach_what_a_node_serves() {
    use crate::ninep::{NOFID, Rmsg, Tmsg};
    let (mut server, mut mine, mut theirs, _, (me, _)) = Box::pin(shared_by()).await;
    let scratch = crate::testutil::Scratch::new("node-served-users");
    let (anchor, shared) = serve_memfs(&mut server, &scratch, crate::ninep::memfs::MemFs::new());
    let peer = server.peer_id();
    let attach = Tmsg::Attach { fid: 1, afid: NOFID, uname: Vec::new(), aname: Vec::new(), n_uname: 0 }.encode(1).expect("encode");

    // My laptop, as me
    mine.ask_served(&peer, 1, &anchor, "notes", attach.clone()).expect("ask");
    assert!(matches!(served_answer(&mut [&mut mine, &mut server, &mut theirs], 1).await, Rmsg::Attach { .. }));
    assert_eq!(shared.lock().attached.first().map(|attached| attached.uname.clone()), Some(me.id().to_string().into_bytes()), "who's asking, as the server says");

    // Theirs, as them, or saying it's me
    theirs.ask_served(&peer, 2, &anchor, "notes", attach.clone()).expect("ask");
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Lerror { ecode: 13 });
    let forged = crate::net::serve::Asked {
        user: Some(serde_bytes::ByteBuf::from(me.id().to_bytes())),
        session: 3,
        anchor: serde_bytes::ByteBuf::from(anchor.to_bytes()),
        service: "notes".into(),
        message: serde_bytes::ByteBuf::from(attach.clone()),
    };
    let request = theirs.swarm.behaviour_mut().serve.send_request(&peer, forged);
    theirs.asking_served.insert(request, (3, attach));
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 3).await, Rmsg::Lerror { ecode: 13 });
    assert_eq!(shared.lock().attached.len(), 1, "theirs never reached it");
}

/// Another user reaches what a node serves of an anchor only as grants on
/// it say: nothing without, reading with `/anchor/read`, and changing it
/// only with `/anchor/write`. The serve claim reaches them as a guest, and
/// a session stays theirs.
#[tokio::test]
async fn other_users_reach_what_a_node_serves_as_grants_on_it_say() {
    use crate::grants::{READ, USER, WRITE};
    use crate::ninep::{NOFID, Rmsg, Tmsg};
    let (mut server, mut mine, mut theirs, _, (me, them)) = Box::pin(shared_by()).await;
    let genesis = found(&mut [&mut server, &mut mine, &mut theirs], &me);
    server.catalog().grant(&genesis, &[them.id()], &[USER.to_owned()], &[]).expect("grant");
    server.reload().expect("reload");
    assert!(until(&mut [&mut server, &mut mine, &mut theirs], |n| says(n[2], &them.id(), USER)).await);
    let scratch = crate::testutil::Scratch::new("node-served-guests");
    let mut fs = crate::ninep::memfs::MemFs::new();
    fs.file("hello", b"hello");
    let (anchor, shared) = serve_memfs(&mut server, &scratch, fs);
    let view = crate::claim::view(&anchor, &me.id()).expect("view");
    let peer = server.peer_id();
    let ask = |node: &mut Node, session: u64, message: Tmsg, tag: u16| node.ask_served(&peer, session, &view, "notes", message.encode(tag).expect("encode")).expect("ask");
    let attach = || Tmsg::Attach { fid: 1, afid: NOFID, uname: Vec::new(), aname: Vec::new(), n_uname: 0 };

    // Nothing's shared
    ask(&mut theirs, 1, attach(), 1);
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 1).await, Rmsg::Lerror { ecode: 13 });

    // Shared to read, which is all they may do, as themselves
    server.catalog().grant_on(&genesis, &anchor, &[them.id()], &[READ.to_owned()], &[], &[]).expect("share");
    server.reload().expect("reload");
    let shared_with = |n: &[&mut Node]| n[2].catalog().serving(&view).ok().flatten().is_some() && n[1].guest_of(&n[0].peer_id(), Some(&them.id().to_bytes())).ok().flatten().is_some();
    assert!(until(&mut [&mut theirs, &mut server, &mut mine], shared_with).await, "the serve claim's theirs to see, and they're a guest");
    ask(&mut theirs, 2, attach(), 1);
    assert!(matches!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Attach { .. }));
    let attached = shared.lock().attached.last().cloned().expect("attached");
    assert_eq!((attached.uname, attached.aname), (them.id().to_string().into_bytes(), anchor.to_string().into_bytes()), "who they are, and the anchor itself");
    ask(&mut theirs, 2, Tmsg::Walk { fid: 1, newfid: 2, names: vec![b"hello".to_vec()] }, 2);
    served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await;
    ask(&mut theirs, 2, Tmsg::Lopen { fid: 2, flags: 2 }, 3);
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Lerror { ecode: 30 }, "not to write");
    ask(&mut theirs, 2, Tmsg::Lopen { fid: 2, flags: 0 }, 4);
    served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await;
    ask(&mut theirs, 2, Tmsg::Read { fid: 2, offset: 0, count: 100 }, 5);
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Read { data: b"hello".to_vec() });
    ask(&mut theirs, 2, Tmsg::Write { fid: 2, offset: 0, data: b"mine now".to_vec() }, 6);
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Lerror { ecode: 30 });

    // A session's theirs alone: what's asked in it for anyone else, or of
    // another anchor, isn't sent
    let forged = crate::net::serve::Asked {
        user: Some(serde_bytes::ByteBuf::from(me.id().to_bytes())),
        session: 2,
        anchor: serde_bytes::ByteBuf::from(view.to_bytes()),
        service: "notes".into(),
        message: serde_bytes::ByteBuf::from(Tmsg::Clunk { fid: 2 }.encode(7).expect("encode")),
    };
    let request = theirs.swarm.behaviour_mut().serve.send_request(&peer, forged);
    theirs.asking_served.insert(request, (2, Tmsg::Clunk { fid: 2 }.encode(7).expect("encode")));
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Lerror { ecode: 13 });

    // Let write, they may
    server.catalog().grant_on(&genesis, &anchor, &[them.id()], &[WRITE.to_owned()], &[], &[]).expect("share");
    server.reload().expect("reload");
    ask(&mut theirs, 2, Tmsg::Write { fid: 2, offset: 0, data: b"ours".to_vec() }, 8);
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Write { count: 4 });

    // Taken away, nothing more
    server.catalog().grant_on(&genesis, &anchor, &[them.id()], &[], &[READ.to_owned(), WRITE.to_owned()], &[]).expect("unshare");
    server.reload().expect("reload");
    ask(&mut theirs, 2, Tmsg::Read { fid: 2, offset: 0, count: 100 }, 9);
    assert_eq!(served_answer(&mut [&mut theirs, &mut server, &mut mine], 2).await, Rmsg::Lerror { ecode: 13 });
}

/// What a device's called reaches every member, since it targets the
/// device's certificate, which they hold.
#[tokio::test]
async fn names_reach_every_member() {
    let (mut a, mut b, _) = Box::pin(holding()).await;
    one_user(&mut [&mut a, &mut b]);
    let (mine, theirs) = (a.catalog().signer().expect("signer").id(), b.catalog().signer().expect("signer").id());
    a.catalog().name_device(&mine, "ender").expect("name");
    a.catalog().name_device(&theirs, "theseus").expect("name");
    a.announce().expect("announce");
    let names = |node: &Node| node.catalog().device_names().expect("names");
    let expected = |node: &Node| {
        let names = names(node);
        names.contains(&(mine.clone(), "ender".to_owned())) && names.contains(&(theirs.clone(), "theseus".to_owned()))
    };
    assert!(until(&mut [&mut a, &mut b], |n| expected(n[1])).await, "{:?}", names(&b));
    // Renamed, the tomb goes the same way
    a.catalog().name_device(&theirs, "theseus-desk").expect("rename");
    a.announce().expect("announce");
    assert!(until(&mut [&mut a, &mut b], |n| names(n[1]).contains(&(theirs.clone(), "theseus-desk".to_owned()))).await, "{:?}", names(&b));
}
