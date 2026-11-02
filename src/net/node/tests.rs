use super::*;
use crate::net::mesh::{self, Ticket};
use crate::store::Db;
use libp2p::core::transport::MemoryTransport;
use libp2p::multiaddr::Protocol;

/// A node over the in-memory transport, listening at a fresh address.
async fn node(swarm_key: PreSharedKey) -> Node {
    let key = Keypair::generate_ed25519();
    let members = Members::open(Db::memory().expect("db"), crate::net::mesh::MAIN).expect("members");
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
    let ticket = Ticket { swarm_key, inviter: inviter.peer_id(), members, user: None, protected: false };
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
        node.cursors.set(&peer, latest).expect("cursor");
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
    // A key the user never certified, as a stranger's
    a.catalog_mut().set_signer(crate::keys::Key::generate().expect("key")).expect("signer");
    a.catalog().tag(&link(unsigned), &link(&other)).expect("tag");
    assert!(tags(&a, unsigned).is_empty(), "not even where it was made");

    assert_eq!(fetch(&mut a, &mut b, link(signed)).await.0, 1);
    assert_eq!(fetch(&mut a, &mut b, link(unsigned)).await.0, 1);
    assert!(until(&mut [&mut a, &mut b], |n| tags(n[1], signed) == [link(&tag)]).await);
    // The stranger's tag arrived along with its leaf, but doesn't count
    let claims = b.catalog().claims().expect("claims");
    assert!(!claims.backrefs(unsigned.cid().multihash()).expect("backrefs").is_empty());
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
        (0, a.trim(2, keys(&blocks)).expect("trim")),
        (1, b.trim(2, keys(&blocks)).expect("trim")),
        (2, c.trim(2, keys(&blocks)).expect("trim")),
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
    let trims = [(0, a.trim(2, keys(&blocks)).expect("trim")), (1, b.trim(2, keys(&blocks)).expect("trim"))];
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
    let id = a.trim(1, keys(std::slice::from_ref(leaf))).expect("trim");
    let reports = trimmed(&mut [&mut a, &mut b], &[(0, id)]).await;
    assert_eq!(reports, [trim::Report { considered: 1, dropped: 0, freed: 0 }]);
    assert!(has(&a, leaf));
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
    let id = a.trim(1, keys(std::slice::from_ref(leaf))).expect("trim");
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
