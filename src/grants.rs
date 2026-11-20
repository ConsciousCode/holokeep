//! Who holds what in a mesh: its grants, worked out (see `claim::Grant`).
//!
//! A mesh's grants are one history, by `prev`, from its first, which gives
//! its founder `/`. Every machine works out the same answer from the same
//! grants, whatever order they arrived in. Grants are worked out in
//! **scopes**: the mesh's own, those without `on`, from its founder; and
//! each user's view of an anchor, those `on` it, from that user, who holds
//! `/anchor` on their own view of every anchor. A grant on an anchor is
//! about the view of whoever it's judged from: "I'll take your sets on
//! this as mine", not anything of the anchor's everywhere. In each:
//!
//! - **A grant is valid** if one of the users who signed it held, in the
//!   state its `prev` names (its ancestors, worked out alone), what it
//!   needs: `/mesh/user`, the scope's power to give (`/mesh/grant`, or
//!   `/anchor/grant` on the anchor), and each command it gives or takes
//!   away.
//! - **Taking away undoes what was concurrent with it.** A valid grant
//!   doesn't count for a signer who, once the grants taking away that
//!   count and are concurrent with it (neither is before the other) are
//!   heeded too, no longer holds what it needs: whether taken from them,
//!   or gone with what they were given by someone taken away. So a `prev`
//!   from before one's power went gains nothing, however late it's made.
//!   Grants taking away are decided first, the most senior signer's first
//!   (whoever was given the power to give earliest, whoever it's judged
//!   from before all), so when two take each other's commands away
//!   concurrently, the senior keeps theirs.
//! - **Taking away wins.** A command given is held unless a grant that
//!   counts takes it away after, or concurrently.
//! - **What was given goes with the giver's power to give it**: a command
//!   given is held only while whoever gave it holds the power to give and
//!   the command, and `/mesh/user`, however that came about, unless
//!   someone else gave it too.
//! - **The founder always holds everything**, and a user everything on
//!   their own view of an anchor, while they're a user of the mesh.
//!
//! Grants on roles are kept, but not yet worked out.
//!
//! Every grant's state at its `prev` is worked out afresh, and again with
//! what's taken away concurrently with it, if anything is: polynomial, of
//! low degree, in grants, fine for the dozens a mesh has.

use std::collections::BTreeMap;

use crate::cid::CidRef as _;
use crate::claim::{Grant, covers};
use crate::model::Link;

/// Being a user of the mesh: acting in it at all.
pub const USER: &str = "/mesh/user";
/// Being a machine of the mesh: in its roster, holding its plaintext.
pub const MACHINE: &str = "/mesh/machine";
/// Being a client of the mesh: a device of one of its users that's no
/// machine, let in by every member serving its user where it listens for
/// clients, and counted on for nothing.
pub const CLIENT: &str = "/mesh/client";
/// Giving and taking away the mesh commands one holds.
pub const GRANT: &str = "/mesh/grant";
/// Every mesh command: an operator's.
pub const OPERATOR: &str = "/mesh";
/// Every command on an anchor: its owner's, on their own view of it.
pub const ANCHOR: &str = "/anchor";
/// Seeing what someone's view of an anchor is, and reaches.
pub const READ: &str = "/anchor/read";
/// Sets on an anchor, for its owner, that count in their view of it.
pub const WRITE: &str = "/anchor/write";
/// Giving and taking away the commands on an anchor one holds.
pub const ANCHOR_GRANT: &str = "/anchor/grant";

/// A grant, and the users who signed it: a user's root key signing, or a
/// device the user certified.
#[derive(Debug, Clone)]
pub struct Signed {
    pub cid: Link,
    pub grant: Grant,
    pub by: Vec<Link>,
}

struct Node {
    cid: Link,
    grant: Grant,
    by: Vec<Link>,
    /// Indices of the grants before it, by `prev`, however far back.
    before: Vec<bool>,
    /// The longest path back to the first.
    depth: usize,
}

/// Whose commands, on what: the mesh's, from its founder, or one user's on
/// their view of an anchor.
#[derive(Clone)]
struct Scope {
    founder: Link,
    on: Option<Link>,
}

impl Scope {
    /// The command to give and take away in it.
    const fn grant(&self) -> &'static str {
        if self.on.is_none() { GRANT } else { ANCHOR_GRANT }
    }

    const fn is_mesh(&self) -> bool {
        self.on.is_none()
    }
}

impl Node {
    /// What its signer must hold in a scope: the commands it gives and
    /// takes away, and the scope's power to give, and on the mesh, to act
    /// at all. (On an anchor, being a user is a matter for the mesh.)
    fn needs<'a>(&'a self, scope: &Scope) -> impl Iterator<Item = &'a str> {
        let base: &[&'static str] = if scope.is_mesh() { &[USER, GRANT] } else { &[ANCHOR_GRANT] };
        base.iter().copied().chain(self.grant.add().iter().chain(self.grant.del()).map(String::as_str))
    }

    /// What its giver must hold for what it gives to be held.
    fn gift_needs<'a>(&'a self, scope: &Scope) -> impl Iterator<Item = &'a str> {
        let base: &[&'static str] = if scope.is_mesh() { &[USER, GRANT] } else { &[ANCHOR_GRANT] };
        base.iter().copied().chain(self.grant.add().iter().map(String::as_str))
    }

    fn in_scope(&self, scope: &Scope) -> bool {
        self.grant.on() == scope.on.as_ref()
    }

    fn targets(&self, who: &Link) -> bool {
        self.grant.target().contains(who)
    }
}

/// Whether two commands overlap: holding one or the other, some of the
/// same is held.
fn overlap(a: &str, b: &str) -> bool {
    covers(a, b) || covers(b, a)
}

/// One scope's grants, worked out.
struct Judgement {
    scope: Scope,
    /// The users each valid grant's valid for: those of its signers who
    /// held what it needs. Empty for those not in the scope.
    valid: Vec<Vec<Link>>,
    /// Each grant's state at its `prev`: its ancestors, worked out alone.
    prior: Vec<Judged>,
    judged: Judged,
}

/// Which grants of some set count, and which given commands are held.
#[derive(Clone)]
struct Judged {
    /// Grants that count, each with the signers it counts for.
    counts: Vec<Option<Vec<Link>>>,
    /// Grants giving commands whose giver can give them still.
    supported: Vec<bool>,
}

impl Judged {
    const fn empty() -> Self {
        Self { counts: Vec::new(), supported: Vec::new() }
    }
}

/// What a user holds on someone's view of an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Whose view.
    pub owner: Link,
    pub anchor: Link,
    pub user: Link,
    /// The commands on it they hold, of those given them.
    pub held: Vec<String>,
    /// Their sets that still count in the owner's view, write taken away
    /// from them: those `stands` named, and before them.
    pub stands: Vec<Link>,
}

/// A mesh's grants, worked out.
pub struct State {
    founder: Link,
    nodes: Vec<Node>,
    mesh: Judgement,
    /// Each view of an anchor someone's granted on, by (owner, anchor).
    anchors: Vec<Judgement>,
    /// Grants which name a grant that isn't here, or that do, however far
    /// back: they wait till it is.
    waiting: Vec<Link>,
}

impl State {
    /// Work out a mesh's grants from its first, `genesis`, which must give
    /// its one target, the founder, `/`, signed by them. None, if it
    /// doesn't, or isn't among them.
    pub fn new(genesis: &Link, grants: impl IntoIterator<Item = Signed>) -> Option<Self> {
        let all: BTreeMap<Vec<u8>, Signed> = grants.into_iter().map(|signed| (signed.cid.to_bytes(), signed)).collect();
        let first = all.get(&genesis.to_bytes())?;
        let [founder] = first.grant.target() else {
            return None;
        };
        let founding = first.grant.prev().is_empty() && first.grant.on().is_none() && first.grant.del().is_empty() && first.grant.add() == ["/"];
        (founding && first.by.contains(founder)).then_some(())?;
        let founder = founder.clone();

        // Those reaching the first by `prev`, in order: by depth, then CID
        let mut depth: BTreeMap<Vec<u8>, usize> = BTreeMap::from([(genesis.to_bytes(), 0)]);
        let mut pending: Vec<&Signed> = all.values().filter(|signed| signed.cid != *genesis && !signed.grant.prev().is_empty()).collect();
        loop {
            let before = pending.len();
            pending.retain(|signed| {
                let deepest = signed.grant.prev().iter().map(|prev| depth.get(&prev.to_bytes()).copied()).collect::<Option<Vec<_>>>();
                deepest.is_none_or(|prev| {
                    depth.insert(signed.cid.to_bytes(), prev.into_iter().max().unwrap_or_default().saturating_add(1));
                    false
                })
            });
            if pending.len() == before {
                break;
            }
        }
        let waiting = pending.iter().map(|signed| signed.cid.clone()).collect();
        let mut order: Vec<(usize, Vec<u8>)> = depth.into_iter().map(|(cid, depth)| (depth, cid)).collect();
        order.sort();
        let index: BTreeMap<&[u8], usize> = order.iter().enumerate().map(|(i, (_, cid))| (cid.as_slice(), i)).collect();
        let mut nodes: Vec<Node> = Vec::with_capacity(order.len());
        for (depth, cid) in &order {
            let Some(signed) = all.get(cid) else {
                continue;
            };
            let mut before = vec![false; order.len()];
            for prev in signed.grant.prev() {
                if let Some(&i) = index.get(prev.to_bytes().as_slice())
                    && let Some(node) = nodes.get(i)
                {
                    for (j, &earlier) in node.before.iter().enumerate() {
                        if earlier && let Some(slot) = before.get_mut(j) {
                            *slot = true;
                        }
                    }
                    if let Some(slot) = before.get_mut(i) {
                        *slot = true;
                    }
                }
            }
            nodes.push(Node { cid: signed.cid.clone(), grant: signed.grant.clone(), by: signed.by.clone(), before, depth: *depth });
        }

        let mut state = Self {
            founder: founder.clone(),
            nodes,
            mesh: Judgement { scope: Scope { founder, on: None }, valid: Vec::new(), prior: Vec::new(), judged: Judged::empty() },
            anchors: Vec::new(),
            waiting,
        };
        state.mesh = state.work_out(state.mesh.scope.clone(), None);
        // Every view of an anchor granted on: by whoever signed a grant on it
        let mut views: BTreeMap<(Vec<u8>, Vec<u8>), (Link, Link)> = BTreeMap::new();
        for node in &state.nodes {
            if let Some(anchor) = node.grant.on().filter(|on| crate::claim::is_anchor(on)) {
                for by in &node.by {
                    views.entry((by.to_bytes(), anchor.to_bytes())).or_insert_with(|| (by.clone(), anchor.clone()));
                }
            }
        }
        let anchors = views.into_values().map(|(owner, anchor)| state.work_out(Scope { founder: owner, on: Some(anchor) }, Some(&state.mesh))).collect();
        state.anchors = anchors;
        Some(state)
    }

    /// Work out a scope's grants: each one's state at its `prev`, whom it's
    /// valid for, and then all of them. An anchor's scope, given the mesh's,
    /// asks it whether a signer's a user.
    fn work_out(&self, scope: Scope, mesh: Option<&Judgement>) -> Judgement {
        let n = self.nodes.len();
        let mut judgement = Judgement { scope, valid: Vec::with_capacity(n), prior: Vec::with_capacity(n), judged: Judged::empty() };
        for i in 0..n {
            let Some(node) = self.nodes.get(i) else {
                continue;
            };
            let in_scope = node.in_scope(&judgement.scope);
            // The mesh's state at every grant's `prev`, since an anchor's
            // scope asks it; an anchor's, only at its own grants
            if !in_scope && !judgement.scope.is_mesh() {
                judgement.valid.push(Vec::new());
                judgement.prior.push(Judged::empty());
                continue;
            }
            let users = mesh.and_then(|mesh| mesh.prior.get(i).map(|prior| (mesh, prior)));
            let judged = self.judge(&judgement, users, &node.before);
            let valid = if !in_scope {
                Vec::new()
            } else if i == 0 {
                vec![self.founder.clone()]
            } else {
                let scope = &judgement.scope;
                node.by
                    .iter()
                    .filter(|&by| {
                        let user = users.is_none_or(|(mesh, prior)| self.holds_in(mesh, prior, by, USER));
                        user && (*by == scope.founder || node.needs(scope).all(|need| self.holds_in(&judgement, &judged, by, need)))
                    })
                    .cloned()
                    .collect()
            };
            judgement.valid.push(valid);
            judgement.prior.push(judged);
        }
        let everything = vec![true; n];
        judgement.judged = self.judge(&judgement, mesh.map(|mesh| (mesh, &mesh.judged)), &everything);
        judgement
    }

    /// Which of a set of grants count, and which of those giving are
    /// supported, from which of them are valid, in a scope; on an anchor,
    /// with who's a user as a state of the mesh's says.
    fn judge(&self, judgement: &Judgement, users: Option<(&Judgement, &Judged)>, members: &[bool]) -> Judged {
        let scope = &judgement.scope;
        let n = self.nodes.len();
        let member = |i: usize| {
            members.get(i).copied().unwrap_or(false)
                && self.nodes.get(i).is_some_and(|node| node.in_scope(scope))
                && judgement.valid.get(i).is_some_and(|valid| !valid.is_empty())
        };
        // Seniority: when each user was first given what lets them give
        let mut rank: BTreeMap<Vec<u8>, usize> = BTreeMap::from([(scope.founder.to_bytes(), 0)]);
        for (i, node) in self.nodes.iter().enumerate() {
            if member(i) && node.grant.add().iter().any(|add| covers(add, scope.grant())) {
                for target in node.grant.target() {
                    rank.entry(target.to_bytes()).or_insert_with(|| i.saturating_add(1));
                }
            }
        }
        let rank_of = |who: &Link| rank.get(&who.to_bytes()).copied().unwrap_or(usize::MAX);

        let mut counts: Vec<Option<Vec<Link>>> = vec![None; n];
        // Who of its signers a grant still counts for: those who, in its
        // state at its `prev` with the takings decided so far that are
        // concurrent with it heeded too, still hold what it needs; and on
        // an anchor, are users still, in the mesh's state so heeded.
        let standing = |i: usize, counts: &[Option<Vec<Link>>]| -> Vec<Link> {
            let (Some(node), Some(valid)) = (self.nodes.get(i), judgement.valid.get(i)) else {
                return Vec::new();
            };
            let mesh = users.map(|(mesh, _)| (mesh, self.heeded(mesh, None, i, &mesh.judged.counts)));
            let heeded = self.heeded(judgement, mesh.as_ref().map(|(mesh, state)| (*mesh, state)), i, counts);
            valid
                .iter()
                .filter(|&signer| {
                    let user = mesh.as_ref().is_none_or(|(mesh, state)| self.holds_in(mesh, state, signer, USER));
                    user && (*signer == scope.founder || node.needs(scope).all(|need| self.holds_in(judgement, &heeded, signer, need)))
                })
                .cloned()
                .collect()
        };
        let mut taking: Vec<usize> = (0..n).filter(|&i| member(i) && self.nodes.get(i).is_some_and(|node| !node.grant.del().is_empty())).collect();
        taking.sort_by_key(|&i| {
            let senior = judgement.valid.get(i).and_then(|valid| valid.iter().map(rank_of).min()).unwrap_or(usize::MAX);
            (senior, self.nodes.get(i).map(|node| (node.depth, node.cid.to_bytes())))
        });
        for &i in &taking {
            let stands = standing(i, &counts);
            if let Some(slot) = counts.get_mut(i) {
                *slot = (!stands.is_empty()).then_some(stands);
            }
        }
        let decided = counts.clone();
        for i in (0..n).filter(|&i| member(i) && !taking.contains(&i)) {
            let stands = standing(i, &decided);
            if let Some(slot) = counts.get_mut(i) {
                *slot = (!stands.is_empty()).then_some(stands);
            }
        }
        self.support(judgement, users, counts, |_| true)
    }

    /// Whether neither of two grants is before the other.
    fn concurrent(&self, i: usize, j: usize) -> bool {
        let (Some(a), Some(b)) = (self.nodes.get(i), self.nodes.get(j)) else {
            return false;
        };
        i != j && !a.before.get(j).copied().unwrap_or(false) && !b.before.get(i).copied().unwrap_or(false)
    }

    /// A grant's state at its `prev` in a scope, with what counts of these,
    /// concurrent with it, heeded too: only what its ancestors gave is held
    /// there, as what's given concurrently makes nothing valid.
    fn heeded(&self, judgement: &Judgement, users: Option<(&Judgement, &Judged)>, i: usize, counts: &[Option<Vec<Link>>]) -> Judged {
        let n = self.nodes.len();
        let (Some(node), Some(prior)) = (self.nodes.get(i), judgement.prior.get(i)) else {
            return Judged::empty();
        };
        let ancestor = |j: usize| node.before.get(j).copied().unwrap_or(false);
        let taken = |j: usize| counts.get(j).is_some_and(Option::is_some) && self.concurrent(i, j);
        if !(0..n).any(taken) {
            return prior.clone();
        }
        let seen: Vec<Option<Vec<Link>>> = (0..n)
            .map(|j| {
                if ancestor(j) {
                    prior.counts.get(j).cloned().flatten()
                } else if taken(j) {
                    counts.get(j).cloned().flatten()
                } else {
                    None
                }
            })
            .collect();
        self.support(judgement, users, seen, ancestor)
    }

    /// Which grants giving, among some that count, are supported: what's
    /// given is held while its giver can give it, from whoever it's judged
    /// from out, as far as that goes; on an anchor, while its giver's a
    /// user, in a state of the mesh's.
    fn support(&self, judgement: &Judgement, users: Option<(&Judgement, &Judged)>, counts: Vec<Option<Vec<Link>>>, among: impl Fn(usize) -> bool) -> Judged {
        let scope = &judgement.scope;
        let n = self.nodes.len();
        let mut judged = Judged { counts, supported: vec![false; n] };
        loop {
            let mut grew = false;
            for i in (0..n).filter(|&i| among(i)) {
                if judged.supported.get(i).copied().unwrap_or(true) {
                    continue;
                }
                let (Some(node), Some(Some(signers))) = (self.nodes.get(i), judged.counts.get(i)) else {
                    continue;
                };
                if node.grant.add().is_empty() || !node.in_scope(scope) {
                    continue;
                }
                let gives = signers.iter().any(|signer| {
                    let user = users.is_none_or(|(mesh, state)| self.holds_in(mesh, state, signer, USER));
                    user && (*signer == scope.founder || node.gift_needs(scope).all(|need| self.holds_in_judged(scope, &judged, signer, need)))
                });
                if gives && let Some(slot) = judged.supported.get_mut(i) {
                    *slot = true;
                    grew = true;
                }
            }
            if !grew {
                return judged;
            }
        }
    }

    /// Whether someone holds a command in a scope, as some grants are
    /// judged: given by a supported grant, and not taken away after or
    /// concurrently by one that counts.
    fn holds_in(&self, judgement: &Judgement, judged: &Judged, who: &Link, command: &str) -> bool {
        self.holds_in_judged(&judgement.scope, judged, who, command)
    }

    fn holds_in_judged(&self, scope: &Scope, judged: &Judged, who: &Link, command: &str) -> bool {
        if *who == scope.founder {
            return true;
        }
        self.nodes.iter().enumerate().any(|(i, giving)| {
            judged.supported.get(i).copied().unwrap_or(false)
                && giving.in_scope(scope)
                && giving.targets(who)
                && giving.grant.add().iter().any(|add| covers(add, command))
                && !self.nodes.iter().enumerate().any(|(j, taking)| {
                    judged.counts.get(j).is_some_and(Option::is_some)
                        && taking.in_scope(scope)
                        && taking.targets(who)
                        && !giving.before.get(j).copied().unwrap_or(false)
                        && taking.grant.del().iter().any(|del| overlap(del, command))
                })
        })
    }

    /// Whether someone holds a command on the mesh.
    pub fn holds(&self, who: &Link, command: &str) -> bool {
        self.holds_in(&self.mesh, &self.mesh.judged, who, command)
    }

    /// The view of an anchor an owner's granted on, if they have.
    fn view(&self, owner: &Link, anchor: &Link) -> Option<&Judgement> {
        self.anchors.iter().find(|view| view.scope.founder == *owner && view.scope.on.as_ref() == Some(anchor))
    }

    /// Whether the mesh's own grants name someone, given or taken anything
    /// there: its founder, or one of its users, machines or clients, now or
    /// before. Only one never named may be a visitor, so a user taken from
    /// the mesh doesn't keep what was shared with them.
    fn named(&self, who: &Link) -> bool {
        *who == self.founder || self.nodes.iter().any(|node| node.in_scope(&self.mesh.scope) && node.targets(who))
    }

    /// Whether someone holds a command on an owner's view of an anchor:
    /// the owner, everything while they're a user of the mesh; anyone
    /// else, as the owner's grants on it, and those they let others make,
    /// say. One the mesh's grants have never named, a visitor, holds only
    /// what lets it read: what it sets, or gives, no one's said counts.
    pub fn holds_on(&self, owner: &Link, anchor: &Link, who: &Link, command: &str) -> bool {
        if !self.holds(owner, USER) {
            return false;
        }
        if who == owner {
            return true;
        }
        if !self.holds(who, USER) && (self.named(who) || !covers(READ, command)) {
            return false;
        }
        self.view(owner, anchor).is_some_and(|view| self.holds_in(view, &view.judged, who, command))
    }

    /// Who holds what on each view of an anchor that's been granted on:
    /// everyone given anything there, with which of the commands given them
    /// they hold, and, write taken from them, which of their sets still
    /// count.
    pub fn shares(&self) -> Vec<Share> {
        let mut shares = Vec::new();
        for view in &self.anchors {
            let (owner, Some(anchor)) = (&view.scope.founder, &view.scope.on) else {
                continue;
            };
            let mut given: BTreeMap<Vec<u8>, (Link, std::collections::BTreeSet<String>, Vec<Link>)> = BTreeMap::new();
            for (i, node) in self.nodes.iter().enumerate().filter(|(_, node)| node.in_scope(&view.scope)) {
                let counts = view.judged.counts.get(i).is_some_and(Option::is_some);
                for target in node.grant.target().iter().filter(|target| *target != owner) {
                    let entry = given.entry(target.to_bytes()).or_insert_with(|| (target.clone(), std::collections::BTreeSet::new(), Vec::new()));
                    entry.1.extend(node.grant.add().iter().cloned());
                    if counts && node.grant.del().iter().any(|del| covers(del, WRITE)) {
                        entry.2.extend(node.grant.stands().iter().cloned());
                    }
                }
            }
            for (user, commands, mut stands) in given.into_values() {
                let held: Vec<String> = commands.into_iter().filter(|command| self.holds_on(owner, anchor, &user, command)).collect();
                if held.iter().any(|command| covers(command, WRITE)) {
                    stands.clear();
                }
                stands.sort_by_key(Link::to_bytes);
                stands.dedup();
                shares.push(Share { owner: owner.clone(), anchor: anchor.clone(), user, held, stands });
            }
        }
        shares
    }

    /// The mesh's founder, its first operator.
    pub const fn founder(&self) -> &Link {
        &self.founder
    }

    /// Whether a grant counts: on the mesh, or on an anchor, for whoever's
    /// view it's judged in.
    pub fn counts(&self, cid: &Link) -> bool {
        self.nodes.iter().position(|node| node.cid == *cid).is_some_and(|i| {
            std::iter::once(&self.mesh).chain(&self.anchors).any(|view| view.judged.counts.get(i).is_some_and(Option::is_some))
        })
    }

    /// The grants nothing here follows, which a new grant names as `prev`.
    pub fn heads(&self) -> Vec<Link> {
        let n = self.nodes.len();
        (0..n)
            .filter(|&i| !self.nodes.iter().any(|node| node.before.get(i).copied().unwrap_or(false)))
            .filter_map(|i| self.nodes.get(i).map(|node| node.cid.clone()))
            .collect()
    }

    /// Every grant reaching the first, in order.
    pub fn grants(&self) -> impl Iterator<Item = &Link> {
        self.nodes.iter().map(|node| &node.cid)
    }

    /// Grants waiting for one before them that isn't here.
    pub fn waiting(&self) -> &[Link] {
        &self.waiting
    }

    /// The mesh's users: who holds `/mesh/user`, the founder among them.
    pub fn users(&self) -> Vec<Link> {
        let mut users: Vec<Link> = std::iter::once(self.founder.clone())
            .chain(self.holders().into_iter().map(|(who, _)| who))
            .filter(|who| self.holds(who, USER))
            .collect();
        users.sort_by_key(crate::cid::CidRef::to_bytes);
        users.dedup();
        users
    }

    /// Everyone given anything on the mesh, with which of the commands
    /// they were given they hold now.
    pub fn holders(&self) -> Vec<(Link, Vec<String>)> {
        let mut given: BTreeMap<Vec<u8>, (Link, std::collections::BTreeSet<String>)> = BTreeMap::new();
        for node in self.nodes.iter().filter(|node| node.in_scope(&self.mesh.scope)) {
            for target in node.grant.target() {
                given.entry(target.to_bytes()).or_insert_with(|| (target.clone(), std::collections::BTreeSet::new())).1.extend(node.grant.add().iter().cloned());
            }
        }
        given.into_values()
            .map(|(who, commands)| {
                let held = commands.into_iter().filter(|command| self.holds(&who, command)).collect();
                (who, held)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::Claim;
    use crate::keys::Key;

    fn key() -> Link {
        Key::generate().expect("key").id()
    }

    /// A history of grants being made, each signed by one user.
    struct History {
        genesis: Link,
        grants: Vec<Signed>,
    }

    impl History {
        fn new(founder: &Link) -> Self {
            let grant = Grant::new([founder.clone()], None, ["/".to_owned()], [], [], []).expect("grant");
            let genesis = Claim::Grant(grant.clone()).cid();
            Self { genesis: genesis.clone(), grants: vec![Signed { cid: genesis, grant, by: vec![founder.clone()] }] }
        }

        /// `by` gives or takes away commands from `to`, having seen `prev`.
        fn grant(&mut self, by: &Link, to: &Link, add: &[&str], del: &[&str], prev: &[&Link]) -> Link {
            let strings = |list: &[&str]| list.iter().map(|&c| c.to_owned()).collect::<Vec<_>>();
            let grant = Grant::new([to.clone()], None, strings(add), strings(del), [], prev.iter().map(|&p| p.clone())).expect("grant");
            let cid = Claim::Grant(grant.clone()).cid();
            self.grants.push(Signed { cid: cid.clone(), grant, by: vec![by.clone()] });
            cid
        }

        /// `by` gives or takes away commands on their view of `anchor`, or
        /// one they hold commands on, from `to`.
        fn grant_on(&mut self, by: &Link, to: &Link, anchor: &Link, add: &[&str], del: &[&str], prev: &[&Link]) -> Link {
            self.push_on(by, to, anchor, (add, del), &[], prev)
        }

        /// `by` takes `/anchor/write` away from `to`, these of their sets
        /// standing.
        fn take_write(&mut self, by: &Link, to: &Link, anchor: &Link, stands: &[&Link], prev: &[&Link]) -> Link {
            self.push_on(by, to, anchor, (&[], &[WRITE]), stands, prev)
        }

        fn push_on(&mut self, by: &Link, to: &Link, anchor: &Link, (add, del): (&[&str], &[&str]), stands: &[&Link], prev: &[&Link]) -> Link {
            let strings = |list: &[&str]| list.iter().map(|&c| c.to_owned()).collect::<Vec<_>>();
            let grant = Grant::new([to.clone()], Some(anchor.clone()), strings(add), strings(del), stands.iter().map(|&s| s.clone()), prev.iter().map(|&p| p.clone())).expect("grant");
            let cid = Claim::Grant(grant.clone()).cid();
            self.grants.push(Signed { cid: cid.clone(), grant, by: vec![by.clone()] });
            cid
        }

        fn state(&self) -> State {
            State::new(&self.genesis, self.grants.iter().cloned()).expect("state")
        }
    }

    #[test]
    fn the_founder_holds_everything_and_gives_what_they_will() {
        let (founder, user, machine) = (key(), key(), key());
        let mut history = History::new(&founder);
        let g = history.genesis.clone();
        let recognized = history.grant(&founder, &user, &[USER], &[], &[&g]);
        history.grant(&founder, &machine, &[MACHINE], &[], &[&recognized]);
        let state = history.state();
        assert!(state.holds(&founder, "/anything/at/all"));
        assert!(state.holds(&user, USER) && !state.holds(&user, MACHINE) && !state.holds(&user, GRANT));
        assert!(state.holds(&machine, MACHINE) && !state.holds(&machine, USER));
        assert_eq!(state.heads().len(), 1);
        let holders = state.holders();
        assert_eq!(holders.len(), 3);
    }

    #[test]
    fn only_what_one_holds_can_be_given() {
        let (founder, user, other) = (key(), key(), key());
        let mut history = History::new(&founder);
        let g = history.genesis.clone();
        let recognized = history.grant(&founder, &user, &[USER], &[], &[&g]);
        // A user who can't give
        let forged = history.grant(&user, &other, &[USER], &[], &[&recognized]);
        let state = history.state();
        assert!(!state.counts(&forged) && !state.holds(&other, USER));
        // Given the power to give users, but not machines
        let delegated = history.grant(&founder, &user, &[GRANT], &[], &[&forged]);
        let given = history.grant(&user, &other, &[USER], &[], &[&delegated]);
        let machine = history.grant(&user, &other, &[MACHINE], &[], &[&given]);
        let state = history.state();
        assert!(state.counts(&given) && state.holds(&other, USER));
        assert!(!state.counts(&machine) && !state.holds(&other, MACHINE));
    }

    #[test]
    fn taking_away_wins_over_giving_concurrently() {
        let (founder, op, user) = (key(), key(), key());
        let mut history = History::new(&founder);
        let g = history.genesis.clone();
        let made = history.grant(&founder, &op, &[OPERATOR, USER], &[], &[&g]);
        let given = history.grant(&founder, &user, &[USER], &[], &[&made]);
        // The operator takes the user away while the founder gives again
        history.grant(&op, &user, &[], &[USER], &[&given]);
        history.grant(&founder, &user, &[USER], &[], &[&given]);
        assert!(!history.state().holds(&user, USER));
        // Given again after both, it's held
        let state = history.state();
        let heads = state.heads();
        let heads: Vec<&Link> = heads.iter().collect();
        history.grant(&founder, &user, &[USER], &[], &heads);
        assert!(history.state().holds(&user, USER));
    }

    #[test]
    fn taking_away_undoes_what_the_taken_did_concurrently() {
        let (founder, op, stranger) = (key(), key(), key());
        let mut history = History::new(&founder);
        let g = history.genesis.clone();
        let made = history.grant(&founder, &op, &[OPERATOR], &[], &[&g]);
        // The operator's device, unaware it's been demoted, admits a machine
        let removed = history.grant(&founder, &op, &[], &[OPERATOR], &[&made]);
        let admitted = history.grant(&op, &stranger, &[MACHINE], &[], &[&made]);
        let state = history.state();
        assert!(state.counts(&removed));
        assert!(!state.counts(&admitted));
        assert!(!state.holds(&stranger, MACHINE) && !state.holds(&op, MACHINE));
        // What it did before it was demoted stands, while it could give it
        let mut history = History::new(&founder);
        let made = history.grant(&founder, &op, &[OPERATOR], &[], &[&g]);
        let admitted = history.grant(&op, &stranger, &[MACHINE], &[], &[&made]);
        history.grant(&founder, &op, &[], &[GRANT], &[&admitted]);
        let state = history.state();
        assert!(state.counts(&admitted), "it counted, made before");
        assert!(!state.holds(&stranger, MACHINE), "but goes with the power to give it");
        assert!(state.holds(&op, MACHINE));
    }

    #[test]
    fn a_prev_from_before_ones_power_went_gains_nothing() {
        let (founder, op, deputy, machine, other) = (key(), key(), key(), key(), key());
        let mut history = History::new(&founder);
        let g = history.genesis.clone();
        let made = history.grant(&founder, &op, &[OPERATOR], &[], &[&g]);
        let deputized = history.grant(&op, &deputy, &[OPERATOR], &[], &[&made]);
        let admitted = history.grant(&founder, &machine, &[MACHINE], &[], &[&deputized]);
        // The operator's taken away, and with them what they gave the deputy
        let removed = history.grant(&founder, &op, &[], &[OPERATOR], &[&admitted]);
        assert!(!history.state().holds(&deputy, GRANT));
        // Ever after, the deputy, naming grants from before that, takes a
        // machine away, and gives one: neither counts
        let taken = history.grant(&deputy, &machine, &[], &[MACHINE], &[&admitted]);
        let given = history.grant(&deputy, &other, &[MACHINE], &[], &[&admitted]);
        let state = history.state();
        assert!(state.counts(&removed));
        assert!(!state.counts(&taken) && !state.counts(&given));
        assert!(state.holds(&machine, MACHINE) && !state.holds(&other, MACHINE));
        // Before the operator went, what the deputy did stands
        let mut history = History::new(&founder);
        let made = history.grant(&founder, &op, &[OPERATOR], &[], &[&g]);
        let deputized = history.grant(&op, &deputy, &[OPERATOR], &[], &[&made]);
        let admitted = history.grant(&founder, &machine, &[MACHINE], &[], &[&deputized]);
        let taken = history.grant(&deputy, &machine, &[], &[MACHINE], &[&admitted]);
        history.grant(&founder, &op, &[], &[OPERATOR], &[&taken]);
        let state = history.state();
        assert!(state.counts(&taken) && !state.holds(&machine, MACHINE));
        // And given the deputy's power another way concurrently, a stale
        // `prev` still gains nothing: it's what its ancestors gave that counts
        let mut history = History::new(&founder);
        let made = history.grant(&founder, &op, &[OPERATOR], &[], &[&g]);
        let deputized = history.grant(&op, &deputy, &[OPERATOR], &[], &[&made]);
        let admitted = history.grant(&founder, &machine, &[MACHINE], &[], &[&deputized]);
        let removed = history.grant(&founder, &op, &[], &[OPERATOR], &[&admitted]);
        history.grant(&founder, &deputy, &[OPERATOR], &[], &[&removed]);
        let taken = history.grant(&deputy, &machine, &[], &[MACHINE], &[&admitted]);
        let state = history.state();
        assert!(state.holds(&deputy, GRANT) && !state.counts(&taken) && state.holds(&machine, MACHINE));
    }

    #[test]
    fn of_two_taking_each_other_away_the_senior_keeps_theirs() {
        let (founder, first, second) = (key(), key(), key());
        let mut history = History::new(&founder);
        let g = history.genesis.clone();
        let one = history.grant(&founder, &first, &[OPERATOR], &[], &[&g]);
        let two = history.grant(&founder, &second, &[OPERATOR], &[], &[&one]);
        history.grant(&second, &first, &[], &[OPERATOR], &[&two]);
        history.grant(&first, &second, &[], &[OPERATOR], &[&two]);
        let state = history.state();
        assert!(state.holds(&first, OPERATOR), "made operator first");
        assert!(!state.holds(&second, OPERATOR));
        // Nor can anyone take the founder's away
        history.grant(&first, &founder, &[], &["/"], &[&two]);
        assert!(history.state().holds(&founder, OPERATOR));
    }

    /// A history with a founder, and users `u`, `b` and `c`.
    fn users() -> (History, Link, Link, Link, Link, Link) {
        let (founder, u, b, c) = (key(), key(), key(), key());
        let mut history = History::new(&founder);
        let g = history.genesis.clone();
        let one = history.grant(&founder, &u, &[USER], &[], &[&g]);
        let two = history.grant(&founder, &b, &[USER], &[], &[&one]);
        let three = history.grant(&founder, &c, &[USER], &[], &[&two]);
        (history, founder, u, b, c, three)
    }

    #[test]
    fn grants_on_an_anchor_are_of_whoever_its_judged_from() {
        let (mut history, founder, u, b, c, last) = users();
        let anchor = crate::claim::anchor().expect("anchor");
        let shared = history.grant_on(&u, &b, &anchor, &[ANCHOR_GRANT, READ], &[], &[&last]);
        let passed = history.grant_on(&b, &c, &anchor, &[READ], &[], &[&shared]);
        let beyond = history.grant_on(&b, &c, &anchor, &[WRITE], &[], &[&passed]);
        let state = history.state();
        assert!(state.holds_on(&u, &anchor, &u, ANCHOR), "an owner holds everything on their own view");
        assert!(state.holds_on(&u, &anchor, &b, READ) && !state.holds_on(&u, &anchor, &b, WRITE));
        assert!(state.holds_on(&u, &anchor, &c, READ), "passed on");
        assert!(!state.holds_on(&u, &anchor, &c, WRITE), "b can't give what b doesn't hold on u's view");
        assert!(state.holds_on(&b, &anchor, &c, WRITE) && state.counts(&beyond), "but on b's own view, b holds everything");
        assert!(!state.holds_on(&u, &anchor, &founder, READ), "the founder holds nothing on a user's view");
        let other = crate::claim::anchor().expect("anchor");
        assert!(!state.holds_on(&u, &other, &b, READ), "nor does a grant on one anchor give anything on another");

        // u takes away b's power to give: what b gave c on u's view goes
        let heads = state.heads();
        let heads: Vec<&Link> = heads.iter().collect();
        history.grant_on(&u, &b, &anchor, &[], &[ANCHOR_GRANT], &heads);
        let state = history.state();
        assert!(state.holds_on(&u, &anchor, &b, READ) && !state.holds_on(&u, &anchor, &c, READ));
        assert!(state.holds_on(&b, &anchor, &c, READ), "not on b's own view");
    }

    #[test]
    fn a_visitor_only_reads() {
        let (mut history, _, u, b, _, last) = users();
        let anchor = crate::claim::anchor().expect("anchor");
        let visitor = crate::keys::Key::generate().expect("key").id();
        history.grant_on(&u, &visitor, &anchor, &[ANCHOR_GRANT, READ, WRITE], &[], &[&last]);
        let state = history.state();
        assert!(state.holds_on(&u, &anchor, &visitor, READ));
        assert!(!state.holds_on(&u, &anchor, &visitor, WRITE) && !state.holds_on(&u, &anchor, &visitor, ANCHOR_GRANT));
        assert!(!state.holds_on(&b, &anchor, &visitor, READ), "only on the view shared");
        let share = state.shares().into_iter().find(|share| share.user == visitor).expect("shared");
        assert_eq!(share.held, [READ]);
    }

    #[test]
    fn a_user_taken_from_the_mesh_holds_nothing_on_anchors() {
        let (mut history, founder, u, b, c, last) = users();
        let anchor = crate::claim::anchor().expect("anchor");
        let shared = history.grant_on(&u, &b, &anchor, &[ANCHOR_GRANT, READ, WRITE], &[], &[&last]);
        let removed = history.grant(&founder, &b, &[], &[USER], &[&shared]);
        // b, naming grants from before, passes it on anyway
        let backdated = history.grant_on(&b, &c, &anchor, &[READ], &[], &[&shared]);
        let state = history.state();
        assert!(state.counts(&removed) && !state.counts(&backdated));
        assert!(!state.holds_on(&u, &anchor, &b, READ) && !state.holds_on(&u, &anchor, &c, READ));
        assert!(!state.holds_on(&b, &anchor, &b, READ), "nor on their own view, no longer a user");
    }

    #[test]
    fn taking_write_away_says_which_sets_stand() {
        let (mut history, _, u, b, _, last) = users();
        let anchor = crate::claim::anchor().expect("anchor");
        let (set, other) = (Claim::Tomb(crate::claim::Tomb::new([key()]).expect("tomb")).cid(), Claim::Tomb(crate::claim::Tomb::new([key()]).expect("tomb")).cid());
        let given = history.grant_on(&u, &b, &anchor, &[READ, WRITE], &[], &[&last]);
        let shares = history.state().shares();
        assert_eq!(shares.len(), 1);
        assert_eq!((&shares[0].owner, &shares[0].user, shares[0].held.as_slice()), (&u, &b, [READ.to_owned(), WRITE.to_owned()].as_slice()));
        history.take_write(&u, &b, &anchor, &[&set, &other], &[&given]);
        let after = history.state().shares();
        assert_eq!(after[0].held, [READ.to_owned()]);
        let mut stands = vec![set, other];
        stands.sort_by_key(Link::to_bytes);
        assert_eq!(after[0].stands, stands);
    }

    #[test]
    fn grants_wait_for_those_before_them() {
        let (founder, user) = (key(), key());
        let mut history = History::new(&founder);
        let absent = Claim::Grant(Grant::new([user.clone()], None, [USER.to_owned()], [], [], [history.genesis.clone()]).expect("grant")).cid();
        let waiting = history.grant(&founder, &user, &[USER], &[], &[&absent]);
        let state = history.state();
        assert_eq!(state.waiting(), [waiting]);
        assert!(!state.holds(&user, USER));
        // Nor is a history with another first, or none, any mesh's
        assert!(State::new(&absent, history.grants.iter().cloned()).is_none());
        let impostor = key();
        let mut forged = History::new(&founder);
        if let Some(first) = forged.grants.first_mut() {
            first.by = vec![impostor];
        }
        assert!(State::new(&forged.genesis, forged.grants.iter().cloned()).is_none());
    }
}
