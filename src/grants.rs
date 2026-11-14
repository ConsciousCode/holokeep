//! Who holds what in a mesh: its grants, worked out (see `claim::Grant`).
//!
//! A mesh's grants are one history, by `prev`, from its first, which gives
//! its founder `/`. Every machine works out the same answer from the same
//! grants, whatever order they arrived in:
//!
//! - **A grant is valid** if one of the users who signed it held, in the
//!   state its `prev` names (its ancestors, worked out alone), `/mesh/user`,
//!   `/mesh/grant`, and each command it gives or takes away.
//! - **Taking away undoes what was concurrent with it.** A valid grant
//!   doesn't count if a grant that counts, concurrent with it (neither is
//!   before the other), takes from its signer a command it needed. Grants
//!   taking away are decided first, the most senior signer's first (whoever
//!   was given `/mesh/grant` earliest, the founder before all), so when two
//!   take each other's commands away concurrently, the senior keeps theirs.
//! - **Taking away wins.** A command given is held unless a grant that
//!   counts takes it away after, or concurrently.
//! - **What was given goes with the giver's power to give it**: a command
//!   given is held only while whoever gave it holds `/mesh/grant` and the
//!   command, however that came about, unless someone else gave it too.
//! - **The founder always holds everything.**
//!
//! Grants on an anchor or role (`on`) are kept, but not yet worked out.
//!
//! Working out is quadratic in grants per grant, as every grant's state at
//! its `prev` is worked out afresh: fine for the dozens a mesh has.

use std::collections::BTreeMap;

use crate::cid::CidRef as _;
use crate::claim::{Grant, covers};
use crate::model::Link;

/// Being a user of the mesh: acting in it at all.
pub const USER: &str = "/mesh/user";
/// Being a machine of the mesh: in its roster, holding its plaintext.
pub const MACHINE: &str = "/mesh/machine";
/// Giving and taking away the mesh commands one holds.
pub const GRANT: &str = "/mesh/grant";
/// Every mesh command: an operator's.
pub const OPERATOR: &str = "/mesh";

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

impl Node {
    /// What its signer must hold: the commands it gives and takes away,
    /// and to act at all.
    fn needs(&self) -> impl Iterator<Item = &str> {
        [USER, GRANT].into_iter().chain(self.grant.add().iter().chain(self.grant.del()).map(String::as_str))
    }

    const fn on_mesh(&self) -> bool {
        self.grant.on().is_none()
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

/// A mesh's grants, worked out.
pub struct State {
    founder: Link,
    nodes: Vec<Node>,
    /// The users each valid grant's valid for: those of its signers who
    /// held what it needs.
    valid: Vec<Vec<Link>>,
    judged: Judged,
    /// Grants which name a grant that isn't here, or that do, however far
    /// back: they wait till it is.
    waiting: Vec<Link>,
}

/// Which grants of some set count, and which given commands are held.
struct Judged {
    /// Grants that count, each with the signers it counts for.
    counts: Vec<Option<Vec<Link>>>,
    /// Grants giving commands whose giver can give them still.
    supported: Vec<bool>,
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

        let mut state = Self { founder, nodes, valid: Vec::new(), judged: Judged { counts: Vec::new(), supported: Vec::new() }, waiting };
        for i in 0..state.nodes.len() {
            let valid = if i == 0 {
                vec![state.founder.clone()]
            } else {
                let members = state.nodes.get(i).map(|node| node.before.clone()).unwrap_or_default();
                let judged = state.judge(&members);
                state.nodes.get(i).map(|node| {
                    node.by.iter().filter(|&by| *by == state.founder || node.needs().all(|need| state.holds_in(&judged, by, need))).cloned().collect()
                }).unwrap_or_default()
            };
            state.valid.push(valid);
        }
        let everything = vec![true; state.nodes.len()];
        state.judged = state.judge(&everything);
        Some(state)
    }

    /// Which of a set of grants count, and which of those giving are
    /// supported, from which of them are valid.
    fn judge(&self, members: &[bool]) -> Judged {
        let n = self.nodes.len();
        let member = |i: usize| members.get(i).copied().unwrap_or(false) && self.valid.get(i).is_some_and(|valid| !valid.is_empty());
        let concurrent = |i: usize, j: usize| {
            let (Some(a), Some(b)) = (self.nodes.get(i), self.nodes.get(j)) else {
                return false;
            };
            i != j && !a.before.get(j).copied().unwrap_or(false) && !b.before.get(i).copied().unwrap_or(false)
        };
        // Seniority: when each user was first given what lets them give
        let mut rank: BTreeMap<Vec<u8>, usize> = BTreeMap::from([(self.founder.to_bytes(), 0)]);
        for (i, node) in self.nodes.iter().enumerate() {
            if member(i) && node.on_mesh() && node.grant.add().iter().any(|add| covers(add, GRANT)) {
                for target in node.grant.target() {
                    rank.entry(target.to_bytes()).or_insert_with(|| i.saturating_add(1));
                }
            }
        }
        let rank_of = |who: &Link| rank.get(&who.to_bytes()).copied().unwrap_or(usize::MAX);

        let mut counts: Vec<Option<Vec<Link>>> = vec![None; n];
        // Who of its signers a grant still counts for, given what counts
        // that takes away from them concurrently.
        let standing = |i: usize, counts: &[Option<Vec<Link>>]| -> Vec<Link> {
            let (Some(node), Some(valid)) = (self.nodes.get(i), self.valid.get(i)) else {
                return Vec::new();
            };
            valid.iter().filter(|&signer| {
                *signer == self.founder || !counts.iter().enumerate().any(|(j, counted)| {
                    counted.is_some() && concurrent(i, j) && self.nodes.get(j).is_some_and(|taker| {
                        taker.on_mesh() && taker.targets(signer) && taker.grant.del().iter().any(|del| node.needs().any(|need| overlap(del, need)))
                    })
                })
            }).cloned().collect()
        };
        let mut taking: Vec<usize> = (0..n).filter(|&i| member(i) && self.nodes.get(i).is_some_and(|node| node.on_mesh() && !node.grant.del().is_empty())).collect();
        taking.sort_by_key(|&i| {
            let senior = self.valid.get(i).and_then(|valid| valid.iter().map(rank_of).min()).unwrap_or(usize::MAX);
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

        // What's given is held while its giver can give it: from the
        // founder out, as far as that goes
        let mut judged = Judged { counts, supported: vec![false; n] };
        loop {
            let mut grew = false;
            for i in 0..n {
                if judged.supported.get(i).copied().unwrap_or(true) {
                    continue;
                }
                let (Some(node), Some(Some(signers))) = (self.nodes.get(i), judged.counts.get(i)) else {
                    continue;
                };
                if node.grant.add().is_empty() || !node.on_mesh() {
                    continue;
                }
                let gives = signers.iter().any(|signer| {
                    *signer == self.founder
                        || [USER, GRANT].into_iter().chain(node.grant.add().iter().map(String::as_str)).all(|need| self.holds_in(&judged, signer, need))
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

    /// Whether someone holds a command on the mesh, as some grants are
    /// judged: given by a supported grant, and not taken away after or
    /// concurrently by one that counts.
    fn holds_in(&self, judged: &Judged, who: &Link, command: &str) -> bool {
        if *who == self.founder {
            return true;
        }
        self.nodes.iter().enumerate().any(|(i, giving)| {
            judged.supported.get(i).copied().unwrap_or(false)
                && giving.on_mesh()
                && giving.targets(who)
                && giving.grant.add().iter().any(|add| covers(add, command))
                && !self.nodes.iter().enumerate().any(|(j, taking)| {
                    judged.counts.get(j).is_some_and(Option::is_some)
                        && taking.on_mesh()
                        && taking.targets(who)
                        && !giving.before.get(j).copied().unwrap_or(false)
                        && taking.grant.del().iter().any(|del| overlap(del, command))
                })
        })
    }

    /// Whether someone holds a command on the mesh.
    pub fn holds(&self, who: &Link, command: &str) -> bool {
        self.holds_in(&self.judged, who, command)
    }

    /// The mesh's founder, its first operator.
    pub const fn founder(&self) -> &Link {
        &self.founder
    }

    /// Whether a grant counts.
    pub fn counts(&self, cid: &Link) -> bool {
        self.nodes.iter().position(|node| node.cid == *cid).and_then(|i| self.judged.counts.get(i)).is_some_and(Option::is_some)
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

    /// Everyone given anything on the mesh, with which of the commands
    /// they were given they hold now.
    pub fn holders(&self) -> Vec<(Link, Vec<String>)> {
        let mut given: BTreeMap<Vec<u8>, (Link, std::collections::BTreeSet<String>)> = BTreeMap::new();
        for node in self.nodes.iter().filter(|node| node.on_mesh()) {
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
