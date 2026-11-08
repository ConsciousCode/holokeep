//! Merging an anchor's heads, where it's forked: sets made without seeing
//! each other, as by two devices between syncs; and what's in conflict.
//!
//! Every node computes the same merge from the same claims, so nothing
//! has to agree on it; the next set of the anchor, by anyone, names every
//! head as its `prev`, and says what it is.
//!
//! More than two heads merge two at a time, in order, each pair over what
//! it has in common. Directories merge three ways, name by name, against
//! the pair's latest common ancestor, or if they've more than one, those
//! merged in turn, as when two devices each go on from one merge. A side
//! changed a name if it ends otherwise than the ancestor, or if any set on
//! its way changed it from what whoever set it saw, or says it wrote it,
//! even back again.
//!
//! Each name is a multi-value register: every version of it written
//! without a later write having seen it is unresolved, and more than one
//! is a **conflict**. That isn't stored in the tree, which holds the latest
//! version of each name, of the latest set that made it so, but worked out
//! from the sets: a set's conflicts are those of what it came after,
//! merged, less what it changed or says it wrote. A change wins over a
//! removal. Without a common ancestor, as when a repo joins a mesh, every
//! name is a change. Anything that isn't every head a directory is the
//! latest head's change.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;

use crate::cid::CidRef;
use crate::dag::{BlockSink, DagLink, DirLayoutBuilder as _, DirLayoutStrategy as _};
use crate::export::{self, Kind};
use crate::model::Link;

use super::{Catalog, Result, SetOf};

/// Where something is under an anchor's value: the names down to it.
pub type Path = Vec<Vec<u8>>;

/// Every name in conflict, with its versions, oldest first.
pub type Conflicts = BTreeMap<Path, Vec<Version>>;

/// Where a set comes in the order sets are taken in, everywhere: by `at`,
/// then the value, then the set.
type Order = (u64, Vec<u8>, Vec<u8>);

/// A version of a name in conflict: what it is, and the set it's of, the
/// latest to make it so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub cid: Link,
    pub size: Option<u64>,
    pub set: Link,
    order: Order,
}

impl Version {
    /// How it's told apart from the others: the end of its set's CID.
    pub fn tag(&self) -> String {
        tag(&self.set)
    }

    fn same(&self, other: &Self) -> bool {
        self.cid == other.cid && self.set == other.set
    }
}

/// What an anchor is as of some sets.
///
/// The tree holds each name's latest version; and each name with more than
/// one version unresolved is noted, though they may all be the same,
/// written by sets that didn't see each other.
#[derive(Clone, Debug)]
pub struct State {
    pub value: Link,
    pub conflicts: Conflicts,
}

impl State {
    /// What's in conflict: each name with versions that differ, and one of
    /// each, the latest of it, oldest first.
    pub fn in_conflict(&self) -> impl Iterator<Item = (&Path, Vec<Version>)> {
        self.conflicts.iter().map(|(path, versions)| (path, by_cid(versions))).filter(|(_, versions)| versions.len() > 1)
    }
}

/// What an anchor's shown as: its tree with each version in conflict that
/// isn't the latest beside it, as `name (conflict <tag>)`, and where each
/// of those is, with the path of the name it's a version of.
#[derive(Clone, Debug)]
pub struct View {
    pub value: Link,
    pub state: State,
    pub shown: BTreeMap<Path, Path>,
}

/// A head, as merged: what it says and what's in conflict there, which set
/// it is, and the steps its side took on the way there since what's merged
/// over, so a change it made and undid still counts as its change.
#[derive(Clone)]
struct Head {
    value: Link,
    conflicts: Conflicts,
    set: Link,
    order: Order,
    path: Vec<Step>,
    reach: Vec<bool>,
}

/// A set on a side's way, at some place in the tree: what it said there,
/// and what what it came after said, merged, as whoever set it saw; the
/// paths there or below it says it wrote; and which set it is.
#[derive(Clone)]
struct Step {
    now: Then,
    was: Then,
    wrote: Vec<Path>,
    set: Link,
    order: Order,
}

impl Step {
    /// Whether it changed what's here, or within it.
    fn touched(&self) -> bool {
        self.was.differs(&self.now) || !self.wrote.is_empty()
    }
}

/// What a set said at some place in the tree: something, nothing (as an
/// empty directory, where a name's asked after), or what can't be told
/// apart name by name (as if every name had changed).
#[derive(Clone, PartialEq)]
enum Then {
    Is(Link),
    Nothing,
    Unknown,
}

impl Then {
    fn differs(&self, other: &Self) -> bool {
        *self == Self::Unknown || *other == Self::Unknown || self != other
    }
}

/// What a head said of a name: what's there, whether it changed it, and on
/// the way, how.
struct Said<'h> {
    head: &'h Head,
    now: Option<Entry>,
    changed: bool,
    steps: Vec<Step>,
}

/// One side of a merge: the sets it comes to, as `reach` says, what's so
/// there, and the set it's of.
struct Side {
    reach: Vec<bool>,
    state: State,
    set: Link,
    order: Order,
}

/// An entry of a directory: what it links to, and the size its link says.
pub type Entry = (Link, Option<u64>);

/// A directory's entries, by name.
type Listing = BTreeMap<Vec<u8>, Entry>;

/// What's being merged over: its tree, what's in conflict there, and the
/// set it's of, as what's there and not in conflict is.
struct Base<'a> {
    value: Option<&'a Link>,
    conflicts: &'a Conflicts,
    of: Option<(Link, Order)>,
    before: &'a [bool],
}

/// An anchor's sets, as merging them goes.
struct Sets<'a> {
    all: &'a [SetOf],
    index: BTreeMap<Vec<u8>, usize>,
    wrote: HashMap<Vec<u8>, Vec<Path>>,
    listed: RefCell<HashMap<Vec<u8>, Option<Listing>>>,
}

impl Sets<'_> {
    fn order(&self, at: usize) -> Order {
        self.all.get(at).map_or_else(Order::default, |(set, value, when, _)| (*when, value.to_bytes(), set.to_bytes()))
    }

    fn wrote(&self, at: usize) -> Vec<Path> {
        self.all.get(at).and_then(|(set, ..)| self.wrote.get(&set.to_bytes())).cloned().unwrap_or_default()
    }

    /// The positions of the sets a set came after that are here, if it says
    /// any: none for one with nothing before it, or an older build's.
    fn prev(&self, at: usize) -> Vec<usize> {
        let mut prev: Vec<usize> = self.all.get(at)
            .and_then(|(.., prev)| prev.as_ref())
            .map(|prev| prev.iter().filter_map(|prev| self.index.get(&prev.to_bytes()).copied()).collect())
            .unwrap_or_default();
        prev.sort_unstable();
        prev.dedup();
        prev
    }
}

/// A sink putting blocks into a catalog through a shared reference.
struct Putting<'a>(&'a Catalog);

impl BlockSink for Putting<'_> {
    fn put(&mut self, block: crate::block::Block) -> io::Result<()> {
        self.0.put_block(&block, crate::cid::CidVersion::V1).map(drop).map_err(io::Error::other)
    }
}

/// What's in conflict at or within a path.
fn within<'a>(conflicts: &'a Conflicts, here: &'a Path) -> impl Iterator<Item = (&'a Path, &'a Vec<Version>)> + 'a {
    conflicts.range(here.clone()..).take_while(move |(path, _)| path.starts_with(here))
}

impl Catalog {
    /// What a forked anchor is: its heads, as (set, value, at) by `at`,
    /// merged.
    pub(super) fn merge_heads(&self, anchor: &Link, heads: &[(Link, Link, u64)]) -> Result<Link> {
        Ok(self.state_of(anchor, &heads.iter().map(|(set, ..)| set.clone()).collect::<Vec<_>>())?.value)
    }

    /// What an anchor is as of these of its sets: their trees merged, and
    /// what's in conflict.
    pub fn state_of(&self, anchor: &Link, heads: &[Link]) -> Result<State> {
        let key: Vec<u8> = std::iter::once(b'h').chain(heads.iter().flat_map(CidRef::to_bytes)).collect();
        if let Some(state) = self.states.borrow().get(&key) {
            return Ok(state.clone());
        }
        let claims = self.claims.as_ref().ok_or(super::Error::NoClaims)?;
        let sets = claims.sets(anchor.multihash())?;
        let mut wrote: HashMap<Vec<u8>, Vec<Path>> = HashMap::new();
        for (set, path) in claims.wrote(anchor.multihash())? {
            wrote.entry(set.to_bytes()).or_default().push(path.split(|&byte| byte == b'/').map(<[u8]>::to_vec).collect());
        }
        let index: BTreeMap<Vec<u8>, usize> = sets.iter().enumerate().map(|(i, (set, ..))| (set.to_bytes(), i)).collect();
        let sets = Sets { all: &sets, index, wrote, listed: RefCell::default() };
        let mut from: Vec<usize> = Vec::new();
        for head in heads {
            match sets.index.get(&head.to_bytes()) {
                Some(&at) => from.push(at),
                None => return Err(super::Error::User(format!("{head} isn't a set of {anchor} here that counts"))),
            }
        }
        from.sort_unstable();
        from.dedup();
        self.settle(&sets)?;
        let state = self.merged(&sets, &from)?;
        self.states.borrow_mut().insert(key, state.clone());
        Ok(state)
    }

    /// What an anchor's shown as, as of these of its sets: their state,
    /// with each version in conflict beside the latest.
    pub fn view_of(&self, anchor: &Link, heads: &[Link]) -> Result<View> {
        let key: Vec<u8> = std::iter::once(b'v').chain(heads.iter().flat_map(CidRef::to_bytes)).collect();
        if let Some(view) = self.views.borrow().get(&key) {
            return Ok(view.clone());
        }
        let view = self.show(self.state_of(anchor, heads)?)?;
        self.views.borrow_mut().insert(key, view.clone());
        Ok(view)
    }

    /// Work out each set's state, each after what it came after, so none
    /// waits on another in turn.
    fn settle(&self, sets: &Sets<'_>) -> io::Result<()> {
        let mut waiting: Vec<usize> = (0..sets.all.len()).map(|at| sets.prev(at).len()).collect();
        let mut after: Vec<Vec<usize>> = vec![Vec::new(); sets.all.len()];
        for at in 0..sets.all.len() {
            for prev in sets.prev(at) {
                if let Some(slot) = after.get_mut(prev) {
                    slot.push(at);
                }
            }
        }
        let mut ready: Vec<usize> = waiting.iter().enumerate().filter(|&(_, &n)| n == 0).map(|(at, _)| at).rev().collect();
        while let Some(at) = ready.pop() {
            self.set_state(sets, at)?;
            for &next in after.get(at).map(Vec::as_slice).unwrap_or_default() {
                if let Some(n) = waiting.get_mut(next) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        ready.push(next);
                    }
                }
            }
        }
        Ok(())
    }

    /// A set's state: what it says, and what was in conflict in what it
    /// came after, merged, that it neither changed nor says it wrote.
    fn set_state(&self, sets: &Sets<'_>, at: usize) -> io::Result<State> {
        let (set, value, ..) = sets.all.get(at).ok_or_else(|| io::Error::other("no such set"))?;
        let key: Vec<u8> = std::iter::once(b's').chain(set.to_bytes()).collect();
        if let Some(state) = self.states.borrow().get(&key) {
            return Ok(state.clone());
        }
        let prev = sets.prev(at);
        let mut conflicts = Conflicts::new();
        if !prev.is_empty() {
            let was = self.merged(sets, &prev)?;
            let wrote = sets.wrote(at);
            for (path, versions) in was.conflicts {
                let written = wrote.iter().any(|wrote| path.starts_with(wrote));
                if !written && self.entry_at(sets, value, &path)? == self.entry_at(sets, &was.value, &path)? {
                    conflicts.insert(path, versions);
                }
            }
        }
        let state = State { value: value.clone(), conflicts };
        self.states.borrow_mut().insert(key, state.clone());
        Ok(state)
    }

    /// These sets merged, two at a time, in order, each pair over what it
    /// has in common: its latest common set's state, or if there's more
    /// than one, those merged in turn, as that's what's gone on from. Two at
    /// a time, as two of them may have more in common than all of them do.
    /// Worked out the same everywhere, from the same sets.
    fn merged(&self, sets: &Sets<'_>, from: &[usize]) -> io::Result<State> {
        if let [one] = from {
            return self.set_state(sets, *one);
        }
        let key: Vec<u8> = std::iter::once(b'm').chain(from.iter().filter_map(|&at| sets.all.get(at)).flat_map(|(set, ..)| set.to_bytes())).collect();
        if let Some(state) = self.states.borrow().get(&key) {
            return Ok(state.clone());
        }
        let mut sides: Vec<Side> = Vec::new();
        for &at in from {
            let (set, ..) = sets.all.get(at).ok_or_else(|| io::Error::other("no such set"))?;
            sides.push(Side { reach: reach(sets.all, &sets.index, at), state: self.set_state(sets, at)?, set: set.clone(), order: sets.order(at) });
        }
        let mut sides = sides.into_iter();
        let mut merged = sides.next().ok_or_else(|| io::Error::other("no heads"))?;
        for side in sides {
            let state = self.merge_sides(sets, &merged, &side)?;
            let reach = merged.reach.iter().zip(&side.reach).map(|(a, b)| *a || *b).collect();
            merged = Side { reach, state, set: side.set, order: side.order };
        }
        self.states.borrow_mut().insert(key, merged.state.clone());
        Ok(merged.state)
    }

    /// Two sides merged, over what they have in common.
    fn merge_sides(&self, sets: &Sets<'_>, a: &Side, b: &Side) -> io::Result<State> {
        let latest = latest_common(sets.all, &sets.index, &[&a.reach, &b.reach]);
        let base = match latest.as_slice() {
            [] => None,
            [one] => Some(self.set_state(sets, *one)?),
            many => Some(self.merged(sets, many)?),
        };
        // What both had come to already, and so isn't either side's
        let mut before = vec![false; sets.all.len()];
        for &at in &latest {
            for (slot, seen) in before.iter_mut().zip(reach(sets.all, &sets.index, at)) {
                *slot = *slot || seen;
            }
        }
        let mut heads: Vec<Head> = Vec::new();
        for side in [a, b] {
            // Each set of its own and what it came after: a set with
            // nothing before it is of another past, and says nothing of
            // what changed in this one
            let mut path: Vec<Step> = Vec::new();
            for (on, _) in side.reach.iter().zip(&before).enumerate().filter(|&(_, (&seen, &before))| seen && !before) {
                let prev = sets.prev(on);
                let Some((set, said, ..)) = sets.all.get(on).filter(|_| !prev.is_empty()) else {
                    continue;
                };
                let was = self.merged(sets, &prev)?.value;
                let wrote = sets.wrote(on);
                if was != *said || !wrote.is_empty() {
                    path.push(Step { now: Then::Is(said.clone()), was: Then::Is(was), wrote, set: set.clone(), order: sets.order(on) });
                }
            }
            heads.push(Head { value: side.state.value.clone(), conflicts: side.state.conflicts.clone(), set: side.set.clone(), order: side.order.clone(), path, reach: side.reach.clone() });
        }
        let empty = Conflicts::new();
        let base_value = base.as_ref().map(|base| &base.value).filter(|base| self.is_dir(base).unwrap_or(false));
        let of = latest.last().map(|&at| (sets.all.get(at).map(|(set, ..)| set.clone()), sets.order(at)));
        let base = Base {
            value: base_value,
            conflicts: base.as_ref().map_or(&empty, |base| &base.conflicts),
            of: of.and_then(|(set, order)| set.map(|set| (set, order))),
            before: &before,
        };
        let mut conflicts = Conflicts::new();
        let value = self.merge_values(sets, &base, &heads, &mut conflicts)?;
        Ok(State { value, conflicts })
    }

    /// Heads' values merged, over what they had in common, if that's
    /// known and here.
    fn merge_values(&self, sets: &Sets<'_>, base: &Base<'_>, heads: &[Head], conflicts: &mut Conflicts) -> io::Result<Link> {
        let latest = heads.iter().max_by(|a, b| a.order.cmp(&b.order)).ok_or_else(|| io::Error::other("no heads"))?;
        let mut dirs = true;
        for head in heads {
            dirs = dirs && self.is_dir(&head.value)?;
        }
        if !dirs {
            // The latest change wins
            let changed = heads.iter().filter(|head| Some(&head.value) != base.value).max_by(|a, b| a.order.cmp(&b.order));
            return Ok(changed.unwrap_or(latest).value.clone());
        }
        let refs: Vec<&Head> = heads.iter().collect();
        Ok(self.merge_dirs(sets, base, &Vec::new(), base.value, &refs, conflicts)?.cid.into())
    }

    fn is_dir(&self, cid: &Link) -> io::Result<bool> {
        Ok(matches!(export::stat(self, cid)?, Kind::Directory))
    }

    fn entries(&self, dir: Option<&Link>) -> io::Result<Listing> {
        let Some(dir) = dir else {
            return Ok(BTreeMap::new());
        };
        Ok(export::list(self, dir)?.into_iter().map(|entry| (entry.name, (entry.cid, entry.size))).collect())
    }

    /// A directory's entries, listed once: none where it's not a directory.
    fn listing(&self, sets: &Sets<'_>, cid: &Link) -> io::Result<Option<Listing>> {
        if let Some(found) = sets.listed.borrow().get(&cid.to_bytes()) {
            return Ok(found.clone());
        }
        let found = if self.is_dir(cid)? { Some(self.entries(Some(cid))?) } else { None };
        sets.listed.borrow_mut().insert(cid.to_bytes(), found.clone());
        Ok(found)
    }

    /// What's at a path of a tree, if anything.
    fn entry_at(&self, sets: &Sets<'_>, root: &Link, path: &[Vec<u8>]) -> io::Result<Option<Link>> {
        let mut at = root.clone();
        for name in path {
            let Some(listing) = self.listing(sets, &at)? else {
                return Ok(None);
            };
            let Some((cid, _)) = listing.get(name) else {
                return Ok(None);
            };
            at = cid.clone();
        }
        Ok(Some(at))
    }

    /// The set whose write a path holds, of the sets in `region`: of those
    /// that changed it from what whoever set it saw, or say they wrote it,
    /// the latest to make it so that nothing else that changed it came
    /// after.
    fn made(&self, sets: &Sets<'_>, region: &[bool], path: &Path, cid: &Link) -> io::Result<Option<(Link, Order)>> {
        let mut touched: Vec<(usize, bool)> = Vec::new();
        for at in (0..sets.all.len()).filter(|&at| region.get(at).copied().unwrap_or(false)) {
            let Some((_, value, ..)) = sets.all.get(at) else {
                continue;
            };
            let now = self.entry_at(sets, value, path)?;
            let prev = sets.prev(at);
            let changed = if prev.is_empty() {
                now.is_some()
            } else {
                sets.wrote(at).iter().any(|wrote| path.starts_with(wrote)) || self.entry_at(sets, &self.merged(sets, &prev)?.value, path)? != now
            };
            if changed {
                touched.push((at, now.as_ref() == Some(cid)));
            }
        }
        let mut found: Option<usize> = None;
        for &(at, makes) in &touched {
            if !makes {
                continue;
            }
            let gone_on = touched.iter().any(|&(later, _)| later != at && reach(sets.all, &sets.index, later).get(at).copied().unwrap_or(false));
            if !gone_on && found.is_none_or(|found| sets.order(found) < sets.order(at)) {
                found = Some(at);
            }
        }
        Ok(found.and_then(|at| sets.all.get(at).map(|(set, ..)| (set.clone(), sets.order(at)))))
    }

    /// Directories at `prefix` merged, name by name, over what was there,
    /// noting what's in conflict in `conflicts`.
    fn merge_dirs(&self, sets: &Sets<'_>, base: &Base<'_>, prefix: &Path, was_dir: Option<&Link>, heads: &[&Head], conflicts: &mut Conflicts) -> io::Result<DagLink> {
        let base_entries = self.entries(was_dir)?;
        let mut sides = Vec::new();
        for head in heads {
            sides.push(self.entries(Some(&head.value))?);
        }
        // The steps each side took, listed
        let mut paths: Vec<Vec<(Option<Listing>, Option<Listing>)>> = Vec::new();
        for head in heads {
            let mut path = Vec::new();
            for step in &head.path {
                path.push((self.then_listing(sets, &step.now)?, self.then_listing(sets, &step.was)?));
            }
            paths.push(path);
        }
        let names: BTreeSet<&Vec<u8>> = base_entries.keys().chain(sides.iter().flat_map(BTreeMap::keys)).collect();
        let mut merged: BTreeMap<Vec<u8>, DagLink> = BTreeMap::new();
        for name in names {
            let mut here = prefix.clone();
            here.push(name.clone());
            let was = base_entries.get(name);
            let was_conflicts: Vec<(&Path, &Vec<Version>)> = within(base.conflicts, &here).collect();
            // What every head said of it, whether it changed it, and on the
            // way, how
            let mut said: Vec<Said<'_>> = Vec::new();
            for ((head, side), path) in heads.iter().zip(&sides).zip(&paths) {
                let steps: Vec<Step> = path.iter().zip(&head.path)
                    .map(|((now, was), step)| Step {
                        now: at(now.as_ref(), name),
                        was: at(was.as_ref(), name),
                        wrote: step.wrote.iter().filter(|wrote| wrote.first() == Some(name)).map(|wrote| wrote.get(1..).unwrap_or_default().to_vec()).collect(),
                        set: step.set.clone(),
                        order: step.order.clone(),
                    })
                    .filter(Step::touched)
                    .collect();
                let now = side.get(name);
                let changed = now.map(|(cid, _)| cid) != was.map(|(cid, _)| cid)
                    || !steps.is_empty()
                    || within(&head.conflicts, &here).collect::<Vec<_>>() != was_conflicts;
                said.push(Said { head, now: now.cloned(), changed, steps });
            }
            if said.iter().all(|said| !said.changed) {
                if let Some(was) = was {
                    merged.insert(name.clone(), link_of(was));
                    for (path, versions) in &was_conflicts {
                        conflicts.insert((*path).clone(), (*versions).clone());
                    }
                }
                continue;
            }
            let versions = self.versions_of(sets, base, &here, was, &said)?;
            let Some(latest) = versions.last().cloned() else {
                // Removed on every side that changed it
                continue;
            };
            let distinct: Vec<Version> = by_cid(&versions);
            if distinct.len() == 1 {
                merged.insert(name.clone(), link_of(&(latest.cid.clone(), latest.size)));
                // The same, of more than one set: no conflict, but each
                // goes on till what's seen it goes on from it
                if versions.len() > 1 {
                    conflicts.insert(here.clone(), versions.clone());
                }
                // What's in conflict within it, as what holds it says
                for held in said.iter().filter(|said| said.now.as_ref().map(|(cid, _)| cid) == Some(&latest.cid)) {
                    let source = if held.changed { &held.head.conflicts } else { base.conflicts };
                    for (path, versions) in within(source, &here).filter(|(path, _)| path.len() > here.len()) {
                        conflicts.insert(path.clone(), versions.clone());
                    }
                }
                continue;
            }
            let mut all_dirs = true;
            for version in &distinct {
                all_dirs = all_dirs && self.is_dir(&version.cid)?;
            }
            let was_a_dir = match was {
                Some((cid, _)) => self.is_dir(cid)?,
                None => true,
            };
            if all_dirs && was_a_dir {
                let sub = sub_heads(sets.all.len(), base, &here, &distinct, &said);
                let refs: Vec<&Head> = sub.iter().collect();
                merged.insert(name.clone(), self.merge_dirs(sets, base, &here, was.map(|(cid, _)| cid), &refs, conflicts)?);
                continue;
            }
            // A conflict: the latest by its name, every version noted
            merged.insert(name.clone(), link_of(&(latest.cid.clone(), latest.size)));
            conflicts.insert(here, versions);
        }
        self.build(merged)
    }

    /// The versions of a name that survive a merge, oldest first: each
    /// head's own, if it changed it, or else what was; and of what both
    /// sides had come to, what neither's gone on from.
    fn versions_of(&self, sets: &Sets<'_>, base: &Base<'_>, here: &Path, was: Option<&Entry>, said: &[Said<'_>]) -> io::Result<Vec<Version>> {
        let was_versions: Vec<Version> = match (base.conflicts.get(here), was) {
            (Some(versions), _) => versions.clone(),
            (None, Some((cid, size))) => self.made(sets, base.before, here, cid)?
                .or_else(|| base.of.clone())
                .map(|(set, order)| vec![Version { cid: cid.clone(), size: *size, set, order }])
                .unwrap_or_default(),
            (None, None) => Vec::new(),
        };
        let mut held: Vec<Vec<Version>> = Vec::new();
        for said in said {
            if !said.changed {
                held.push(was_versions.clone());
                continue;
            }
            held.push(match (said.head.conflicts.get(here), &said.now) {
                (Some(versions), _) => versions.clone(),
                (None, Some((cid, size))) => {
                    let (set, order) = self.made(sets, &said.head.reach, here, cid)?.unwrap_or_else(|| (said.head.set.clone(), said.head.order.clone()));
                    vec![Version { cid: cid.clone(), size: *size, set, order }]
                },
                (None, None) => Vec::new(),
            });
        }
        let from_before = |version: &Version| sets.index.get(&version.set.to_bytes()).is_some_and(|&at| base.before.get(at).copied().unwrap_or(false));
        let mut versions: Vec<Version> = Vec::new();
        for side in &held {
            for version in side {
                if from_before(version) && !held.iter().all(|other| other.iter().any(|seen| seen.same(version))) {
                    continue;
                }
                // The same written by sets that didn't see each other is two
                // versions, each gone on from only by what saw it
                if !versions.iter().any(|seen| seen.same(version)) {
                    versions.push(version.clone());
                }
            }
        }
        versions.sort_by(|a, b| a.order.cmp(&b.order));
        Ok(versions)
    }

    fn then_listing(&self, sets: &Sets<'_>, then: &Then) -> io::Result<Option<Listing>> {
        match then {
            Then::Nothing => Ok(Some(BTreeMap::new())),
            Then::Unknown => Ok(None),
            Then::Is(cid) => self.listing(sets, cid),
        }
    }

    /// A directory of these entries, as the importer builds them.
    fn build(&self, entries: BTreeMap<Vec<u8>, DagLink>) -> io::Result<DagLink> {
        let mut dir = crate::import::Importer::default().directory.builder();
        let mut sink = Putting(self);
        for (name, link) in entries {
            dir.add_link(name, link, &mut sink)?;
        }
        dir.finalize(&mut sink)
    }

    /// A tree with these paths changed: to what each says, or gone.
    fn edit_tree(&self, root: &Link, changes: &BTreeMap<Path, Option<Entry>>) -> io::Result<Link> {
        Ok(self.edit_dir(Some(root), changes, 0)?.cid.into())
    }

    fn edit_dir(&self, dir: Option<&Link>, changes: &BTreeMap<Path, Option<Entry>>, depth: usize) -> io::Result<DagLink> {
        let listed = self.entries(dir)?;
        let mut entries: BTreeMap<Vec<u8>, DagLink> = listed.iter().map(|(name, entry)| (name.clone(), link_of(entry))).collect();
        let mut below: BTreeMap<Vec<u8>, BTreeMap<Path, Option<Entry>>> = BTreeMap::new();
        for (path, change) in changes {
            match path.get(depth..) {
                Some([name]) => match change {
                    Some(entry) => {
                        entries.insert(name.clone(), link_of(entry));
                    },
                    None => {
                        entries.remove(name);
                    },
                },
                Some([name, ..]) => {
                    below.entry(name.clone()).or_default().insert(path.clone(), change.clone());
                },
                _ => {},
            }
        }
        for (name, changes) in below {
            let within = listed.get(&name).map(|(cid, _)| cid.clone()).filter(|cid| self.is_dir(cid).unwrap_or(false));
            entries.insert(name, self.edit_dir(within.as_ref(), &changes, depth.saturating_add(1))?);
        }
        self.build(entries)
    }

    /// What's at a path of a tree, if anything.
    fn at_path(&self, root: &Link, path: &[Vec<u8>]) -> io::Result<Option<Link>> {
        let mut at = root.clone();
        for name in path {
            if !self.is_dir(&at)? {
                return Ok(None);
            }
            let Some((cid, _)) = self.entries(Some(&at))?.remove(name) else {
                return Ok(None);
            };
            at = cid;
        }
        Ok(Some(at))
    }

    /// A state as it's shown: each version in conflict that isn't the
    /// latest beside it, as `name (conflict <tag>)`, or where that's taken,
    /// with a number after the tag.
    fn show(&self, state: State) -> io::Result<View> {
        if state.in_conflict().next().is_none() {
            return Ok(View { value: state.value.clone(), state, shown: BTreeMap::new() });
        }
        let mut changes: BTreeMap<Path, Option<Entry>> = BTreeMap::new();
        let mut shown: BTreeMap<Path, Path> = BTreeMap::new();
        for (path, versions) in &state.conflicts {
            let Some((name, parent)) = path.split_last() else {
                continue;
            };
            let taken = self.entries(self.at_path(&state.value, parent)?.as_ref())?;
            let Some(latest) = versions.last() else {
                continue;
            };
            for version in by_cid(versions).iter().rev().filter(|version| version.cid != latest.cid) {
                let tag = version.tag();
                let mut n: u32 = 1;
                let place = loop {
                    let tagged = if n == 1 { tag.clone() } else { format!("{tag} {n}") };
                    let mut place = parent.to_vec();
                    let named = conflict_name(name, &tagged);
                    let free = !taken.contains_key(&named);
                    place.push(named);
                    if free && !changes.contains_key(&place) {
                        break place;
                    }
                    n = n.saturating_add(1);
                };
                changes.insert(place.clone(), Some((version.cid.clone(), version.size)));
                shown.insert(place, path.clone());
            }
        }
        let value = self.edit_tree(&state.value, &changes)?;
        Ok(View { value, state, shown })
    }

    /// What's to be said of a tree built over a view: the tree, without the
    /// versions shown beside names in conflict that weren't touched, and
    /// the names in conflict it resolved without changing them. Changing a
    /// conflict, its name or a version beside it, resolves it, and versions
    /// beside it still there are then files of those names.
    pub fn unshow(&self, view: &View, built: &Link) -> Result<(Link, Vec<Path>)> {
        let mut by_conflict: BTreeMap<&Path, Vec<&Path>> = BTreeMap::new();
        for (place, path) in &view.shown {
            by_conflict.entry(path).or_default().push(place);
        }
        let mut changes: BTreeMap<Path, Option<Entry>> = BTreeMap::new();
        let mut wrote: Vec<Path> = Vec::new();
        for (path, places) in by_conflict {
            let named_before = self.at_path(&view.value, path)?;
            let named_now = self.at_path(built, path)?;
            let mut touched = named_before != named_now;
            for place in &places {
                touched = touched || self.at_path(&view.value, place)? != self.at_path(built, place)?;
            }
            if !touched {
                for place in places {
                    changes.insert(place.clone(), None);
                }
            } else if named_before == named_now {
                wrote.push(path.clone());
            }
        }
        let value = if changes.is_empty() { built.clone() } else { self.edit_tree(built, &changes)? };
        Ok((value, wrote))
    }
}

/// Each version of a directory as a head to merge within, with what's in
/// conflict there and what the heads holding it took on the way.
fn sub_heads(len: usize, base: &Base<'_>, here: &Path, distinct: &[Version], said: &[Said<'_>]) -> Vec<Head> {
    let mut sub: Vec<Head> = Vec::new();
    for version in distinct {
        let mut conflicts = Conflicts::new();
        let mut path = Vec::new();
        let mut reach = vec![false; len];
        for held in said.iter().filter(|said| said.now.as_ref().map(|(cid, _)| cid) == Some(&version.cid)) {
            let source = if held.changed { &held.head.conflicts } else { base.conflicts };
            conflicts.extend(within(source, here).map(|(path, versions)| (path.clone(), versions.clone())));
            path.extend(held.steps.iter().cloned());
            for (slot, seen) in reach.iter_mut().zip(&held.head.reach) {
                *slot = *slot || *seen;
            }
        }
        sub.push(Head { value: version.cid.clone(), conflicts, set: version.set.clone(), order: version.order.clone(), path, reach });
    }
    sub
}

/// Versions, one of each thing they are, the latest of it, oldest first.
fn by_cid(versions: &[Version]) -> Vec<Version> {
    let mut latest: Vec<Version> = Vec::new();
    for version in versions {
        match latest.iter_mut().find(|seen| seen.cid == version.cid) {
            Some(seen) if seen.order < version.order => *seen = version.clone(),
            Some(_) => {},
            None => latest.push(version.clone()),
        }
    }
    latest.sort_by(|a, b| a.order.cmp(&b.order));
    latest
}

/// What a listed step said of a name.
fn at(listed: Option<&Listing>, name: &[u8]) -> Then {
    listed.map_or(Then::Unknown, |listed| listed.get(name).map_or(Then::Nothing, |(cid, _)| Then::Is(cid.clone())))
}

fn link_of((cid, size): &Entry) -> DagLink {
    DagLink { cid: crate::cid::Cidv1::from(cid.clone()), tsize: size.unwrap_or_default(), filesize: 0 }
}

/// How a version's told apart: the end of its set's CID.
fn tag(set: &Link) -> String {
    let text = set.to_string();
    text.get(text.len().saturating_sub(6)..).unwrap_or(&text).to_owned()
}

/// A version's name beside the one it's in conflict with: before the
/// extension, so it still opens as what it is.
fn conflict_name(name: &[u8], tag: &str) -> Vec<u8> {
    let dot = name.iter().rposition(|&byte| byte == b'.').filter(|&at| at > 0);
    let (stem, ext) = name.split_at(dot.unwrap_or(name.len()));
    [stem, format!(" (conflict {tag})").as_bytes(), ext].concat()
}

/// The sets a set comes after, and itself, by position: by `prev`, or for an
/// older build's set, every set before it.
fn reach(sets: &[SetOf], index: &BTreeMap<Vec<u8>, usize>, start: usize) -> Vec<bool> {
    let mut seen = vec![false; sets.len()];
    let mut stack = vec![start];
    while let Some(at) = stack.pop() {
        if seen.get(at).copied().unwrap_or(true) {
            continue;
        }
        if let Some(slot) = seen.get_mut(at) {
            *slot = true;
        }
        match sets.get(at).and_then(|(_, _, _, prev)| prev.as_ref()) {
            Some(prev) => stack.extend(prev.iter().filter_map(|prev| index.get(&prev.to_bytes()).copied())),
            None => {
                for earlier in seen.iter_mut().take(at) {
                    *earlier = true;
                }
            },
        }
    }
    seen
}

/// The latest sets every one of these sides comes to, none of which another of
/// them comes after, by position: more than one, once two devices have each
/// gone on from the same merge, which no set says.
fn latest_common(sets: &[SetOf], index: &BTreeMap<Vec<u8>, usize>, reaches: &[&[bool]]) -> Vec<usize> {
    let mut common: Option<Vec<bool>> = None;
    for seen in reaches {
        common = Some(common.map_or_else(|| seen.to_vec(), |common| common.iter().zip(seen.iter()).map(|(a, b)| *a && *b).collect()));
    }
    let shared: Vec<usize> = common.unwrap_or_default().iter().enumerate().filter(|&(_, &shared)| shared).map(|(at, _)| at).collect();
    let mut covered = vec![false; sets.len()];
    for &at in &shared {
        for (earlier, _) in reach(sets, index, at).iter().enumerate().filter(|&(earlier, &seen)| seen && earlier != at) {
            if let Some(slot) = covered.get_mut(earlier) {
                *slot = true;
            }
        }
    }
    shared.into_iter().filter(|&at| !covered.get(at).copied().unwrap_or(false)).collect()
}
