//! Merging an anchor's heads, where it's forked: sets made without seeing
//! each other, as by two devices between syncs.
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
//! its way changed it from what whoever set it saw, even back again: what
//! changed on one side only is taken; what changed the same on every side
//! that changed it is no conflict; directories changed on more than one
//! side are merged in turn; and anything else changed differently is a
//! conflict, kept side by side, the latest version by its name and each
//! other's as `name (conflict <tag>)`, a version being of the latest set
//! that made it so. A change wins over a removal. Without a common
//! ancestor, as when a repo joins a mesh, every name is a change. Anything
//! that isn't every head a directory is the latest head's change.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crate::cid::CidRef as _;
use crate::dag::{BlockSink, DagLink, DirLayoutBuilder as _, DirLayoutStrategy as _};
use crate::export::{self, Kind};
use crate::model::Link;

use super::{Catalog, Result};

/// A head, as merged: what it says, how its conflicts are tagged and where
/// it comes among the sets, and the steps its side took on the way there
/// since what's merged over, so a change it made and undid still counts as
/// its change.
struct Head {
    value: Link,
    tag: String,
    at: usize,
    path: Vec<Step>,
}

/// A set on a side's way, at some place in the tree: what it said there,
/// and what what it came after said, merged, as whoever set it saw; and
/// where it comes among the sets, and its tag, as what it changed is of it.
#[derive(Clone)]
struct Step {
    now: Then,
    was: Then,
    at: usize,
    tag: String,
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

/// One side of a merge: the sets it comes to, as `reach` says, what it
/// says, how its conflicts are tagged and where it comes among the sets.
struct Side {
    reach: Vec<bool>,
    value: Link,
    tag: String,
    at: usize,
}

/// An entry of a directory: what it links to, and the size its link says.
type Entry = (Link, Option<u64>);

/// A directory's entries, by name.
type Listing = BTreeMap<Vec<u8>, Entry>;

/// A sink putting blocks into a catalog through a shared reference.
struct Putting<'a>(&'a Catalog);

impl BlockSink for Putting<'_> {
    fn put(&mut self, block: crate::block::Block) -> io::Result<()> {
        self.0.put_block(&block, crate::cid::CidVersion::V1).map(drop).map_err(io::Error::other)
    }
}

impl Catalog {
    /// What a forked anchor is: its heads, as (set, value, at) by `at`,
    /// merged.
    pub(super) fn merge_heads(&self, anchor: &Link, heads: &[(Link, Link, u64)]) -> Result<Link> {
        let claims = self.claims.as_ref().ok_or(super::Error::NoClaims)?;
        let sets = claims.sets(anchor.multihash())?;
        let index: BTreeMap<Vec<u8>, usize> = sets.iter().enumerate().map(|(i, (set, ..))| (set.to_bytes(), i)).collect();
        let from: Option<Vec<usize>> = heads.iter().map(|(set, _, _)| index.get(&set.to_bytes()).copied()).collect();
        if let Some(from) = from {
            return Ok(self.merged(&sets, &index, &from)?);
        }
        let heads: Vec<Head> = heads.iter().map(|(set, value, _)| Head { value: value.clone(), tag: tag(set), at: usize::MAX, path: Vec::new() }).collect();
        Ok(self.merge_values(None, &(0, String::new()), &heads)?)
    }

    /// These sets merged, two at a time, in order, each pair over what it
    /// has in common: its latest common set's value, or if there's more
    /// than one, those merged in turn, as that's what's gone on from. Two at
    /// a time, as two of them may have more in common than all of them do.
    /// Worked out the same everywhere, from the same sets.
    fn merged(&self, sets: &[super::SetOf], index: &BTreeMap<Vec<u8>, usize>, from: &[usize]) -> io::Result<Link> {
        let mut sides: Vec<Side> = Vec::new();
        for &at in from {
            let (set, value, ..) = sets.get(at).ok_or_else(|| io::Error::other("no such set"))?;
            sides.push(Side { reach: reach(sets, index, at), value: value.clone(), tag: tag(set), at });
        }
        if let [one] = sides.as_slice() {
            return Ok(one.value.clone());
        }
        // Kept, as the catalog keeps what heads merge to
        let key: Vec<u8> = from.iter().filter_map(|&at| sets.get(at)).flat_map(|(set, ..)| set.to_bytes()).collect();
        if let Some(merged) = self.merges.borrow().get(&key) {
            return Ok(merged.clone());
        }
        let merged = self.merging(sets, index, sides)?;
        self.merges.borrow_mut().insert(key, merged.clone());
        Ok(merged)
    }

    fn merging(&self, sets: &[super::SetOf], index: &BTreeMap<Vec<u8>, usize>, sides: Vec<Side>) -> io::Result<Link> {
        if sides.len() > 2 {
            let mut sides = sides.into_iter();
            let mut merged = sides.next().ok_or_else(|| io::Error::other("no heads"))?;
            for side in sides {
                let value = self.merge_sides(sets, index, &[&merged, &side])?;
                let reach = merged.reach.iter().zip(&side.reach).map(|(a, b)| *a || *b).collect();
                merged = Side { reach, value, tag: side.tag, at: side.at };
            }
            return Ok(merged.value);
        }
        let sides: Vec<&Side> = sides.iter().collect();
        self.merge_sides(sets, index, &sides)
    }

    /// Two sides merged, over what they have in common.
    fn merge_sides(&self, sets: &[super::SetOf], index: &BTreeMap<Vec<u8>, usize>, sides: &[&Side]) -> io::Result<Link> {
        let reaches: Vec<&[bool]> = sides.iter().map(|side| side.reach.as_slice()).collect();
        let latest = latest_common(sets, index, &reaches);
        let base = match latest.as_slice() {
            [] => None,
            [one] => sets.get(*one).map(|(_, value, ..)| value.clone()),
            // What isn't here to merge, the latest of them says it
            many => self.merged(sets, index, many).ok().or_else(|| many.last().and_then(|at| sets.get(*at)).map(|(_, value, ..)| value.clone())),
        };
        // What every side had come to already, and so isn't any side's
        let mut before = vec![false; sets.len()];
        for &at in &latest {
            for (slot, seen) in before.iter_mut().zip(reach(sets, index, at)) {
                *slot = *slot || seen;
            }
        }
        let heads: Vec<Head> = sides.iter()
            .map(|side| {
                // Each set of its own and what it came after: a set with
                // nothing before it is of another past, and says nothing of
                // what changed in this one
                let mut path: Vec<Step> = Vec::new();
                for (on, _) in side.reach.iter().zip(&before).enumerate().filter(|&(_, (&seen, &before))| seen && !before) {
                    let Some((set, said, _, Some(prev))) = sets.get(on) else {
                        continue;
                    };
                    let was: Option<Vec<usize>> = prev.iter().map(|prev| index.get(&prev.to_bytes()).copied()).collect();
                    let Some(mut was) = was.filter(|was| !was.is_empty()) else {
                        continue;
                    };
                    was.sort_unstable();
                    was.dedup();
                    // What isn't here to merge, nothing's told of
                    let was = self.merged(sets, index, &was).map_or(Then::Unknown, Then::Is);
                    if was != Then::Is(said.clone()) {
                        path.push(Step { now: Then::Is(said.clone()), was, at: on, tag: tag(set) });
                    }
                }
                Head { value: side.value.clone(), tag: side.tag.clone(), at: side.at, path }
            })
            .collect();
        // What it had in common is of the latest it had in common
        let base_of = latest.last().and_then(|&at| sets.get(at)).map_or((0, String::new()), |(set, ..)| (0, tag(set)));
        self.merge_values(base.as_ref(), &base_of, &heads)
    }

    /// Heads' values merged, over what they had in common, if that's
    /// known and here.
    fn merge_values(&self, base: Option<&Link>, base_of: &(usize, String), heads: &[Head]) -> io::Result<Link> {
        let distinct: BTreeSet<Vec<u8>> = heads.iter().map(|head| head.value.to_bytes()).collect();
        let latest = heads.last().ok_or_else(|| io::Error::other("no heads"))?;
        if distinct.len() == 1 {
            return Ok(latest.value.clone());
        }
        let base = base.filter(|base| self.is_dir(base).unwrap_or(false));
        let mut dirs = true;
        for head in heads {
            dirs = dirs && self.is_dir(&head.value)?;
        }
        if !dirs {
            // The latest change wins
            let changed = heads.iter().rev().find(|head| Some(&head.value) != base);
            return Ok(changed.unwrap_or(latest).value.clone());
        }
        let refs: Vec<&Head> = heads.iter().collect();
        Ok(self.merge_dirs(base, base_of, &refs)?.cid.into())
    }

    /// A step's directory, listed, once: none where it's not a directory.
    fn listing(&self, then: &Then, listed: &mut BTreeMap<Vec<u8>, Option<Listing>>) -> io::Result<Option<Listing>> {
        match then {
            Then::Nothing => Ok(Some(BTreeMap::new())),
            Then::Unknown => Ok(None),
            Then::Is(cid) => {
                if let Some(found) = listed.get(&cid.to_bytes()) {
                    return Ok(found.clone());
                }
                let found = if self.is_dir(cid)? { Some(self.entries(Some(cid))?) } else { None };
                listed.insert(cid.to_bytes(), found.clone());
                Ok(found)
            },
        }
    }

    fn is_dir(&self, cid: &Link) -> io::Result<bool> {
        Ok(matches!(export::stat(self, cid)?, Kind::Directory))
    }

    fn entries(&self, dir: Option<&Link>) -> io::Result<BTreeMap<Vec<u8>, Entry>> {
        let Some(dir) = dir else {
            return Ok(BTreeMap::new());
        };
        Ok(export::list(self, dir)?.into_iter().map(|entry| (entry.name, (entry.cid, entry.size))).collect())
    }

    /// Directories merged, name by name, over `base`, which is of
    /// `base_of`: older than any change since.
    fn merge_dirs(&self, base: Option<&Link>, base_of: &(usize, String), heads: &[&Head]) -> io::Result<DagLink> {
        let base = self.entries(base)?;
        let mut sides = Vec::new();
        for head in heads {
            sides.push(self.entries(Some(&head.value))?);
        }
        // The steps each side took on the way, listed
        let mut listed: BTreeMap<Vec<u8>, Option<Listing>> = BTreeMap::new();
        let mut paths: Vec<Vec<(Option<Listing>, Option<Listing>)>> = Vec::new();
        for head in heads {
            let mut path = Vec::new();
            for step in &head.path {
                path.push((self.listing(&step.now, &mut listed)?, self.listing(&step.was, &mut listed)?));
            }
            paths.push(path);
        }
        let names: BTreeSet<&Vec<u8>> = base.keys().chain(sides.iter().flat_map(BTreeMap::keys)).collect();
        let mut merged: BTreeMap<Vec<u8>, DagLink> = BTreeMap::new();
        for name in names {
            let was = base.get(name);
            let same = |a: Option<&Entry>, b: Option<&Entry>| a.map(|(cid, _)| cid) == b.map(|(cid, _)| cid);
            // Each head that changed it, latest last, what to, and what it
            // said on the way: changed, even if it's back as it was
            let changed: Vec<(&Head, Option<&Entry>, Vec<Step>)> = heads.iter().zip(&sides).zip(&paths)
                .map(|((head, side), path)| {
                    let path: Vec<Step> = path.iter()
                        .zip(&head.path)
                        .map(|((now, was), step)| Step { now: at(now.as_ref(), name), was: at(was.as_ref(), name), at: step.at, tag: step.tag.clone() })
                        .filter(|step| step.was.differs(&step.now))
                        .collect();
                    (*head, side.get(name), path)
                })
                .filter(|(_, now, path)| !same(*now, was) || !path.is_empty())
                .collect();
            // Each version, with what every head that changed it so said on
            // the way, and what it's of: the latest set to make it so; what
            // was, what it was of, older than any change; or failing those,
            // the latest head that has it. Of that, and not of whichever
            // heads are merged, so a conflict comes out the same however
            // it's come to
            let mut versions: Vec<((usize, String), &Entry, Vec<Step>)> = Vec::new();
            for (head, now, path) in &changed {
                let Some(now) = now else {
                    continue;
                };
                let made = path.iter().filter(|step| step.now == Then::Is(now.0.clone())).map(|step| (step.at, step.tag.clone())).max();
                let of = made.unwrap_or_else(|| if same(Some(now), was) { base_of.clone() } else { (head.at, head.tag.clone()) });
                match versions.iter_mut().find(|(_, seen, _)| same(Some(seen), Some(now))) {
                    Some((was_of, _, seen)) => {
                        seen.extend(path.iter().cloned());
                        *was_of = was_of.clone().max(of);
                    },
                    None => versions.push((of, now, path.clone())),
                }
            }
            versions.sort_by(|(a, ..), (b, ..)| a.cmp(b));
            let entry = match (changed.is_empty(), versions.as_slice()) {
                (true, _) => was.cloned(),
                // Removed on every side that changed it
                (false, []) => None,
                (false, [(_, one, _)]) => Some((*one).clone()),
                (false, many) => {
                    let mut all_dirs = true;
                    for (_, (cid, _), _) in many {
                        all_dirs = all_dirs && self.is_dir(cid)?;
                    }
                    let was_dir = match was {
                        Some((cid, _)) => self.is_dir(cid)?,
                        None => true,
                    };
                    if all_dirs && was_dir {
                        let sub: Vec<Head> = many.iter()
                            .map(|((at, tag), (cid, _), path)| Head { value: cid.clone(), tag: tag.clone(), at: *at, path: path.clone() })
                            .collect();
                        let refs: Vec<&Head> = sub.iter().collect();
                        merged.insert(name.clone(), self.merge_dirs(was.map(|(cid, _)| cid), base_of, &refs)?);
                        continue;
                    }
                    // A conflict: the latest by its name, the rest beside it
                    let Some((last, others)) = many.split_last() else {
                        continue;
                    };
                    for ((_, tag), entry, _) in others {
                        merged.insert(conflict_name(name, tag), link_of(entry));
                    }
                    Some(last.1.clone())
                },
            };
            if let Some(entry) = entry {
                merged.insert(name.clone(), link_of(&entry));
            }
        }
        let mut dir = crate::import::Importer::default().directory.builder();
        let mut sink = Putting(self);
        for (name, link) in merged {
            dir.add_link(name, link, &mut sink)?;
        }
        dir.finalize(&mut sink)
    }
}

/// What a listed step said of a name.
fn at(listed: Option<&Listing>, name: &[u8]) -> Then {
    listed.map_or(Then::Unknown, |listed| listed.get(name).map_or(Then::Nothing, |(cid, _)| Then::Is(cid.clone())))
}

fn link_of((cid, size): &Entry) -> DagLink {
    DagLink { cid: crate::cid::Cidv1::from(cid.clone()), tsize: size.unwrap_or_default(), filesize: 0 }
}

/// How a head's conflicts are told apart: the end of its set's CID.
fn tag(set: &Link) -> String {
    let text = set.to_string();
    text.get(text.len().saturating_sub(6)..).unwrap_or(&text).to_owned()
}

/// A conflicting version's name beside the one it conflicts with: before
/// the extension, so it still opens as what it is.
fn conflict_name(name: &[u8], tag: &str) -> Vec<u8> {
    let dot = name.iter().rposition(|&byte| byte == b'.').filter(|&at| at > 0);
    let (stem, ext) = name.split_at(dot.unwrap_or(name.len()));
    [stem, format!(" (conflict {tag})").as_bytes(), ext].concat()
}

/// The sets a set comes after, and itself, by position: by `prev`, or for an
/// older build's set, every set before it.
fn reach(sets: &[super::SetOf], index: &BTreeMap<Vec<u8>, usize>, start: usize) -> Vec<bool> {
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
fn latest_common(sets: &[super::SetOf], index: &BTreeMap<Vec<u8>, usize>, reaches: &[&[bool]]) -> Vec<usize> {
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
