//! Merging an anchor's heads, where it's forked: sets made without seeing
//! each other, as by two devices between syncs.
//!
//! Every node computes the same merge from the same claims, so nothing
//! has to agree on it; the next set of the anchor, by anyone, names every
//! head as its `prev`, and says what it is.
//!
//! Directories merge three ways, name by name, against the heads' latest
//! common ancestor: what changed on one side only is taken; what changed
//! the same on every side that changed it is no conflict; directories
//! changed on more than one side are merged in turn; and anything else
//! changed differently is a conflict, kept side by side, the latest head's
//! by its name and each other's as `name (conflict <tag>)`. A change wins
//! over a removal. Without a common ancestor, as when a repo joins a mesh,
//! every name is a change. Anything that isn't every head a directory is
//! the latest head's change.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crate::cid::CidRef as _;
use crate::dag::{BlockSink, DagLink, DirLayoutBuilder as _, DirLayoutStrategy as _};
use crate::export::{self, Kind};
use crate::model::Link;

use super::{Catalog, Result};

/// A head, as merged: what it says, and how its conflicts are tagged.
struct Head {
    value: Link,
    tag: String,
}

/// An entry of a directory: what it links to, and the size its link says.
type Entry = (Link, Option<u64>);

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
        let base = common_ancestor(&sets, heads.iter().map(|(set, _, _)| set));
        let heads: Vec<Head> = heads.iter().map(|(set, value, _)| Head { value: value.clone(), tag: tag(set) }).collect();
        Ok(self.merge_values(base.as_ref(), &heads)?)
    }

    /// Heads' values merged, over what they had in common, if that's
    /// known and here.
    fn merge_values(&self, base: Option<&Link>, heads: &[Head]) -> io::Result<Link> {
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
        Ok(self.merge_dirs(base, &refs)?.cid.into())
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

    /// Directories merged, name by name, over `base`.
    fn merge_dirs(&self, base: Option<&Link>, heads: &[&Head]) -> io::Result<DagLink> {
        let base = self.entries(base)?;
        let mut sides = Vec::new();
        for head in heads {
            sides.push(self.entries(Some(&head.value))?);
        }
        let names: BTreeSet<&Vec<u8>> = base.keys().chain(sides.iter().flat_map(BTreeMap::keys)).collect();
        let mut merged: BTreeMap<Vec<u8>, DagLink> = BTreeMap::new();
        for name in names {
            let was = base.get(name);
            let same = |a: Option<&Entry>, b: Option<&Entry>| a.map(|(cid, _)| cid) == b.map(|(cid, _)| cid);
            // Each head that changed it, latest last, and what to
            let changed: Vec<(&Head, Option<&Entry>)> = heads.iter().zip(&sides)
                .map(|(head, side)| (*head, side.get(name)))
                .filter(|(_, now)| !same(*now, was))
                .collect();
            let mut versions: Vec<(&Head, &Entry)> = Vec::new();
            for (head, now) in &changed {
                if let Some(now) = now
                    && !versions.iter().any(|(_, seen)| same(Some(seen), Some(now)))
                {
                    versions.push((head, now));
                }
            }
            let entry = match (changed.is_empty(), versions.as_slice()) {
                (true, _) => was.cloned(),
                // Removed on every side that changed it
                (false, []) => None,
                (false, [(_, one)]) => Some((*one).clone()),
                (false, many) => {
                    let mut all_dirs = true;
                    for (_, (cid, _)) in many {
                        all_dirs = all_dirs && self.is_dir(cid)?;
                    }
                    let was_dir = match was {
                        Some((cid, _)) => self.is_dir(cid)?,
                        None => true,
                    };
                    if all_dirs && was_dir {
                        let sub: Vec<Head> = many.iter().map(|(head, (cid, _))| Head { value: cid.clone(), tag: head.tag.clone() }).collect();
                        let refs: Vec<&Head> = sub.iter().collect();
                        merged.insert(name.clone(), self.merge_dirs(was.map(|(cid, _)| cid), &refs)?);
                        continue;
                    }
                    // A conflict: the latest by its name, the rest beside it
                    let Some((last, others)) = many.split_last() else {
                        continue;
                    };
                    for (head, entry) in others {
                        merged.insert(conflict_name(name, &head.tag), link_of(entry));
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

/// The value of the latest set every head comes after, if any: by `prev`,
/// or for an older build's set, every set before it.
fn common_ancestor<'a>(sets: &[super::SetOf], heads: impl Iterator<Item = &'a Link>) -> Option<Link> {
    let index: BTreeMap<Vec<u8>, usize> = sets.iter().enumerate().map(|(i, (set, ..))| (set.to_bytes(), i)).collect();
    let mut common: Option<Vec<bool>> = None;
    for head in heads {
        let start = *index.get(&head.to_bytes())?;
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
                // An older build's set comes after every set before it
                None => {
                    for earlier in seen.iter_mut().take(at) {
                        *earlier = true;
                    }
                },
            }
        }
        common = Some(match common {
            None => seen,
            Some(common) => common.iter().zip(&seen).map(|(a, b)| *a && *b).collect(),
        });
    }
    let common = common?;
    let latest = common.iter().rposition(|&shared| shared)?;
    sets.get(latest).map(|(_, value, ..)| value.clone())
}
