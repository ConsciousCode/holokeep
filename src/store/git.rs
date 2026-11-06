//! Git objects that come whole, kept as deltas: each commit new here has
//! its trees compared with its parents', path by path, and what a parent
//! has where the commit has something else is kept as a delta on that,
//! as the version after it, so the newest is whole.
//!
//! Objects come in any order, so a commit waits till what it's compared
//! by is here, being looked at again each time git objects have stopped
//! coming for a while, a few times at most.

use std::collections::{BTreeMap, HashMap};

use crate::block::Block;
use crate::cid::{BaseCid as _, CidRef as _, GIT_RAW_CODEC};
use crate::git::{self, Kind};
use crate::model::Link;

use super::{BlockIndex as _, Catalog, Result};

/// How many times a commit's looked at without all it's compared by
/// here, before it's let go of.
const TRIES: u32 = 8;

/// Commits waiting to be looked at, and whether git objects have come
/// since they last were.
#[derive(Default)]
pub struct Commits {
    waiting: BTreeMap<Vec<u8>, (Link, u32)>,
    arrived: bool,
}

impl Commits {
    /// A block new here: a git object's noted, and a commit waits.
    pub fn arrived(&mut self, block: &Block) {
        if block.cid().codec() != GIT_RAW_CODEC {
            return;
        }
        self.arrived = true;
        if block.data().starts_with(b"commit ") {
            let link: Link = block.cid().clone().into();
            self.waiting.entry(link.to_bytes()).or_insert((link, 0));
        }
    }
}

/// What a pass made deltas of, and how many commits still wait.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GitDeltas {
    pub deltas: usize,
    pub waiting: usize,
}

impl Catalog {
    /// Whether git objects have come since this was last asked, so a pass
    /// would do better to wait till they stop.
    pub fn git_arriving(&self) -> bool {
        std::mem::take(&mut self.commits.borrow_mut().arrived)
    }

    /// Whether any commits wait to be looked at.
    pub fn git_waiting(&self) -> bool {
        !self.commits.borrow().waiting.is_empty()
    }

    /// Look at each commit waiting: what its parents have where it has
    /// something else, kept as deltas on what it has.
    pub fn git_deltas(&self) -> Result<GitDeltas> {
        let waiting = std::mem::take(&mut self.commits.borrow_mut().waiting);
        let mut done = GitDeltas::default();
        let mut still = BTreeMap::new();
        for (key, (commit, tries)) in waiting {
            let whole = self.commit_deltas(&commit, &mut done.deltas)?;
            let tries = tries.saturating_add(1);
            if !whole && tries < TRIES {
                still.insert(key, (commit, tries));
            }
        }
        done.waiting = still.len();
        let mut commits = self.commits.borrow_mut();
        for (key, waiting) in still {
            commits.waiting.entry(key).or_insert(waiting);
        }
        Ok(done)
    }

    /// A commit compared with its parents. Returns whether everything it
    /// was compared by was here.
    fn commit_deltas(&self, commit: &Link, deltas: &mut usize) -> Result<bool> {
        let Some((tree, parents)) = self.commit_of(commit)? else {
            return Ok(false);
        };
        let mut whole = true;
        for parent in parents {
            match self.commit_of(&parent)? {
                Some((older, _)) => whole &= self.tree_deltas(&older, &tree, deltas, 0)?,
                None => whole = false,
            }
        }
        Ok(whole)
    }

    /// A commit's tree and parents, if it's here.
    fn commit_of(&self, commit: &Link) -> Result<Option<(Link, Vec<Link>)>> {
        let Some(block) = self.get_block(commit)? else {
            return Ok(None);
        };
        Ok(match git::parse(block.data()) {
            Ok((Kind::Commit, content)) => git::commit(content).ok(),
            _ => None,
        })
    }

    /// Two versions of a tree compared, path by path, the older and what
    /// it has kept as deltas on the newer and what it has. Returns whether
    /// everything compared was here.
    fn tree_deltas(&self, older: &Link, newer: &Link, deltas: &mut usize, depth: usize) -> Result<bool> {
        if older == newer {
            return Ok(true);
        }
        if depth > crate::export::MAX_DEPTH {
            return Ok(true);
        }
        let (Some(old), Some(new)) = (self.get_block(older)?, self.get_block(newer)?) else {
            return Ok(false);
        };
        let (Ok((Kind::Tree, old_content)), Ok((Kind::Tree, new_content))) = (git::parse(old.data()), git::parse(new.data())) else {
            return Ok(true);
        };
        let (Ok(old_entries), Ok(new_entries)) = (git::entries(old_content), git::entries(new_content)) else {
            return Ok(true);
        };
        if self.revise(older, newer)? {
            *deltas = deltas.saturating_add(1);
        }
        let before: HashMap<&[u8], &git::Entry<'_>> = old_entries.iter().map(|entry| (entry.name, entry)).collect();
        let mut whole = true;
        for entry in &new_entries {
            let Some(was) = before.get(entry.name).filter(|was| was.link != entry.link) else {
                continue;
            };
            if was.is_tree() && entry.is_tree() {
                whole &= self.tree_deltas(&was.link, &entry.link, deltas, depth.saturating_add(1))?;
            }
            else if was.is_blob() && entry.is_blob() {
                if !self.has(was.link.multihash())? || !self.has(entry.link.multihash())? {
                    whole = false;
                }
                else if self.revise(&was.link, &entry.link)? {
                    *deltas = deltas.saturating_add(1);
                }
            }
        }
        Ok(whole)
    }
}
