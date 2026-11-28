//! Which blocks were used lately: served to a member or to Amino, or
//! fetched.
//!
//! A node short of space lets go first of what's least used, so what's
//! held settles into what's wanted, as a cache's does, with no age to
//! set: whatever's used least is what goes, however long ago that was.
//!
//! Held in memory, for every swarm in the process, and lost on restart,
//! when everything's as unused as everything else again.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::multihash::Multihash;

/// The most blocks remembered: past it, the older half is forgotten.
const REMEMBERED: usize = 1 << 17;

#[derive(Default)]
struct Recent {
    /// Each block's last use, as a count of uses.
    at: HashMap<Vec<u8>, u64>,
    uses: u64,
}

fn recent() -> &'static Mutex<Recent> {
    static RECENT: OnceLock<Mutex<Recent>> = OnceLock::new();
    RECENT.get_or_init(Mutex::default)
}

/// Note a block's been used now, by its multihash.
pub fn used(key: &[u8]) {
    let Ok(mut recent) = recent().lock() else {
        return;
    };
    recent.uses = recent.uses.saturating_add(1);
    let now = recent.uses;
    recent.at.insert(key.to_vec(), now);
    if recent.at.len() > REMEMBERED {
        let half = now.saturating_sub(u64::try_from(REMEMBERED / 2).unwrap_or(u64::MAX));
        recent.at.retain(|_, at| *at > half);
    }
}

/// The `n` of these used least lately, never used first.
pub fn least_used(mut keys: Vec<Multihash>, n: usize) -> Vec<Multihash> {
    if let Ok(recent) = recent().lock() {
        keys.sort_by_key(|key| recent.at.get(&key.to_bytes()).copied().unwrap_or(0));
    }
    keys.truncate(n);
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whats_used_least_lately_comes_first_and_whats_never_used_before_it() {
        let key = |n: u8| Multihash::decode(&[0x12, 1, n]).expect("multihash");
        let (old, new, never) = (key(1), key(2), key(3));
        used(&old.to_bytes());
        used(&new.to_bytes());
        assert_eq!(least_used(vec![new.clone(), old.clone(), never.clone()], 2), [never.clone(), old.clone()]);
        // Used again, it's the latest
        used(&old.to_bytes());
        assert_eq!(least_used(vec![new.clone(), old, never], 2).get(1), Some(&new));
    }
}
