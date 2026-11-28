//! Replication as a balance: a copy is kept where it's worth more than
//! the space it takes.
//!
//! The copies a block settles at follow from how full the mesh is,
//! rather than being a count set in advance. See the wiki's "Replication
//! as a Balance".
//!
//! Space costs the odds of being full, `p / (1 − p)`: 1 at half full,
//! without bound as a node fills. A copy is worth how much it lowers
//! the chance of losing its block, each copy being lost with the same
//! chance `q`, weighted so that a block's `n`-th copy, `n` its
//! `copies`, is worth 1: the `k`-th is worth `q^(k − n)`.

use serde::{Deserialize, Serialize};

/// The chance of a copy being lost, as assumed till more's known.
pub const PRIOR: f64 = 0.1;

/// How full a node is: what it stores, and what it would store at most,
/// its target or else what it stores and its free space together.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fill {
    pub stored: u64,
    pub capacity: u64,
}

impl Fill {
    /// How full a node is that stores this much, under a target if it
    /// has one, else with this much free; None if neither's known.
    pub fn of(stored: u64, target: Option<u64>, free: Option<u64>) -> Option<Self> {
        let capacity = target.or_else(|| free.map(|free| free.saturating_add(stored)))?;
        Some(Self { stored, capacity })
    }

    /// What space costs here: the odds of being full.
    pub fn cost(self) -> f64 {
        self.cost_with(0)
    }

    /// What space would cost here with this much more stored.
    pub fn cost_with(self, more: u64) -> f64 {
        let stored = self.stored.saturating_add(more);
        if stored >= self.capacity {
            return f64::INFINITY;
        }
        // Space short of the capacity, over what's stored, inverted
        let free = self.capacity.saturating_sub(stored);
        lossy(stored) / lossy(free)
    }

    /// The share of the capacity stored.
    pub fn share(self) -> f64 {
        if self.capacity == 0 {
            return 1.0;
        }
        lossy(self.stored) / lossy(self.capacity)
    }
}

/// What space costs a node whose fill isn't known: as at half full.
pub const UNKNOWN: f64 = 1.0;

/// The cost of a fill that may not be known.
pub fn cost(fill: Option<Fill>, more: u64) -> f64 {
    fill.map_or(UNKNOWN, |fill| fill.cost_with(more))
}

/// What a block's `k`-th copy is worth, of `n` wanted, each copy lost
/// with the chance `q`: `q^(k − n)`.
///
/// A copy that adds nothing, the 0th, is worth nothing. The last copy
/// never goes whatever it's worth; what it's worth says whether it's
/// moved.
pub fn value(k: usize, n: usize, q: f64) -> f64 {
    if k == 0 {
        return 0.0;
    }
    let exponent = i32::try_from(k).unwrap_or(i32::MAX).saturating_sub(i32::try_from(n).unwrap_or(i32::MAX));
    q.clamp(f64::MIN_POSITIVE, 1.0).powi(exponent)
}

/// What a block's copies are worth: `n` wanted, each lost with the
/// chance `q`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Worth {
    pub n: usize,
    pub q: f64,
}

impl Worth {
    /// What its `k`-th copy is worth.
    pub fn of(self, k: usize) -> f64 {
        value(k, self.n, self.q)
    }

    /// What every copy's worth to a block that wants only one where it
    /// counts, such as a client's, whose own copies don't: all there is.
    pub const EVERYTHING: Self = Self { n: usize::MAX, q: PRIOR };

    /// Whether a copy that makes it `k` is worth what space costs: a
    /// copy's taken where it's worth as much, and goes only where it's
    /// worth less, so a node whose fill isn't known, as at half full,
    /// keeps a block's `n`-th copy and no more.
    pub fn outweighs(self, k: usize, cost: f64) -> bool {
        self.of(k) >= cost
    }
}

/// What a node weighs copies by: the copies a block wants unless a keep
/// says otherwise, the chance of losing a copy, and what space costs, here
/// or, cheapest, elsewhere, as what's weighing asks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Scales {
    pub copies: usize,
    pub q: f64,
    pub cost: f64,
}

impl Scales {
    /// What the copies of a block wanting `n` are worth.
    pub const fn worth(self, n: usize) -> Worth {
        Worth { n, q: self.q }
    }
}

/// The rendezvous weight of a member whose space costs this: emptier
/// members win in proportion.
pub fn weight(cost: f64) -> f64 {
    1.0 / cost.max(1e-12)
}

/// A count as a float, for ratios: exact to 2^53, near enough past it.
fn lossy(n: u64) -> f64 {
    // Two halves, each exact
    let (high, low) = (u32::try_from(n >> 32).unwrap_or(u32::MAX), u32::try_from(n & u64::from(u32::MAX)).unwrap_or(u32::MAX));
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_costs_the_odds_of_being_full() {
        let half = Fill { stored: 50, capacity: 100 };
        assert!((half.cost() - 1.0).abs() < 1e-12);
        assert!((Fill { stored: 90, capacity: 100 }.cost() - 9.0).abs() < 1e-9);
        assert!(Fill { stored: 0, capacity: 100 }.cost().abs() < 1e-12);
        assert!(half.cost_with(50).is_infinite(), "full costs without bound");
        assert!(Fill { stored: 0, capacity: 0 }.cost().is_infinite(), "a target of nothing has no room");
        assert!((half.cost_with(30) - 4.0).abs() < 1e-9, "with what it would take");
        assert!((cost(None, 7) - UNKNOWN).abs() < f64::EPSILON);
    }

    #[test]
    fn a_fill_is_under_the_target_or_else_the_free_space() {
        assert_eq!(Fill::of(10, Some(100), Some(5)), Some(Fill { stored: 10, capacity: 100 }));
        assert_eq!(Fill::of(10, None, Some(30)), Some(Fill { stored: 10, capacity: 40 }));
        assert_eq!(Fill::of(10, None, None), None);
    }

    #[test]
    fn the_nth_copy_is_worth_what_space_costs_at_half_full() {
        let q = 0.1;
        assert!((value(2, 2, q) - 1.0).abs() < 1e-12);
        assert!((value(3, 2, q) - 0.1).abs() < 1e-12);
        assert!((value(2, 3, q) - 10.0).abs() < 1e-9);
        assert!((value(1, 2, q) - 10.0).abs() < 1e-9);
        assert!(Worth::EVERYTHING.of(1).is_infinite() && Worth::EVERYTHING.of(5).is_infinite());
        assert!(value(0, 2, q).abs() < f64::EPSILON, "a copy adding nothing is worth nothing");
        // Kept till: the 3rd of 2 past 9.1%, the 2nd of 3 past 90.9%
        let till = |v: f64| v / (1.0 + v);
        assert!((till(value(3, 2, q)) - 0.0909).abs() < 1e-3);
        assert!((till(value(2, 3, q)) - 0.909).abs() < 1e-3);
    }
}
