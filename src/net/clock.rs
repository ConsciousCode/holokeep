//! How far machines' clocks are apart: `/holokeep/clock/1.0.0`.
//!
//! Every announce, a member asks each other member connected for the
//! time, as NTP does: it notes when it asked and when the answer came,
//! by its own clock, and the member says when it was asked and when it
//! answered, by its. From those four times come how far ahead the
//! member's clock is and how long the round trip took. Of the last few,
//! the one with the shortest round trip is taken, as the least delayed.
//!
//! It's advisory. Nothing is judged by it: a grant's expiry is still each
//! machine's own clock's. It's for saying how far this machine's clock is
//! from the mesh's, the median of the members', so a clock far out can be
//! seen and set right.

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/clock/1.0.0");

/// How many of the last measurements of each member are kept, to take
/// the least delayed.
const SAMPLES: usize = 8;

/// How far from the mesh's this machine's clock may be before it's said,
/// in microseconds.
pub const SKEW: i64 = 2_000_000;

/// Asking for the time: nothing to say.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asked {}

/// The time: when the ask arrived and when the answer left, in
/// microseconds since the Unix epoch, by the answerer's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Told {
    pub got: u64,
    pub sent: u64,
}

/// Now, in microseconds since the Unix epoch, by this machine's clock.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| u64::try_from(since.as_micros()).unwrap_or(u64::MAX))
}

/// One measurement: how far ahead the member's clock is, and the round
/// trip, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset {
    pub ahead: i64,
    pub trip: u64,
}

impl Offset {
    /// From when this asked and heard back, by its clock, and when the
    /// member was asked and answered, by its.
    pub fn of(asked: u64, told: Told, heard: u64) -> Self {
        let (asked, got, sent, heard) = (i128::from(asked), i128::from(told.got), i128::from(told.sent), i128::from(heard));
        let ahead = i128::midpoint(got.saturating_sub(asked), sent.saturating_sub(heard));
        let trip = heard.saturating_sub(asked).saturating_sub(sent.saturating_sub(got));
        Self { ahead: i64::try_from(ahead).unwrap_or(if ahead < 0 { i64::MIN } else { i64::MAX }), trip: u64::try_from(trip.max(0)).unwrap_or(u64::MAX) }
    }
}

/// What's been measured of each member's clock.
#[derive(Debug, Default)]
pub struct Clocks {
    samples: HashMap<PeerId, VecDeque<Offset>>,
}

impl Clocks {
    pub fn record(&mut self, peer: PeerId, offset: Offset) {
        let samples = self.samples.entry(peer).or_default();
        if samples.len() == SAMPLES {
            samples.pop_front();
        }
        samples.push_back(offset);
    }

    pub fn forget(&mut self, peer: &PeerId) {
        self.samples.remove(peer);
    }

    /// The best measurement of a member's clock: the least delayed.
    pub fn of(&self, peer: &PeerId) -> Option<Offset> {
        self.samples.get(peer)?.iter().min_by_key(|offset| offset.trip).copied()
    }

    /// Each member measured, and its best measurement.
    pub fn all(&self) -> Vec<(PeerId, Offset)> {
        let mut all: Vec<(PeerId, Offset)> = self.samples.keys().filter_map(|peer| Some((*peer, self.of(peer)?))).collect();
        all.sort_by_key(|(peer, _)| *peer);
        all
    }

    /// How far ahead the mesh's clock is of this machine's: the median
    /// of the members', counting this machine's own as none ahead, and
    /// how many members that's of. None if no member's measured.
    pub fn mesh(&self) -> Option<(i64, usize)> {
        let mut aheads: Vec<i64> = self.all().into_iter().map(|(_, offset)| offset.ahead).collect();
        if aheads.is_empty() {
            return None;
        }
        let members = aheads.len();
        aheads.push(0);
        aheads.sort_unstable();
        // An even count, so the two in the middle's mean
        let middle = aheads.len() / 2;
        let median = if aheads.len() % 2 == 1 {
            aheads.get(middle).copied()
        } else {
            Some(i64::midpoint(aheads.get(middle.saturating_sub(1)).copied().unwrap_or(0), aheads.get(middle).copied().unwrap_or(0)))
        };
        Some((median.unwrap_or(0), members))
    }
}

/// An offset in microseconds, as people read it: "+1.204 s", "-12 ms".
pub fn shown(micros: i64) -> String {
    let sign = if micros < 0 { "-" } else { "+" };
    let micros = micros.unsigned_abs();
    if micros >= 1_000_000 {
        format!("{sign}{}.{:03} s", micros / 1_000_000, micros % 1_000_000 / 1000)
    } else {
        format!("{sign}{} ms", micros / 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clock_ahead_is_measured_however_long_the_trip() {
        // The member's clock is 5 s ahead; 40 ms each way, 2 ms to answer
        let offset = Offset::of(1_000_000, Told { got: 6_040_000, sent: 6_042_000 }, 1_082_000);
        assert_eq!(offset, Offset { ahead: 5_000_000, trip: 80_000 });
        let behind = Offset::of(10_000_000, Told { got: 7_010_000, sent: 7_010_000 }, 10_020_000);
        assert_eq!(behind, Offset { ahead: -3_000_000, trip: 20_000 });
    }

    #[test]
    fn the_least_delayed_measurement_counts_and_the_mesh_is_the_median() {
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut clocks = Clocks::default();
        assert_eq!(clocks.mesh(), None);
        clocks.record(a, Offset { ahead: 900_000, trip: 300_000 });
        clocks.record(a, Offset { ahead: 1_000_000, trip: 10_000 });
        assert_eq!(clocks.of(&a), Some(Offset { ahead: 1_000_000, trip: 10_000 }));
        // Of this machine, at none, and a: between
        assert_eq!(clocks.mesh(), Some((500_000, 1)));
        clocks.record(b, Offset { ahead: 1_200_000, trip: 5_000 });
        // Of 0, 1 s and 1.2 s
        assert_eq!(clocks.mesh(), Some((1_000_000, 2)));
        clocks.record(c, Offset { ahead: -60_000_000, trip: 5_000 });
        assert_eq!(clocks.mesh(), Some((500_000, 3)), "one far out doesn't move it far");
        clocks.forget(&c);
        assert_eq!(clocks.mesh(), Some((1_000_000, 2)));
        for _ in 0..SAMPLES {
            clocks.record(a, Offset { ahead: 0, trip: 50_000 });
        }
        assert_eq!(clocks.of(&a), Some(Offset { ahead: 0, trip: 50_000 }), "only the last few count");
    }

    #[test]
    fn offsets_are_shown_in_their_unit() {
        assert_eq!(shown(1_204_000), "+1.204 s");
        assert_eq!(shown(-12_345), "-12 ms");
        assert_eq!(shown(0), "+0 ms");
    }
}
