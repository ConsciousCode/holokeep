//! How safe blocks are, for `hk block where`, `hk dag health` and `hk fs
//! stat --copies`.
//!
//! Where each one's copies are, what those risk, and how many failures it
//! would take to lose them all, against what its keeps say it should.
//!
//! What's here is the catalog's to say; what other members hold, the
//! running node's, from what they've said (sightings) or, asked, say now.
//! A copy's being held is all this says: whether its bytes are whole is
//! the volume's to look after, as a mirror does, and the audits'.

use std::collections::{BTreeMap, BTreeSet};

use crate::cid::CidRef as _;
use crate::model::Link;
use crate::store::{Catalog, Replica, Result};

/// A copy another member holds, as it said when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elsewhere {
    pub peer: String,
    pub replica: Replica,
    /// When it said so, in seconds since the epoch.
    pub seen: i64,
}

/// What's known of copies on other members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Known {
    /// Whether a running node said, so other members' copies are known at
    /// all.
    pub node: bool,
    /// How many members the node could have asked: those connected,
    /// hosting the account's user.
    pub connected: usize,
    /// Each block's copies elsewhere, by its multihash.
    pub elsewhere: BTreeMap<Vec<u8>, Vec<Elsewhere>>,
    /// The members asked, which answered.
    pub asked: BTreeSet<String>,
    /// The members asked which didn't answer.
    pub unanswered: BTreeSet<String>,
}

/// A block, and how safe it is.
#[derive(Debug, Clone)]
pub struct Health {
    pub cid: Link,
    /// Its size, if known.
    pub size: Option<u64>,
    /// The copies here, if they count: a client's are a cache.
    pub here: Vec<Replica>,
    pub elsewhere: Vec<Elsewhere>,
    /// How many failures it should take to lose it.
    pub target: usize,
    /// Whether a keep says so, rather than the mesh.
    pub kept: bool,
    /// How many failures it would take.
    pub tolerance: usize,
    /// Risks every copy shares, any one of which failing loses them all.
    pub shared: Vec<String>,
}

impl Health {
    /// Of a block, from what's here and what's known elsewhere. Copies here
    /// count if `own`; `copies` is the mesh's target, where no keep says.
    pub fn of(catalog: &Catalog, cid: &Link, size: Option<u64>, known: &Known, own: bool, copies: usize) -> Result<Self> {
        let key = cid.multihash();
        let here = if own { catalog.replicas(key)? } else { Vec::new() };
        let elsewhere = known.elsewhere.get(&key.to_bytes()).cloned().unwrap_or_default();
        let wanted = catalog.copies_wanted(key, copies)?;
        // A volume two nodes share is one copy
        let distinct: BTreeMap<&[u8], &Vec<String>> = here.iter().chain(elsewhere.iter().map(|copy| &copy.replica)).map(|replica| (replica.label.as_slice(), &replica.risks)).collect();
        let distinct: Vec<Vec<String>> = distinct.into_values().cloned().collect();
        let tolerance = crate::store::tolerance(&distinct, distinct.len());
        let shared = distinct.split_first().map_or_else(Vec::new, |(first, rest)| first.iter().filter(|risk| rest.iter().all(|risks| risks.contains(risk))).cloned().collect());
        Ok(Self { cid: cid.clone(), size, here, elsewhere, target: wanted.unwrap_or(copies), kept: wanted.is_some() && catalog.claims().is_some(), tolerance, shared })
    }

    pub const fn short(&self) -> bool {
        self.tolerance < self.target
    }
}

/// Many blocks' health, together.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub blocks: usize,
    pub bytes: u64,
    /// The least and most failures it would take to lose one.
    pub least: Option<usize>,
    pub most: Option<usize>,
    /// The least and most failures it should take, as their keeps say.
    pub targets: Option<(usize, usize)>,
    /// Blocks short of their targets, and their bytes, and one of them.
    pub short: (usize, u64, Option<Link>),
    /// Blocks with no copy here, though copies count here.
    pub not_here: (usize, u64),
    /// Blocks with no copy anywhere known.
    pub none: (usize, u64, Option<Link>),
    /// Blocks whose every copy one risk failing loses, by the risks.
    pub one_risk: BTreeMap<Vec<String>, (usize, u64)>,
}

impl Summary {
    pub fn add(&mut self, health: &Health, own: bool) {
        let size = health.size.unwrap_or_default();
        self.blocks = self.blocks.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
        self.least = Some(self.least.map_or(health.tolerance, |least| least.min(health.tolerance)));
        self.most = Some(self.most.map_or(health.tolerance, |most| most.max(health.tolerance)));
        self.targets = Some(self.targets.map_or((health.target, health.target), |(least, most)| (least.min(health.target), most.max(health.target))));
        let add = |(count, bytes): (usize, u64)| (count.saturating_add(1), bytes.saturating_add(size));
        if health.short() {
            let (count, bytes) = add((self.short.0, self.short.1));
            self.short = (count, bytes, self.short.2.take().or_else(|| Some(health.cid.clone())));
        }
        if own && health.here.is_empty() {
            self.not_here = add(self.not_here);
        }
        if health.tolerance == 0 {
            let (count, bytes) = add((self.none.0, self.none.1));
            self.none = (count, bytes, self.none.2.take().or_else(|| Some(health.cid.clone())));
        }
        if !health.shared.is_empty() {
            let entry = self.one_risk.entry(health.shared.clone()).or_default();
            *entry = add(*entry);
        }
    }
}

/// A count of bytes, for people: in binary units, to a tenth.
pub fn bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0usize;
    let mut scaled = bytes;
    while scaled >= 1024 && unit < UNITS.len().saturating_sub(1) {
        scaled /= 1024;
        unit = unit.saturating_add(1);
    }
    if unit == 0 {
        return format!("{bytes} bytes");
    }
    let divisor = 1u128 << 10u32.saturating_mul(u32::try_from(unit).unwrap_or_default());
    // In tenths, rounded
    let tenths = (u128::from(bytes).saturating_mul(10).saturating_add(divisor / 2)).checked_div(divisor).unwrap_or_default();
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS.get(unit).copied().unwrap_or("bytes"))
}

/// How long ago a time was, roughly: `just now`, `5m ago`, `3h ago`, `2d
/// ago`.
pub fn ago(seen: i64, now: i64) -> String {
    let secs = now.saturating_sub(seen).max(0);
    match secs {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{}m ago", secs / 60),
        3600..86_400 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// Seconds since the epoch, now.
pub fn now() -> i64 {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// A volume label as text, as it goes over the control socket.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// A volume label from text, as `hex` makes it.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| text.get(i..i.saturating_add(2)).and_then(|pair| u8::from_str_radix(pair, 16).ok())).collect()
}

#[cfg(test)]
mod tests;
