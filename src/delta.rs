//! Deltas: a block's bytes as copies from another's and bytes of its own,
//! in git's delta format, so a pack's deltas are kept as they come.
//!
//! A delta is the base's size and the target's, each a little-endian
//! base-128 varint, then ops till the end: `1sssoooo` copies from the base,
//! the `o` bits saying which of 4 offset bytes follow and the `s` bits
//! which of 3 size bytes (a size of 0 meaning 0x10000); `0nnnnnnn`, n > 0,
//! inserts the next n bytes.
//!
//! `encode` finds a delta between two blocks, as git's does: the base's
//! 16-byte windows indexed by a hash, the target's windows hashed as they
//! roll past, and each match extended both ways.

#[derive(Debug, thiserror::Error)]
#[error("a bad delta: {0}")]
pub struct Error(&'static str);

pub type Result<T> = std::result::Result<T, Error>;

/// The most one copy op copies.
const MOST_COPIED: usize = 0x00ff_ffff;

/// The most one insert op inserts.
const MOST_INSERTED: usize = 0x7f;

/// One op of a delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op<'a> {
    Copy { offset: usize, len: usize },
    Insert(&'a [u8]),
}

/// A delta's base size, target size and ops.
pub struct Ops<'a> {
    delta: &'a [u8],
    at: usize,
}

fn varint(delta: &[u8], at: &mut usize) -> Result<usize> {
    let mut value = 0_usize;
    let mut shift = 0_u32;
    loop {
        let c = *delta.get(*at).ok_or(Error("cut short"))?;
        *at = at.saturating_add(1);
        value |= usize::from(c & 0x7f).checked_shl(shift).filter(|_| shift < usize::BITS).ok_or(Error("a size too big"))?;
        shift = shift.saturating_add(7);
        if c & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// A delta's sizes, of its base and its target, and its ops.
pub fn read(delta: &[u8]) -> Result<(usize, usize, Ops<'_>)> {
    let mut at = 0;
    let source = varint(delta, &mut at)?;
    let target = varint(delta, &mut at)?;
    Ok((source, target, Ops { delta, at }))
}

impl<'a> Iterator for Ops<'a> {
    type Item = Result<Op<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let op = *self.delta.get(self.at)?;
        self.at = self.at.saturating_add(1);
        Some(self.op(op))
    }
}

impl<'a> Ops<'a> {
    fn op(&mut self, op: u8) -> Result<Op<'a>> {
        if op & 0x80 != 0 {
            let mut field = |bits: u32, from: u32| -> Result<usize> {
                let mut value = 0_usize;
                for bit in 0..bits {
                    if op & (1 << (from.saturating_add(bit))) != 0 {
                        let c = *self.delta.get(self.at).ok_or(Error("cut short"))?;
                        self.at = self.at.saturating_add(1);
                        value |= usize::from(c) << bit.saturating_mul(8);
                    }
                }
                Ok(value)
            };
            let offset = field(4, 0)?;
            let len = match field(3, 4)? {
                0 => 0x10000,
                len => len,
            };
            Ok(Op::Copy { offset, len })
        }
        else if op != 0 {
            let end = self.at.saturating_add(usize::from(op));
            let bytes = self.delta.get(self.at..end).ok_or(Error("cut short"))?;
            self.at = end;
            Ok(Op::Insert(bytes))
        }
        else {
            Err(Error("the reserved op"))
        }
    }
}

/// A delta applied to its base.
pub fn apply(base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    let (source, target, ops) = read(delta)?;
    if source != base.len() {
        return Err(Error("a delta on another base"));
    }
    let mut out = Vec::with_capacity(target.min(1 << 30));
    for op in ops {
        match op? {
            Op::Copy { offset, len } => {
                let end = offset.checked_add(len).ok_or(Error("copying too much"))?;
                out.extend_from_slice(base.get(offset..end).ok_or(Error("copying past the base"))?);
            },
            Op::Insert(bytes) => out.extend_from_slice(bytes),
        }
        if out.len() > target {
            return Err(Error("making too much"));
        }
    }
    if out.len() != target {
        return Err(Error("making the wrong size"));
    }
    Ok(out)
}

/// A delta, written op by op.
pub struct Writer(Vec<u8>);

fn push_varint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let low = u8::try_from(value & 0x7f).unwrap_or_default();
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

impl Writer {
    /// A delta from a base of `source` bytes to a target of `target`.
    pub fn new(source: usize, target: usize) -> Self {
        let mut out = Vec::new();
        push_varint(&mut out, source);
        push_varint(&mut out, target);
        Self(out)
    }

    pub fn copy(&mut self, mut offset: usize, mut len: usize) -> Result<()> {
        while len > 0 {
            let now = len.min(MOST_COPIED);
            if u32::try_from(offset).is_err() {
                return Err(Error("copying from past 4 GiB"));
            }
            let mut op = 0x80_u8;
            let at = self.0.len();
            self.0.push(0);
            for bit in 0..4_u32 {
                let byte = u8::try_from((offset >> bit.saturating_mul(8)) & 0xff).unwrap_or_default();
                if byte != 0 {
                    op |= 1 << bit;
                    self.0.push(byte);
                }
            }
            // A size of 0x10000 is said by none of its bytes
            if now != 0x10000 {
                for bit in 0..3_u32 {
                    let byte = u8::try_from((now >> bit.saturating_mul(8)) & 0xff).unwrap_or_default();
                    if byte != 0 {
                        op |= 1 << bit.saturating_add(4);
                        self.0.push(byte);
                    }
                }
            }
            if let Some(slot) = self.0.get_mut(at) {
                *slot = op;
            }
            offset = offset.saturating_add(now);
            len = len.saturating_sub(now);
        }
        Ok(())
    }

    pub fn insert(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(MOST_INSERTED) {
            self.0.push(u8::try_from(chunk.len()).unwrap_or_default());
            self.0.extend_from_slice(chunk);
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// The bytes a match is found by: a window of the base, at every multiple
/// of this, or of the target, at every offset.
const WINDOW: usize = 16;

/// The most places in the base a window of the target is looked for at.
const MOST_CANDIDATES: usize = 64;

/// A match shorter than this is looked past, for one that goes further.
const LAZY: usize = 128;

/// What a window's hash is rolled by.
const MULTIPLIER: u64 = 0x0100_0000_01b3;

fn window_hash(window: &[u8]) -> u64 {
    window.iter().fold(0_u64, |hash, &byte| hash.wrapping_mul(MULTIPLIER).wrapping_add(u64::from(byte)))
}

/// The base's windows, by hash: chains of positions, from a head per
/// bucket.
struct Index {
    heads: Vec<u32>,
    next: Vec<u32>,
    at: Vec<u32>,
    shift: u32,
}

const NONE: u32 = u32::MAX;

impl Index {
    fn new(base: &[u8]) -> Self {
        // Offsets past 4 GiB can't be copied from
        let reach = base.len().min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
        let count = reach / WINDOW;
        let bits = usize::BITS.saturating_sub(count.max(1).leading_zeros()).max(4);
        let mut index = Self { heads: vec![NONE; 1 << bits], next: Vec::with_capacity(count), at: Vec::with_capacity(count), shift: 64_u32.saturating_sub(bits) };
        // Last first, so a chain gives the earliest first
        for n in (0..count).rev() {
            let at = n.saturating_mul(WINDOW);
            let Some(window) = base.get(at..at.saturating_add(WINDOW)) else {
                continue;
            };
            let bucket = index.bucket(window_hash(window));
            let entry = u32::try_from(index.at.len()).unwrap_or(NONE);
            if let Some(head) = index.heads.get_mut(bucket) {
                index.next.push(std::mem::replace(head, entry));
                index.at.push(u32::try_from(at).unwrap_or(NONE));
            }
        }
        index
    }

    fn bucket(&self, hash: u64) -> usize {
        usize::try_from(hash.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> self.shift).unwrap_or_default()
    }

    /// Where in the base a window with this hash may be.
    fn candidates(&self, hash: u64) -> impl Iterator<Item = usize> + '_ {
        let mut entry = self.heads.get(self.bucket(hash)).copied().unwrap_or(NONE);
        std::iter::from_fn(move || {
            let i = usize::try_from(entry).ok().filter(|_| entry != NONE)?;
            entry = self.next.get(i).copied().unwrap_or(NONE);
            self.at.get(i).and_then(|&at| usize::try_from(at).ok())
        })
        .take(MOST_CANDIDATES)
    }
}

/// A delta from `base` to `target`: as short as matches of whole windows
/// make it, not necessarily the shortest.
pub fn encode(base: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    let mut out = Writer::new(base.len(), target.len());
    let index = Index::new(base);
    // What a window's first byte adds to its hash
    let top = (1..WINDOW).fold(1_u64, |power, _| power.wrapping_mul(MULTIPLIER));
    let mut literal = 0_usize;
    let mut at = 0_usize;
    let mut rolled: Option<u64> = None;
    // The longest match through a window of the target, back as far as
    // what's not yet in the delta: where it starts in the base, in the
    // target, and how long it is
    let found = |at: usize, hash: u64, literal: usize| -> Option<(usize, usize, usize)> {
        let window = target.get(at..at.saturating_add(WINDOW))?;
        let mut best: Option<(usize, usize, usize)> = None;
        for from in index.candidates(hash) {
            if base.get(from..from.saturating_add(WINDOW)) != Some(window) {
                continue;
            }
            let ahead = common(base.get(from..).unwrap_or_default().iter(), target.get(at..).unwrap_or_default().iter());
            let behind = common(base.get(..from).unwrap_or_default().iter().rev(), target.get(literal..at).unwrap_or_default().iter().rev());
            let len = ahead.saturating_add(behind);
            if best.is_none_or(|(_, _, most)| len > most) {
                best = Some((from.saturating_sub(behind), at.saturating_sub(behind), len));
            }
        }
        best
    };
    let end = |(_, start, len): (usize, usize, usize)| start.saturating_add(len);
    while let Some(window) = target.get(at..at.saturating_add(WINDOW)) {
        let hash = rolled.unwrap_or_else(|| window_hash(window));
        if let Some(mut best) = found(at, hash, literal) {
            // A short match may be one of many alike, as in repetitive
            // text, while the one that goes on starts a little later
            if best.2 < LAZY {
                for later in at.saturating_add(1)..=at.saturating_add(WINDOW) {
                    let Some(window) = target.get(later..later.saturating_add(WINDOW)) else {
                        break;
                    };
                    if let Some(other) = found(later, window_hash(window), literal)
                        && end(other) > end(best)
                    {
                        best = other;
                    }
                }
            }
            let (from, start, len) = best;
            out.insert(target.get(literal..start).unwrap_or_default());
            out.copy(from, len)?;
            at = start.saturating_add(len);
            literal = at;
            rolled = None;
            continue;
        }
        rolled = match (window.first(), target.get(at.saturating_add(WINDOW))) {
            (Some(&gone), Some(&next)) => Some(hash.wrapping_sub(u64::from(gone).wrapping_mul(top)).wrapping_mul(MULTIPLIER).wrapping_add(u64::from(next))),
            _ => None,
        };
        at = at.saturating_add(1);
    }
    out.insert(target.get(literal..).unwrap_or_default());
    Ok(out.finish())
}

/// How many items two sequences start with alike.
fn common<'a>(a: impl Iterator<Item = &'a u8>, b: impl Iterator<Item = &'a u8>) -> usize {
    a.zip(b).take_while(|(a, b)| a == b).count()
}

/// A delta between contents made a delta between blocks whose bytes are
/// those contents after headers: the base's `skip` bytes long, and the
/// target's `header`.
pub fn behind_headers(delta: &[u8], skip: usize, header: &[u8]) -> Result<Vec<u8>> {
    let (source, target, ops) = read(delta)?;
    let mut out = Writer::new(source.saturating_add(skip), target.saturating_add(header.len()));
    out.insert(header);
    for op in ops {
        match op? {
            Op::Copy { offset, len } => out.copy(offset.saturating_add(skip), len)?,
            Op::Insert(bytes) => out.insert(bytes),
        }
    }
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delta_copies_and_inserts() {
        // Source 5, target 8: copy 5 from 0, insert "abc"
        let delta = [5, 8, 0x80 | 0x10, 5, 3, b'a', b'b', b'c'];
        assert_eq!(apply(b"hello", &delta).expect("apply"), b"helloabc");
        assert!(apply(b"hell", &delta).is_err(), "another base");
        assert!(apply(b"hello", &[5, 8, 0]).is_err(), "the reserved op");
        assert!(apply(b"hello", &[5, 1, 0x80 | 0x10, 5]).is_err(), "too much");
    }

    #[test]
    fn what_is_written_is_read_back() {
        let base: Vec<u8> = (0..200_000_u32).map(|i| u8::try_from(i % 251).unwrap_or_default()).collect();
        let mut want = base.get(70_000..170_000).expect("range").to_vec();
        want.extend_from_slice(&[9; 300]);
        want.extend_from_slice(base.get(..0x10000).expect("range"));
        let mut delta = Writer::new(base.len(), want.len());
        delta.copy(70_000, 100_000).expect("copy");
        delta.insert(&[9; 300]);
        delta.copy(0, 0x10000).expect("copy");
        assert_eq!(apply(&base, &delta.finish()).expect("apply"), want);
    }

    #[test]
    fn a_delta_behind_headers_makes_the_whole_block() {
        let delta = [5, 8, 0x80 | 0x10, 5, 3, b'a', b'b', b'c'];
        let moved = behind_headers(&delta, 7, b"blob 8\0").expect("moved");
        assert_eq!(apply(b"blob 5\0hello", &moved).expect("apply"), b"blob 8\0helloabc");
    }
    #[test]
    fn an_encoded_delta_makes_its_target_and_is_small() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let base: Vec<u8> = (0..300_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        // An insertion, a deletion, a change, and a move
        let mut target = base.get(..1000).expect("range").to_vec();
        target.extend_from_slice(b"something new in the middle");
        target.extend_from_slice(base.get(1000..50_000).expect("range"));
        target.extend_from_slice(base.get(60_000..200_000).expect("range"));
        target.push(7);
        target.extend_from_slice(base.get(200_001..250_000).expect("range"));
        target.extend_from_slice(base.get(..5000).expect("range"));
        let delta = encode(&base, &target).expect("encode");
        assert_eq!(apply(&base, &delta).expect("apply"), target);
        assert!(delta.len() < 100, "{} bytes", delta.len());
        for (base, target) in [(&b""[..], &b"new"[..]), (b"old", b""), (b"short", b"shorter"), (b"", b"")] {
            assert_eq!(apply(base, &encode(base, target).expect("encode")).expect("apply"), target);
        }
        let unrelated: Vec<u8> = (0..10_000_u32).map(|i| u8::try_from(i % 7).unwrap_or_default()).collect();
        assert_eq!(apply(&base, &encode(&base, &unrelated).expect("encode")).expect("apply"), unrelated);
    }

    #[test]
    fn text_edited_is_a_short_delta() {
        let base = (0..2000).fold(String::new(), |mut text, i| {
            text.push_str("line ");
            text.push_str(&i.to_string());
            text.push_str(": the quick brown fox\n");
            text
        });
        let target = base.replace("line 1000:", "line one thousand:").replace("line 5:", "");
        let delta = encode(base.as_bytes(), target.as_bytes()).expect("encode");
        assert_eq!(apply(base.as_bytes(), &delta).expect("apply"), target.as_bytes());
        assert!(delta.len() < 60, "{} bytes", delta.len());
    }
}
