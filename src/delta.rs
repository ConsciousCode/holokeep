//! Deltas: a block's bytes as copies from another's and bytes of its own,
//! in git's delta format, so a pack's deltas are kept as they come.
//!
//! A delta is the base's size and the target's, each a little-endian
//! base-128 varint, then ops till the end: `1sssoooo` copies from the base,
//! the `o` bits saying which of 4 offset bytes follow and the `s` bits
//! which of 3 size bytes (a size of 0 meaning 0x10000); `0nnnnnnn`, n > 0,
//! inserts the next n bytes.

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
}
