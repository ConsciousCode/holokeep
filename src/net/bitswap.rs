//! Bitswap 1.2.0's messages, as Amino's peers send them: wants, blocks,
//! and what's had and not, protobuf on the wire, each message prefixed by
//! its length as a varint.
//!
//! ```protobuf
//! message Message {
//!   message Wantlist {
//!     enum WantType { Block = 0; Have = 1; }
//!     message Entry {
//!       bytes block = 1; int32 priority = 2; bool cancel = 3;
//!       WantType wantType = 4; bool sendDontHave = 5;
//!     }
//!     repeated Entry entries = 1; bool full = 2;
//!   }
//!   message Block { bytes prefix = 1; bytes data = 2; }
//!   enum BlockPresenceType { Have = 0; DontHave = 1; }
//!   message BlockPresence { bytes cid = 1; BlockPresenceType type = 2; }
//!   Wantlist wantlist = 1;
//!   repeated bytes blocks = 2;          // 1.0.0's, CIDv0 alone
//!   repeated Block payload = 3;
//!   repeated BlockPresence blockPresences = 4;
//!   int32 pendingBytes = 5;
//! }
//! ```

use std::io;

use crate::cid::{AnyCid, BaseCid as _, Cid as _, CidRef as _, CidSpec, CidVersion};
use crate::model::Link;
use crate::multihash::MultihashFunc;
use crate::pb::{self, DecodeError, LEN, VARINT};

/// The protocol, as Amino's peers speak it.
pub const PROTOCOL: &str = "/ipfs/bitswap/1.2.0";

/// The most a message may be, as Kubo's limit has it: a block's at most
/// 2 MiB, and a message carries a few.
pub const MESSAGE: usize = 4 << 20;

/// Whether a want's for the block, or to hear whether it's had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantType {
    Block,
    Have,
}

/// One want of a wantlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub cid: Link,
    pub priority: i32,
    pub cancel: bool,
    pub want: WantType,
    /// Whether to be told if it isn't had.
    pub send_dont_have: bool,
}

/// What's had, or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Have,
    DontHave,
}

/// A message, either way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub wants: Vec<Entry>,
    /// Whether the wantlist is all the sender wants, in place of what it
    /// sent before, or more of it.
    pub full: bool,
    /// Blocks, each as its CID and data.
    pub blocks: Vec<(Link, Vec<u8>)>,
    pub presences: Vec<(Link, Presence)>,
    pub pending_bytes: i32,
}

impl Message {
    pub const fn is_empty(&self) -> bool {
        self.wants.is_empty() && self.blocks.is_empty() && self.presences.is_empty()
    }

    /// The message on the wire, without its length.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.wants.is_empty() || self.full {
            let mut list = Vec::new();
            for entry in &self.wants {
                let mut e = Vec::new();
                pb::put_bytes(&mut e, 1, &entry.cid.to_bytes());
                if entry.priority != 0 {
                    pb::put_uint(&mut e, 2, u64::from(entry.priority.cast_unsigned()));
                }
                if entry.cancel {
                    pb::put_uint(&mut e, 3, 1);
                }
                if entry.want == WantType::Have {
                    pb::put_uint(&mut e, 4, 1);
                }
                if entry.send_dont_have {
                    pb::put_uint(&mut e, 5, 1);
                }
                pb::put_bytes(&mut list, 1, &e);
            }
            if self.full {
                pb::put_uint(&mut list, 2, 1);
            }
            pb::put_bytes(&mut out, 1, &list);
        }
        for (cid, data) in &self.blocks {
            let mut block = Vec::new();
            pb::put_bytes(&mut block, 1, &prefix(cid));
            pb::put_bytes(&mut block, 2, data);
            pb::put_bytes(&mut out, 3, &block);
        }
        for (cid, presence) in &self.presences {
            let mut p = Vec::new();
            pb::put_bytes(&mut p, 1, &cid.to_bytes());
            if *presence == Presence::DontHave {
                pb::put_uint(&mut p, 2, 1);
            }
            pb::put_bytes(&mut out, 4, &p);
        }
        if self.pending_bytes != 0 {
            pb::put_uint(&mut out, 5, u64::from(self.pending_bytes.cast_unsigned()));
        }
        out
    }

    /// A message from the wire, without its length. Blocks are hashed as
    /// their prefixes say, so each is what its CID names; what can't be
    /// read is an error, and fields not known are skipped, as protobuf
    /// has it.
    pub fn decode(mut buf: &[u8]) -> Result<Self, DecodeError> {
        let mut message = Self::default();
        while !buf.is_empty() {
            match pb::read_tag(&mut buf)? {
                (1, LEN) => {
                    let mut list = pb::read_bytes(&mut buf)?;
                    while !list.is_empty() {
                        match pb::read_tag(&mut list)? {
                            (1, LEN) => message.wants.push(entry(pb::read_bytes(&mut list)?)?),
                            (2, VARINT) => message.full = crate::varint::read(&mut list)? != 0,
                            (_, wire) => skip(&mut list, wire)?,
                        }
                    }
                },
                // 1.0.0's blocks: data alone, under CIDv0
                (2, LEN) => {
                    let data = pb::read_bytes(&mut buf)?;
                    let cid = CidSpec::new(CidVersion::V0, crate::cid::DAG_PB_CODEC, MultihashFunc::Sha2_256).ok_or(DecodeError::Truncated)?.hash(data);
                    message.blocks.push((cid, data.to_vec()));
                },
                (3, LEN) => {
                    let mut block = pb::read_bytes(&mut buf)?;
                    let (mut prefix, mut data) = (None, None);
                    while !block.is_empty() {
                        match pb::read_tag(&mut block)? {
                            (1, LEN) => prefix = Some(pb::read_bytes(&mut block)?),
                            (2, LEN) => data = Some(pb::read_bytes(&mut block)?),
                            (_, wire) => skip(&mut block, wire)?,
                        }
                    }
                    let (prefix, data) = (prefix.ok_or(DecodeError::Truncated)?, data.unwrap_or_default());
                    message.blocks.push((hashed(prefix, data)?, data.to_vec()));
                },
                (4, LEN) => {
                    let mut p = pb::read_bytes(&mut buf)?;
                    let (mut cid, mut presence) = (None, Presence::Have);
                    while !p.is_empty() {
                        match pb::read_tag(&mut p)? {
                            (1, LEN) => cid = Some(link(pb::read_bytes(&mut p)?)?),
                            (2, VARINT) => presence = if crate::varint::read(&mut p)? == 1 { Presence::DontHave } else { Presence::Have },
                            (_, wire) => skip(&mut p, wire)?,
                        }
                    }
                    message.presences.push((cid.ok_or(DecodeError::Truncated)?, presence));
                },
                (5, VARINT) => message.pending_bytes = i32::try_from(crate::varint::read(&mut buf)?).unwrap_or_default(),
                (_, wire) => skip(&mut buf, wire)?,
            }
        }
        Ok(message)
    }
}

fn entry(mut buf: &[u8]) -> Result<Entry, DecodeError> {
    let (mut cid, mut priority, mut cancel, mut want, mut send_dont_have) = (None, 0, false, WantType::Block, false);
    while !buf.is_empty() {
        match pb::read_tag(&mut buf)? {
            (1, LEN) => cid = Some(link(pb::read_bytes(&mut buf)?)?),
            // An int32, so negative ones are ten bytes, of which the low
            // four are what counts
            (2, VARINT) => priority = u32::try_from(crate::varint::read(&mut buf)? & 0xffff_ffff).unwrap_or_default().cast_signed(),
            (3, VARINT) => cancel = crate::varint::read(&mut buf)? != 0,
            (4, VARINT) => want = if crate::varint::read(&mut buf)? == 1 { WantType::Have } else { WantType::Block },
            (5, VARINT) => send_dont_have = crate::varint::read(&mut buf)? != 0,
            (_, wire) => skip(&mut buf, wire)?,
        }
    }
    Ok(Entry { cid: cid.ok_or(DecodeError::Truncated)?, priority, cancel, want, send_dont_have })
}

fn link(bytes: &[u8]) -> Result<Link, DecodeError> {
    Link::decode(bytes).map_err(|_| DecodeError::Truncated)
}

/// Skip a field of a wire type.
fn skip(buf: &mut &[u8], wire: u64) -> Result<(), DecodeError> {
    match wire {
        VARINT => drop(crate::varint::read(buf)?),
        LEN => drop(pb::read_bytes(buf)?),
        pb::FIXED64 => *buf = buf.get(8..).ok_or(DecodeError::Truncated)?,
        pb::FIXED32 => *buf = buf.get(4..).ok_or(DecodeError::Truncated)?,
        _ => return Err(DecodeError::Truncated),
    }
    Ok(())
}

/// A CID's prefix, as 1.1.0 sends it beside a block: its version, codec,
/// hash function and digest length, each a varint.
fn prefix(cid: &Link) -> Vec<u8> {
    let mut out = Vec::new();
    let version = match cid {
        AnyCid::V0(_) => 0,
        AnyCid::V1(_) => 1,
    };
    for value in [version, cid.codec(), cid.hashcode(), u64::try_from(cid.multihash().digest().len()).unwrap_or_default()] {
        crate::varint::write(&mut out, value);
    }
    out
}

/// The CID of a block's data, as its prefix says to hash it.
fn hashed(mut prefix: &[u8], data: &[u8]) -> Result<Link, DecodeError> {
    let version = crate::varint::read(&mut prefix)?;
    let codec = crate::varint::read(&mut prefix)?;
    let code = crate::varint::read(&mut prefix)?;
    let function = MultihashFunc::try_from(code).map_err(|_| DecodeError::Truncated)?;
    let version = if version == 0 { CidVersion::V0 } else { CidVersion::V1 };
    Ok(CidSpec::new(version, codec, function).ok_or(DecodeError::Truncated)?.hash(data))
}

/// Read one message, its length first; none at the end of the stream.
pub async fn read(stream: &mut (impl futures::AsyncRead + Unpin)) -> io::Result<Option<Message>> {
    use futures::AsyncReadExt as _;
    let mut len = Vec::new();
    loop {
        let mut byte = [0u8];
        if stream.read(&mut byte).await? == 0 {
            return if len.is_empty() { Ok(None) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        }
        len.push(byte[0]);
        if byte[0] & 0x80 == 0 || len.len() >= 10 {
            break;
        }
    }
    let len = usize::try_from(crate::varint::read(&mut len.as_slice()).map_err(io::Error::other)?).map_err(io::Error::other)?;
    if len > MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("a message of {len} bytes")));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Message::decode(&buf).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Write one message, its length first.
pub async fn write(stream: &mut (impl futures::AsyncWrite + Unpin), message: &Message) -> io::Result<()> {
    use futures::AsyncWriteExt as _;
    let data = message.encode();
    let mut out = Vec::with_capacity(data.len().saturating_add(10));
    crate::varint::write(&mut out, u64::try_from(data.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(&data);
    stream.write_all(&out).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests;
