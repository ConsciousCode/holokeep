//! A store specialized for UnixFS: dag-pb nodes as a node row and link
//! rows, the way Kubo writes them.
//!
//! dag-pb's wire format is far more permissive than what this can
//! represent, so it only admits nodes it can manifest byte-for-byte: every
//! link named and sized, blocksizes one per link (or none), no mode or
//! mtime, canonical field order. Anything else is declined and belongs in
//! a generic store.
//!
//! Since links are rows, backreferences come for free. Link targets are
//! interned multihashes, with the CID prefix each link was written with
//! kept alongside to manifest it.

use rusqlite::{OptionalExtension, params};

use crate::block::Block;
use crate::cid::{BaseCid, CidRef, DAG_PB_CODEC};
use crate::multihash::Multihash;
use crate::pb::{PbLink, PbNode};
use crate::unixfs::{DataBuf, DataType};

use super::{BlockIndex, BlockSource, BlockStore, Db, Error, Key, MAX_DIGEST_LEN, Put, RefIndex, Result, Store, query_keys, split_cid};

const NAME: &str = "unixfs";

/// Admits canonical UnixFS nodes, keeping them as rows.
pub struct UnixfsStore {
    db: Db,
}

/// A node as rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    /// Everything but the blocksizes, which go with the links.
    data: DataBuf,
    links: Vec<Link>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    /// The CID's version and codec, empty for CIDv0.
    prefix: Vec<u8>,
    /// The CID's multihash.
    target: Vec<u8>,
    name: Vec<u8>,
    tsize: u64,
    blocksize: Option<u64>,
}

impl Node {
    /// The rows for a block, if it can be manifested from them exactly.
    fn parse(block: &Block) -> Option<Self> {
        if block.cid().codec() != DAG_PB_CODEC {
            return None;
        }
        let node = PbNode::decode(block.data()).ok()?;
        let mut data = DataBuf::decode(node.data?).ok()?;
        let blocksizes = std::mem::take(&mut data.blocksizes);
        if !blocksizes.is_empty() && blocksizes.len() != node.links.len() {
            return None;
        }
        let links = node.links
            .iter()
            .enumerate()
            .map(|(i, link)| {
                let (prefix, target) = split_cid(&link.hash)?;
                (target.len() <= MAX_DIGEST_LEN).then_some(())?;
                Some(Link {
                    prefix: prefix.to_vec(),
                    target: target.to_bytes(),
                    name: link.name?.to_vec(),
                    tsize: link.tsize?,
                    blocksize: blocksizes.get(i).copied(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let parsed = Self { data, links };
        // SQLite integers are signed
        if !parsed.fits_i64() || parsed.manifest() != block.data() {
            return None;
        }
        Some(parsed)
    }

    fn fits_i64(&self) -> bool {
        let fits = |n: Option<u64>| n.is_none_or(|n| i64::try_from(n).is_ok());
        fits(self.data.filesize) && fits(self.data.hash_type) && fits(self.data.fanout)
            && self.links.iter().all(|l| fits(Some(l.tsize)) && fits(l.blocksize))
    }

    /// The block's bytes.
    fn manifest(&self) -> Vec<u8> {
        let mut data = self.data.clone();
        data.blocksizes = self.links.iter().filter_map(|l| l.blocksize).collect();
        let data = data.encode();
        PbNode {
            links: self.links
                .iter()
                .map(|l| PbLink { hash: [&l.prefix[..], &l.target].concat().into(), name: Some(&l.name), tsize: Some(l.tsize) })
                .collect(),
            data: Some(&data),
        }
        .encode()
    }
}

/// Integers come back from `SQLite` signed.
fn unsigned(n: Option<i64>) -> Result<Option<u64>> {
    n.map(|n| u64::try_from(n).map_err(|_| Error::Invalid { store: NAME, reason: format!("negative integer {n}") }))
        .transpose()
}

fn signed(n: Option<u64>) -> Option<i64> {
    // Checked by Node::fits_i64 before anything's written
    n.and_then(|n| i64::try_from(n).ok())
}

impl UnixfsStore {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS unixfs_nodes (
                 block INTEGER PRIMARY KEY REFERENCES multihashes (id),
                 type INTEGER NOT NULL,
                 data BLOB,
                 filesize INTEGER,
                 hash_type INTEGER,
                 fanout INTEGER
             );
             CREATE TABLE IF NOT EXISTS unixfs_links (
                 node INTEGER NOT NULL REFERENCES unixfs_nodes (block) ON DELETE CASCADE,
                 idx INTEGER NOT NULL,
                 target INTEGER NOT NULL REFERENCES multihashes (id),
                 prefix BLOB NOT NULL,
                 name BLOB NOT NULL,
                 tsize INTEGER NOT NULL,
                 blocksize INTEGER,
                 PRIMARY KEY (node, idx)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS unixfs_links_target ON unixfs_links (target);",
        )?;
        Ok(Self { db })
    }

    fn load(&self, key: Key<'_>) -> Result<Option<Node>> {
        let conn = self.db.conn();
        let row = conn
            .query_row(
                "SELECT n.block, n.type, n.data, n.filesize, n.hash_type, n.fanout
                 FROM multihashes m JOIN unixfs_nodes n ON n.block = m.id WHERE m.multihash = ?1",
                [key.to_bytes()],
                |row| Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                )),
            )
            .optional()?;
        let Some((id, data_type, data, filesize, hash_type, fanout)) = row else {
            return Ok(None);
        };
        let data_type = u64::try_from(data_type).ok()
            .and_then(|t| DataType::try_from(t).ok())
            .ok_or_else(|| Error::Invalid { store: NAME, reason: format!("type {data_type}") })?;

        let mut stmt = conn.prepare_cached(
            "SELECT l.prefix, m.multihash, l.name, l.tsize, l.blocksize
             FROM unixfs_links l JOIN multihashes m ON m.id = l.target
             WHERE l.node = ?1 ORDER BY l.idx",
        )?;
        let links = stmt
            .query_map([id], |row| Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            )))?
            .map(|row| {
                let (prefix, target, name, tsize, blocksize) = row?;
                Ok(Link {
                    prefix,
                    target,
                    name,
                    tsize: unsigned(Some(tsize))?.unwrap_or_default(),
                    blocksize: unsigned(blocksize)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Some(Node {
            data: DataBuf {
                data_type,
                data,
                filesize: unsigned(filesize)?,
                blocksizes: Vec::new(),
                hash_type: unsigned(hash_type)?,
                fanout: unsigned(fanout)?,
            },
            links,
        }))
    }
}

impl Store for UnixfsStore {
    fn name(&self) -> &'static str { NAME }
}

impl BlockIndex for UnixfsStore {
    fn has(&self, key: Key<'_>) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached(
                "SELECT 1 FROM multihashes m JOIN unixfs_nodes n ON n.block = m.id WHERE m.multihash = ?1",
            )?
            .query_row([key.to_bytes()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    fn keys(&self) -> Result<Vec<Multihash>> {
        query_keys(&self.db, NAME, "SELECT m.multihash FROM unixfs_nodes n JOIN multihashes m ON m.id = n.block")
    }
}

impl BlockSource for UnixfsStore {
    fn get(&self, key: Key<'_>) -> Result<Option<Vec<u8>>> {
        Ok(self.load(key)?.map(|node| node.manifest()))
    }
}

impl BlockStore for UnixfsStore {
    fn put(&self, block: &Block) -> Result<Put> {
        let Some(node) = Node::parse(block) else {
            return Ok(Put::Declined);
        };
        if self.has(block.cid().multihash())? {
            return Ok(Put::Stored);
        }
        self.db.atomically(|| {
            let conn = self.db.conn();
            let id = self.db.intern(block.cid().multihash())?;
            conn.execute(
                "INSERT INTO unixfs_nodes (block, type, data, filesize, hash_type, fanout)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    u64::from(node.data.data_type).cast_signed(),
                    node.data.data,
                    signed(node.data.filesize),
                    signed(node.data.hash_type),
                    signed(node.data.fanout),
                ],
            )?;
            let mut stmt = conn.prepare_cached(
                "INSERT INTO unixfs_links (node, idx, target, prefix, name, tsize, blocksize)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for (idx, link) in node.links.iter().enumerate() {
                let target = Multihash::<Box<[u8]>>::decode(&link.target)
                    .map_err(|e| Error::Invalid { store: NAME, reason: format!("link multihash: {e}") })?;
                stmt.execute(params![
                    id,
                    i64::try_from(idx).unwrap_or(i64::MAX),
                    self.db.intern(target.as_ref())?,
                    link.prefix,
                    link.name,
                    signed(Some(link.tsize)),
                    signed(link.blocksize),
                ])?;
            }
            Ok::<_, Error>(())
        })?;
        Ok(Put::Stored)
    }
}

impl RefIndex for UnixfsStore {
    fn backrefs(&self, key: Key<'_>) -> Result<Vec<Multihash>> {
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT DISTINCT n.multihash FROM multihashes t
             JOIN unixfs_links l ON l.target = t.id
             JOIN multihashes n ON n.id = l.node
             WHERE t.multihash = ?1",
        )?;
        let rows = stmt.query_map([key.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|bytes| super::decode_key(NAME, &bytes?)).collect()
    }
}
