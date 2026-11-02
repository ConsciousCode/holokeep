//! Telling holders of what links to what they hold:
//! `/holokeep/notices/1.0.0`.
//!
//! A node makes a best effort to know every backreference to the blocks it
//! holds, tags included, which takes hearing of structure written on other
//! nodes. So a node notices structure (UnixFS nodes, IPLD, claims, which
//! are small) to members, each block with the multihashes it links to, and
//! a member wants what it doesn't have and links to something it holds;
//! what's wanted is pushed, as copies are. There are two triggers:
//!
//! - Structure arriving in the catalog, written here or sent from
//!   elsewhere, is noticed to each member in turn, from a cursor over the
//!   generations the catalog's database stamps, one for each member: a
//!   member which was away hears of what it missed when it's back, and a
//!   new one hears of everything. A cursor moves on only once the member's
//!   answered.
//! - A block sent to a member, as a copy or fetched, takes the structure
//!   linking to it along, noticed to that member.
//!
//! Either way it's one hop: structure linking to what a member holds, not
//! what links to that in turn.

use std::str::FromStr;

use libp2p::{PeerId, StreamProtocol};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::block::Block;
use crate::cid::{BaseCid, Cid, CidRef};
use crate::model::Link;
use crate::multihash::Multihash;
use crate::store::{BlockIndex, Catalog, Db, RefIndex};

use super::durability::Push;
use super::mesh::Result;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/notices/1.0.0");

/// The most blocks in one notice.
pub const BATCH: usize = 256;

/// Structure, as (CID, the multihashes it links to).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Notice {
    blocks: Vec<(ByteBuf, Vec<ByteBuf>)>,
}

impl Notice {
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// The CIDs of what's wanted of a notice.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Wants {
    want: Vec<ByteBuf>,
}

/// Notices of structure, with what each links to, in batches. Structure
/// which can't be read here is left out.
pub fn notices(catalog: &Catalog, structure: &[Link]) -> Result<Vec<Notice>> {
    let mut notices = Vec::new();
    let mut notice = Notice::default();
    for cid in structure {
        if !catalog.visible(cid.multihash())? {
            continue;
        }
        let Ok(Some(block)) = catalog.get_block(cid) else {
            continue;
        };
        // A signature's about what it signs, not the key or the chain it
        // continues: those would draw every signature to any holder of one
        let links = match crate::claim::Claim::parse(block.data()) {
            Some(crate::claim::Claim::Sign(sign)) => sign.signs().to_vec(),
            _ => crate::links::links(cid.codec(), block.data()).unwrap_or_default(),
        };
        if links.is_empty() {
            continue;
        }
        let targets = links.iter().map(|link| ByteBuf::from(link.multihash().to_bytes())).collect();
        notice.blocks.push((ByteBuf::from(cid.to_bytes()), targets));
        if notice.blocks.len() >= BATCH {
            notices.push(std::mem::take(&mut notice));
        }
    }
    if !notice.is_empty() {
        notices.push(notice);
    }
    Ok(notices)
}

/// The structure here linking to any of these blocks, with the claims
/// about any claims among it, however deep.
///
/// A claim goes with its signatures and its tombs, and theirs, since
/// without them it's not what it says.
pub fn backrefs<'a>(catalog: &Catalog, keys: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<Link>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut structure = Vec::new();
    let mut pending: Vec<Multihash<Vec<u8>>> = keys.into_iter().filter_map(|key| Multihash::decode(key).ok()).collect();
    let mut first = true;
    while !pending.is_empty() {
        let mut claims = Vec::new();
        for key in pending {
            for source in catalog.backrefs(key.as_ref())? {
                if !seen.insert(source.to_bytes()) {
                    continue;
                }
                if let Some(cid) = catalog.cid_of(source.as_ref())?
                    && catalog.holds(&cid)?
                    && catalog.visible(cid.multihash())?
                {
                    if is_claim(catalog, &cid)? {
                        claims.push(Multihash::<Vec<u8>>::decode(&cid.multihash().to_bytes()).map_err(|e| super::mesh::Error::Invalid(format!("{e:?}")))?);
                    } else if !first {
                        continue;
                    }
                    structure.push(cid);
                }
            }
        }
        pending = claims;
        first = false;
    }
    Ok(structure)
}

/// Whether a block here is a claim.
fn is_claim(catalog: &Catalog, cid: &Link) -> Result<bool> {
    if crate::claim::dissolved(cid).is_some() {
        return Ok(true);
    }
    Ok(match catalog.claims() {
        Some(claims) => claims.has(cid.multihash())?,
        None => false,
    })
}

/// Want what's noticed which isn't here and links to something that is,
/// or to something else wanted of the same notice: a keep noticed with
/// what it keeps, before that's here, goes with it.
pub fn answer(catalog: &Catalog, notice: &Notice) -> Result<Wants> {
    let mut candidates = Vec::new();
    for (cid, targets) in &notice.blocks {
        let Ok(link) = Link::decode(cid) else {
            continue;
        };
        if catalog.holds(&link)? {
            continue;
        }
        let targets: Vec<Multihash<Vec<u8>>> = targets.iter().filter_map(|target| Multihash::decode(target).ok()).collect();
        candidates.push((cid, link.multihash().to_bytes(), targets));
    }
    let mut wanted = std::collections::BTreeSet::new();
    let mut want = Vec::new();
    loop {
        let before = want.len();
        for (cid, key, targets) in &candidates {
            if wanted.contains(key) {
                continue;
            }
            for target in targets {
                if wanted.contains(&target.to_bytes()) || held(catalog, target)? {
                    wanted.insert(key.clone());
                    want.push((*cid).clone());
                    break;
                }
            }
        }
        if want.len() == before {
            return Ok(Wants { want });
        }
    }
}

/// Whether a block's here to link to: an identity block only if it's a
/// dissolved claim held here, since otherwise it's no one's in particular.
fn held(catalog: &Catalog, key: &Multihash<Vec<u8>>) -> Result<bool> {
    if key.code() == crate::block::IDENTITY {
        return match catalog.cid_of(key.as_ref())? {
            Some(cid) => Ok(catalog.holds(&cid)?),
            None => Ok(false),
        };
    }
    Ok(catalog.has(key.as_ref())?)
}

/// Pushes of what a member wants, of what's here.
pub fn pushes(catalog: &Catalog, wants: &Wants) -> Result<Vec<Push>> {
    let mut blocks: Vec<Block> = Vec::new();
    for cid in &wants.want {
        if let Ok(link) = Link::decode(cid)
            && let Ok(Some(block)) = catalog.get_block(&link)
        {
            blocks.push(block);
        }
    }
    Push::batches(catalog, blocks)
}

/// How far through the catalog's generations each member of a mesh's
/// been noticed.
///
/// A member of the main mesh is known by its peer ID, of another by the
/// mesh's name, a slash, and its peer ID, since one peer may be in several.
pub struct Cursors {
    db: Db,
    prefix: String,
}

impl Cursors {
    pub fn open(db: Db, mesh: &str) -> Result<Self> {
        db.conn().execute_batch(
            "-- How far through the generations of the catalog's database each
             -- member's been noticed of the structure which arrived.
             CREATE TABLE IF NOT EXISTS notice_cursors (
                 peer TEXT PRIMARY KEY,
                 generation INTEGER NOT NULL
             );",
        )?;
        let prefix = if mesh == super::mesh::MAIN { String::new() } else { format!("{mesh}/") };
        Ok(Self { db, prefix })
    }

    fn name(&self, peer: &PeerId) -> String {
        format!("{}{peer}", self.prefix)
    }

    pub fn get(&self, peer: &PeerId) -> Result<i64> {
        Ok(self.db.conn()
            .prepare_cached("SELECT generation FROM notice_cursors WHERE peer = ?1")?
            .query_row([self.name(peer)], |row| row.get(0))
            .or_else(|e| if e == rusqlite::Error::QueryReturnedNoRows { Ok(0) } else { Err(e) })?)
    }

    pub fn set(&self, peer: &PeerId, generation: i64) -> Result<()> {
        self.db.conn()
            .prepare_cached("INSERT OR REPLACE INTO notice_cursors (peer, generation) VALUES (?1, ?2)")?
            .execute(params![self.name(peer), generation])?;
        Ok(())
    }

    /// Every member with a cursor, and where it is.
    pub fn list(&self) -> Result<Vec<(PeerId, i64)>> {
        let mut stmt = self.db.conn().prepare_cached("SELECT peer, generation FROM notice_cursors ORDER BY peer")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get(1)?)))?;
        let mut cursors = Vec::new();
        for row in rows {
            let (peer, generation): (String, i64) = row?;
            let Some(peer) = peer.strip_prefix(&self.prefix).filter(|peer| !peer.contains('/')) else {
                continue;
            };
            if let Ok(peer) = PeerId::from_str(peer) {
                cursors.push((peer, generation));
            }
        }
        Ok(cursors)
    }
}
