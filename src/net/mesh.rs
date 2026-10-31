//! Who's in the mesh.
//!
//! Every node of a repository shares its *swarm key*,
//! a libp2p private-network key: a connection is encrypted with it before
//! anything else is said, so a machine without it can't speak to the mesh
//! at all, let alone be found by it. Beyond that, each node keeps a list
//! of *members*, the peers it lets in, so a node can be shut out without
//! changing the key. Until users have DIDs, holding the key and being on
//! the list is what being yours means.
//!
//! The keys are secrets, so they're files beside the catalog, not rows in
//! it: the catalog's database is a volume another node may open. The swarm
//! key is in Kubo's `swarm.key` format.
//!
//! A machine joins with a ticket: the swarm key, and the inviter's peer
//! id, addresses and members. The inviter names the new machine's peer id
//! when making it, so the two-step is: `hk node id` on the new machine,
//! `hk node invite <id>` on one in the mesh, `hk node join <ticket>` back
//! on the new one.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::str::FromStr;

use libp2p::identity::Keypair;
use libp2p::pnet::PreSharedKey;
use libp2p::{Multiaddr, PeerId};
use rusqlite::params;

use crate::model::Ipld;
use crate::store::Db;

/// The file holding a node's own key.
const NODE_KEY: &str = "node.key";

/// The file holding the repository's swarm key.
const SWARM_KEY: &str = "swarm.key";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Store(#[from] crate::store::Error),

    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Write a secret, readable only by its owner.
fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(data)?;
    Ok(())
}

/// This node's key, made the first time it's asked for.
pub fn node_key(dir: &Path) -> Result<Keypair> {
    let path = dir.join(NODE_KEY);
    match fs::read(&path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes).map_err(|e| Error::Invalid(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)?;
            let key = Keypair::generate_ed25519();
            let bytes = key.to_protobuf_encoding().map_err(|e| Error::Invalid(e.to_string()))?;
            write_secret(&path, &bytes)?;
            Ok(key)
        },
        Err(e) => Err(e.into()),
    }
}

/// The repository's swarm key, if this node is in a mesh.
pub fn swarm_key(dir: &Path) -> Result<Option<PreSharedKey>> {
    let path = dir.join(SWARM_KEY);
    match fs::read_to_string(&path) {
        Ok(text) => PreSharedKey::from_str(&text).map(Some).map_err(|e| Error::Invalid(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A new, random swarm key.
pub fn fresh_swarm_key() -> Result<PreSharedKey> {
    let mut key = [0; 32];
    getrandom::getrandom(&mut key).map_err(io::Error::from)?;
    Ok(PreSharedKey::new(key))
}

/// Keep a swarm key, unless there's already a different one: a node is in
/// one mesh.
pub fn set_swarm_key(dir: &Path, key: PreSharedKey) -> Result<()> {
    match swarm_key(dir)? {
        Some(existing) if existing.fingerprint().to_string() == key.fingerprint().to_string() => Ok(()),
        Some(_) => Err(Error::Invalid("this node is already in another mesh".into())),
        None => {
            fs::create_dir_all(dir)?;
            write_secret(&dir.join(SWARM_KEY), format!("{key}\n").as_bytes())
        },
    }
}

/// The swarm key, made if this node isn't in a mesh yet: inviting another
/// makes one.
pub fn ensure_swarm_key(dir: &Path) -> Result<PreSharedKey> {
    if let Some(key) = swarm_key(dir)? {
        return Ok(key);
    }
    let key = fresh_swarm_key()?;
    set_swarm_key(dir, key)?;
    Ok(key)
}

/// The peers a node lets in, and where they've been seen listening.
pub struct Members {
    db: Db,
}

impl Members {
    pub fn open(db: Db) -> Result<Self> {
        db.conn().execute_batch(
            "-- The peers this node lets into the mesh.
             CREATE TABLE IF NOT EXISTS members (
                 peer TEXT PRIMARY KEY
             );
             -- Where members have been seen listening, to dial them again.
             CREATE TABLE IF NOT EXISTS member_addrs (
                 peer TEXT NOT NULL REFERENCES members (peer) ON DELETE CASCADE,
                 addr TEXT NOT NULL,
                 PRIMARY KEY (peer, addr)
             ) WITHOUT ROWID;",
        )?;
        Ok(Self { db })
    }

    /// Let a peer in. Returns whether it's new.
    pub fn add(&self, peer: &PeerId) -> Result<bool> {
        Ok(self.db.conn().prepare_cached("INSERT OR IGNORE INTO members (peer) VALUES (?1)")?.execute([peer.to_string()])? > 0)
    }

    /// Note where a member listens, if it's a member.
    pub fn add_addr(&self, peer: &PeerId, addr: &Multiaddr) -> Result<()> {
        self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO member_addrs (peer, addr) SELECT peer, ?2 FROM members WHERE peer = ?1")?
            .execute(params![peer.to_string(), addr.to_string()])?;
        Ok(())
    }

    pub fn contains(&self, peer: &PeerId) -> Result<bool> {
        Ok(self.db.conn().prepare_cached("SELECT 1 FROM members WHERE peer = ?1")?.exists([peer.to_string()])?)
    }

    /// Every member, and where each listens.
    pub fn list(&self) -> Result<BTreeMap<PeerId, Vec<Multiaddr>>> {
        let mut members = BTreeMap::new();
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT m.peer, a.addr FROM members m LEFT JOIN member_addrs a ON a.peer = m.peer ORDER BY m.peer, a.addr",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))?;
        for row in rows {
            let (peer, addr) = row?;
            let peer = PeerId::from_str(&peer).map_err(|e| Error::Invalid(format!("member {peer}: {e}")))?;
            let addrs: &mut Vec<Multiaddr> = members.entry(peer).or_default();
            if let Some(addr) = addr.and_then(|addr| addr.parse().ok()) {
                addrs.push(addr);
            }
        }
        Ok(members)
    }

    /// Take in members another member knows of. Returns those new here.
    pub fn merge(&self, other: &BTreeMap<PeerId, Vec<Multiaddr>>) -> Result<Vec<PeerId>> {
        let mut new = Vec::new();
        for (peer, addrs) in other {
            if self.add(peer)? {
                new.push(*peer);
            }
            for addr in addrs {
                self.add_addr(peer, addr)?;
            }
        }
        Ok(new)
    }
}

/// What a machine needs to join a mesh.
#[derive(Debug, Clone)]
pub struct Ticket {
    pub swarm_key: PreSharedKey,
    /// The node which made it, and where it listens.
    pub inviter: PeerId,
    /// Every member the inviter knows of, itself included, and where each
    /// listens.
    pub members: BTreeMap<PeerId, Vec<Multiaddr>>,
}

impl Ticket {
    /// As dag-cbor in multibase: base32, so it survives being pasted.
    pub fn encode(&self) -> String {
        let members = self.members.iter().map(|(peer, addrs)| {
            Ipld::List(vec![
                Ipld::Bytes(peer.to_bytes()),
                Ipld::List(addrs.iter().map(|addr| Ipld::Bytes(addr.to_vec())).collect()),
            ])
        });
        let ticket = Ipld::Map(BTreeMap::from([
            ("inviter".to_owned(), Ipld::Bytes(self.inviter.to_bytes())),
            ("key".to_owned(), Ipld::String(self.swarm_key.to_string())),
            ("members".to_owned(), Ipld::List(members.collect())),
        ]));
        multibase::encode(multibase::Base::Base32Lower, crate::dagcbor::to_vec(&ticket).unwrap_or_default())
    }

    pub fn decode(text: &str) -> Result<Self> {
        let invalid = |what: &str| Error::Invalid(format!("not a ticket: {what}"));
        let (_, bytes) = multibase::decode(text.trim()).map_err(|_| invalid("multibase"))?;
        let Ipld::Map(mut map) = crate::dagcbor::from_slice(&bytes).map_err(|_| invalid("dag-cbor"))? else {
            return Err(invalid("not a map"));
        };
        let peer = |ipld: Option<Ipld>| match ipld {
            Some(Ipld::Bytes(bytes)) => PeerId::from_bytes(&bytes).map_err(|_| invalid("peer id")),
            _ => Err(invalid("peer id")),
        };
        let inviter = peer(map.remove("inviter"))?;
        let Some(Ipld::String(key)) = map.remove("key") else {
            return Err(invalid("key"));
        };
        let swarm_key = PreSharedKey::from_str(&key).map_err(|_| invalid("key"))?;
        let Some(Ipld::List(list)) = map.remove("members") else {
            return Err(invalid("members"));
        };
        let mut members = BTreeMap::new();
        for member in list {
            let Ipld::List(member) = member else {
                return Err(invalid("member"));
            };
            let mut member = member.into_iter();
            let id = peer(member.next())?;
            let Some(Ipld::List(addrs)) = member.next() else {
                return Err(invalid("addresses"));
            };
            let addrs = addrs.into_iter().map(|addr| match addr {
                Ipld::Bytes(bytes) => Multiaddr::try_from(bytes).map_err(|_| invalid("address")),
                _ => Err(invalid("address")),
            });
            members.insert(id, addrs.collect::<Result<_>>()?);
        }
        Ok(Self { swarm_key, inviter, members })
    }
}
