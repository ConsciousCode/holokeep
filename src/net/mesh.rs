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
use std::path::{Path, PathBuf};
use std::str::FromStr;

use libp2p::identity::Keypair;
use libp2p::pnet::PreSharedKey;
use libp2p::{Multiaddr, PeerId};
use rusqlite::{OptionalExtension, params};

use crate::model::{Ipld, Link};
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

impl Error {
    /// Whether it failed only since something else was writing to the
    /// database: what failed can be tried again later.
    pub const fn is_busy(&self) -> bool {
        match self {
            Self::Store(e) => e.is_busy(),
            Self::Db(e) => crate::store::is_busy(e),
            Self::Io(_) | Self::Invalid(_) => false,
        }
    }
}

/// What's tried again later anyway, unless it failed for good: a node goes
/// on while something else is writing, such as a big import.
pub fn unless_busy(done: Result<()>, what: &str) -> Result<()> {
    match done {
        Err(e) if e.is_busy() => {
            eprintln!("{what} waits, the database being busy");
            Ok(())
        },
        done => done,
    }
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

/// Keep a swarm key, unless there's already a different one: a mesh has
/// one.
pub fn set_swarm_key(dir: &Path, key: PreSharedKey) -> Result<()> {
    match swarm_key(dir)? {
        Some(existing) if existing.fingerprint().to_string() == key.fingerprint().to_string() => Ok(()),
        Some(_) => Err(Error::Invalid("this node is already in another mesh by that name: join with --mesh and another name".into())),
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

/// The mesh a node is in first, whose state is where it always was: the
/// repo's owner's, unless it's said otherwise.
pub const MAIN: &str = "main";

/// A mesh this node is in, by the repo and the mesh's name.
///
/// A node may be in several, each a swarm of its own under its own key,
/// for one of the host's accounts: its repo is what that mesh hears of and
/// holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub repo: PathBuf,
    pub mesh: String,
}

impl Place {
    pub fn new(repo: &Path, mesh: &str) -> Self {
        Self { repo: repo.to_owned(), mesh: mesh.to_owned() }
    }

    /// The main mesh of a repo.
    pub fn main(repo: &Path) -> Self {
        Self::new(repo, MAIN)
    }

    pub fn is_main(&self) -> bool {
        self.mesh == MAIN
    }

    /// Where the mesh's own files are, its swarm key and socket: the repo
    /// for the main one, otherwise `meshes/<name>` in it.
    pub fn dir(&self) -> PathBuf {
        if self.is_main() { self.repo.clone() } else { self.repo.join("meshes").join(&self.mesh) }
    }

    /// Whether a name will do for a mesh: a plain word, so it's a
    /// directory's name.
    pub fn valid(name: &str) -> bool {
        !name.is_empty() && name.len() <= 64 && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }
}

/// The peers a node lets into one of its meshes, and where they've been
/// seen listening.
pub struct Members {
    db: Db,
    mesh: String,
}

impl Members {
    pub fn open(db: Db, mesh: &str) -> Result<Self> {
        db.conn().execute_batch(
            "-- Peers no longer members of a mesh, which others may still
             -- say are.
             CREATE TABLE IF NOT EXISTS mesh_forgotten (
                 mesh TEXT NOT NULL,
                 peer TEXT NOT NULL,
                 PRIMARY KEY (mesh, peer)
             ) WITHOUT ROWID;
             -- The peers this node lets into each mesh it's in.
             CREATE TABLE IF NOT EXISTS mesh_members (
                 mesh TEXT NOT NULL,
                 peer TEXT NOT NULL,
                 PRIMARY KEY (mesh, peer)
             ) WITHOUT ROWID;
             -- Where members have been seen listening, to dial them again.
             CREATE TABLE IF NOT EXISTS mesh_member_addrs (
                 mesh TEXT NOT NULL,
                 peer TEXT NOT NULL,
                 addr TEXT NOT NULL,
                 PRIMARY KEY (mesh, peer, addr),
                 FOREIGN KEY (mesh, peer) REFERENCES mesh_members (mesh, peer) ON DELETE CASCADE
             ) WITHOUT ROWID;
             -- Each mesh other than the main one, and the account, by uid,
             -- it's for; whether it's protected, holding friends' vaults,
             -- and how many bytes the account may have here, if limited.
             CREATE TABLE IF NOT EXISTS meshes (
                 name TEXT PRIMARY KEY,
                 uid INTEGER NOT NULL,
                 protected INTEGER NOT NULL DEFAULT 0,
                 quota INTEGER
             );",
        )?;
        if !db.conn().prepare("SELECT 1 FROM pragma_table_info('meshes') WHERE name = 'protected'")?.exists([])? {
            db.conn().execute_batch("ALTER TABLE meshes ADD COLUMN protected INTEGER NOT NULL DEFAULT 0; ALTER TABLE meshes ADD COLUMN quota INTEGER;")?;
        }
        // From when a node was in one mesh
        let old = db.conn().prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'members'")?.exists([])?;
        if old {
            db.conn().execute_batch(&format!(
                "INSERT OR IGNORE INTO mesh_members (mesh, peer) SELECT '{MAIN}', peer FROM members;
                 INSERT OR IGNORE INTO mesh_member_addrs (mesh, peer, addr) SELECT '{MAIN}', peer, addr FROM member_addrs;
                 DROP TABLE member_addrs;
                 DROP TABLE members;"
            ))?;
        }
        Ok(Self { db, mesh: mesh.to_owned() })
    }

    /// Which mesh these are the members of.
    pub fn mesh(&self) -> &str {
        &self.mesh
    }

    /// The account, by uid, a mesh other than the main one is for.
    pub fn account(&self) -> Result<Option<u32>> {
        Ok(self.db.conn().prepare_cached("SELECT uid FROM meshes WHERE name = ?1")?.query_row([&self.mesh], |row| row.get(0)).optional()?)
    }

    /// Say which account the mesh is for.
    pub fn set_account(&self, uid: u32) -> Result<()> {
        self.db.conn()
            .prepare_cached("INSERT INTO meshes (name, uid) VALUES (?1, ?2) ON CONFLICT (name) DO UPDATE SET uid = excluded.uid")?
            .execute(params![self.mesh, uid])?;
        Ok(())
    }

    /// Say the mesh is protected, and how many bytes its account may have
    /// here, if it's limited.
    pub fn set_protected(&self, quota: Option<u64>) -> Result<()> {
        self.db.conn()
            .prepare_cached("UPDATE meshes SET protected = 1, quota = ?2 WHERE name = ?1")?
            .execute(params![self.mesh, quota.map(|quota| i64::try_from(quota).unwrap_or(i64::MAX))])?;
        Ok(())
    }

    /// Whether the mesh is protected, and if so, its account's quota.
    pub fn protected(&self) -> Result<Option<Option<u64>>> {
        let row: Option<(bool, Option<i64>)> = self.db.conn()
            .prepare_cached("SELECT protected, quota FROM meshes WHERE name = ?1")?
            .query_row([&self.mesh], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        Ok(row.filter(|(protected, _)| *protected).map(|(_, quota)| quota.and_then(|quota| u64::try_from(quota).ok())))
    }

    /// Every mesh this node is in but the main one, and its account.
    pub fn meshes(&self) -> Result<Vec<(String, u32)>> {
        Ok(self.db.conn()
            .prepare_cached("SELECT name, uid FROM meshes ORDER BY name")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Every member of every mesh this node is in: whom collecting waits
    /// on, since what's here may be kept in any of them.
    pub fn everyone(&self) -> Result<Vec<PeerId>> {
        let peers: Vec<String> = self.db.conn()
            .prepare_cached("SELECT DISTINCT peer FROM mesh_members ORDER BY peer")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(peers.iter().filter_map(|peer| PeerId::from_str(peer).ok()).collect())
    }

    /// Let a peer in, as asked to, whatever's been forgotten. Returns whether
    /// it's new.
    pub fn add(&self, peer: &PeerId) -> Result<bool> {
        self.db.conn().prepare_cached("DELETE FROM mesh_forgotten WHERE mesh = ?1 AND peer = ?2")?.execute([&self.mesh, &peer.to_string()])?;
        Ok(self.db.conn()
            .prepare_cached("INSERT OR IGNORE INTO mesh_members (mesh, peer) VALUES (?1, ?2)")?
            .execute([&self.mesh, &peer.to_string()])? > 0)
    }

    /// Note where a member listens, if it's a member.
    pub fn add_addr(&self, peer: &PeerId, addr: &Multiaddr) -> Result<()> {
        self.db.conn()
            .prepare_cached(
                "INSERT OR IGNORE INTO mesh_member_addrs (mesh, peer, addr)
                 SELECT mesh, peer, ?3 FROM mesh_members WHERE mesh = ?1 AND peer = ?2",
            )?
            .execute(params![self.mesh, peer.to_string(), addr.to_string()])?;
        Ok(())
    }

    pub fn contains(&self, peer: &PeerId) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM mesh_members WHERE mesh = ?1 AND peer = ?2")?
            .exists([&self.mesh, &peer.to_string()])?)
    }

    /// Every member, and where each listens.
    pub fn list(&self) -> Result<BTreeMap<PeerId, Vec<Multiaddr>>> {
        let mut members = BTreeMap::new();
        let mut stmt = self.db.conn().prepare_cached(
            "SELECT m.peer, a.addr FROM mesh_members m LEFT JOIN mesh_member_addrs a ON a.mesh = m.mesh AND a.peer = m.peer
             WHERE m.mesh = ?1 ORDER BY m.peer, a.addr",
        )?;
        let rows = stmt.query_map([&self.mesh], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))?;
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

    /// No longer let a peer in, or count it as a member, nor take it for one
    /// when others say it is, until it's invited again. Returns whether it
    /// was one.
    pub fn forget(&self, peer: &PeerId) -> Result<bool> {
        let conn = self.db.conn();
        conn.prepare_cached("DELETE FROM mesh_member_addrs WHERE mesh = ?1 AND peer = ?2")?.execute([&self.mesh, &peer.to_string()])?;
        let was = conn.prepare_cached("DELETE FROM mesh_members WHERE mesh = ?1 AND peer = ?2")?.execute([&self.mesh, &peer.to_string()])? > 0;
        conn.prepare_cached("INSERT OR IGNORE INTO mesh_forgotten (mesh, peer) VALUES (?1, ?2)")?.execute([&self.mesh, &peer.to_string()])?;
        Ok(was)
    }

    fn forgotten(&self, peer: &PeerId) -> Result<bool> {
        Ok(self.db.conn()
            .prepare_cached("SELECT 1 FROM mesh_forgotten WHERE mesh = ?1 AND peer = ?2")?
            .exists([&self.mesh, &peer.to_string()])?)
    }

    /// Take in members another member knows of, but those forgotten here.
    /// Returns those new here.
    pub fn merge(&self, other: &BTreeMap<PeerId, Vec<Multiaddr>>) -> Result<Vec<PeerId>> {
        let mut new = Vec::new();
        for (peer, addrs) in other {
            if self.forgotten(peer)? {
                continue;
            }
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
    /// The user's root key, and the blocks the joiner needs to be one of
    /// its devices: every certificate and revocation, signed, the
    /// joiner's among them, and the root key, sealed, with what keeps it.
    pub user: Option<(Link, Vec<Vec<u8>>)>,
    /// Whether the mesh is protected: the joiner holds nothing of the
    /// inviter's but what the inviter holds of its vault, and joins with
    /// its own.
    pub protected: bool,
    /// For a protected mesh holding a vault already, what the vault has
    /// it keep sealed with the user's passphrase, the vault itself and the
    /// user's root key, so a machine that's lost everything else recovers
    /// them by joining.
    pub sealed: Vec<Vec<u8>>,
    /// ...and the rest of what it keeps there: the manifests, to restore.
    pub held: Vec<Link>,
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
        let mut ticket = BTreeMap::from([
            ("inviter".to_owned(), Ipld::Bytes(self.inviter.to_bytes())),
            ("key".to_owned(), Ipld::String(self.swarm_key.to_string())),
            ("members".to_owned(), Ipld::List(members.collect())),
        ]);
        if let Some((user, certificate)) = &self.user {
            ticket.insert("user".to_owned(), Ipld::Link(user.clone()));
            ticket.insert("blocks".to_owned(), Ipld::List(certificate.iter().cloned().map(Ipld::Bytes).collect()));
        }
        if self.protected {
            ticket.insert("protected".to_owned(), Ipld::Bool(true));
        }
        if !self.sealed.is_empty() {
            ticket.insert("sealed".to_owned(), Ipld::List(self.sealed.iter().cloned().map(Ipld::Bytes).collect()));
        }
        if !self.held.is_empty() {
            ticket.insert("held".to_owned(), Ipld::List(self.held.iter().cloned().map(Ipld::Link).collect()));
        }
        let ticket = Ipld::Map(ticket);
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
        let user = match (map.remove("user"), map.remove("blocks")) {
            (Some(Ipld::Link(user)), Some(Ipld::List(blocks))) => {
                let blocks = blocks.into_iter().map(|block| match block {
                    Ipld::Bytes(bytes) => Ok(bytes),
                    _ => Err(invalid("blocks")),
                });
                Some((user, blocks.collect::<Result<_>>()?))
            },
            (None, None) => None,
            _ => return Err(invalid("user")),
        };
        let protected = match map.remove("protected") {
            None => false,
            Some(Ipld::Bool(protected)) => protected,
            Some(_) => return Err(invalid("protected")),
        };
        let sealed = match map.remove("sealed") {
            None => Vec::new(),
            Some(Ipld::List(list)) => list.into_iter().map(|item| match item {
                Ipld::Bytes(bytes) => Ok(bytes),
                _ => Err(invalid("sealed")),
            }).collect::<Result<_>>()?,
            Some(_) => return Err(invalid("sealed")),
        };
        let held = match map.remove("held") {
            None => Vec::new(),
            Some(Ipld::List(list)) => list.into_iter().map(|item| match item {
                Ipld::Link(link) => Ok(link),
                _ => Err(invalid("held")),
            }).collect::<Result<_>>()?,
            Some(_) => return Err(invalid("held")),
        };
        Ok(Self { swarm_key, inviter, members, user, protected, sealed, held })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    #[test]
    fn each_mesh_has_its_own_members_and_account() {
        let db = Db::memory().expect("db");
        // From when a node was in one mesh
        let old = peer();
        db.conn().execute_batch(&format!(
            "CREATE TABLE members (peer TEXT PRIMARY KEY);
             CREATE TABLE member_addrs (peer TEXT NOT NULL, addr TEXT NOT NULL, PRIMARY KEY (peer, addr));
             INSERT INTO members VALUES ('{old}');
             INSERT INTO member_addrs VALUES ('{old}', '/ip4/127.0.0.1/tcp/1');"
        )).expect("old");
        let main = Members::open(db.clone(), MAIN).expect("main");
        let other = Members::open(db, "other").expect("other");
        assert_eq!(main.list().expect("list").into_iter().collect::<Vec<_>>(), [(old, vec!["/ip4/127.0.0.1/tcp/1".parse().expect("addr")])]);
        assert!(other.list().expect("list").is_empty());

        let theirs = peer();
        assert!(other.add(&theirs).expect("add") && other.add(&old).expect("add"));
        other.add_addr(&old, &"/ip4/127.0.0.1/tcp/2".parse().expect("addr")).expect("addr");
        assert!(!main.contains(&theirs).expect("contains") && other.contains(&theirs).expect("contains"));
        // One peer in both, listening on another port in each
        assert_eq!(main.list().expect("list").get(&old).map(Vec::len), Some(1));
        assert_eq!(other.list().expect("list").get(&old).map(Vec::len), Some(1));
        let mut everyone = vec![old, theirs];
        everyone.sort();
        assert_eq!(main.everyone().expect("everyone"), everyone);

        assert_eq!(other.account().expect("account"), None);
        other.set_account(60001).expect("set");
        assert_eq!(other.account().expect("account"), Some(60001));
        assert_eq!(main.meshes().expect("meshes"), [("other".to_owned(), 60001)]);
        assert!(Place::valid("friends-2") && !Place::valid("../up") && !Place::valid(""));
        assert_eq!(Place::new(Path::new("/r"), "x").dir(), Path::new("/r/meshes/x"));
        assert_eq!(Place::main(Path::new("/r")).dir(), Path::new("/r"));
    }
}
