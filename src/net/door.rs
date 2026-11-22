//! The door: where someone outside a holder's meshes reads a sealed
//! anchor it holds, or writes it, by capability: `/holokeep/cap/1.0.0`.
//!
//! It's a swarm of its own, apart from the member's (`hk node run
//! --door`), with no private network, letting in anyone, who may ask this
//! and nothing else. So a stranger never reaches the mesh's swarm, nor
//! anything it answers. What it answers is only what a capability's
//! holder could prove they may read:
//!
//! - **Heads.** The claims held of a sealed anchor, its sets and their
//!   signs, and the head blocks they set it to, to one who proves they know
//!   its heads' block access token, which is derived from its read key
//!   (see `cap::head_bat`): checked against the token in a head block
//!   held.
//! - **Blocks.** Sealed blocks, each to one who proves they know its
//!   token, checked against the token the block carries in the clear.
//! - **Keyrings.** A sealed view's latest keyring, to anyone: its read key
//!   boxed to each reader, which only they open (see `cap::add_reader`).
//! - **Writes.** A head a capability's writer wrote, its blocks in as
//!   many requests as they take, each with the head's set and the
//!   writer's sign of it, which the claims held of the sealed view must
//!   judge one a writer may make (see `cap::may_write`). The set and sign
//!   are kept with the last, once all else is here, for the owner's node
//!   to take in.
//!
//! A proof is `vault::prove` of the token, over the CID asked for (the
//! sealed view, for heads), the asker's peer ID, and when, so it's no use
//! to anyone else or for long. Tokens are a holder's policy, not a secret:
//! they keep an honest holder from serving ciphertext to whoever has only
//! its CIDs, as for offline attack, without asking the owner's mesh
//! anything.

use std::cell::RefCell;
use std::time::Duration;

use futures::StreamExt as _;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent, dial_opts::DialOpts};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::mesh::{Error, Result};
use crate::cid::{BaseCid as _, Cid as _, CidRef as _};
use crate::model::Link;
use crate::store::Catalog;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/holokeep/cap/1.0.0");

/// The most an answer of blocks carries; what's left out is asked again.
const BUDGET: usize = 4 << 20;

/// How many blocks a reader asks for at once.
const BATCH: usize = 64;

/// How long a reader waits for an answer, or to connect.
const PATIENCE: Duration = Duration::from_secs(30);

/// What's asked at the door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Asked {
    /// A sealed anchor's heads: its sealed view, when, and the proof.
    Heads { view: ByteBuf, at: u64, proof: ByteBuf },
    /// Sealed blocks, each with its proof, all as of when.
    Blocks { wanted: Vec<(ByteBuf, ByteBuf)>, at: u64 },
    /// Some blocks of a head a writer wrote of a sealed view, by CID, with
    /// the head's set and the writer's sign of it, which say it may; the
    /// last of them says so, and then the set and sign are kept too.
    Write { view: ByteBuf, set: ByteBuf, sign: ByteBuf, blocks: Vec<(ByteBuf, ByteBuf)>, last: bool },
    /// A sealed view's latest keyring, and its owner key's sign of it: to
    /// anyone, its boxes saying nothing to whoever isn't a reader.
    Keyring { view: ByteBuf },
}

/// The most block bytes a writer sends at once, under the most a request
/// may be.
const WRITE_BUDGET: usize = 768 << 10;

/// What the door says: blocks, by CID. Nothing, for what isn't proved or
/// isn't here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Told {
    pub blocks: Vec<(ByteBuf, ByteBuf)>,
}

/// Now, in seconds, by this machine's clock, as proofs say when.
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

fn proof_of(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

/// Answer what's asked, from what's held, for whoever asked.
pub fn answer(catalog: &Catalog, who: &PeerId, question: Asked, now: u64) -> Result<Told> {
    let asker = who.to_bytes();
    let mut told = Told::default();
    match question {
        Asked::Heads { view, at, proof } => {
            let (Ok(view), Some(proof)) = (Link::decode(&view), proof_of(&proof)) else {
                return Ok(told);
            };
            let claims = crate::cap::claims_about(catalog, &view).map_err(|e| Error::Invalid(e.to_string()))?;
            let mut heads = Vec::new();
            for (_, data) in &claims {
                if let Some(crate::claim::Claim::Set(set)) = crate::claim::Claim::parse(data)
                    && let Some(head) = catalog.get_block(set.value())?
                {
                    heads.push((set.value().clone(), head));
                }
            }
            // Proved against any head held: they share one token
            if !heads.iter().any(|(_, head)| crate::vault::check(head.data(), &view, &asker, at, &proof, now)) {
                return Ok(told);
            }
            told.blocks.extend(claims.into_iter().map(|(cid, data)| (ByteBuf::from(cid.to_bytes()), ByteBuf::from(data))));
            told.blocks.extend(heads.into_iter().map(|(cid, head)| (ByteBuf::from(cid.to_bytes()), ByteBuf::from(head.into_data().into_vec()))));
        },
        Asked::Blocks { wanted, at } => {
            let mut size = 0usize;
            for (cid, proof) in wanted {
                let (Ok(link), Some(proof)) = (Link::decode(&cid), proof_of(&proof)) else {
                    continue;
                };
                let Some(block) = catalog.get_block(&link)? else {
                    continue;
                };
                if !crate::vault::check(block.data(), &link, &asker, at, &proof, now) {
                    continue;
                }
                if !told.blocks.is_empty() && size.saturating_add(block.len()) > BUDGET {
                    break;
                }
                size = size.saturating_add(block.len());
                told.blocks.push((cid, ByteBuf::from(block.into_data().into_vec())));
            }
        },
        Asked::Keyring { view } => {
            let Ok(view) = Link::decode(&view) else {
                return Ok(told);
            };
            let held = crate::cap::keyring_held(catalog, &view).map_err(|e| Error::Invalid(e.to_string()))?;
            told.blocks.extend(held.into_iter().map(|(cid, data)| (ByteBuf::from(cid.to_bytes()), ByteBuf::from(data))));
        },
        Asked::Write { view, set, sign, blocks, last } => {
            let Ok(view) = Link::decode(&view) else {
                return Ok(told);
            };
            if !crate::cap::may_write(catalog, &view, &set, &sign).map_err(|e| Error::Invalid(e.to_string()))? {
                return Ok(told);
            }
            let mut put = Vec::with_capacity(blocks.len().saturating_add(2));
            for (cid, data) in blocks {
                let block = Link::decode(&cid).ok().and_then(|link| crate::block::Block::verify(link.into(), data.into_vec().into_boxed_slice()).ok());
                put.push(block.ok_or_else(|| Error::Invalid("a block that isn't its CID's".into()))?);
            }
            // The set and sign last, once all else is here: what takes it in
            // looks for them
            if last {
                put.extend([&set, &sign].into_iter().filter_map(|data| crate::claim::Claim::parse(data)).map(|claim| claim.block()));
            }
            for block in &put {
                catalog.put_block(block, crate::cid::CidVersion::V1)?;
            }
            told.blocks.push((ByteBuf::from(view.to_bytes()), ByteBuf::new()));
        },
    }
    Ok(told)
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    cap: request_response::cbor::Behaviour<Asked, Told>,
}

fn behaviour() -> Behaviour {
    let codec = request_response::cbor::codec::Codec::default().set_request_size_maximum(1 << 20).set_response_size_maximum(u64::try_from(BUDGET.saturating_mul(2)).unwrap_or(u64::MAX));
    Behaviour { cap: request_response::Behaviour::with_codec(codec, [(PROTOCOL, ProtocolSupport::Full)], request_response::Config::default().with_request_timeout(PATIENCE)) }
}

/// A door, listening, answering from a catalog of its own.
pub struct Door {
    swarm: Swarm<Behaviour>,
    catalog: Catalog,
    /// The repo, whose accounts' keys a write's kept with.
    repo: Option<std::path::PathBuf>,
    /// The blocks of each writer's write taken so far, till its last.
    writing: std::collections::HashMap<PeerId, Vec<Link>>,
}

impl Door {
    pub fn new(transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, catalog: Catalog) -> Self {
        let swarm = Swarm::new(transport, behaviour(), key.public().to_peer_id(), libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_mins(1)));
        Self { swarm, catalog, repo: None, writing: std::collections::HashMap::new() }
    }

    /// Keep writes taken as whichever of the repo's accounts holds the
    /// sealed view they're of (see `keep`).
    #[must_use]
    pub fn keeping_in(mut self, repo: &std::path::Path) -> Self {
        self.repo = Some(repo.to_path_buf());
        self
    }

    /// Keep a write taken, the last of it here, as each of the repo's
    /// accounts with a key here that keeps a manifest of its sealed view,
    /// as a friend's account holding a vault does: so the vault's
    /// protected meshes hold it, and the owner's machines, which take it
    /// in. The owner's own machines take it in from here.
    fn keep(&mut self, view: &Link, blocks: &[Link]) -> Result<()> {
        let Some(repo) = self.repo.clone() else {
            return Ok(());
        };
        let Some(home) = self.catalog.signer().cloned().map(|key| (self.catalog.uid(), key)) else {
            return Ok(());
        };
        let accounts = self.catalog.claims().map(crate::store::ClaimStore::accounts).transpose()?.unwrap_or_default();
        for account in accounts.into_iter().filter(|account| account.uid != home.0) {
            if !repo.join("accounts").join(format!("{}.key", account.uid)).exists() {
                continue;
            }
            self.catalog.act_for(account.uid, crate::keys::account_key(&repo, account.uid)?)?;
            let kept = crate::cap::keep_written(&self.catalog, view, blocks);
            self.catalog.act_for(home.0, home.1.clone())?;
            if kept.map_err(|e| Error::Invalid(e.to_string()))? {
                eprintln!("kept a write of {view}, as account {}", account.uid);
            }
        }
        Ok(())
    }

    pub fn listen(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.listen_on(addr).map_err(|e| Error::Invalid(format!("listening at the door: {e}")))?;
        Ok(())
    }

    /// Where it listens, once it does.
    pub async fn listening(&mut self) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = self.swarm.select_next_some().await {
                return address;
            }
        }
    }

    /// Answer what's asked, for good.
    pub async fn run(mut self) {
        loop {
            self.step().await;
        }
    }

    /// Answer the next thing asked, if that's what comes.
    pub async fn step(&mut self) {
        if let SwarmEvent::Behaviour(BehaviourEvent::Cap(request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. })) = self.swarm.select_next_some().await {
            // What a write brings, to keep once its last is taken
            let writing = match &request {
                Asked::Write { view, set, sign, blocks, last } => Link::decode(view).ok().map(|view| {
                    let mut cids: Vec<Link> = blocks.iter().filter_map(|(cid, _)| Link::decode(cid).ok()).collect();
                    if *last {
                        cids.extend([set, sign].into_iter().filter_map(|data| crate::claim::Claim::parse(data)).map(|claim| claim.cid()));
                    }
                    (view, cids, *last)
                }),
                _ => None,
            };
            let told = answer(&self.catalog, &peer, request, now()).unwrap_or_else(|e| {
                eprintln!("the door couldn't answer {peer}: {e}");
                Told::default()
            });
            if let Some((view, cids, last)) = writing.filter(|_| !told.blocks.is_empty()) {
                self.writing.entry(peer).or_default().extend(cids);
                if last {
                    let cids = self.writing.remove(&peer).unwrap_or_default();
                    if let Err(e) = self.keep(&view, &cids) {
                        eprintln!("the door couldn't keep {peer}'s write: {e}");
                    }
                }
            }
            let _ = self.swarm.behaviour_mut().cap.send_response(channel, told);
        }
    }
}

/// Open the door for a repo, on a thread of its own, with a catalog of its
/// own, over TCP, as the node's key: it answers there till the process
/// ends.
pub fn open(repo: &std::path::Path, key: &Keypair, addr: Multiaddr) -> Result<()> {
    // Opened here first, so a repo that won't open says so at once
    drop(Catalog::open_repo(repo)?);
    let (repo, key) = (repo.to_path_buf(), key.clone());
    std::thread::Builder::new().name("door".to_owned()).spawn(move || {
        let run = || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(async {
                let base = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true));
                let mut door = Door::new(super::clients::client_transport(base, &key)?, &key, Catalog::open_repo(&repo)?).keeping_in(&repo);
                door.listen(addr)?;
                eprintln!("the door's open on {}", door.listening().await);
                door.run().await;
                Ok(())
            })
        };
        if let Err(e) = run() {
            eprintln!("the door's shut: {e}");
        }
    })?;
    Ok(())
}

/// A reader at a holder's door, outside its meshes.
pub struct Reader {
    runtime: tokio::runtime::Runtime,
    swarm: RefCell<Swarm<Behaviour>>,
    door: PeerId,
}

impl Reader {
    /// Connect to a door, at an address ending in its peer ID, over TCP,
    /// with a key made for the purpose.
    pub fn connect(addr: &Multiaddr) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let key = Keypair::generate_ed25519();
        let transport = {
            let _entered = runtime.enter();
            super::clients::client_transport(libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true)), &key)?
        };
        Self::over(runtime, transport, &key, addr)
    }

    /// Connect over a transport.
    pub fn over(runtime: tokio::runtime::Runtime, transport: Boxed<(PeerId, StreamMuxerBox)>, key: &Keypair, addr: &Multiaddr) -> Result<Self> {
        let door = addr.iter().find_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        }).ok_or_else(|| Error::Invalid(format!("{addr} doesn't say whose door it is: end it with /p2p/<peer>")))?;
        let mut swarm = {
            let _entered = runtime.enter();
            Swarm::new(transport, behaviour(), key.public().to_peer_id(), libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_mins(1)))
        };
        runtime.block_on(async {
            swarm.dial(DialOpts::peer_id(door).addresses(vec![addr.clone()]).build()).map_err(|e| Error::Invalid(format!("dialing {addr}: {e}")))?;
            let connected = async {
                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == door => return Ok(()),
                        SwarmEvent::OutgoingConnectionError { error, .. } => return Err(Error::Invalid(format!("couldn't reach the door at {addr}: {error}"))),
                        _ => {},
                    }
                }
            };
            tokio::time::timeout(PATIENCE, connected).await.map_err(|_| Error::Invalid(format!("the door at {addr} didn't answer")))?
        })?;
        Ok(Self { runtime, swarm: RefCell::new(swarm), door })
    }

    fn me(&self) -> Vec<u8> {
        self.swarm.borrow().local_peer_id().to_bytes()
    }

    fn ask(&self, asked: Asked) -> Result<Vec<(Link, Vec<u8>)>> {
        let told = self.told(asked)?;
        // Each checked against its CID: a door may be wrong, or lie
        Ok(told.blocks.into_iter().filter_map(|(cid, data)| {
            let link = Link::decode(&cid).ok()?;
            crate::block::Block::verify(link.clone().into(), data.into_vec().into_boxed_slice()).ok().map(|block| (link, block.into_data().into_vec()))
        }).collect())
    }

    /// A sealed view's latest keyring the door holds, and its owner key's
    /// sign of it, by CID, each checked against it.
    pub fn keyring(&self, view: &Link) -> Result<Vec<(Link, Vec<u8>)>> {
        self.ask(Asked::Keyring { view: ByteBuf::from(view.to_bytes()) })
    }

    /// Write a head a writer wrote of a sealed view: its blocks, in as
    /// many requests as it takes, the set and sign with each, which say it
    /// may, and the head block among the last.
    pub fn write(&self, view: &Link, set: &crate::block::Block, sign: &crate::block::Block, blocks: &[crate::block::Block]) -> Result<()> {
        let mut batches: Vec<Vec<(ByteBuf, ByteBuf)>> = vec![Vec::new()];
        let mut size = 0usize;
        for block in blocks {
            let len = block.data().len();
            if size.saturating_add(len) > WRITE_BUDGET && batches.last().is_some_and(|batch| !batch.is_empty()) {
                batches.push(Vec::new());
                size = 0;
            }
            size = size.saturating_add(len);
            if let Some(batch) = batches.last_mut() {
                batch.push((ByteBuf::from(crate::cid::AnyCid::V1(block.cid().clone()).to_bytes()), ByteBuf::from(block.data().to_vec())));
            }
        }
        let n = batches.len();
        for (i, blocks) in batches.into_iter().enumerate() {
            let asked = Asked::Write {
                view: ByteBuf::from(view.to_bytes()),
                set: ByteBuf::from(set.data().to_vec()),
                sign: ByteBuf::from(sign.data().to_vec()),
                blocks,
                last: i.saturating_add(1) == n,
            };
            if self.told(asked)?.blocks.is_empty() {
                return Err(Error::Invalid("the door won't take it: it doesn't hold the anchor, or the capability's write was taken away".into()));
            }
        }
        Ok(())
    }

    /// What the door tells, as it tells it.
    fn told(&self, asked: Asked) -> Result<Told> {
        let mut swarm = self.swarm.borrow_mut();
        let door = self.door;
        let told = self.runtime.block_on(async {
            let sent = swarm.behaviour_mut().cap.send_request(&door, asked);
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::Behaviour(BehaviourEvent::Cap(request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. })) if request_id == sent => return Ok(response),
                    SwarmEvent::Behaviour(BehaviourEvent::Cap(request_response::Event::OutboundFailure { request_id, error, .. })) if request_id == sent => return Err(Error::Invalid(format!("the door didn't answer: {error}"))),
                    SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } if peer_id == door => return Err(Error::Invalid("the door closed".into())),
                    _ => {},
                }
            }
        })?;
        Ok(told)
    }

    /// The claims the door holds of a sealed anchor, and the heads they
    /// set it to, proving the read key's known: nothing, if it holds none
    /// or the proof's no good.
    pub fn heads(&self, view: &Link, read: &[u8; 32]) -> Result<Vec<(Link, Vec<u8>)>> {
        let at = now();
        let proof = crate::vault::prove(&crate::cap::head_bat(read), view, &self.me(), at);
        self.ask(Asked::Heads { view: ByteBuf::from(view.to_bytes()), at, proof: ByteBuf::from(proof.to_vec()) })
    }
}

impl crate::cap::Heads for Reader {
    fn heads_of(&self, live: &crate::cap::Live) -> crate::cap::Result<Vec<Vec<u8>>> {
        Ok(self.heads(&live.view, live.read()).map_err(|e| crate::cap::Error::Invalid(e.to_string()))?.into_iter().map(|(_, data)| data).collect())
    }
}

impl crate::cap::Source for Reader {
    fn sealed(&self, wanted: &[(Link, [u8; 32])]) -> crate::cap::Result<Vec<Vec<u8>>> {
        let me = self.me();
        let mut got: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();
        let mut left: Vec<&(Link, [u8; 32])> = wanted.iter().filter(|(cid, _)| cid.hashcode() != crate::block::IDENTITY).collect();
        while !left.is_empty() {
            let at = now();
            let batch: Vec<(ByteBuf, ByteBuf)> = left.iter().take(BATCH).map(|(cid, bat)| (ByteBuf::from(cid.to_bytes()), ByteBuf::from(crate::vault::prove(bat, cid, &me, at).to_vec()))).collect();
            let told = self.ask(Asked::Blocks { wanted: batch, at }).map_err(|e| crate::cap::Error::Invalid(e.to_string()))?;
            if told.is_empty() {
                let (cid, _) = left.first().copied().ok_or_else(|| crate::cap::Error::Invalid("nothing".into()))?;
                return Err(crate::cap::Error::Invalid(format!("the door won't give {cid}: it hasn't it, or the capability's not for it")));
            }
            for (cid, data) in told {
                got.insert(cid.to_bytes(), data);
            }
            left.retain(|(cid, _)| !got.contains_key(&cid.to_bytes()));
        }
        wanted.iter().map(|(cid, _)| {
            if cid.hashcode() == crate::block::IDENTITY {
                return Ok(cid.digest_ref().to_vec());
            }
            got.get(&cid.to_bytes()).cloned().ok_or_else(|| crate::cap::Error::Invalid(format!("the door gave no {cid}")))
        }).collect()
    }
}

#[cfg(test)]
mod tests;
