//! `hk node run`: the process which owns this node's place in the mesh.
//!
//! Commands which only read and write the repo open its database
//! directly, as before; `SQLite`'s WAL lets them alongside the daemon. Those
//! which need the mesh ask the daemon, over a Unix socket in the repo: a
//! line naming the command, answered by lines until the daemon hangs up.
//!
//! Everything runs on one thread, the catalog's database included, so the
//! storage code stays synchronous.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libp2p::Multiaddr;
use sha2::Digest as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::net::unix::OwnedWriteHalf;

use super::mesh::{self, Error, Members, Result};
use super::node::{Event, FetchId, Node};
use crate::store::Db;

/// The daemon's socket, in the repo.
const SOCKET: &str = "node.sock";

/// Where a node listens unless told otherwise.
pub const LISTEN: &str = "/ip4/0.0.0.0/tcp/4011";

/// How often to dial members which aren't connected.
const REDIAL: Duration = Duration::from_mins(1);

/// The members of the repo's mesh, as this node knows them.
pub fn members(dir: &Path) -> Result<Members> {
    Members::open(Db::open(&dir.join("blocks.db"))?)
}

/// The daemon's socket: in the repo, unless the path is too long for a
/// socket (about a hundred bytes), then in the temporary directory, named
/// for the repo.
fn socket(dir: &Path) -> PathBuf {
    let path = dir.join(SOCKET);
    if path.as_os_str().len() < 100 {
        return path;
    }
    let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_owned());
    let hash = sha2::Sha256::digest(dir.as_os_str().as_encoded_bytes());
    let name = hash.iter().take(8).fold(String::new(), |mut name, byte| {
        let _ = write!(name, "{byte:02x}");
        name
    });
    std::env::temp_dir().join(format!("hk-{name}.sock"))
}

/// Ask the running daemon something, or None if there isn't one.
pub fn ask(dir: &Path, command: &str) -> Result<Option<Vec<String>>> {
    ask_within(dir, command, Some(Duration::from_secs(10)))
}

/// Ask the running daemon something which may take a while, such as
/// fetching a DAG: as long as it takes.
pub fn ask_patiently(dir: &Path, command: &str) -> Result<Option<Vec<String>>> {
    ask_within(dir, command, None)
}

fn ask_within(dir: &Path, command: &str, time: Option<Duration>) -> Result<Option<Vec<String>>> {
    let Ok(mut stream) = UnixStream::connect(socket(dir)) else {
        return Ok(None);
    };
    stream.set_read_timeout(time)?;
    writeln!(stream, "{command}")?;
    let lines = BufReader::new(stream).lines().collect::<std::io::Result<_>>()?;
    Ok(Some(lines))
}

/// Run the node until interrupted.
pub async fn run(dir: &Path, listen: Multiaddr) -> Result<()> {
    let key = mesh::node_key(dir)?;
    let swarm_key = mesh::swarm_key(dir)?.ok_or_else(|| Error::Invalid("this node isn't in a mesh: invite another, or join one".into()))?;
    let catalog = crate::store::Catalog::open_repo(dir)?;
    let mut node = Node::tcp(&key, swarm_key, catalog, members(dir)?)?;
    node.listen(listen)?;
    node.dial_members()?;
    let path = socket(dir);
    // A socket nothing answers on is left from a daemon that died
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            return Err(Error::Invalid(format!("a node is already running on {}", dir.display())));
        }
        std::fs::remove_file(&path)?;
    }
    let control = UnixListener::bind(&path)?;
    eprintln!("node {} in mesh {}", node.peer_id(), swarm_key.fingerprint());
    let mut redial = tokio::time::interval(REDIAL);
    // Those waiting on fetches, to be answered when they finish
    let mut waiting: HashMap<FetchId, OwnedWriteHalf> = HashMap::new();
    let result = loop {
        tokio::select! {
            event = node.next() => match event {
                Ok(Event::Fetched { id, fetched, missing }) => {
                    if let Some(mut write) = waiting.remove(&id) {
                        let mut out = format!("fetched {fetched}\n");
                        for cid in missing {
                            let _ = writeln!(out, "missing {cid}");
                        }
                        // They may have given up
                        let _ = write.write_all(out.as_bytes()).await;
                    }
                },
                Ok(event) => report(&event),
                Err(e) => break Err(e),
            },
            accepted = control.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                match answer(&mut node, stream).await {
                    Ok(Some((id, write))) => {
                        waiting.insert(id, write);
                    },
                    Ok(None) => {},
                    Err(e) => eprintln!("control: {e}"),
                }
            },
            _ = redial.tick() => node.dial_members()?,
            _ = tokio::signal::ctrl_c() => break Ok(()),
        }
    };
    std::fs::remove_file(&path)?;
    result
}

fn report(event: &Event) {
    match event {
        Event::Listening(addr) => eprintln!("listening on {addr}"),
        Event::Connected(peer) => eprintln!("connected to {peer}"),
        Event::Disconnected(peer) => eprintln!("disconnected from {peer}"),
        Event::Learned(peers) => {
            for peer in peers {
                eprintln!("learned of member {peer}");
            }
        },
        // Members which are offline fail to be dialed all the time
        Event::Failed(..) => {},
        Event::Fetched { fetched, missing, .. } => eprintln!("fetched {fetched} blocks, {} missing", missing.len()),
    }
}

/// Answer one command on the control socket, or say which fetch it waits
/// on, to be answered when that finishes.
async fn answer(node: &mut Node, stream: tokio::net::UnixStream) -> Result<Option<(FetchId, OwnedWriteHalf)>> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(1), tokio::io::BufReader::new(read).read_line(&mut line))
        .await
        .map_err(|_| Error::Invalid("no command".into()))??;
    let mut out = String::new();
    match line.trim() {
        "peers" => {
            let connected = node.connected();
            for (peer, addrs) in node.members().list()? {
                let state = if connected.contains(&peer) { "connected" } else { "-" };
                let addrs: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                let _ = writeln!(out, "{peer}\t{state}\t{}", addrs.join(" "));
            }
        },
        "listeners" => {
            for addr in node.listeners() {
                let _ = writeln!(out, "{addr}");
            }
        },
        "reload" => {
            node.reload()?;
            node.dial_members()?;
        },
        command if command.starts_with("fetch ") => {
            let cid = command.trim_start_matches("fetch ").trim();
            match cid.parse::<crate::model::Link>() {
                Ok(root) => return Ok(Some((node.fetch(root)?, write))),
                Err(_) => {
                    let _ = writeln!(out, "not a CID: {cid}");
                },
            }
        },
        other => {
            let _ = writeln!(out, "unknown command {other:?}");
        },
    }
    write.write_all(out.as_bytes()).await?;
    Ok(None)
}
