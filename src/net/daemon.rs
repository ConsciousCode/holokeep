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
use super::durability::Report;
use super::node::{AuditId, Event, FetchId, Node};
use crate::store::Db;

/// The daemon's socket, in the repo.
const SOCKET: &str = "node.sock";

/// Where a node listens unless told otherwise.
pub const LISTEN: &str = "/ip4/0.0.0.0/tcp/4011";

/// How often to dial members which aren't connected.
const REDIAL: Duration = Duration::from_mins(1);

/// How often to audit what's held, and raise what's short.
const AUDIT: Duration = Duration::from_hours(1);

/// How often to notice members of structure which arrived, such as from
/// commands run since.
const ANNOUNCE: Duration = Duration::from_secs(10);

/// How long after starting to first audit, so members have connected.
const SETTLE: Duration = Duration::from_secs(30);

/// Someone on the control socket waiting for something to finish.
enum Waiter {
    Fetch(FetchId),
    Audit(AuditId),
}

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

/// Have the running daemon fetch the DAG under a root: how many blocks it
/// fetched and the CIDs no connected member had, or None if it isn't
/// running.
pub fn fetch(dir: &Path, root: &crate::model::Link) -> Result<Option<(usize, Vec<String>)>> {
    let Some(lines) = ask_patiently(dir, &format!("fetch {root}"))? else {
        return Ok(None);
    };
    let (mut fetched, mut missing) = (None, Vec::new());
    for line in lines {
        if let Some(n) = line.strip_prefix("fetched ") {
            fetched = n.trim().parse().ok();
        } else if let Some(cid) = line.strip_prefix("missing ") {
            missing.push(cid.trim().to_owned());
        } else if line.starts_with("unknown command") {
            // A daemon from before fetching, still running after an upgrade
            return Err(Error::Invalid("the running node is older than this hk: restart `hk node run`".into()));
        } else if let Some(e) = line.strip_prefix("error: ") {
            return Err(Error::Invalid(e.to_owned()));
        }
    }
    let fetched = fetched.ok_or_else(|| Error::Invalid("the node hung up without saying what it fetched".into()))?;
    Ok(Some((fetched, missing)))
}

/// Have the running daemon audit now, as many failures to lose a block as
/// it's run with unless said: what it reported, or None if it isn't
/// running.
pub fn audit(dir: &Path, copies: Option<usize>) -> Result<Option<Report>> {
    let command = copies.map_or_else(|| "audit".to_owned(), |copies| format!("audit {copies}"));
    let Some(lines) = ask_patiently(dir, &command)? else {
        return Ok(None);
    };
    let mut report = None;
    for line in lines {
        let mut words = line.split_whitespace();
        if words.next() == Some("audited") {
            let mut number = || words.next().and_then(|n| n.parse().ok()).unwrap_or_default();
            report = Some(Report { advertised: number(), copied: number(), short: number() });
        } else if line.starts_with("unknown command") {
            return Err(Error::Invalid("the running node is older than this hk: restart `hk node run`".into()));
        } else if let Some(e) = line.strip_prefix("error: ") {
            return Err(Error::Invalid(e.to_owned()));
        }
    }
    report.map(Some).ok_or_else(|| Error::Invalid("the node hung up without saying what it audited".into()))
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

/// Run the node until interrupted, auditing every so often that it would
/// take `copies` failures to lose each block it holds.
pub async fn run(dir: &Path, listen: Multiaddr, copies: usize) -> Result<()> {
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
    let start = tokio::time::Instant::now().checked_add(SETTLE).unwrap_or_else(tokio::time::Instant::now);
    let mut audit = tokio::time::interval_at(start, AUDIT);
    let mut announce = tokio::time::interval(ANNOUNCE);
    // Those waiting on fetches and audits, to be answered when they finish
    let mut fetching: HashMap<FetchId, OwnedWriteHalf> = HashMap::new();
    let mut auditing: HashMap<AuditId, OwnedWriteHalf> = HashMap::new();
    let result = loop {
        tokio::select! {
            event = node.next() => match event {
                Ok(Event::Audited { id, report }) => {
                    eprintln!("audited: {} advertised, {} copied, {} short", report.advertised, report.copied, report.short);
                    if let Some(mut write) = auditing.remove(&id) {
                        let line = format!("audited {} {} {}\n", report.advertised, report.copied, report.short);
                        let _ = write.write_all(line.as_bytes()).await;
                    }
                },
                Ok(Event::Fetched { id, fetched, missing }) => {
                    if let Some(mut write) = fetching.remove(&id) {
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
                match answer(&mut node, stream, copies).await {
                    Ok(Some((Waiter::Fetch(id), write))) => {
                        fetching.insert(id, write);
                    },
                    Ok(Some((Waiter::Audit(id), write))) => {
                        auditing.insert(id, write);
                    },
                    Ok(None) => {},
                    Err(e) => eprintln!("control: {e}"),
                }
            },
            _ = redial.tick() => node.dial_members()?,
            _ = announce.tick() => node.announce()?,
            _ = audit.tick() => {
                if !node.auditing() {
                    node.audit(copies)?;
                }
            },
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
        // Members which are offline fail to be dialed all the time, and
        // audits are reported as they finish
        Event::Failed(..) | Event::Audited { .. } => {},
        Event::Fetched { fetched, missing, .. } => eprintln!("fetched {fetched} blocks, {} missing", missing.len()),
    }
}

/// Answer one command on the control socket, or say which fetch it waits
/// on, to be answered when that finishes.
async fn answer(node: &mut Node, stream: tokio::net::UnixStream, copies: usize) -> Result<Option<(Waiter, OwnedWriteHalf)>> {
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
                Ok(root) => return Ok(Some((Waiter::Fetch(node.fetch(root)?), write))),
                Err(_) => {
                    let _ = writeln!(out, "error: not a CID: {cid}");
                },
            }
        },
        "audit" => return Ok(Some((Waiter::Audit(node.audit(copies)?), write))),
        command if command.starts_with("audit ") => match command.trim_start_matches("audit ").trim().parse() {
            Ok(copies) => return Ok(Some((Waiter::Audit(node.audit(copies)?), write))),
            Err(_) => {
                let _ = writeln!(out, "error: not a number of copies: {command}");
            },
        },
        other => {
            // Not prefixed with "error: ", which daemons from before fetching
                // didn't, so a newer hk can tell an old daemon by it
                let _ = writeln!(out, "unknown command {other:?}");
        },
    }
    write.write_all(out.as_bytes()).await?;
    Ok(None)
}
