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
use super::node::{AuditId, Event, FetchId, Node, TrimId};
use crate::store::Db;

/// The daemon's socket, in the repo.
const SOCKET: &str = "node.sock";

/// Where a node listens unless told otherwise.
pub const LISTEN: &str = "/ip4/0.0.0.0/tcp/4011";

/// How often to dial members which aren't connected.
const REDIAL: Duration = Duration::from_mins(1);

/// How often to notice members of structure which arrived, such as from
/// commands run since.
const ANNOUNCE: Duration = Duration::from_secs(10);

/// How long after starting to begin the trickle, so members have
/// connected.
const SETTLE: Duration = Duration::from_secs(5);

/// How often to look at free space, to trim between the watermarks.
const PRESSURE: Duration = Duration::from_secs(30);

/// How often to collect garbage from a sample of what's here, when
/// collecting.
const COLLECT: Duration = Duration::from_mins(1);

/// Someone on the control socket waiting for something to finish.
#[derive(Debug, Clone, Copy)]
enum Waiter {
    Fetch(FetchId),
    Audit(AuditId),
    Trim(TrimId),
}

/// Parse a size: bytes, or with a K, M, G or T suffix, in powers of two.
pub fn parse_size(text: &str) -> std::result::Result<u64, String> {
    let text = text.trim();
    let (number, shift) = match text.char_indices().last() {
        Some((at, unit)) if unit.is_ascii_alphabetic() => {
            let shift = match unit.to_ascii_uppercase() {
                'K' => 10,
                'M' => 20,
                'G' => 30,
                'T' => 40,
                _ => return Err(format!("unknown unit in {text:?}")),
            };
            (text.get(..at).unwrap_or_default(), shift)
        },
        _ => (text, 0),
    };
    let number: u64 = number.trim().parse().map_err(|_| format!("not a size: {text:?}"))?;
    number.checked_shl(shift).filter(|size| size >> shift == number).ok_or_else(|| format!("too large: {text:?}"))
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

/// Have the running daemon let go of whatever the mesh can spare of what's
/// here, pressed or not: (considered, dropped, freed), or None if it isn't
/// running.
pub fn trim(dir: &Path) -> Result<Option<super::trim::Report>> {
    let Some(lines) = ask_patiently(dir, "trim")? else {
        return Ok(None);
    };
    for line in lines {
        let mut words = line.split_whitespace();
        if words.next() == Some("trimmed") {
            let mut number = || words.next().and_then(|n| n.parse::<u64>().ok()).unwrap_or_default();
            let (considered, dropped, freed) = (number(), number(), number());
            return Ok(Some(super::trim::Report {
                considered: usize::try_from(considered).unwrap_or_default(),
                dropped: usize::try_from(dropped).unwrap_or_default(),
                freed,
            }));
        }
        if line.starts_with("unknown command") {
            return Err(Error::Invalid("the running node is older than this hk: restart `hk node run`".into()));
        }
    }
    Err(Error::Invalid("the node hung up without saying what it trimmed".into()))
}

/// Have the running daemon collect garbage from everything here now: what
/// it did, or None if it isn't running.
///
/// What it condemns is let go of only once its grace is up and every
/// member's said it doesn't keep it.
pub fn collect(dir: &Path) -> Result<Option<super::collect::Report>> {
    let Some(lines) = ask_patiently(dir, "collect")? else {
        return Ok(None);
    };
    for line in lines {
        let mut words = line.split_whitespace();
        if words.next() == Some("collected") {
            let mut number = || words.next().and_then(|n| n.parse::<u64>().ok()).unwrap_or_default();
            let (condemned, pardoned, collected, freed) = (number(), number(), number(), number());
            let count = |n: u64| usize::try_from(n).unwrap_or_default();
            return Ok(Some(super::collect::Report { condemned: count(condemned), pardoned: count(pardoned), collected: count(collected), freed }));
        }
        if line.starts_with("unknown command") {
            return Err(Error::Invalid("the running node is older than this hk: restart `hk node run`".into()));
        }
    }
    Err(Error::Invalid("the node hung up without saying what it collected".into()))
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

/// Run the node until interrupted, auditing as a trickle that it would
/// take `copies` failures to lose each block it holds.
///
/// Free space is kept between watermarks, `(low, high)`: below the low,
/// the node lets go of copies the mesh can spare until it's above the
/// high. If `collecting`, garbage is collected too, a sample at a time.
pub async fn run(dir: &Path, listen: Multiaddr, copies: usize, (low, high): (u64, u64), collecting: bool) -> Result<()> {
    let key = mesh::node_key(dir)?;
    let swarm_key = mesh::swarm_key(dir)?.ok_or_else(|| Error::Invalid("this node isn't in a mesh: invite another, or join one".into()))?;
    let catalog = crate::store::Catalog::open_repo(dir)?;
    let mut node = Node::tcp(&key, swarm_key, catalog, members(dir)?)?;
    node.set_watermarks(low, high);
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
    let later = |delay| tokio::time::Instant::now().checked_add(delay).unwrap_or_else(tokio::time::Instant::now);
    let mut trickle = later(SETTLE);
    let mut announce = tokio::time::interval(ANNOUNCE);
    let mut pressure = later(SETTLE);
    let mut collect = later(SETTLE);
    let mut waiting = Waiting::default();
    let result = loop {
        tokio::select! {
            event = node.next() => match event {
                Ok(event) => {
                    // Still pressed, and a trim helped: again, at once
                    if let Event::Trimmed { report, .. } = &event
                        && report.dropped > 0
                    {
                        pressure = tokio::time::Instant::now();
                    }
                    waiting.finished(event).await;
                },
                Err(e) => break Err(e),
            },
            accepted = control.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                match answer(&mut node, stream, copies, collecting).await {
                    Ok(Some((waiter, write))) => waiting.wait(waiter, write),
                    Ok(None) => {},
                    Err(e) => eprintln!("control: {e}"),
                }
            },
            _ = redial.tick() => node.dial_members()?,
            _ = announce.tick() => {
                node.announce()?;
                // What's been added since is copied without waiting out a
                // calm interval
                if node.arrived()? && !node.connected().is_empty() {
                    trickle = tokio::time::Instant::now();
                }
            },
            () = tokio::time::sleep_until(trickle) => {
                if !node.auditing() {
                    node.trickle(copies)?;
                }
                trickle = later(node.trickle_delay());
            },
            () = tokio::time::sleep_until(pressure) => {
                if !node.trimming() && node.pressed()? && !node.connected().is_empty() {
                    node.trim_some(copies, false)?;
                }
                pressure = later(PRESSURE);
            },
            () = tokio::time::sleep_until(collect), if collecting => {
                let report = node.collect(false)?;
                if report.collected > 0 {
                    eprintln!("collected: {} let go of, {} bytes freed", report.collected, report.freed);
                }
                collect = later(COLLECT);
            },
            _ = tokio::signal::ctrl_c() => break Ok(()),
        }
    };
    std::fs::remove_file(&path)?;
    result
}

/// Those on the control socket waiting on fetches, audits and trims, to be
/// answered when they finish.
#[derive(Default)]
struct Waiting {
    fetching: HashMap<FetchId, OwnedWriteHalf>,
    auditing: HashMap<AuditId, OwnedWriteHalf>,
    trimming: HashMap<TrimId, OwnedWriteHalf>,
}

impl Waiting {
    fn wait(&mut self, waiter: Waiter, write: OwnedWriteHalf) {
        match waiter {
            Waiter::Fetch(id) => self.fetching.insert(id, write),
            Waiter::Audit(id) => self.auditing.insert(id, write),
            Waiter::Trim(id) => self.trimming.insert(id, write),
        };
    }

    /// Answer whoever was waiting on what's finished, and report it.
    async fn finished(&mut self, event: Event) {
        let (write, out) = match event {
            Event::Audited { id, report } => {
                // The trickle's ticks are worth hearing of only when they do
                // something
                if report.copied > 0 || self.auditing.contains_key(&id) {
                    eprintln!("audited: {} advertised, {} copied, {} short", report.advertised, report.copied, report.short);
                }
                (self.auditing.remove(&id), format!("audited {} {} {}\n", report.advertised, report.copied, report.short))
            },
            Event::Trimmed { id, report } => {
                if report.dropped > 0 || self.trimming.contains_key(&id) {
                    eprintln!("trimmed: {} spare, {} let go of, {} bytes freed", report.considered, report.dropped, report.freed);
                }
                (self.trimming.remove(&id), format!("trimmed {} {} {}\n", report.considered, report.dropped, report.freed))
            },
            Event::Fetched { id, fetched, missing } => {
                let mut out = format!("fetched {fetched}\n");
                for cid in missing {
                    let _ = writeln!(out, "missing {cid}");
                }
                (self.fetching.remove(&id), out)
            },
            event => {
                report(&event);
                return;
            },
        };
        if let Some(mut write) = write {
            // They may have given up
            let _ = write.write_all(out.as_bytes()).await;
        }
    }
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
        Event::Failed(..) | Event::Audited { .. } | Event::Trimmed { .. } => {},
        Event::Fetched { fetched, missing, .. } => eprintln!("fetched {fetched} blocks, {} missing", missing.len()),
        Event::Collected { collected } => eprintln!("collected: {collected} let go of"),
    }
}

/// Answer one command on the control socket, or say which fetch it waits
/// on, to be answered when that finishes.
async fn answer(node: &mut Node, stream: tokio::net::UnixStream, copies: usize, collecting: bool) -> Result<Option<(Waiter, OwnedWriteHalf)>> {
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
        "status" => {
            let _ = writeln!(out, "peer\t{}", node.peer_id());
            let _ = writeln!(out, "connected\t{}", node.connected().len());
            let _ = writeln!(out, "blocks\t{}", node.catalog().block_count()?);
            let _ = writeln!(out, "copies\t{copies}");
            let _ = writeln!(out, "trickle\t{:.1}s", node.trickle_interval().as_secs_f64());
            let free = node.catalog().offer()?.free;
            let _ = writeln!(out, "free\t{}", free.map_or_else(|| "unknown".to_owned(), |free| format!("{} MiB", free >> 20)));
            let marks = node.watermarks();
            let _ = writeln!(out, "watermarks\t{} MiB to {} MiB", marks.low >> 20, marks.high >> 20);
            let _ = writeln!(out, "pressed\t{}", if marks.pressed() { "yes" } else { "no" });
            let _ = writeln!(out, "collecting\t{}", if collecting { "yes" } else { "no" });
            let _ = writeln!(out, "condemned\t{}", node.condemned().count()?);
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
        "trim" => return Ok(Some((Waiter::Trim(node.trim_some(copies, true)?), write))),
        "collect" => {
            let report = node.collect(true)?;
            let _ = writeln!(out, "collected {} {} {} {}", report.condemned, report.pardoned, report.collected, report.freed);
        },
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
