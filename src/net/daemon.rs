//! `hk node run`: the process which owns this node's place in the mesh.
//!
//! Commands which only read and write the repo open its database
//! directly, as before; `SQLite`'s WAL lets them alongside the daemon. Those
//! which need the mesh ask the daemon, over a Unix socket in the repo: a
//! line naming the command, answered by lines until the daemon hangs up.
//!
//! Everything runs on one thread, the catalog's database included, so the
//! storage code stays synchronous.
//!
//! The socket knows who's asking, by uid. The repo's owner, whose the
//! daemon is, may ask anything, as may root; with `--shared`, the host's
//! other users may connect too, to fetch and to say and see things as
//! their own accounts (`as` and a command, see `account`), the repo
//! signing for each with a key of its own, kept in `accounts/`.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use libp2p::Multiaddr;
use sha2::Digest as _;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::net::unix::OwnedWriteHalf;

use super::mesh::{self, Error, Members, Place, Result};
use super::durability::Report;
use super::node::{AuditId, Event, FetchId, Node, TrimId};
use crate::cid::CidRef as _;
use crate::store::{Db, ExternalFile, Mount};

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

/// Watches the directories of files imported in place, sending the path of
/// whatever changes in them; a file is watched through its directory since
/// editors often replace rather than write. What a watch misses, the
/// trickle's sample notices in time.
struct Watch {
    watcher: Option<notify::RecommendedWatcher>,
    dirs: HashSet<PathBuf>,
}

impl Watch {
    fn new(changes: tokio::sync::mpsc::UnboundedSender<PathBuf>) -> Self {
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            // Reads, ours included, change nothing
            if let Ok(event) = event
                && !matches!(event.kind, notify::EventKind::Access(_))
            {
                for path in event.paths {
                    let _ = changes.send(path);
                }
            }
        });
        let watcher = watcher.map_err(|e| eprintln!("not watching files imported in place: {e}")).ok();
        Self { watcher, dirs: HashSet::new() }
    }

    /// Watch the directories of these files too.
    fn add(&mut self, files: &[ExternalFile]) {
        let Some(watcher) = &mut self.watcher else {
            return;
        };
        for dir in files.iter().filter_map(|file| file.path.parent()) {
            if self.dirs.insert(dir.to_owned()) {
                use notify::Watcher as _;
                // Tried once; the trickle covers it otherwise
                if let Err(e) = watcher.watch(dir, notify::RecursiveMode::NonRecursive) {
                    eprintln!("not watching {}: {e}", dir.display());
                }
            }
        }
    }
}

/// How long after a mount's changed to import it again, so a write in
/// progress can finish.
const SETTLE_WRITE: Duration = Duration::from_secs(2);

/// What's mounted being imported again as it changes, each on a blocking
/// thread with its own connection to the repo, so the node carries on.
struct Remounts {
    dir: PathBuf,
    /// Anchors being imported again.
    pending: HashSet<Vec<u8>>,
    done: tokio::sync::mpsc::UnboundedSender<(Mount, std::result::Result<crate::model::Link, String>)>,
}

impl Remounts {
    /// Import again whatever's mounted over these paths, unless it's on its
    /// way already.
    fn changed(&mut self, node: &Node, paths: &[PathBuf]) -> Result<()> {
        for path in paths {
            for mount in node.catalog().mounts_over(path)? {
                if !self.pending.insert(mount.anchor.to_bytes()) {
                    continue;
                }
                let (dir, done) = (self.dir.clone(), self.done.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(SETTLE_WRITE).await;
                    let importing = mount.clone();
                    let root = tokio::task::spawn_blocking(move || {
                        let mut catalog = crate::store::Catalog::open_repo(&dir).map_err(|e| e.to_string())?;
                        catalog.remount(&importing).map_err(|e| e.to_string())
                    })
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));
                    let _ = done.send((mount, root));
                });
            }
        }
        Ok(())
    }

    fn finished(&mut self, mount: &Mount, root: &std::result::Result<crate::model::Link, String>) {
        self.pending.remove(&mount.anchor.to_bytes());
        match root {
            Ok(root) => eprintln!("{} is {root} now, as {} says", mount.path.display(), mount.anchor),
            Err(e) => eprintln!("{} couldn't be imported again, so {} stays as it was: {e}", mount.path.display(), mount.anchor),
        }
    }
}

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
pub fn members(place: &Place) -> Result<Members> {
    Members::open(Db::open(&place.repo.join("blocks.db"))?, &place.mesh)
}

/// The daemon's socket: in the repo, unless the path is too long for a
/// socket (about a hundred bytes), then in the temporary directory, named
/// for the repo.
fn socket(place: &Place) -> PathBuf {
    let dir = place.dir();
    let path = dir.join(SOCKET);
    if path.as_os_str().len() < 100 {
        return path;
    }
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    let hash = sha2::Sha256::digest(dir.as_os_str().as_encoded_bytes());
    let name = hash.iter().take(8).fold(String::new(), |mut name, byte| {
        let _ = write!(name, "{byte:02x}");
        name
    });
    std::env::temp_dir().join(format!("hk-{name}.sock"))
}

/// Ask the running daemon something, or None if there isn't one.
pub fn ask(place: &Place, command: &str) -> Result<Option<Vec<String>>> {
    ask_within(place, command, Some(Duration::from_secs(10)))
}

/// Ask the running daemon something which may take a while, such as
/// fetching a DAG: as long as it takes.
pub fn ask_patiently(place: &Place, command: &str) -> Result<Option<Vec<String>>> {
    ask_within(place, command, None)
}

/// Have the running daemon fetch the DAG under a root: how many blocks it
/// fetched and the CIDs no connected member had, or None if it isn't
/// running.
pub fn fetch(place: &Place, root: &crate::model::Link) -> Result<Option<(usize, Vec<String>)>> {
    let Some(lines) = ask_patiently(place, &format!("fetch {root}"))? else {
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
pub fn audit(place: &Place, copies: Option<usize>) -> Result<Option<Report>> {
    let command = copies.map_or_else(|| "audit".to_owned(), |copies| format!("audit {copies}"));
    let Some(lines) = ask_patiently(place, &command)? else {
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
pub fn trim(place: &Place) -> Result<Option<super::trim::Report>> {
    let Some(lines) = ask_patiently(place, "trim")? else {
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
pub fn collect(place: &Place) -> Result<Option<super::collect::Report>> {
    let Some(lines) = ask_patiently(place, "collect")? else {
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

fn ask_within(place: &Place, command: &str, time: Option<Duration>) -> Result<Option<Vec<String>>> {
    let Ok(mut stream) = UnixStream::connect(socket(place)) else {
        return Ok(None);
    };
    stream.set_read_timeout(time)?;
    writeln!(stream, "{command}")?;
    let lines = BufReader::new(stream).lines().collect::<std::io::Result<_>>()?;
    Ok(Some(lines))
}

/// The node for a mesh, acting for the account it's for.
fn open_node(place: &Place) -> Result<Node> {
    let dir = place.repo.as_path();
    let key = mesh::node_key(dir)?;
    let swarm_key = mesh::swarm_key(&place.dir())?.ok_or_else(|| Error::Invalid("this node isn't in that mesh: invite another, or join one".into()))?;
    let mut catalog = crate::store::Catalog::open_repo(dir)?;
    let members = members(place)?;
    // A mesh for another of the host's accounts holds and hears of its repo
    if let Some(uid) = members.account()? {
        catalog.act_for(uid, crate::keys::account_key(dir, uid)?)?;
    }
    // A friend's account takes no more than it's allowed
    if let Some(quota) = members.protected()? {
        catalog.set_quota(quota);
    }
    Node::tcp(&key, swarm_key, catalog, members)
}

/// Run the node until interrupted, auditing as a trickle that it would
/// take `copies` failures to lose each block it holds.
///
/// Free space is kept between watermarks, `(low, high)`: below the low,
/// the node lets go of copies the mesh can spare until it's above the
/// high. If `collecting`, garbage is collected too, a sample at a time.
pub async fn run(place: &Place, listen: Multiaddr, copies: usize, (low, high): (u64, u64), collecting: bool, shared: bool) -> Result<()> {
    let mut node = open_node(place)?;
    node.set_watermarks(low, high);
    node.listen(listen)?;
    node.dial_members()?;
    let path = socket(place);
    // A socket nothing answers on is left from a daemon that died
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            return Err(Error::Invalid(format!("a node is already running on {} in mesh {}", place.repo.display(), place.mesh)));
        }
        std::fs::remove_file(&path)?;
    }
    let control = UnixListener::bind(&path)?;
    if shared {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    }
    eprintln!("node {} in mesh {}", node.peer_id(), place.mesh);
    let mut redial = tokio::time::interval(REDIAL);
    let later = |delay| tokio::time::Instant::now().checked_add(delay).unwrap_or_else(tokio::time::Instant::now);
    let mut trickle = later(SETTLE);
    let mut announce = tokio::time::interval(ANNOUNCE);
    let mut pressure = later(SETTLE);
    let mut collect = later(SETTLE);
    let mut waiting = Waiting::default();
    let (notify, mut changes) = tokio::sync::mpsc::unbounded_channel();
    // Files imported in place are watched by the main mesh's node alone
    let mut watch = if place.is_main() { watch_external(&node, notify)? } else { Watch::new(notify) };
    let (done, mut remounted) = tokio::sync::mpsc::unbounded_channel();
    let mut remounts = Remounts { dir: place.repo.clone(), pending: HashSet::new(), done };
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
                match answer(&mut node, place, stream, copies, collecting).await {
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
                if node.arrived()? {
                    // Perhaps files imported in place, to watch
                    if place.is_main() {
                        watch.add(&node.catalog().external_files(None)?);
                    }
                    if !node.connected().is_empty() {
                        trickle = tokio::time::Instant::now();
                    }
                }
            },
            () = tokio::time::sleep_until(trickle) => {
                if !node.auditing() {
                    node.trickle(copies)?;
                }
                let paths = node.take_changed();
                if place.is_main() {
                    remounts.changed(&node, &paths)?;
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
            Some(path) = changes.recv() => on_change(&mut node, &mut remounts, path)?,
            Some((mount, root)) = remounted.recv() => remounts.finished(&mount, &root),
            _ = tokio::signal::ctrl_c() => break Ok(()),
        }
    };
    std::fs::remove_file(&path)?;
    result
}

/// Files imported in place: watched from now, and looked at once in the
/// background for what changed while the node wasn't running, so it needn't
/// wait.
fn watch_external(node: &Node, notify: tokio::sync::mpsc::UnboundedSender<PathBuf>) -> Result<Watch> {
    let mut watch = Watch::new(notify.clone());
    let files = node.catalog().external_files(None)?;
    watch.add(&files);
    tokio::task::spawn_blocking(move || {
        for file in files.into_iter().filter(ExternalFile::changed) {
            let _ = notify.send(file.path);
        }
    });
    Ok(watch)
}

/// Something changed at a path: forget what was imported from it, if that
/// was, and import again whatever's mounted over it.
fn on_change(node: &mut Node, remounts: &mut Remounts, path: PathBuf) -> Result<()> {
    let files = node.catalog().external_at(&path)?;
    let lost = node.forget_changed(&files)?;
    if lost > 0 {
        eprintln!("{} changed: {lost} blocks imported from it are no longer here", path.display());
    }
    let mut paths = node.take_changed();
    // Something new in a mounted directory
    if files.is_empty() {
        paths.push(path);
    }
    remounts.changed(node, &paths)
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

/// Answer a command as one of the host's users' accounts, signing with
/// its key here, made the first time it asks, then act for the owner
/// again.
fn as_account(node: &mut Node, dir: &Path, uid: u32, command: &str) -> Result<Vec<String>> {
    let home = node.catalog().uid();
    if uid == home {
        return Ok(crate::account::answer(node.catalog_mut(), command));
    }
    let key = crate::keys::account_key(dir, uid)?;
    let back = crate::keys::account_key(dir, home)?;
    node.catalog_mut().act_for(uid, key)?;
    let lines = crate::account::answer(node.catalog_mut(), command);
    node.catalog_mut().act_for(home, back)?;
    Ok(lines)
}

/// Answer one command on the control socket, or say which fetch it waits
/// on, to be answered when that finishes.
async fn answer(node: &mut Node, place: &Place, stream: tokio::net::UnixStream, copies: usize, collecting: bool) -> Result<Option<(Waiter, OwnedWriteHalf)>> {
    let uid = stream.peer_cred()?.uid();
    let me = rustix::process::getuid().as_raw();
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(1), tokio::io::BufReader::new(read).read_line(&mut line))
        .await
        .map_err(|_| Error::Invalid("no command".into()))??;
    let mut out = String::new();
    if let Some(command) = line.trim_end_matches(['\r', '\n']).strip_prefix("as\t") {
        for line in as_account(node, &place.repo, uid, command)? {
            let _ = writeln!(out, "{line}");
        }
        write.write_all(out.as_bytes()).await?;
        return Ok(None);
    }
    if uid != me && uid != 0 && !line.starts_with("fetch ") {
        write.write_all(format!("error: only the repo's owner, uid {me}, may ask that\n").as_bytes()).await?;
        return Ok(None);
    }
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
            let _ = writeln!(out, "account\t{}", node.catalog().uid());
            match node.catalog().quota_left()? {
                Some((quota, left)) => {
                    let _ = writeln!(out, "used\t{} of {} bytes", quota.saturating_sub(left), quota);
                },
                None => {
                    let _ = writeln!(out, "used\t{} bytes", node.catalog().used()?);
                },
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
