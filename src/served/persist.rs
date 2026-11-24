//! Keeping what servers serve, as sets of their anchors.
//!
//! The tree a service serves of an anchor whose serve claim has `persist`
//! on is kept as sets of the anchor, signed by the serving node's account,
//! as if it had been written through the mount (see the wiki's Servers
//! page, Persistence).
//!
//! The serving node looks at each such tree every `EVERY`, and sets the
//! anchor when it's changed, so at most that often. Whatever's `QTTMP`, a
//! file or a directory, is left out: a server says that of what mustn't
//! be kept, such as handshakes, and the rest is kept.
//!
//! Each directory is listed every time, which costs a message or so; a
//! file is read again only if it seems changed: its qid's version moved,
//! or, where a server doesn't keep versions (zero), its size or mtime did.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use crate::dag::{self, DagLink, DirLayoutBuilder as _, DirLayoutStrategy as _};
use crate::import::Importer;
use crate::cid::CidRef as _;
use crate::model::Link;
use crate::ninep::client::Client;
use crate::ninep::{Qid, Time};
use crate::store::Catalog;

/// How often a server's tree is looked at again, and so the most often its
/// anchor is set.
pub const EVERY: Duration = Duration::from_mins(1);

/// What was last kept of a file: enough to tell it's unchanged without
/// reading it.
#[derive(Debug, Clone)]
struct Seen {
    qid: Qid,
    size: u64,
    mtime: Time,
    link: DagLink,
}

/// What's known of the files of each anchor's tree, by their paths.
type Files = HashMap<Vec<Vec<u8>>, Seen>;

/// Keeps what this node serves with persistence on, remembering what it's
/// seen of each tree so only what's changed is read again.
#[derive(Debug, Default)]
pub struct Persister {
    seen: HashMap<Vec<u8>, Files>,
    /// Each anchor's server, whether it was last reached, so its going and
    /// coming back are said once.
    reached: HashMap<Vec<u8>, bool>,
}

/// What became of an anchor in a round.
#[derive(Debug, PartialEq, Eq)]
pub enum Kept {
    /// It's set to what its server serves now, by this set.
    Set(Link),
    /// What its server serves is what it is already.
    Same,
    /// Its server serves nothing to keep: its root is `QTTMP`.
    Nothing,
}

impl Persister {
    /// Keep what each anchor this node, `node`, serves with persistence on
    /// is now, for the account `catalog` acts for, from the services
    /// `repo`'s config says: what became of each, or why it couldn't be.
    pub fn round(&mut self, repo: &Path, catalog: &mut Catalog, node: &[u8]) -> io::Result<Vec<(Link, io::Result<Kept>)>> {
        let served = match catalog.claims() {
            Some(claims) => claims.served_by(node).map_err(io::Error::other)?,
            None => return Ok(Vec::new()),
        };
        let mut done = Vec::new();
        for (anchor, serve) in served.into_iter().filter(|(_, serve)| serve.persist()) {
            let key = anchor.to_bytes();
            let client = crate::served::service(repo, serve.service()).map_err(io::Error::other).and_then(|service| crate::served::connect(&service).map_err(io::Error::other));
            let reached = client.is_ok();
            if self.reached.insert(key.clone(), reached) != Some(reached) {
                match &client {
                    Ok(_) => eprintln!("keeping what {} serves of {anchor}", serve.service()),
                    Err(e) => eprintln!("not keeping what {} serves of {anchor}, as it can't be reached: {e}", serve.service()),
                }
            }
            let Ok(client) = client else {
                continue;
            };
            let files = self.seen.entry(key).or_default();
            done.push((anchor.clone(), keep(&client, catalog, &anchor, files)));
        }
        Ok(done)
    }
}

/// Keep what a server serves of an anchor now, as a set of it, if that's
/// changed: `files` is what was seen of it, and becomes what is.
fn keep(client: &Client, catalog: &mut Catalog, anchor: &Link, files: &mut Files) -> io::Result<Kept> {
    let user = catalog.user().map_err(io::Error::other)?;
    let uname = user.map(|user| user.to_string().into_bytes()).unwrap_or_default();
    let (fid, qid) = client.attach(&uname, anchor.to_string().as_bytes(), rustix::process::getuid().as_raw())?;
    let mut walk = Walk { client, was: std::mem::take(files), now: Files::new(), importer: Importer::default() };
    let root = catalog.batch_breathing(|catalog| walk.node(fid, qid, &mut Vec::new(), catalog).map_err(crate::store::Error::from));
    let _ = client.clunk(fid);
    *files = walk.now;
    let Some(root) = root.map_err(io::Error::other)? else {
        return Ok(Kept::Nothing);
    };
    let root = Link::V1(root.cid);
    if catalog.anchor_value(anchor).map_err(io::Error::other)?.as_ref() == Some(&root) {
        return Ok(Kept::Same);
    }
    Ok(Kept::Set(catalog.set_anchor(anchor, &root).map_err(io::Error::other)?))
}

/// A walk of a server's tree, made blocks as it goes.
struct Walk<'a> {
    client: &'a Client,
    /// What was seen of its files last time, and what is now.
    was: Files,
    now: Files,
    importer: Importer,
}

impl Walk<'_> {
    /// What's at a fid, as blocks, if it's anything to keep. The caller
    /// clunks the fid.
    fn node(&mut self, fid: u32, qid: Qid, path: &mut Vec<Vec<u8>>, sink: &mut Catalog) -> io::Result<Option<DagLink>> {
        if qid.is_tmp() {
            return Ok(None);
        }
        if qid.is_dir() {
            return self.dir(fid, path, sink).map(Some);
        }
        if qid.is_symlink() {
            return dag::symlink_node(&self.client.readlink(fid)?, sink).map(Some);
        }
        self.file(fid, qid, path, sink).map(Some)
    }

    fn dir(&mut self, fid: u32, path: &mut Vec<Vec<u8>>, sink: &mut Catalog) -> io::Result<DagLink> {
        // Listed through a fid of its own, as an open fid walks nowhere
        let (listing, _) = self.client.walk(fid, &[])?;
        let entries = self.client.lopen(listing, 0).and_then(|_| self.client.readdir_all(listing));
        let _ = self.client.clunk(listing);
        let mut dir = self.importer.directory.builder();
        for entry in entries? {
            if entry.name == b"." || entry.name == b".." || entry.qid.is_tmp() {
                continue;
            }
            let (child, qids) = match self.client.walk(fid, &[&entry.name]) {
                Ok(walked) => walked,
                // Gone since it was listed
                Err(e) if e.raw_os_error() == Some(crate::ninep::client::libc_errno::ENOENT) => continue,
                Err(e) => return Err(e),
            };
            path.push(entry.name.clone());
            let link = self.node(child, qids.last().copied().unwrap_or(entry.qid), path, sink);
            path.pop();
            let _ = self.client.clunk(child);
            if let Some(link) = link? {
                dir.add_link(entry.name, link, sink)?;
            }
        }
        sink.breathe().map_err(io::Error::other)?;
        dir.finalize(sink)
    }

    fn file(&mut self, fid: u32, qid: Qid, path: &[Vec<u8>], sink: &mut Catalog) -> io::Result<DagLink> {
        let was = self.was.remove(path);
        // Its version moved on with every change, so where it's the same
        // it's unchanged
        if let Some(was) = was.as_ref().filter(|was| qid.version != 0 && was.qid == qid) {
            let link = was.link.clone();
            self.now.insert(path.to_vec(), was.clone());
            return Ok(link);
        }
        let attr = self.client.getattr(fid)?;
        if let Some(was) = was.filter(|was| was.qid == attr.qid && was.size == attr.size && was.mtime == attr.mtime && attr.mtime != (0, 0)) {
            let link = was.link.clone();
            self.now.insert(path.to_vec(), was);
            return Ok(link);
        }
        self.client.lopen(fid, 0)?;
        let link = self.importer.add_file(Reading { client: self.client, fid, offset: 0 }, sink)?;
        self.now.insert(path.to_vec(), Seen { qid: attr.qid, size: attr.size, mtime: attr.mtime, link: link.clone() });
        Ok(link)
    }
}

/// An open fid, read from the start to its end.
struct Reading<'a> {
    client: &'a Client,
    fid: u32,
    offset: u64,
}

impl Read for Reading<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.client.read(self.fid, self.offset, u32::try_from(buf.len()).unwrap_or(u32::MAX))?;
        let n = data.len().min(buf.len());
        buf.get_mut(..n).unwrap_or_default().copy_from_slice(data.get(..n).unwrap_or_default());
        self.offset = self.offset.saturating_add(dag::len64(data.get(..n).unwrap_or_default()));
        Ok(n)
    }
}

/// Keep what this node serves with persistence on, every `EVERY`, until
/// `stop`: on a thread of its own, with a catalog of its own.
pub fn run(repo: std::path::PathBuf, node: Vec<u8>, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::Ordering;
    std::thread::Builder::new()
        .name("persist".into())
        .spawn(move || {
            let mut persister = Persister::default();
            let mut catalog = None;
            while !stop.load(Ordering::Relaxed) {
                // Only with services to keep, since nothing's on by default
                if crate::served::services(&repo).is_ok_and(|services| !services.is_empty()) {
                    if catalog.is_none() {
                        catalog = Catalog::open_repo(&repo).map_err(|e| eprintln!("not keeping what's served: {e}")).ok();
                    }
                    if let Some(catalog) = catalog.as_mut() {
                        let round = persister.round(&repo, catalog, &node).unwrap_or_else(|e| {
                            eprintln!("not keeping what's served: {e}");
                            Vec::new()
                        });
                        for (anchor, kept) in round {
                            match kept {
                                Ok(Kept::Set(set)) => eprintln!("{anchor} is what its server serves now, by {set}"),
                                Ok(Kept::Same | Kept::Nothing) => {},
                                Err(e) => eprintln!("couldn't keep what's served of {anchor}: {e}"),
                            }
                        }
                    }
                }
                let deadline = std::time::Instant::now().checked_add(EVERY);
                while !stop.load(Ordering::Relaxed) && deadline.is_some_and(|deadline| std::time::Instant::now() < deadline) {
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        })
        .map_err(|e| eprintln!("not keeping what's served: {e}"))
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;

    /// A repo serving an anchor from a filesystem in memory, persisted or
    /// not, as node `me`.
    fn serving(scratch: &Scratch, fs: crate::ninep::memfs::MemFs, persist: bool) -> (Catalog, Link, crate::ninep::memfs::Shared, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let (repo, run) = (scratch.path().join("repo"), scratch.path().join("run"));
        let catalog = Catalog::open_repo(&repo).expect("catalog");
        let anchor = catalog.new_anchor().expect("anchor");
        catalog.serve_anchor(&anchor, b"me", "notes", persist).expect("serve");
        std::fs::create_dir_all(&run).expect("mkdir");
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let socket = run.join("notes.9p");
        let shared = crate::ninep::memfs::Shared::new(fs);
        crate::ninep::memfs::listen(shared.clone(), &socket).expect("listen");
        std::fs::write(repo.join(crate::config::FILE), format!("[[serve]]\nname = \"notes\"\nsocket = {:?}\n", socket.display().to_string())).expect("config");
        std::fs::set_permissions(repo.join(crate::config::FILE), std::fs::Permissions::from_mode(0o644)).expect("chmod");
        (catalog, anchor, shared, repo)
    }

    fn tree(catalog: &Catalog, anchor: &Link, out: &Path) -> Vec<(String, Vec<u8>)> {
        let value = catalog.anchor_value(anchor).expect("value").expect("set");
        crate::export::get(catalog, &value, out).expect("get");
        let mut found = Vec::new();
        let mut dirs = vec![out.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("dir").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    let rel = path.strip_prefix(out).expect("under").display().to_string();
                    found.push((rel, std::fs::read(&path).expect("read")));
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn whats_served_with_persistence_on_is_kept_as_sets_without_whats_tmp() {
        let scratch = Scratch::new("persist");
        let mut fs = crate::ninep::memfs::MemFs::new();
        fs.file("notes/today.md", b"one");
        fs.file("big", &vec![7u8; 3 << 20]);
        fs.tmp("session", b"a handshake");
        fs.tmp("cache/whatever", b"x");
        let (mut catalog, anchor, shared, repo) = serving(&scratch, fs, true);
        let mut persister = Persister::default();

        let round = persister.round(&repo, &mut catalog, b"me").expect("round");
        assert!(matches!(round.as_slice(), [(of, Ok(Kept::Set(_)))] if *of == anchor), "{round:?}");
        let first = scratch.path().join("first");
        assert_eq!(tree(&catalog, &anchor, &first), [("big".to_owned(), vec![7u8; 3 << 20]), ("notes/today.md".to_owned(), b"one".to_vec())], "nothing tmp");

        // Unchanged, it's not set again
        let round = persister.round(&repo, &mut catalog, b"me").expect("round");
        assert!(matches!(round.as_slice(), [(_, Ok(Kept::Same))]), "{round:?}");
        shared.lock().rewrite("notes/today.md", b"two");
        shared.lock().rewrite("big", b"small now");
        let round = persister.round(&repo, &mut catalog, b"me").expect("round");
        assert!(matches!(round.as_slice(), [(_, Ok(Kept::Set(_)))]), "{round:?}");
        assert_eq!(tree(&catalog, &anchor, &scratch.path().join("second")), [("big".to_owned(), b"small now".to_vec()), ("notes/today.md".to_owned(), b"two".to_vec())]);
        assert_eq!(catalog.anchor_history(&anchor).expect("history").len(), 2, "a set for each change");

        // Nor are files read again whose versions say they're the same
        let reads = shared.lock().reads;
        shared.lock().file("notes/new.md", b"new");
        let round = persister.round(&repo, &mut catalog, b"me").expect("round");
        assert!(matches!(round.as_slice(), [(_, Ok(Kept::Set(_)))]), "{round:?}");
        assert_eq!(shared.lock().reads.saturating_sub(reads), 2, "the new file alone, to its end");
    }

    #[test]
    fn only_whats_served_with_persistence_on_by_this_node_is_kept() {
        let scratch = Scratch::new("persist-off");
        let mut fs = crate::ninep::memfs::MemFs::new();
        fs.file("a", b"a");
        let (mut catalog, anchor, _shared, repo) = serving(&scratch, fs, false);
        let mut persister = Persister::default();
        assert!(persister.round(&repo, &mut catalog, b"me").expect("round").is_empty(), "not persisted");
        catalog.serve_anchor(&anchor, b"someone else", "notes", true).expect("serve");
        assert!(persister.round(&repo, &mut catalog, b"me").expect("round").is_empty(), "not this node's");
        catalog.serve_anchor(&anchor, b"me", "gone", true).expect("serve");
        assert!(persister.round(&repo, &mut catalog, b"me").expect("round").is_empty(), "a service it hasn't, or can't reach, is nothing to keep");
        assert_eq!(catalog.anchor_value(&anchor).expect("value"), None);
    }
}
