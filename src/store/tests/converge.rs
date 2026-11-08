//! Replicas of one anchor, each editing what it's seen and syncing with the
//! others in any order: whatever happens, what they settle on keeps every
//! write nothing came after, shows the last of what came one after another,
//! and is the same in any repo, whatever order the sets arrive in.
//!
//! Replicas see and edit an anchor as the mount shows it, with each version
//! of a name in conflict beside it. Each write is a write, even of what was
//! there before, as when a change is undone; deleting the versions shown
//! beside a name keeps the latest, a write of it; but changing nothing, as
//! the mount sees it, says nothing.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;

use super::raw;
use crate::block::Block;
use crate::cid::{CidRef, CidVersion};
use crate::claim::Claim;
use crate::dag::{BlockSink, DagLink, DirLayoutBuilder as _, DirLayoutStrategy as _};
use crate::model::Link;
use crate::store::Catalog;
use crate::store::merge::View;
use crate::testutil::Scratch;

const REPLICAS: usize = 3;
const FILES: [&str; 3] = ["a.txt", "b", "c.md"];

#[derive(Clone, Debug)]
enum Op {
    /// A replica writes a file.
    Write { at: usize, file: usize, content: u8 },
    /// A replica removes a file.
    Remove { at: usize, file: usize },
    /// A replica deletes every version shown beside a file, keeping the
    /// latest.
    Resolve { at: usize, file: usize },
    /// One replica learns every set another has.
    Sync { from: usize, to: usize },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..REPLICAS, 0..FILES.len(), 0..3u8).prop_map(|(at, file, content)| Op::Write { at, file, content }),
        1 => (0..REPLICAS, 0..FILES.len()).prop_map(|(at, file)| Op::Remove { at, file }),
        1 => (0..REPLICAS, 0..FILES.len()).prop_map(|(at, file)| Op::Resolve { at, file }),
        3 => (0..REPLICAS, 0..REPLICAS).prop_map(|(from, to)| Op::Sync { from, to }),
    ]
}

/// A change a replica made: to which file, what it wrote (none, a removal),
/// in which set, and the sets it had seen when it did.
struct Change {
    file: usize,
    wrote: Option<u8>,
    set: Vec<u8>,
    seen: BTreeSet<Vec<u8>>,
}

struct Sink<'a>(&'a Catalog);

impl BlockSink for Sink<'_> {
    fn put(&mut self, block: Block) -> std::io::Result<()> {
        self.0.put_block(&block, CidVersion::V1).map(drop).map_err(std::io::Error::other)
    }
}

fn content(n: u8) -> Vec<u8> {
    format!("version {n}").into_bytes()
}

/// A flat directory's files, by name, as what they hold.
fn files(repo: &Catalog, dir: &Link) -> BTreeMap<String, Vec<u8>> {
    crate::export::list(repo, dir).expect("list").into_iter()
        .map(|entry| {
            let block = repo.get_block(&entry.cid).expect("get").expect("here");
            (String::from_utf8(entry.name).expect("name"), block.data().to_vec())
        })
        .collect()
}

/// A flat directory of these files.
fn dir(repo: &Catalog, files: &BTreeMap<String, Vec<u8>>) -> Link {
    let mut builder = crate::import::Importer::default().directory.builder();
    let mut sink = Sink(repo);
    for (name, data) in files {
        let block = raw(data);
        repo.put_block(&block, CidVersion::V1).expect("put");
        let link = DagLink { cid: block.cid().clone(), tsize: u64::try_from(data.len()).expect("size"), filesize: 0 };
        builder.add_link(name.as_bytes().to_vec(), link, &mut sink).expect("add");
    }
    crate::cid::AnyCid::V1(builder.finalize(&mut sink).expect("finalize").cid)
}

/// What a replica sees: the view of the heads of the sets it knows of, as
/// the mount shows it, and those heads.
fn seen(repo: &Catalog, anchor: &Link, known: &BTreeSet<Vec<u8>>) -> Option<(View, Vec<Link>)> {
    let sets = repo.sets_of(anchor).expect("sets");
    let named: BTreeSet<Vec<u8>> = sets.iter()
        .filter(|(set, ..)| known.contains(&set.to_bytes()))
        .flat_map(|(.., prev)| prev.iter().flatten().map(CidRef::to_bytes))
        .collect();
    let heads: Vec<Link> = sets.into_iter()
        .filter(|(set, ..)| known.contains(&set.to_bytes()) && !named.contains(&set.to_bytes()))
        .map(|(set, ..)| set)
        .collect();
    if heads.is_empty() {
        return None;
    }
    Some((repo.view_of(anchor, &heads).expect("view"), heads))
}

fn is_copy_of(name: &str, file: &str) -> bool {
    let dot = file.rfind('.').filter(|&at| at > 0).unwrap_or(file.len());
    let (stem, ext) = file.split_at(dot);
    name.strip_prefix(stem).and_then(|rest| rest.strip_prefix(" (conflict ")).is_some_and(|rest| rest.ends_with(&format!("){ext}")))
}

/// Which version a file holds, by what it says.
fn version(data: &[u8]) -> Option<u8> {
    std::str::from_utf8(data).ok()?.strip_prefix("version ")?.parse().ok()
}

fn run(ops: &[Op], skew: &[u64; REPLICAS], order: &[u64]) -> Result<(), TestCaseError> {
    let scratch = Scratch::new("converge");
    let repo = Catalog::open_repo(&scratch.path().join("repo")).expect("repo");
    let anchor = repo.new_anchor().expect("anchor");
    // Every replica starts from the same set, of nothing: what came of
    // pasts that share nothing, as when a repo joins, is another matter
    let empty = dir(&repo, &BTreeMap::new());
    let start = Claim::Set(crate::claim::Set::new([anchor.clone()], empty, 0).expect("set").after(Some(Vec::new())));
    let mut made: Vec<Claim> = vec![start.clone()];
    let start = repo.put_claim(&start).expect("put").to_bytes();
    let mut known: Vec<BTreeSet<Vec<u8>>> = vec![BTreeSet::from([start.clone()]); REPLICAS];
    let mut changes: Vec<Change> = Vec::new();
    let mut ats: BTreeMap<Vec<u8>, u64> = BTreeMap::from([(start, 0)]);

    for (step, op) in ops.iter().enumerate() {
        let (at, file) = match *op {
            Op::Sync { from, to } => {
                let theirs = known[from].clone();
                known[to].extend(theirs);
                continue;
            },
            Op::Write { at, file, .. } | Op::Remove { at, file } | Op::Resolve { at, file } => (at, file),
        };
        let (view, heads) = seen(&repo, &anchor, &known[at]).expect("seen");
        let mut now = files(&repo, &view.value);
        let name = FILES[file];
        let wrote = match *op {
            Op::Write { content: n, .. } => {
                now.insert(name.to_owned(), content(n));
                Some(n)
            },
            Op::Remove { .. } => {
                now.remove(name);
                None
            },
            // Every version shown beside it deleted: the latest kept
            _ => {
                let shown: Vec<String> = view.shown.iter()
                    .filter(|(_, path)| path.first().map(Vec::as_slice) == Some(name.as_bytes()))
                    .filter_map(|(place, _)| place.last().map(|place| String::from_utf8_lossy(place).into_owned()))
                    .collect();
                for place in &shown {
                    now.remove(place);
                }
                now.get(name).and_then(|data| version(data))
            },
        };
        let built = dir(&repo, &now);
        // Nothing changed, as the mount sees it: nothing's said
        if built == view.value {
            continue;
        }
        let (value, wrote_paths) = repo.unshow(&view, &built).expect("unshow");
        // Its clock, skewed, but after whatever it's seen, as `put_set` does
        let latest = known[at].iter().filter_map(|set| ats.get(set)).max().map_or(0, |at| at.saturating_add(1));
        let when = u64::try_from(step).expect("step").saturating_mul(10).saturating_add(skew[at]).max(latest);
        let set = crate::claim::Set::new([anchor.clone()], value, when).expect("set").after(Some(heads)).wrote(wrote_paths.iter().map(|path| path.join(&b'/')));
        let claim = Claim::Set(set);
        let set = repo.put_claim(&claim).expect("put").to_bytes();
        made.push(claim);
        ats.insert(set.clone(), when);
        changes.push(Change { file, wrote, set: set.clone(), seen: known[at].clone() });
        known[at].insert(set);
    }

    let everything: BTreeSet<Vec<u8>> = known.iter().flatten().cloned().collect();
    let (settled, _) = seen(&repo, &anchor, &everything).expect("seen");
    prop_assert_eq!(repo.anchor_view(&anchor).expect("view").map(|view| view.value), Some(settled.value.clone()), "the catalog settles where its replicas do");
    let after = files(&repo, &settled.value);

    for (file, name) in FILES.iter().enumerate() {
        let on: Vec<&Change> = changes.iter().filter(|change| change.file == file).collect();
        let last: Vec<&&Change> = on.iter().filter(|change| !on.iter().any(|later| later.seen.contains(&change.set))).collect();
        // A write nothing came after is kept, by its name or beside it
        for change in &last {
            if let Some(n) = change.wrote {
                let kept = after.iter().any(|(at, data)| (at == name || is_copy_of(at, name)) && *data == content(n));
                prop_assert!(kept, "{name} lost {n}: {after:?}");
            }
        }
        // What came after everything else done to it is what it is
        if let [only] = last.as_slice() {
            prop_assert_eq!(after.get(*name).cloned(), only.wrote.map(content), "{} isn't its last change: {:?}", name, after);
        }
    }

    // Another repo, the same sets arriving in another order, settles the same
    let other = Catalog::open_repo(&scratch.path().join("other")).expect("other");
    let mut key = order.iter().cycle();
    let mut keyed: Vec<(u64, Claim)> = made.into_iter().map(|claim| (*key.next().unwrap_or(&0), claim)).collect();
    keyed.sort_by_key(|(key, _)| *key);
    for (_, claim) in keyed {
        if let Claim::Set(set) = &claim {
            dir(&other, &files(&repo, set.value()));
        }
        other.put_claim(&claim).expect("put");
    }
    prop_assert_eq!(other.anchor_view(&anchor).expect("view").map(|view| view.value), Some(settled.value), "the same, whatever order it heard in");
    Ok(())
}

proptest! {
    // More with CONVERGE_CASES, to look harder
    #![proptest_config(ProptestConfig { cases: std::env::var("CONVERGE_CASES").ok().and_then(|cases| cases.parse().ok()).unwrap_or(64), ..ProptestConfig::default() })]

    #[test]
    fn replicas_settle_on_every_write(
        ops in proptest::collection::vec(op(), 1..40),
        skew in proptest::array::uniform3(0..30u64),
        order in proptest::collection::vec(any::<u64>(), 1..16),
    ) {
        run(&ops, &skew, &order)?;
    }
}

/// A single write's kept, plainly.
#[test]
fn one_write() {
    run(&[Op::Write { at: 0, file: 0, content: 1 }], &[0; REPLICAS], &[0]).expect("kept");
}

