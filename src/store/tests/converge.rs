//! Replicas of one anchor, each editing what it's seen and syncing with the
//! others in any order: whatever happens, what they settle on keeps every
//! write nothing came after, shows the last of what came one after another,
//! and is the same in any repo, whatever order the sets arrive in.
//!
//! Each write is a write, even of what was there before, as when a change
//! is undone: but writing what's there already, changing nothing, isn't.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;

use super::raw;
use crate::block::Block;
use crate::cid::{CidRef, CidVersion};
use crate::claim::Claim;
use crate::dag::{BlockSink, DagLink, DirLayoutBuilder as _, DirLayoutStrategy as _};
use crate::model::Link;
use crate::store::Catalog;
use crate::testutil::Scratch;

const REPLICAS: usize = 3;
const FILES: [&str; 3] = ["a.txt", "b", "c.md"];

#[derive(Clone, Debug)]
enum Op {
    /// A replica writes a file.
    Write { at: usize, file: usize, content: u8 },
    /// A replica removes a file.
    Remove { at: usize, file: usize },
    /// One replica learns every set another has.
    Sync { from: usize, to: usize },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..REPLICAS, 0..FILES.len(), 0..3u8).prop_map(|(at, file, content)| Op::Write { at, file, content }),
        1 => (0..REPLICAS, 0..FILES.len()).prop_map(|(at, file)| Op::Remove { at, file }),
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

/// What a replica sees: the heads of the sets it knows of, merged, as the
/// catalog would merge them were those all the sets it had.
fn seen(repo: &Catalog, anchor: &Link, known: &BTreeSet<Vec<u8>>) -> Option<(Link, Vec<Link>)> {
    let sets = repo.sets_of(anchor).expect("sets");
    let named: BTreeSet<Vec<u8>> = sets.iter()
        .filter(|(set, ..)| known.contains(&set.to_bytes()))
        .flat_map(|(.., prev)| prev.iter().flatten().map(CidRef::to_bytes))
        .collect();
    let heads: Vec<(Link, Link, u64)> = sets.into_iter()
        .filter(|(set, ..)| known.contains(&set.to_bytes()) && !named.contains(&set.to_bytes()))
        .map(|(set, value, at, _)| (set, value, at))
        .collect();
    let value = match heads.as_slice() {
        [] => return None,
        [(_, value, _)] => value.clone(),
        _ => repo.merge_heads(anchor, &heads).expect("merge"),
    };
    Some((value, heads.into_iter().map(|(set, ..)| set).collect()))
}

fn is_copy_of(name: &str, file: &str) -> bool {
    let dot = file.rfind('.').filter(|&at| at > 0).unwrap_or(file.len());
    let (stem, ext) = file.split_at(dot);
    name.strip_prefix(stem).and_then(|rest| rest.strip_prefix(" (conflict ")).is_some_and(|rest| rest.ends_with(&format!("){ext}")))
}

fn run(ops: &[Op], skew: &[u64; REPLICAS], order: &[u64]) -> Result<(), TestCaseError> {
    let scratch = Scratch::new("converge");
    let repo = Catalog::open_repo(&scratch.path().join("repo")).expect("repo");
    let anchor = repo.new_anchor().expect("anchor");
    // Every replica starts from the same set, of nothing: what came of
    // pasts that share nothing, as when a repo joins, is another matter
    let empty = dir(&repo, &BTreeMap::new());
    let start = crate::claim::Set::new([anchor.clone()], empty, 0).expect("set").after(Some(Vec::new()));
    let start = repo.put_claim(&Claim::Set(start)).expect("put").to_bytes();
    let mut known: Vec<BTreeSet<Vec<u8>>> = vec![BTreeSet::from([start.clone()]); REPLICAS];
    // Files a replica's seen in conflict
    let mut conflicted: BTreeSet<usize> = BTreeSet::new();
    let mut changes: Vec<Change> = Vec::new();
    let mut ats: BTreeMap<Vec<u8>, u64> = BTreeMap::from([(start, 0)]);

    for (step, op) in ops.iter().enumerate() {
        let (at, file, wrote) = match *op {
            Op::Sync { from, to } => {
                let theirs = known[from].clone();
                known[to].extend(theirs);
                continue;
            },
            Op::Write { at, file, content } => (at, file, Some(content)),
            Op::Remove { at, file } => (at, file, None),
        };
        let view = seen(&repo, &anchor, &known[at]);
        let mut now = view.as_ref().map(|(value, _)| files(&repo, value)).unwrap_or_default();
        conflicted.extend(FILES.iter().enumerate().filter(|(_, file)| now.keys().any(|name| is_copy_of(name, file))).map(|(n, _)| n));
        // Writing what's there already changes nothing, so merges nothing
        let changes_it = now.get(FILES[file]) != wrote.map(content).as_ref();
        match wrote {
            Some(n) => now.insert(FILES[file].to_owned(), content(n)),
            None => now.remove(FILES[file]),
        };
        let value = dir(&repo, &now);
        // Its clock, skewed, but after whatever it's seen, as `put_set` does
        let latest = known[at].iter().filter_map(|set| ats.get(set)).max().map_or(0, |at| at.saturating_add(1));
        let when = u64::try_from(step).expect("step").saturating_mul(10).saturating_add(skew[at]).max(latest);
        let prev = view.map(|(_, heads)| heads).unwrap_or_default();
        let set = crate::claim::Set::new([anchor.clone()], value, when).expect("set").after(Some(prev));
        let set = repo.put_claim(&Claim::Set(set)).expect("put").to_bytes();
        ats.insert(set.clone(), when);
        if changes_it {
            changes.push(Change { file, wrote, set: set.clone(), seen: known[at].clone() });
        }
        known[at].insert(set);
    }

    let everything: BTreeSet<Vec<u8>> = known.iter().flatten().cloned().collect();
    let Some((settled, _)) = seen(&repo, &anchor, &everything) else {
        return Ok(());
    };
    prop_assert_eq!(repo.anchor_value(&anchor).expect("value"), Some(settled.clone()), "the catalog settles where its replicas do");
    let after = files(&repo, &settled);

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
        // What came after everything else done to it is what it is, unless
        // it's been in conflict: what's merged over may then be one way of
        // putting a conflict, and a removal, over it, may not stand
        if let [only] = last.as_slice()
            && !conflicted.contains(&file)
            && !after.keys().any(|at| is_copy_of(at, name))
        {
            prop_assert_eq!(after.get(*name).cloned(), only.wrote.map(content), "{} isn't its last change: {:?}", name, after);
        }
    }

    // Another repo, the same sets arriving in another order, settles the same
    let other = Catalog::open_repo(&scratch.path().join("other")).expect("other");
    let sets = repo.sets_of(&anchor).expect("sets");
    let mut key = order.iter().cycle();
    let mut keyed: Vec<(u64, crate::store::SetOf)> = sets.into_iter().map(|set| (*key.next().unwrap_or(&0), set)).collect();
    keyed.sort_by_key(|(key, _)| *key);
    for (_, (_, value, at, prev)) in keyed {
        dir(&other, &files(&repo, &value));
        let set = crate::claim::Set::new([anchor.clone()], value, at).expect("set").after(prev);
        other.put_claim(&Claim::Set(set)).expect("put");
    }
    prop_assert_eq!(other.anchor_value(&anchor).expect("value"), Some(settled), "the same, whatever order it heard in");
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
