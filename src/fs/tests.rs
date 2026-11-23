use std::fs;

use super::*;
use crate::cid::AnyCid;
use crate::import::Importer;
use crate::testutil::Scratch;

fn importer() -> Importer {
    Importer { hidden: true, ..Importer::default() }
}

fn add(catalog: &mut Catalog, path: &Path) -> Link {
    AnyCid::V1(importer().add_path(path, catalog, &mut |_, _| {}).expect("import").expect("root").cid)
}

fn write(path: &Path, data: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, data).expect("write");
}

/// A repo whose root names `vault`, a mount point of an anchor of its own,
/// as a directory made at the mount's top is: returning it, the vault's
/// anchor, and where the vault's files are.
fn soup(scratch: &Scratch) -> (Catalog, Link, PathBuf) {
    let mut catalog = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
    let files = scratch.path().join("vault");
    for (path, data) in [("notes/a.md", "a"), ("notes/b.md", "b"), (".obsidian/app.json", "{}"), ("School/x/y.txt", "y"), ("School/z.txt", "z")] {
        write(&files.join(path), data);
    }
    let value = add(&mut catalog, &files);
    let vault = catalog.new_anchor().expect("anchor");
    catalog.set_anchor(&vault, &value).expect("set");
    let top = scratch.path().join("top");
    fs::create_dir_all(&top).expect("mkdir");
    std::os::unix::fs::symlink(format!("/anchors/{vault}"), top.join("vault")).expect("symlink");
    let root_value = add(&mut catalog, &top);
    let root = catalog.root_anchor().expect("root").expect("a root");
    catalog.set_anchor(&root, &root_value).expect("set");
    (catalog, vault, files)
}

#[test]
fn a_path_is_found_through_mount_points_in_the_anchor_naming_it() {
    let scratch = Scratch::new("fs-locate");
    let (catalog, vault, files) = soup(&scratch);
    let located = locate(&catalog, Path::new("/vault/notes/a.md")).expect("locate");
    assert_eq!((&located.anchor, located.rel.as_path()), (&vault, Path::new("notes/a.md")));
    assert_eq!(located.at, Some(add(&mut Catalog::open_repo(&scratch.path().join("other")).expect("catalog"), &files.join("notes/a.md"))));
    // The same by the anchor's own path, and the mount point itself in the root
    assert_eq!(locate(&catalog, &Path::new("anchors").join(vault.to_string()).join("notes/a.md")).expect("locate"), located);
    let point = locate(&catalog, Path::new("vault")).expect("locate");
    assert_eq!(point.anchor, catalog.root_anchor().expect("root").expect("a root"));
    assert_eq!(mount_point(&catalog, point.at.as_ref().expect("there")).expect("stat"), Some(vault));

    assert!(locate(&catalog, Path::new("/vault/nothing")).is_err());
    assert!(locate(&catalog, Path::new("/vault/notes/../School")).is_err());
    assert!(locate(&catalog, Path::new("/cid/bafkqaaa")).is_err());
}

#[test]
fn a_path_under_cid_or_tags_is_found_too_in_no_anchor_until_a_mount_point() {
    let scratch = Scratch::new("fs-find");
    let (catalog, vault, _) = soup(&scratch);
    let root = catalog.anchor_value(&catalog.root_anchor().expect("root").expect("a root")).expect("value").expect("set");
    let value = catalog.anchor_value(&vault).expect("value").expect("set");
    let school = locate(&catalog, Path::new("/vault/School")).expect("locate").at;

    // What's under a CID is of no anchor, but changes nothing to stat
    let found = find(&catalog, &Path::new("cid").join(value.to_string()).join("School")).expect("find");
    assert_eq!((found.anchor, found.at), (None, school.clone()));
    let found = find(&catalog, &Path::new("cid").join(value.to_string())).expect("find");
    assert_eq!((found.anchor, found.at), (None, Some(value.clone())));
    assert!(locate(&catalog, &Path::new("cid").join(value.to_string()).join("School")).is_err(), "nothing to change");
    // Through a mount point it's in that anchor
    let found = find(&catalog, &Path::new("cid").join(root.to_string()).join("vault/School")).expect("find");
    assert_eq!((found.anchor, found.rel.as_path(), found.at), (Some(vault), Path::new("School"), school.clone()));

    // A tagged CID by the tag's name, or the tag's CID
    let tag = crate::claim::tag("term").expect("tag");
    assert!(find(&catalog, &Path::new("tags/term").join(value.to_string())).is_err(), "not tagged yet");
    catalog.tag(&value, &tag).expect("tag");
    for named in ["term".to_owned(), tag.to_string()] {
        let found = find(&catalog, &Path::new("tags").join(named).join(value.to_string()).join("School")).expect("find");
        assert_eq!((found.anchor, found.at), (None, school.clone()));
    }
    assert!(find(&catalog, &Path::new("tags/term").join(root.to_string())).is_err(), "not tagged");
    for nothing in ["cid", "cid/nonsense", "tags", "tags/term"] {
        assert!(find(&catalog, Path::new(nothing)).is_err(), "{nothing}");
    }
}

#[test]
fn a_directory_is_unlinked_in_one_set_and_every_other_name_kept() {
    let scratch = Scratch::new("fs-remove");
    let (mut catalog, vault, files) = soup(&scratch);
    let heads = catalog.anchor_heads(&vault).expect("heads").len();
    let school = locate(&catalog, Path::new("/vault/School")).expect("locate");
    let b = locate(&catalog, Path::new("/vault/notes/b.md")).expect("locate");
    let done = remove(&mut catalog, &[school, b]).expect("remove");
    assert_eq!(done.len(), 1, "one set, of the one anchor");
    assert_eq!(catalog.anchor_heads(&vault).expect("heads").len(), heads);
    // As if the tree were imported without them, dotfiles and all
    fs::remove_dir_all(files.join("School")).expect("rm");
    fs::remove_file(files.join("notes/b.md")).expect("rm");
    assert_eq!(catalog.anchor_value(&vault).expect("value"), Some(add(&mut catalog, &files)));
    assert!(locate(&catalog, Path::new("/vault/School")).is_err());
    assert!(locate(&catalog, Path::new("/vault/.obsidian/app.json")).is_ok());

    // Unlinking the mount point leaves the anchor as it was
    let value = catalog.anchor_value(&vault).expect("value");
    let point = locate(&catalog, Path::new("vault")).expect("locate");
    remove(&mut catalog, &[point]).expect("remove");
    assert!(locate(&catalog, Path::new("vault")).is_err());
    assert_eq!(catalog.anchor_value(&vault).expect("value"), value);
    let anchor_itself = locate(&catalog, &Path::new("anchors").join(vault.to_string())).expect("locate");
    assert!(remove(&mut catalog, &[anchor_itself]).is_err(), "what an anchor is isn't unlinked");
}

#[test]
fn a_directory_promoted_is_an_anchor_mounted_where_it_was() {
    let scratch = Scratch::new("fs-promote");
    let (mut catalog, vault, _) = soup(&scratch);
    let notes = locate(&catalog, Path::new("/vault/notes")).expect("locate");
    let anchor = promote(&mut catalog, &notes).expect("promote");
    assert_eq!(catalog.anchor_value(&anchor).expect("value"), notes.at);
    let point = locate(&catalog, Path::new("/vault/notes")).expect("locate");
    assert_eq!(point.anchor, vault);
    assert_eq!(mount_point(&catalog, point.at.as_ref().expect("there")).expect("stat"), Some(anchor.clone()));
    // What's under it is found in it now
    let a = locate(&catalog, Path::new("/vault/notes/a.md")).expect("locate");
    assert_eq!((&a.anchor, a.rel.as_path()), (&anchor, Path::new("a.md")));
    assert!(promote(&mut catalog, &point).is_err(), "a mount point already");
}

#[test]
fn mountinfo_paths_are_unescaped() {
    assert_eq!(unescape(r"/home/me/my\040soup"), PathBuf::from("/home/me/my soup"));
    assert_eq!(unescape(r"/plain"), PathBuf::from("/plain"));
    assert_eq!(unescape(r"/odd\0"), PathBuf::from(r"/odd\0"));
}

/// Write a file into an anchor's value at a path, in a set after these
/// of its sets (every head, if none are said): returning the set and
/// what the file is.
fn put(catalog: &mut Catalog, scratch: &Scratch, anchor: &Link, rel: &str, data: &str, after: Option<Vec<Link>>) -> (Link, Link) {
    let file = scratch.path().join("put");
    write(&file, data);
    let cid = add(catalog, &file);
    let base = after.as_ref().map_or_else(
        || catalog.anchor_value(anchor).expect("value"),
        |after| after.first().map(|set| catalog.sets_of(anchor).expect("sets").into_iter().find(|(s, ..)| s == set).expect("set").1),
    );
    let value = catalog.edit_value(base, &Marks::from([(PathBuf::from(rel), Some((cid.clone(), u64::try_from(data.len()).expect("len"))))])).expect("edit");
    let set = after.map_or_else(|| catalog.set_anchor(anchor, &value), |after| catalog.set_anchor_after(anchor, &value, after));
    (set.expect("set"), cid)
}

fn changes(versions: &[Version]) -> Vec<(Change, Option<Link>)> {
    versions.iter().map(|version| (version.change, if let Was::There(cid, _) = &version.was { Some(cid.clone()) } else { None })).collect()
}

#[test]
fn a_paths_log_is_the_sets_that_changed_it_whatever_else_they_changed() {
    let scratch = Scratch::new("fs-log");
    let (mut catalog, vault, _) = soup(&scratch);
    let first = locate(&catalog, Path::new("/vault/notes/a.md")).expect("locate").at;
    let (_, second) = put(&mut catalog, &scratch, &vault, "notes/a.md", "a2", None);
    put(&mut catalog, &scratch, &vault, "notes/b.md", "b2", None);
    let a = locate(&catalog, Path::new("/vault/notes/a.md")).expect("locate");
    remove(&mut catalog, &[a]).expect("remove");
    // Gone, it's still logged, by its directory
    assert_eq!(logged(&catalog, Path::new("/vault/notes/a.md")).expect("logged"), (vault.clone(), PathBuf::from("notes/a.md")));
    let (_, third) = put(&mut catalog, &scratch, &vault, "notes/a.md", "a3", None);

    let (anchor, rel) = logged(&catalog, Path::new("/vault/notes/a.md")).expect("logged");
    let versions = log(&catalog, &anchor, &rel).expect("log");
    assert_eq!(changes(&versions), [(Change::Added, first), (Change::Changed, Some(second)), (Change::Removed, None), (Change::Added, Some(third))]);
    assert!(versions.windows(2).all(|pair| pair.first().map(|v| v.at) < pair.get(1).map(|v| v.at)), "oldest first");
    assert_eq!(versions.iter().map(|version| version.head).collect::<Vec<_>>(), [false, false, false, true]);

    // A mount point's is its anchor's, every set that changed it at all
    let (anchor, rel) = logged(&catalog, Path::new("/vault")).expect("logged");
    assert_eq!((&anchor, rel.as_os_str().is_empty()), (&vault, true));
    assert_eq!(log(&catalog, &anchor, &rel).expect("log").len(), 5);
    assert!(log(&catalog, &vault, Path::new("notes/never.md")).expect("log").is_empty());
}

#[test]
fn a_fork_logs_each_side_that_changed_it_and_not_the_merge_taking_one() {
    let scratch = Scratch::new("fs-log-fork");
    let (mut catalog, vault, _) = soup(&scratch);
    let base: Vec<Link> = catalog.anchor_heads(&vault).expect("heads").into_iter().map(|(set, ..)| set).collect();
    let (ours, a) = put(&mut catalog, &scratch, &vault, "notes/a.md", "ours", Some(base.clone()));
    let (theirs, _) = put(&mut catalog, &scratch, &vault, "notes/b.md", "theirs", Some(base));
    assert_eq!(catalog.anchor_heads(&vault).expect("heads").len(), 2, "forked");
    let versions = log(&catalog, &vault, Path::new("notes/a.md")).expect("log");
    assert_eq!(versions.iter().map(|version| (&version.set, version.head)).collect::<Vec<_>>(), [(&versions.first().expect("first").set, false), (&ours, true)]);
    assert!(versions.iter().all(|version| version.set != theirs), "their side left it be");

    // Setting what the merge is, a.md as ours had it, changes nothing of it
    let merged = catalog.anchor_value(&vault).expect("value");
    let merge = catalog.set_anchor(&vault, merged.as_ref().expect("merged")).expect("set");
    let versions = log(&catalog, &vault, Path::new("notes/a.md")).expect("log");
    assert_eq!(changes(&versions).last(), Some(&(Change::Changed, Some(a))));
    assert!(versions.iter().all(|version| version.set != merge && !version.head));
}
