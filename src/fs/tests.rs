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
