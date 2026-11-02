//! Overlay mounts: what's written to an anchor through `hk mount`.
//!
//! An anchor being written to keeps only what's changed in a work
//! directory of its own, mirroring the anchor's paths, over what the
//! anchor is: a file or directory there is what's at its path, and a
//! directory there merges with the anchor's. The rest is said by *marks*:
//! a path that's gone, so what the anchor had there no longer shows, or a
//! path that's a block already in the soup, as a rename leaves it, so
//! moving something big copies nothing. A mark of either kind hides what
//! the anchor had at the path, and below it.
//!
//! Importing an overlay rebuilds only the directories over what's changed,
//! the rest keeping the links they had, and imports what's in the work
//! directory in place, like any mount; then sets the anchor, if that's
//! anything new. Directories are built the way the importer always builds
//! them, from their entries, so the anchor's what importing the whole tree
//! as it now is would make.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rusqlite::params;

use crate::cid::{BaseCid as _, Cid as _, CidRef as _, Cidv1, RAW_CODEC};
use crate::dag::{DagLink, DirLayoutBuilder as _, DirLayoutStrategy as _};
use crate::export::{self, Fetch};
use crate::model::Link;

use super::{Catalog, Error, InPlace, Mount, Result, path_bytes, path_from};

/// A mark: gone (None), or a block with the size its link says.
pub type Mark = Option<(Link, u64)>;

/// An anchor's marks, by path within it.
pub type Marks = BTreeMap<PathBuf, Mark>;

/// A directory's entries, by name: blocks, with the sizes their links say.
pub type Entries = BTreeMap<Vec<u8>, (Link, Option<u64>)>;

/// What's at a path of what an anchor is, as far as it's from the soup:
/// a block, with the size a link to it says, if that's known.
pub type Base = Option<(Link, Option<u64>)>;

/// What the anchor had at a path, after marks: walking down from the
/// anchor's value, a mark starting over at the block it names or saying
/// there's nothing there.
pub fn resolve(src: &impl Fetch, root: Option<Link>, rel: &Path, marks: &Marks) -> io::Result<Base> {
    let mut here: Base = root.map(|cid| (cid, None));
    let mut path = PathBuf::new();
    if let Some(mark) = marks.get(&path) {
        here = mark.clone().map(|(cid, size)| (cid, Some(size)));
    }
    for name in rel {
        path.push(name);
        here = match marks.get(&path) {
            Some(mark) => mark.clone().map(|(cid, size)| (cid, Some(size))),
            None => match here {
                Some((dir, _)) if is_dir(src, &dir)? => export::list(src, &dir)?
                    .into_iter()
                    .find(|entry| entry.name == name.as_bytes())
                    .map(|entry| (entry.cid, entry.size)),
                _ => None,
            },
        };
    }
    Ok(here)
}

/// Whether a block's a directory, without reading a raw one, which can't
/// be.
fn is_dir(src: &impl Fetch, cid: &Link) -> io::Result<bool> {
    if cid.codec() == RAW_CODEC {
        return Ok(false);
    }
    Ok(export::stat(src, cid)? == export::Kind::Directory)
}

/// The entries of what the anchor had at a directory, after marks, as
/// name to block: its own, less those marked gone, and blocks marked
/// as entries of it.
pub fn base_entries(src: &impl Fetch, root: Option<Link>, rel: &Path, marks: &Marks) -> io::Result<Entries> {
    let mut entries = BTreeMap::new();
    if let Some((dir, _)) = resolve(src, root, rel, marks)?
        && is_dir(src, &dir)?
    {
        for entry in export::list(src, &dir)? {
            entries.insert(entry.name, (entry.cid, entry.size));
        }
    }
    for (path, mark) in marks.range(rel.to_path_buf()..) {
        if !path.starts_with(rel) {
            break;
        }
        if path.parent() != Some(rel) || path == rel {
            continue;
        }
        let Some(name) = path.file_name() else {
            continue;
        };
        match mark {
            Some((cid, size)) => entries.insert(name.as_bytes().to_vec(), (cid.clone(), Some(*size))),
            None => entries.remove(name.as_bytes()),
        };
    }
    Ok(entries)
}

impl Catalog {
    /// An anchor's overlay marks.
    pub fn overlay_marks(&self, anchor: &Link) -> Result<Marks> {
        let mut stmt = self.db.conn().prepare_cached("SELECT path, cid, tsize FROM overlay_marks WHERE anchor = ?1")?;
        let rows = stmt.query_map([anchor.to_bytes()], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, i64>(2)?)))?;
        let mut marks = Marks::new();
        for row in rows {
            let (path, cid, tsize) = row?;
            let mark = match cid {
                Some(cid) => Some((
                    Link::decode(&cid).map_err(|e| Error::Invalid { store: "router", reason: format!("overlay mark: {e:?}") })?,
                    u64::try_from(tsize).unwrap_or_default(),
                )),
                None => None,
            };
            marks.insert(path_from(&path), mark);
        }
        Ok(marks)
    }

    /// Mark a path of an anchor gone, or as a block.
    pub fn set_overlay_mark(&self, anchor: &Link, path: &Path, mark: &Mark) -> Result<()> {
        let (cid, tsize) = match mark {
            Some((cid, tsize)) => (Some(cid.to_bytes()), i64::try_from(*tsize).unwrap_or(i64::MAX)),
            None => (None, 0),
        };
        self.db.conn()
            .prepare_cached("INSERT OR REPLACE INTO overlay_marks (anchor, path, cid, tsize) VALUES (?1, ?2, ?3, ?4)")?
            .execute(params![anchor.to_bytes(), path_bytes(path), cid, tsize])?;
        Ok(())
    }

    /// Forget the marks at a path of an anchor and below it.
    pub fn clear_overlay_marks(&self, anchor: &Link, under: &Path) -> Result<()> {
        for path in self.overlay_marks(anchor)?.into_keys().filter(|path| path.starts_with(under)) {
            self.db.conn()
                .prepare_cached("DELETE FROM overlay_marks WHERE anchor = ?1 AND path = ?2")?
                .execute(params![anchor.to_bytes(), path_bytes(&path)])?;
        }
        Ok(())
    }

    /// Move the marks at a path of an anchor and below it to another,
    /// as a rename does.
    pub fn move_overlay_marks(&self, anchor: &Link, from: &Path, to: &Path) -> Result<()> {
        let moving: Vec<(PathBuf, Mark)> = self.overlay_marks(anchor)?.into_iter().filter(|(path, _)| path.starts_with(from)).collect();
        self.clear_overlay_marks(anchor, from)?;
        for (path, mark) in moving {
            let rest = path.strip_prefix(from).unwrap_or(&path);
            self.set_overlay_mark(anchor, &to.join(rest), &mark)?;
        }
        Ok(())
    }

    /// Import an overlay mount, setting its anchor to what it now is, if
    /// that's anything new, and saying what it is.
    pub fn import_overlay(&mut self, mount: &Mount) -> Result<Link> {
        let marks = self.overlay_marks(&mount.anchor)?;
        let root = self.anchor_value(&mount.anchor)?;
        let importer = mount.importer();
        let built = self.overlay_node(&importer, mount, Path::new(""), root.clone().map(|cid| (cid, None)), &marks)?;
        let value: Link = match built {
            Some(link) => link.cid.into(),
            // Everything's gone: an empty directory
            None => importer.directory.builder().finalize(&mut InPlace::new(self))?.cid.into(),
        };
        if root.as_ref() != Some(&value) {
            self.set_anchor(&mount.anchor, &value)?;
        }
        Ok(value)
    }

    /// What's at a path of an overlay now, built over what the anchor had
    /// there, or nothing.
    fn overlay_node(&mut self, importer: &crate::import::Importer, mount: &Mount, rel: &Path, base: Base, marks: &Marks) -> Result<Option<DagLink>> {
        let base = marks.get(rel).map_or(base, |mark| mark.clone().map(|(cid, size)| (cid, Some(size))));
        let work = mount.path.join(rel);
        let meta = match fs::symlink_metadata(&work) {
            Ok(meta) => Some(meta),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let marked_below = marks.range(rel.to_path_buf()..).take_while(|(path, _)| path.starts_with(rel)).any(|(path, _)| path != rel);
        match meta {
            Some(meta) if !meta.is_dir() => Ok(importer.add_path(&work, &mut InPlace::new(self), &mut |_, _| {})?),
            None if !marked_below => Ok(base.map(|(cid, size)| DagLink { cid: Cidv1::from(cid), tsize: size.unwrap_or_default(), filesize: 0 })),
            _ => {
                // A directory, of what's in the work directory over what
                // the anchor had, less what's gone
                let mut entries: BTreeMap<Vec<u8>, Base> = BTreeMap::new();
                if let Some((dir, _)) = &base
                    && is_dir(&*self, dir)?
                {
                    for entry in export::list(&*self, dir)? {
                        entries.insert(entry.name, Some((entry.cid, entry.size)));
                    }
                }
                for (path, _) in marks.range(rel.to_path_buf()..).take_while(|(path, _)| path.starts_with(rel)) {
                    if path.parent() == Some(rel) && path != rel
                        && let Some(name) = path.file_name()
                    {
                        entries.entry(name.as_bytes().to_vec()).or_insert(None);
                    }
                }
                if meta.is_some() {
                    for entry in fs::read_dir(&work)? {
                        entries.entry(entry?.file_name().as_bytes().to_vec()).or_insert(None);
                    }
                }
                let mut dir = importer.directory.builder();
                for (name, base) in entries {
                    if !importer.hidden && name.starts_with(b".") {
                        continue;
                    }
                    let child = rel.join(std::ffi::OsStr::from_bytes(&name));
                    if let Some(link) = self.overlay_node(importer, mount, &child, base, marks)? {
                        dir.add_link(name, link, &mut InPlace::new(self))?;
                    }
                }
                Ok(Some(dir.finalize(&mut InPlace::new(self))?))
            },
        }
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn an_overlay_is_what_importing_the_tree_as_it_now_is_makes() {
        let scratch = Scratch::new("overlay");
        let mut catalog = Catalog::open_repo(&scratch.path().join("repo")).expect("catalog");
        // What the anchor was
        let before = scratch.path().join("before");
        for (path, data) in [("keep", "kept"), ("change", "old"), ("gone", "bye"), ("dir/a", "a"), ("dir/sub/b", "b"), ("big/x", "x"), ("big/y", "y")] {
            write(&before.join(path), data);
        }
        let root = add(&mut catalog, &before);
        let anchor = catalog.new_anchor().expect("anchor");
        catalog.set_anchor(&anchor, &root).expect("set");
        let mount = Mount { anchor: anchor.clone(), path: scratch.path().join("work"), chunk_size: crate::import::CHUNK_SIZE, width: crate::dag::FILE_WIDTH, hidden: true, overlay: true };
        catalog.mount(&mount).expect("mount");
        // Nothing changed is what it was
        assert_eq!(catalog.import_overlay(&mount).expect("import"), root);

        // Changed: a file rewritten, one added deep in a new directory, one
        // gone, a directory moved, and a directory replaced by a file
        write(&mount.path.join("change"), "new");
        write(&mount.path.join("dir/new/c"), "c");
        catalog.set_overlay_mark(&anchor, Path::new("gone"), &None).expect("mark");
        let marks = catalog.overlay_marks(&anchor).expect("marks");
        let big = resolve(&catalog, Some(root.clone()), Path::new("big"), &marks).expect("resolve").expect("big");
        catalog.set_overlay_mark(&anchor, Path::new("moved"), &Some((big.0, big.1.expect("size")))).expect("mark");
        catalog.set_overlay_mark(&anchor, Path::new("big"), &None).expect("mark");
        write(&mount.path.join("dir/sub"), "a file now");
        catalog.set_overlay_mark(&anchor, Path::new("dir/sub"), &None).expect("mark");
        let value = catalog.import_overlay(&mount).expect("import");

        let after = scratch.path().join("after");
        for (path, data) in [("keep", "kept"), ("change", "new"), ("dir/a", "a"), ("dir/new/c", "c"), ("dir/sub", "a file now"), ("moved/x", "x"), ("moved/y", "y")] {
            write(&after.join(path), data);
        }
        assert_eq!(value, add(&mut catalog, &after));
        assert_eq!(catalog.anchor_value(&anchor).expect("value"), Some(value.clone()));
        assert_eq!(catalog.remount(&mount).expect("remount"), value, "again, the same");

        // What the mount would show, from the soup alone
        let marks = catalog.overlay_marks(&anchor).expect("marks");
        let names = |rel: &str| base_entries(&catalog, Some(root.clone()), Path::new(rel), &marks).expect("entries").into_keys().map(|name| String::from_utf8(name).expect("utf-8")).collect::<Vec<_>>();
        assert_eq!(names(""), ["change", "dir", "keep", "moved"]);
        assert_eq!(names("moved"), ["x", "y"]);

        // Marks move with what's renamed
        catalog.move_overlay_marks(&anchor, Path::new("moved"), Path::new("again")).expect("move");
        let marks = catalog.overlay_marks(&anchor).expect("marks");
        assert!(marks.contains_key(Path::new("again")) && !marks.contains_key(Path::new("moved")));
        catalog.clear_overlay_marks(&anchor, Path::new("")).expect("clear");
        assert!(catalog.overlay_marks(&anchor).expect("marks").is_empty());
    }
}
