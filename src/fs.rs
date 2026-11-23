//! Paths of the soup as `hk mount` shows them, from outside the mount:
//! what's at one, and changing what an anchor names there (`hk fs`).
//!
//! A path is one under a running mount, wherever it's mounted, or else
//! one of the soup itself: a name the root anchor has, or
//! `anchors/<anchor>/…`. It's followed through mount points, so what's
//! at it is found in the anchor whose directory names it, as the mount
//! would write it there.
//!
//! A change is one set of that anchor, its directories built again only
//! along the paths changed, as an overlay's are (see
//! `Catalog::edit_value`): removing a directory reads nothing under it,
//! however big. What it held is collected only once nothing keeps or
//! references it, as for anything let go of. The mount follows the set as
//! it follows any made elsewhere, merging it with what it's yet to commit.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use crate::cid::{BaseCid as _, CidRef as _};
use crate::export::{self, Kind};
use crate::model::Link;
use crate::store::overlay::Marks;
use crate::store::{BlockIndex as _, Catalog, Error, Result};

fn user(what: impl Into<String>) -> Error {
    Error::User(what.into())
}

/// Where holokeep is mounted, from the kernel's list of this process's
/// mounts: FUSE mounts whose source is `holokeep`.
pub fn mount_points() -> Vec<PathBuf> {
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    info.lines()
        .filter_map(|line| {
            let (mine, theirs) = line.split_once(" - ")?;
            let mut theirs = theirs.split(' ');
            let (kind, source) = (theirs.next()?, theirs.next()?);
            (kind.starts_with("fuse") && source == "holokeep").then(|| unescape(mine.split(' ').nth(4).unwrap_or_default()))
        })
        .collect()
}

/// A path as mountinfo writes it, with octal escapes for spaces and such.
fn unescape(field: &str) -> PathBuf {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        let octal = bytes.get(i.saturating_add(1)..i.saturating_add(4)).and_then(|digits| std::str::from_utf8(digits).ok()).and_then(|digits| u8::from_str_radix(digits, 8).ok());
        if let (b'\\', Some(value)) = (byte, octal) {
            out.push(value);
            i = i.saturating_add(4);
        } else {
            out.push(byte);
            i = i.saturating_add(1);
        }
    }
    PathBuf::from(OsStr::from_bytes(&out))
}

/// The soup's path for a path given: under a running mount, what's below
/// it; otherwise, the path as given, of the soup itself.
pub fn soup_path(given: &Path) -> PathBuf {
    let absolute = std::path::absolute(given).unwrap_or_else(|_| given.to_path_buf());
    let mut mounts = mount_points();
    // The deepest first, should one be inside another
    mounts.sort_by_key(|mount| std::cmp::Reverse(mount.as_os_str().len()));
    mounts.iter().find_map(|mount| absolute.strip_prefix(mount).ok().map(Path::to_path_buf)).unwrap_or_else(|| given.to_path_buf())
}

/// What's at a path of the soup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The anchor whose value has it, and where in that value: nowhere,
    /// if it's what the anchor is.
    pub anchor: Link,
    pub rel: PathBuf,
    /// What's there, and the size the directory naming it says, if that's
    /// anything. None if the anchor's nothing yet.
    pub at: Option<Link>,
    pub size: Option<u64>,
}

/// The anchor a mount point names, if a block's one: a symlink to
/// `/anchors/<anchor>`, and nothing under it.
pub fn mount_point(catalog: &Catalog, cid: &Link) -> Result<Option<Link>> {
    let Kind::Symlink(target) = export::stat(catalog, cid)? else {
        return Ok(None);
    };
    Ok(target.strip_prefix(b"/anchors/")
        .and_then(|rest| std::str::from_utf8(rest).ok())
        .and_then(|rest| rest.parse::<Link>().ok())
        .filter(crate::claim::is_anchor))
}

/// What's at a path of the soup, which needn't be of an anchor: one
/// under `cid/` or `tags/` is of none until it's through a mount point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The anchor whose value has it, and where in that value, if any
    pub anchor: Option<Link>,
    pub rel: PathBuf,
    /// What's there, and the size the directory naming it says, if that's
    /// anything. None if the anchor's nothing yet.
    pub at: Option<Link>,
    pub size: Option<u64>,
}

/// Find what's at a path of the soup, following mount points.
pub fn locate(catalog: &Catalog, path: &Path) -> Result<Located> {
    let found = find(catalog, path)?;
    let anchor = found.anchor.ok_or_else(|| user(format!("{}: not of an anchor, so nothing to change", path.display())))?;
    Ok(Located { anchor, rel: found.rel, at: found.at, size: found.size })
}

/// Find what's at any path of the soup, following mount points: one of an
/// anchor, or one under `cid/<cid>` or `tags/<tag>/<cid>`.
pub fn find(catalog: &Catalog, path: &Path) -> Result<Found> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(name.as_bytes().to_vec()),
            Component::RootDir | Component::CurDir => {},
            Component::ParentDir | Component::Prefix(_) => return Err(user(format!("{}: say the path without `..`", path.display()))),
        }
    }
    let named_cid = |name: &[u8]| std::str::from_utf8(name).ok().and_then(|name| name.parse::<Link>().ok());
    let (mut anchor, mut node, rest) = match names.first().map(Vec::as_slice) {
        Some(b"anchors") => {
            let name = names.get(1).ok_or_else(|| user("anchors/ itself isn't of an anchor: name one"))?;
            let anchor = named_cid(name).filter(crate::claim::is_anchor).ok_or_else(|| user(format!("{}: not an anchor", String::from_utf8_lossy(name))))?;
            (Some(anchor.clone()), catalog.anchor_value(&anchor)?, names.get(2..).unwrap_or_default())
        },
        Some(b"cid") => {
            let name = names.get(1).ok_or_else(|| user("cid/ itself is nothing: name a CID under it"))?;
            let cid = named_cid(name).ok_or_else(|| user(format!("{}: not a CID", String::from_utf8_lossy(name))))?;
            (None, Some(cid), names.get(2..).unwrap_or_default())
        },
        Some(b"tags") => {
            let (Some(tag), Some(name)) = (names.get(1), names.get(2)) else {
                return Err(user(format!("{}: name a tag and a CID tagged with it", path.display())));
            };
            let tag = std::str::from_utf8(tag).ok().and_then(crate::claim::tag).filter(|tag| catalog.claims().is_some_and(|claims| claims.tagged(tag.multihash()).is_ok_and(|tagged| !tagged.is_empty()))).or_else(|| named_cid(tag));
            let cid = named_cid(name).ok_or_else(|| user(format!("{}: not a CID", String::from_utf8_lossy(name))))?;
            let tagged = match (&tag, catalog.claims()) {
                (Some(tag), Some(claims)) => claims.tagged(tag.multihash())?.contains(&cid),
                _ => false,
            };
            if !tagged {
                return Err(user(format!("{}: not there", path.display())));
            }
            (None, Some(cid), names.get(3..).unwrap_or_default())
        },
        _ => {
            let root = catalog.root_anchor()?.ok_or_else(|| user("this account has no root anchor yet"))?;
            (Some(root.clone()), catalog.anchor_value(&root)?, names.as_slice())
        },
    };
    let mut rel = PathBuf::new();
    for (i, name) in rest.iter().enumerate() {
        let dir = node.ok_or_else(|| user(format!("{}: not there", path.display())))?;
        let entry = export::list(catalog, &dir)
            .map_err(|e| user(format!("{}: {e}", path.display())))?
            .into_iter()
            .find(|entry| entry.name == *name)
            .ok_or_else(|| user(format!("{}: not there", path.display())))?;
        rel.push(OsStr::from_bytes(name));
        if i.saturating_add(1) == rest.len() {
            return Ok(Found { anchor, rel, at: Some(entry.cid), size: entry.size });
        }
        match mount_point(catalog, &entry.cid)? {
            Some(mounted) => {
                node = catalog.anchor_value(&mounted)?;
                anchor = Some(mounted);
                rel = PathBuf::new();
            },
            None => node = Some(entry.cid),
        }
    }
    Ok(Found { anchor, rel, at: node, size: None })
}

/// What a version of an anchor has at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Was {
    /// Something, and the size the directory naming it says, if any.
    There(Link, Option<u64>),
    /// Nothing.
    Absent,
    /// Who knows: the version isn't here to read.
    NotHere,
}

/// How a set changed what's at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Added,
    Changed,
    Removed,
    /// Its version isn't here to say.
    Unknown,
}

impl Change {
    pub const fn word(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Changed => "changed",
            Self::Removed => "removed",
            Self::Unknown => "not here",
        }
    }
}

/// A set of an anchor that changed what's at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub set: Link,
    /// When, by the setter's clock, in seconds since the epoch.
    pub at: u64,
    /// The keys that signed it.
    pub by: Vec<Link>,
    pub change: Change,
    pub was: Was,
    /// Whether it's a head: what the anchor is, or among what's merged.
    pub head: bool,
}

/// What's at a path in a value of an anchor, reading only what's here.
fn was_at(catalog: &Catalog, value: &Link, rel: &Path) -> Was {
    let here = |cid: &Link| cid.hashcode() == crate::block::IDENTITY || catalog.has(cid.multihash()).unwrap_or(false);
    let (mut node, mut size) = (value.clone(), None);
    for name in rel.components() {
        if !here(&node) {
            return Was::NotHere;
        }
        // What isn't a directory has nothing under it
        let Some(entry) = export::list(catalog, &node).ok().and_then(|entries| entries.into_iter().find(|entry| entry.name == name.as_os_str().as_bytes())) else {
            return Was::Absent;
        };
        (node, size) = (entry.cid, entry.size);
    }
    Was::There(node, size)
}

/// The anchor whose history a path's is, and where in its value: that
/// of the anchor a mount point names, for one; else of the anchor naming
/// it, as `locate` finds, or, gone, that of its directory.
pub fn logged(catalog: &Catalog, path: &Path) -> Result<(Link, PathBuf)> {
    let mounted = |located: &Located| -> Result<Option<Link>> { located.at.as_ref().map_or(Ok(None), |at| mount_point(catalog, at)) };
    match locate(catalog, path) {
        Ok(located) => Ok(match mounted(&located)? {
            Some(anchor) => (anchor, PathBuf::new()),
            None => (located.anchor, located.rel),
        }),
        Err(gone) => {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(gone);
            };
            let Ok(dir) = locate(catalog, parent) else {
                return Err(gone);
            };
            Ok(match mounted(&dir)? {
                Some(anchor) => (anchor, PathBuf::from(name)),
                None => (dir.anchor, dir.rel.join(name)),
            })
        },
    }
}

/// The history of what's at a path of an anchor: each set of it, oldest
/// first, that changed what's there from what it came after.
///
/// A set
/// that names what it replaces (`prev`) came after those, one taking
/// either side of a fork changing nothing, and one with nothing before
/// it, after nothing; one of an older build, after the set before it.
/// A version not here is listed, as it can't be compared.
pub fn log(catalog: &Catalog, anchor: &Link, rel: &Path) -> Result<Vec<Version>> {
    let claims = catalog.claims().ok_or(Error::NoClaims)?;
    let heads: std::collections::HashSet<Vec<u8>> = catalog.anchor_heads(anchor)?.into_iter().map(|(set, ..)| set.to_bytes()).collect();
    let sets = catalog.sets_of(anchor)?;
    // What each had there, first, as a set may be listed before what it
    // replaced, by a clock behind
    let mut by_value: std::collections::HashMap<Vec<u8>, Was> = std::collections::HashMap::new();
    let mut seen: std::collections::HashMap<Vec<u8>, Was> = std::collections::HashMap::new();
    let mut wases = Vec::with_capacity(sets.len());
    for (set, value, ..) in &sets {
        let was = by_value.entry(value.to_bytes()).or_insert_with(|| was_at(catalog, value, rel)).clone();
        seen.insert(set.to_bytes(), was.clone());
        wases.push(was);
    }
    let mut versions = Vec::new();
    let mut last: Option<&Was> = None;
    for ((set, _, at, prev), was) in sets.iter().zip(&wases) {
        let before: Vec<&Was> = prev.as_ref().map_or_else(|| last.into_iter().collect(), |prev| prev.iter().filter_map(|set| seen.get(&set.to_bytes())).collect());
        let change = match was {
            Was::NotHere => Some(Change::Unknown),
            _ if before.contains(&was) => None,
            Was::Absent if before.is_empty() => None,
            Was::Absent => Some(Change::Removed),
            Was::There(..) if before.iter().all(|before| **before == Was::Absent) => Some(Change::Added),
            Was::There(..) => Some(Change::Changed),
        };
        if let Some(change) = change {
            versions.push(Version { by: claims.signers(set)?, head: heads.contains(&set.to_bytes()), set: set.clone(), at: *at, change, was: was.clone() });
        }
        last = Some(was);
    }
    Ok(versions)
}

/// Set each anchor to what it is with marks over it: one set each, of
/// every head it has.
fn edit(catalog: &mut Catalog, edits: BTreeMap<Vec<u8>, (Link, Marks)>) -> Result<Vec<(Link, Link)>> {
    let mut done = Vec::new();
    for (anchor, marks) in edits.into_values() {
        let value = catalog.edit_value(catalog.anchor_value(&anchor)?, &marks)?;
        let heads = catalog.anchor_heads(&anchor)?.into_iter().map(|(set, ..)| set).collect();
        let wrote: Vec<crate::store::merge::Path> = marks.keys().map(|rel| rel.components().map(|part| part.as_os_str().as_bytes().to_vec()).collect()).collect();
        catalog.set_anchor_wrote(&anchor, &value, heads, &wrote)?;
        done.push((anchor, value));
    }
    Ok(done)
}

/// Unlink what's at each path from the anchor naming it: one set for each
/// anchor, reading nothing under what's gone. Returns each anchor set and
/// what it is now.
pub fn remove(catalog: &mut Catalog, paths: &[Located]) -> Result<Vec<(Link, Link)>> {
    let mut edits: BTreeMap<Vec<u8>, (Link, Marks)> = BTreeMap::new();
    for located in paths {
        if located.rel.as_os_str().is_empty() {
            return Err(user(format!("{} is what an anchor is: remove a mount point of it instead", located.anchor)));
        }
        edits.entry(located.anchor.to_bytes()).or_insert_with(|| (located.anchor.clone(), Marks::new())).1.insert(located.rel.clone(), None);
    }
    edit(catalog, edits)
}

/// Make what's at a path an anchor of its own, set to it, and mounted
/// where it was: so it's versioned, kept and shared on its own. Returns
/// the new anchor.
pub fn promote(catalog: &mut Catalog, located: &Located) -> Result<Link> {
    let at = located.at.clone().ok_or_else(|| user("nothing's there"))?;
    if located.rel.as_os_str().is_empty() {
        return Err(user(format!("that's what {} is already", located.anchor)));
    }
    if let Some(mounted) = mount_point(catalog, &at)? {
        return Err(user(format!("that's a mount point already, of {mounted}")));
    }
    let anchor = catalog.new_anchor()?;
    catalog.set_anchor(&anchor, &at)?;
    let link = crate::dag::symlink_node(format!("/anchors/{anchor}").as_bytes(), catalog)?;
    let marks = Marks::from([(located.rel.clone(), Some((link.cid.into(), link.tsize)))]);
    edit(catalog, BTreeMap::from([(located.anchor.to_bytes(), (located.anchor.clone(), marks))]))?;
    Ok(anchor)
}

#[cfg(test)]
mod tests;
