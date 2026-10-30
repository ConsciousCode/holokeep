//! Volumes: places blocks are kept. A volume holds one or more logical
//! blockstores, which differ in form, how they break a block down: the
//! repo's database holds UnixFS nodes as rows and claims as rows and
//! dag-cbor as JSONB, a flatfs directory holds raw blobs as files.
//!
//! Volumes are shareable, unlike most: a drive can move between machines,
//! and more than one node's catalog can index it. So each has a stable
//! identity, a random label written into the volume itself (a row in its
//! database, a file in its directory), by which whichever catalog opens it
//! knows it for the same volume.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::OptionalExtension;

use super::{Db, Result, ShardStore, Store};

/// A volume's identity.
pub type Label = [u8; 16];

/// The file in a directory which holds its label.
const LABEL_FILE: &str = "VOLUME";

/// A place blocks are kept, and the stores it holds them in, most
/// specialized first.
pub struct Volume {
    /// What it's called here, for people; the label is what it is.
    pub name: String,
    label: Label,
    /// How to open it again: `db` or `flatfs`.
    kind: &'static str,
    /// Where it's mounted, if anywhere in particular.
    path: Option<PathBuf>,
    /// The device it's on, as a failure domain: copies on one device are
    /// lost together.
    device: Option<u64>,
    stores: Vec<Box<dyn Store>>,
}

impl Volume {
    /// A database volume.
    pub fn new(name: impl Into<String>, label: Label, stores: Vec<Box<dyn Store>>) -> Self {
        Self { name: name.into(), label, kind: "db", path: None, device: None, stores }
    }

    /// A flatfs directory.
    pub fn flatfs(name: impl Into<String>, shards: Rc<ShardStore>) -> Self {
        let path = shards.dir().to_owned();
        let volume = Self { name: name.into(), label: shards.label(), kind: "flatfs", path: None, device: None, stores: vec![Box::new(shards)] };
        volume.at(&path)
    }

    /// The volume, mounted at a path.
    #[must_use]
    pub fn at(mut self, path: &Path) -> Self {
        self.device = device_of(path);
        self.path = Some(path.to_owned());
        self
    }

    pub const fn label(&self) -> Label { self.label }

    pub const fn kind(&self) -> &'static str { self.kind }

    pub fn path(&self) -> Option<&Path> { self.path.as_deref() }

    pub const fn device(&self) -> Option<u64> { self.device }

    pub fn stores(&self) -> &[Box<dyn Store>] { &self.stores }

    /// The store of a form, if the volume holds one.
    pub fn form(&self, name: &str) -> Option<&dyn Store> {
        self.stores.iter().find(|store| store.name() == name).map(AsRef::as_ref)
    }
}

/// The device a path is on.
pub fn device_of(path: &Path) -> Option<u64> {
    fs::metadata(path).ok().map(|meta| meta.dev())
}

fn fresh() -> Result<Label> {
    let mut label = Label::default();
    getrandom::getrandom(&mut label).map_err(io::Error::from)?;
    Ok(label)
}

/// A database's label, made the first time it's asked for.
pub fn db_label(db: &Db) -> Result<Label> {
    let conn = db.conn();
    conn.execute_batch(
        "-- This database's identity as a volume; one row.
         CREATE TABLE IF NOT EXISTS volume_label (
             label BLOB NOT NULL CHECK (length(label) = 16)
         );",
    )?;
    let label: Option<Vec<u8>> = conn.query_row("SELECT label FROM volume_label", [], |row| row.get(0)).optional()?;
    if let Some(label) = label.and_then(|label| Label::try_from(label).ok()) {
        return Ok(label);
    }
    let label = fresh()?;
    conn.execute("INSERT INTO volume_label (label) VALUES (?1)", [label.as_slice()])?;
    Ok(label)
}

/// A directory's label, from the file which holds it, made the first time
/// it's asked for.
pub fn dir_label(dir: &Path) -> Result<Label> {
    if let Some(label) = read_dir_label(dir)? {
        return Ok(label);
    }
    let label = fresh()?;
    let mut text = String::with_capacity(label.len().saturating_mul(2).saturating_add(1));
    for byte in label {
        let _ = write!(text, "{byte:02x}");
    }
    text.push('\n');
    fs::write(dir.join(LABEL_FILE), text)?;
    Ok(label)
}

/// A directory's label, if it has one.
pub fn read_dir_label(dir: &Path) -> Result<Option<Label>> {
    let path = dir.join(LABEL_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => {
            let mut label = Label::default();
            let bytes = text.trim().as_bytes();
            let invalid = || io::Error::new(io::ErrorKind::InvalidData, format!("{} isn't a volume label", path.display()));
            if bytes.len() != label.len().saturating_mul(2) {
                return Err(invalid().into());
            }
            for (byte, pair) in label.iter_mut().zip(bytes.chunks(2)) {
                let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
                *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
            }
            Ok(Some(label))
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
