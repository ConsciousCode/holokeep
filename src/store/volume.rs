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

use super::{ClaimStore, Db, IpldStore, RawStore, Result, ShardStore, Store, UnixfsStore};

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
    /// The risks it's found to share with others where it's mounted:
    /// whatever fails takes every volume sharing it.
    risks: Vec<String>,
    /// Its database, if it's a database.
    db: Option<Db>,
    stores: Vec<Box<dyn Store>>,
}

impl Volume {
    /// A database volume.
    pub fn new(name: impl Into<String>, label: Label, stores: Vec<Box<dyn Store>>) -> Self {
        Self { name: name.into(), label, kind: "db", path: None, risks: Vec::new(), db: None, stores }
    }

    /// A database volume which others may write to, stamping each block's
    /// arrival and departure with a generation so they can catch up.
    pub fn sqlite(name: impl Into<String>, db: Db, stores: Vec<Box<dyn Store>>) -> Result<Self> {
        let label = db_label(&db)?;
        db.conn().execute_batch(BLOCK_CIDS)?;
        stamp(&db, stores.iter().map(|store| store.name()))?;
        Ok(Self { db: Some(db), ..Self::new(name, label, stores) })
    }

    /// A database volume's file, opened with the forms a database holds,
    /// if it's there and carries the label; any file if there's no label
    /// to expect, making it a volume if it isn't one.
    pub fn open_sqlite(name: impl Into<String>, path: &Path, expect: Option<Label>) -> Result<Option<Self>> {
        if let Some(expect) = expect
            && (!path.is_file() || read_db_label(path)? != Some(expect))
        {
            return Ok(None);
        }
        let db = Db::open(path)?;
        let stores: Vec<Box<dyn Store>> = vec![
            Box::new(UnixfsStore::open(db.clone())?),
            Box::new(ClaimStore::open(db.clone())?),
            Box::new(IpldStore::open(db.clone())?),
            Box::new(RawStore::open(db.clone())?),
        ];
        Ok(Some(Self::sqlite(name, db, stores)?.at(path)))
    }

    /// A flatfs directory.
    pub fn flatfs(name: impl Into<String>, shards: Rc<ShardStore>) -> Self {
        let path = shards.dir().to_owned();
        let volume = Self { name: name.into(), label: shards.label(), kind: "flatfs", path: None, risks: Vec::new(), db: None, stores: vec![Box::new(shards)] };
        volume.at(&path)
    }

    /// The volume, mounted at a path.
    #[must_use]
    pub fn at(mut self, path: &Path) -> Self {
        self.risks = risks_of(path);
        self.path = Some(path.to_owned());
        self
    }

    pub const fn label(&self) -> Label { self.label }

    pub const fn kind(&self) -> &'static str { self.kind }

    pub fn path(&self) -> Option<&Path> { self.path.as_deref() }

    pub fn risks(&self) -> &[String] { &self.risks }

    pub const fn db(&self) -> Option<&Db> { self.db.as_ref() }

    pub fn stores(&self) -> &[Box<dyn Store>] { &self.stores }

    /// The store of a form, if the volume holds one.
    pub fn form(&self, name: &str) -> Option<&dyn Store> {
        self.stores.iter().find(|store| store.name() == name).map(AsRef::as_ref)
    }
}

/// The risks a path can be found to share with others, each something
/// whose failure takes everything sharing it:
///
/// - `disk:` each physical disk under its filesystem, through partitions,
///   LVM, RAID and encryption, by WWID or serial number, which are the
///   same wherever it's plugged in. Device numbers aren't, and neither
///   they nor filesystem UUIDs know that two filesystems share a disk. A
///   mirror's disks are one risk, `disk:a+b`, since it takes both.
/// - `host:` this machine, by its machine id, for disks inside it rather
///   than on USB: what's lost if the machine is.
/// - for a filesystem on no disk, its mount source, `nfs4:server:/data`.
///
/// What can't be found, such as which building a drive is in, is said.
pub fn risks_of(path: &Path) -> Vec<String> {
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    let dev = meta.dev();
    let mount = mount_of(dev);
    // A btrfs subvolume's device number is anonymous; its source isn't
    let block = sysfs_block(dev).or_else(|| {
        let (_, source) = mount.as_ref()?;
        source.starts_with("/dev/").then_some(())?;
        sysfs_block(fs::metadata(source).ok()?.rdev())
    });
    let mut disks = Vec::new();
    if let Some(block) = block {
        disks_under(&block, &mut disks);
    }
    if disks.is_empty() {
        return vec![match mount {
            Some((fstype, source)) => format!("{fstype}:{source}"),
            None => format!("dev:{dev}"),
        }];
    }
    let internal = disks.iter().any(|disk| !disk.usb);
    let mut risks: Vec<String> = disks.into_iter().map(|disk| format!("disk:{}", disk.id)).collect();
    if internal && let Ok(id) = fs::read_to_string("/etc/machine-id") {
        risks.push(format!("host:{}", id.trim()));
    }
    risks.sort();
    risks.dedup();
    risks
}

/// A device number's major and minor, as Linux encodes them.
const fn major_minor(dev: u64) -> (u64, u64) {
    ((dev >> 8 & 0xfff) | (dev >> 32 & !0xfff), (dev & 0xff) | (dev >> 12 & !0xff))
}

/// The filesystem type and source of the mount with this device number.
fn mount_of(dev: u64) -> Option<(String, String)> {
    let (major, minor) = major_minor(dev);
    let id = format!("{major}:{minor}");
    let mounts = fs::read_to_string("/proc/self/mountinfo").ok()?;
    mounts.lines().find_map(|line| {
        let (fields, rest) = line.split_once(" - ")?;
        (fields.split(' ').nth(2)? == id).then_some(())?;
        let mut rest = rest.split(' ');
        Some((rest.next()?.to_owned(), rest.next()?.to_owned()))
    })
}

/// A block device's directory in sysfs.
fn sysfs_block(dev: u64) -> Option<PathBuf> {
    let (major, minor) = major_minor(dev);
    fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")).ok()
}

/// A physical disk.
struct Disk {
    id: String,
    usb: bool,
}

/// RAID levels which survive losing a disk.
const REDUNDANT: [&str; 5] = ["raid1", "raid4", "raid5", "raid6", "raid10"];

/// The disks a block device is on.
fn disks_under(block: &Path, disks: &mut Vec<Disk>) {
    let slaves: Vec<_> = fs::read_dir(block.join("slaves"))
        .into_iter()
        .flatten()
        .filter_map(|entry| fs::canonicalize(entry.ok()?.path()).ok())
        .collect();
    if !slaves.is_empty() {
        let level = fs::read_to_string(block.join("md/level")).unwrap_or_default();
        let mut under = Vec::new();
        for slave in slaves {
            disks_under(&slave, &mut under);
        }
        if REDUNDANT.contains(&level.trim()) {
            let mut ids: Vec<String> = under.iter().map(|disk| disk.id.clone()).collect();
            ids.sort();
            disks.push(Disk { id: ids.join("+"), usb: under.iter().all(|disk| disk.usb) });
        }
        else {
            disks.extend(under);
        }
        return;
    }
    let disk = if block.join("partition").exists() { block.parent().unwrap_or(block) } else { block };
    let id = ["wwid", "device/wwid", "device/serial"]
        .iter()
        .filter_map(|file| fs::read_to_string(disk.join(file)).ok())
        .map(|id| id.trim().to_owned())
        .find(|id| !id.is_empty());
    if let Some(id) = id.or_else(|| Some(disk.file_name()?.to_string_lossy().into_owned())) {
        let usb = disk.components().any(|part| part.as_os_str().to_string_lossy().starts_with("usb"));
        disks.push(Disk { id, usb });
    }
}

/// How many risks would have to fail to lose every copy, where each copy
/// is lost if any of its risks fail: the smallest set of risks touching
/// every copy, counted up to `cap`. Copies with no risks in common need
/// one failure each; a risk they all share loses them all at once.
pub fn tolerance(copies: &[Vec<String>], cap: usize) -> usize {
    let mut all: Vec<&String> = copies.iter().flatten().collect();
    all.sort();
    all.dedup();
    let hits = |chosen: &[&String]| copies.iter().all(|risks| risks.iter().any(|risk| chosen.contains(&risk)));
    (0..cap).find(|&k| subsets(&all, k, &mut Vec::new(), &hits)).unwrap_or(cap)
}

/// Whether some `k` of the risks satisfy `f`.
fn subsets<'a>(from: &[&'a String], k: usize, chosen: &mut Vec<&'a String>, f: &impl Fn(&[&String]) -> bool) -> bool {
    if k == 0 {
        return f(chosen);
    }
    for (i, &risk) in from.iter().enumerate() {
        chosen.push(risk);
        let found = subsets(from.get(i.saturating_add(1)..).unwrap_or_default(), k.saturating_sub(1), chosen, f);
        chosen.pop();
        if found {
            return true;
        }
    }
    false
}

fn fresh() -> Result<Label> {
    let mut label = Label::default();
    getrandom::getrandom(&mut label).map_err(io::Error::from)?;
    Ok(label)
}

/// The CID prefixes (version and codec) each block was put with. Unlike
/// where blocks are, this isn't derivable from the stores, which needn't
/// know how their bytes are meant to be read, so it survives a reindex;
/// and a database volume carries it for its blocks, so whoever catches up
/// with it can read their links.
pub const BLOCK_CIDS: &str = "
    CREATE TABLE IF NOT EXISTS block_cids (
        block INTEGER NOT NULL REFERENCES multihashes (id),
        prefix BLOB NOT NULL,
        PRIMARY KEY (block, prefix)
    ) WITHOUT ROWID;";

/// Each form a database holds which can be stamped: its table of blocks,
/// and the column naming them, which is NULL for rows that aren't blocks.
const FORM_TABLES: [(&str, &str, &str); 4] = [
    ("unixfs", "unixfs_nodes", "block"),
    ("claims", "claims", "claim"),
    ("ipld", "ipld_blocks", "block"),
    ("raw", "raw_blocks", "block"),
];

/// Keep a generation for each block in each form, the database's
/// generation when it last arrived or left: one more than any before.
/// Whoever's seen every generation up to some number catches up by
/// reading the blocks stamped since. It's kept by triggers, so whatever
/// writes to the database stamps what it writes, even by hand.
///
/// Unlike a log, it's a row per block, not per change, and nothing's read
/// but what's changed. A block that leaves keeps its row, as gone, so
/// that whoever saw it arrive sees it leave.
fn stamp<'a>(db: &Db, forms: impl Iterator<Item = &'a str>) -> Result<()> {
    let conn = db.conn();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS generations (
             form TEXT NOT NULL,
             block INTEGER NOT NULL REFERENCES multihashes (id),
             generation INTEGER NOT NULL,
             present INTEGER NOT NULL,
             PRIMARY KEY (form, block)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS generations_generation ON generations (generation);",
    )?;
    for form in forms {
        let Some(&(form, table, column)) = FORM_TABLES.iter().find(|(name, ..)| *name == form) else {
            continue;
        };
        let trigger = format!("generations_{form}");
        let stamped = conn
            .prepare_cached("SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1")?
            .exists([format!("{trigger}_added")])?;
        if stamped {
            continue;
        }
        let next = "(SELECT coalesce(max(generation), 0) + 1 FROM generations)";
        conn.execute_batch(&format!(
            "CREATE TRIGGER {trigger}_added AFTER INSERT ON {table} WHEN NEW.{column} IS NOT NULL BEGIN
                 INSERT OR REPLACE INTO generations (form, block, generation, present)
                 VALUES ('{form}', NEW.{column}, {next}, 1);
             END;
             CREATE TRIGGER {trigger}_removed AFTER DELETE ON {table} WHEN OLD.{column} IS NOT NULL BEGIN
                 INSERT OR REPLACE INTO generations (form, block, generation, present)
                 VALUES ('{form}', OLD.{column}, {next}, 0);
             END;
             -- What was there before it was stamped arrives now
             INSERT OR IGNORE INTO generations (form, block, generation, present)
                 SELECT '{form}', {column}, {next}, 1 FROM {table} WHERE {column} IS NOT NULL;",
        ))?;
    }
    Ok(())
}

/// The latest generation of a database volume.
pub fn generation(db: &Db) -> Result<i64> {
    Ok(db.conn().query_row("SELECT coalesce(max(generation), 0) FROM generations", [], |row| row.get(0))?)
}

/// A database file's label, if it's a volume, without changing it.
fn read_db_label(path: &Path) -> Result<Option<Label>> {
    let conn = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let labelled = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'volume_label'")?
        .exists([])?;
    if !labelled {
        return Ok(None);
    }
    let label: Option<Vec<u8>> = conn.query_row("SELECT label FROM volume_label", [], |row| row.get(0)).optional()?;
    Ok(label.and_then(|label| Label::try_from(label).ok()))
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
