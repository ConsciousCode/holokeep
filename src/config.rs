//! A repo's configuration: `config.toml` in the repo's directory.
//!
//! What's tunable of its nodes and what they mount, so a service runs
//! with no flags. A flag says over the file, and the file over the
//! defaults; a repo with no file has the defaults.
//!
//! ```toml
//! [node]              # the main mesh's node, and every other's defaults
//! copies = 3
//! low-water = "10G"
//! target = "50G"      # the most to keep here
//! ping = "30s"
//! relay = true        # relay between members which can't reach each other
//!
//! [mesh.work]         # the node of `--mesh work`, over [node]
//! listen = "/ip4/0.0.0.0/tcp/4111"
//!
//! [[mount]]           # mounted by `hk node run` while it runs
//! dir = "~/soup"
//!
//! [[serve]]           # a service anchors may be served from
//! name = "notes"
//! socket = "/run/user/1000/notes.9p"
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ::serde::{Deserialize, Deserializer, Serialize};

/// The file's name in the repo's directory.
pub const FILE: &str = "config.toml";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The main mesh's node, and the defaults of every other's.
    #[serde(default, skip_serializing_if = "Node::is_empty")]
    pub node: Node,
    /// Each other mesh's node, by name, over `node`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mesh: BTreeMap<String, Node>,
    /// What the main mesh's node mounts while it runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mount: Vec<Mount>,
    /// The services this node serves anchors from (see `served`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub serve: Vec<Service>,
}

/// A service anchors are served from: a socket speaking 9P2000.L, which
/// serve claims name by `name`. It runs as whoever owns this file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Service {
    pub name: String,
    /// Where: `~/` is the home directory.
    pub socket: PathBuf,
}

impl Service {
    /// Where its socket is, with `~/` the home directory.
    pub fn socket(&self) -> PathBuf {
        home(&self.socket)
    }
}

/// A path, with `~/` the home directory.
fn home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_path_buf(),
    }
}

/// A node's tunables, each as its flag of `hk node run` says, and those
/// with no flag. Unsaid, a flag or the default says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Node {
    /// Where to listen: in `[node]`, the main mesh's alone, as with
    /// `clients` and `door`, since two nodes can't share a port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copies: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "size", serialize_with = "show_size")]
    pub low_water: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "size", serialize_with = "show_size")]
    pub high_water: Option<u64>,
    /// The most to keep here.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "size", serialize_with = "show_size")]
    pub target: Option<u64>,
    /// Whether to collect garbage (`--no-collect` if not).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collect: Option<bool>,
    /// Whether to look for what's lost daily (`--no-lost-scan` if not).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost_scan: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared: Option<bool>,
    /// Whether to listen for clients, and where: `true` where `--clients`
    /// alone would.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<Listen>,
    /// Whether to open a door, and where: `true` where `--door` alone
    /// would.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub door: Option<Listen>,
    /// How often a connection's pinged, and how long an answer's waited
    /// for, before it's closed as dead and its peer dialled again.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "duration", serialize_with = "show_duration")]
    pub ping: Option<Duration>,
    /// How long a connection with nothing going on is kept open.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "duration", serialize_with = "show_duration")]
    pub idle: Option<Duration>,    /// Whether to serve what's public over HTTP, as a trustless gateway,
    /// and where: `true` where `--gateway` alone would.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Listen>,
    /// Whether to relay between members which can't reach each other:
    /// for a member others reach where they can't reach each other, as a
    /// server with a public address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<bool>,
}

/// Where to listen for something that's off unless asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Listen {
    /// On where it would be by default, or off.
    On(bool),
    /// On, here: a multiaddr.
    At(String),
}

impl Listen {
    /// Where to listen, if at all, `default` if it's merely on.
    pub fn at(&self, default: &str) -> Option<String> {
        match self {
            Self::On(true) => Some(default.to_owned()),
            Self::On(false) => None,
            Self::At(at) => Some(at.clone()),
        }
    }
}

/// A directory to mount the soup on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Mount {
    /// Where: `~/` is the home directory.
    pub dir: PathBuf,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
}

impl Mount {
    /// Where, with `~/` the home directory.
    pub fn dir(&self) -> PathBuf {
        home(&self.dir)
    }
}

/// Why a configuration can't be had.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0}: {1}")]
    Invalid(PathBuf, String),
}

impl Config {
    /// The configuration of the repo in `dir`: the defaults, if it has
    /// none.
    pub fn load(dir: &Path) -> Result<Self, Error> {
        let path = dir.join(FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).map_err(|e| Error::Invalid(path, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::Io(path, e)),
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        for (name, node) in &config.mesh {
            if name == "main" {
                return Err("the main mesh's node is [node], not [mesh.main]".into());
            }
            if node.clients.is_some() {
                return Err(format!("[mesh.{name}]: clients are of the main mesh"));
            }
        }
        let mut names = std::collections::HashSet::new();
        for service in &config.serve {
            if service.name.is_empty() || !names.insert(service.name.as_str()) {
                return Err(format!("[[serve]]: each service needs a name of its own, not {:?}", service.name));
            }
        }
        Ok(config)
    }

    /// The node of a mesh: `[node]`, and over it the mesh's own, but for
    /// where `[node]` says to listen, which is the main mesh's alone.
    pub fn node(&self, mesh: &str) -> Node {
        if mesh == "main" {
            return self.node.clone();
        }
        let base = Node { listen: None, clients: None, door: None, gateway: None, ..self.node.clone() };
        self.mesh.get(mesh).map_or_else(|| base.clone(), |own| own.over(&base))
    }
}

impl Node {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// These, and `base`'s where these say nothing.
    #[must_use]
    pub fn over(&self, base: &Self) -> Self {
        Self {
            listen: self.listen.clone().or_else(|| base.listen.clone()),
            copies: self.copies.or(base.copies),
            low_water: self.low_water.or(base.low_water),
            high_water: self.high_water.or(base.high_water),
            target: self.target.or(base.target),
            collect: self.collect.or(base.collect),
            lost_scan: self.lost_scan.or(base.lost_scan),
            shared: self.shared.or(base.shared),
            clients: self.clients.clone().or_else(|| base.clients.clone()),
            door: self.door.clone().or_else(|| base.door.clone()),
            ping: self.ping.or(base.ping),
            idle: self.idle.or(base.idle),
            relay: self.relay.or(base.relay),
            gateway: self.gateway.clone().or_else(|| base.gateway.clone()),
        }
    }
}

/// A size, in bytes or with K, M, G or T: a number of bytes, or a string.
fn size<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Size {
        Bytes(u64),
        Text(String),
    }
    match Size::deserialize(deserializer)? {
        Size::Bytes(bytes) => Ok(Some(bytes)),
        Size::Text(text) => parse_size(&text).map(Some).map_err(::serde::de::Error::custom),
    }
}

#[expect(clippy::ref_option, reason = "as serde's serialize_with passes it")]
fn show_size<S: ::serde::Serializer>(size: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    let size = size.unwrap_or_default();
    let (shift, unit) = [(40, "T"), (30, "G"), (20, "M"), (10, "K")]
        .into_iter()
        .find(|&(shift, _)| size != 0 && size.trailing_zeros() >= shift)
        .unwrap_or((0, ""));
    if unit.is_empty() {
        serializer.serialize_u64(size)
    }
    else {
        serializer.serialize_str(&format!("{}{unit}", size >> shift))
    }
}

/// A size, in bytes or with K, M, G or T (binary).
pub fn parse_size(text: &str) -> Result<u64, String> {
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

/// A duration: a number with `ms`, `s`, `m`, `h` or `d`.
fn duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Duration>, D::Error> {
    parse_duration(&String::deserialize(deserializer)?).map(Some).map_err(::serde::de::Error::custom)
}

#[expect(clippy::ref_option, reason = "as serde's serialize_with passes it")]
fn show_duration<S: ::serde::Serializer>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error> {
    let duration = duration.unwrap_or_default();
    let millis = duration.as_millis();
    let text = [(86_400_000, "d"), (3_600_000, "h"), (60_000, "m"), (1000, "s")]
        .into_iter()
        .find(|&(unit, _)| millis != 0 && millis.is_multiple_of(unit))
        .map_or_else(|| format!("{millis}ms"), |(unit, name)| format!("{}{name}", millis.checked_div(unit).unwrap_or_default()));
    serializer.serialize_str(&text)
}

/// A duration: a number with `ms`, `s`, `m`, `h` or `d`.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit()).ok_or_else(|| format!("{text:?} needs a unit: ms, s, m, h or d"))?;
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().map_err(|_| format!("not a duration: {text:?}"))?;
    let millis: u64 = match unit.trim() {
        "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(format!("unknown unit in {text:?}: ms, s, m, h or d")),
    };
    number.checked_mul(millis).map(Duration::from_millis).ok_or_else(|| format!("too long: {text:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_says_over_defaults_and_a_mesh_over_node() {
        let config = Config::parse(
            r#"
            [node]
            listen = "/ip4/0.0.0.0/tcp/5011"
            copies = 3
            low-water = "10G"
            high-water = 21474836480
            ping = "30s"
            door = true
            relay = true

            [mesh.work]
            copies = 4
            idle = "2h"
            target = "50G"

            [[mount]]
            dir = "~/soup"

            [[mount]]
            dir = "/mnt/soup"
            read-only = true
            "#,
        )
        .expect("parse");
        let main = config.node("main");
        assert_eq!((main.listen.as_deref(), main.copies, main.low_water, main.high_water), (Some("/ip4/0.0.0.0/tcp/5011"), Some(3), Some(10 << 30), Some(20 << 30)));
        assert_eq!((main.ping, main.idle, main.door.and_then(|door| door.at("d"))), (Some(Duration::from_secs(30)), None, Some("d".into())));
        let work = config.node("work");
        assert_eq!((work.listen, work.door, work.copies, work.ping, work.idle), (None, None, Some(4), Some(Duration::from_secs(30)), Some(Duration::from_hours(2))), "where to listen is main's alone");
        assert_eq!((main.target, work.target), (None, Some(50 << 30)));
        assert_eq!(config.node("other").copies, Some(3), "a mesh unsaid is [node]'s");
        assert_eq!((main.relay, work.relay), (Some(true), Some(true)));
        assert!(config.mount.first().is_some_and(|mount| !mount.read_only && !mount.dir().starts_with("~")));
        assert!(config.mount.get(1).is_some_and(|mount| mount.read_only && mount.dir() == Path::new("/mnt/soup")));

        // What it says round-trips, as `hk config show` prints it
        let shown = toml::to_string(&config).expect("show");
        assert_eq!(Config::parse(&shown).expect("parse again"), config, "{shown}");
        assert!(shown.contains("low-water = \"10G\"") && shown.contains("ping = \"30s\""), "{shown}");
    }

    #[test]
    fn what_isnt_understood_is_refused() {
        for bad in [
            "[node]\ncopise = 3",
            "[node]\nping = \"10\"",
            "[node]\nping = \"10y\"",
            "[node]\nlow-water = \"2Q\"",
            "[mesh.main]\ncopies = 3",
            "[mesh.work]\nclients = true",
            "[[mount]]\nread-only = true",
            "nodes = 1",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(Config::parse("").expect("empty"), Config::default());
    }

    #[test]
    fn durations_and_sizes_read() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_hours(24 * 7)));
        assert_eq!(parse_size("2G"), Ok(2 << 30));
        assert_eq!(parse_size("17"), Ok(17));
        assert!(parse_size("99999999999T").is_err());
    }
}
