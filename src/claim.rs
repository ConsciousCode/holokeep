//! Claims: sidecar blocks about their targets, which the README describes.
//!
//! So far `Group`, which is what a tag is, `Keep`, which says to keep its
//! targets, `Set`, which says what an anchor is now, and `Tomb`, which
//! retracts; and, for who may say so, `Sign`, a key's signature of a
//! claim, and `Device`, which a user's root key signs to say a node's key
//! acts for it (see `keys`). And `Lost`, a report that blocks couldn't be
//! found; and `Grant`, which gives or takes away what users and machines
//! may do in a mesh (see `grants`). And `Same`, which says its targets
//! are the same, read through a lens (see `same`). And `Public`, which
//! says its targets and what they link to may be given to anyone who
//! asks, and whether to say so.
//!
//! Signatures are claims about claims, rather than inside them, so equal
//! claims stay equal blocks whoever makes them, and small ones dissolve.
//!
//! An anchor is an empty identity, in the manner of Perkeep's permanodes:
//! claims hung on it are its state. It's an identity CID of `{anchor:
//! <16 random bytes>}`, so it's named without being stored anywhere.
//!
//! A claim is dag-cbor with its type inline, under the key `claim`. Its
//! `target` is a set, written as an array sorted by CID bytes, so equal
//! claims are equal blocks.
//!
//! A claim with one target which encodes to no more than an identity
//! digest allows is *dissolved*: its CID is its own bytes, so it's named
//! without being hashed, and a store keeps it as rows without a multihash.
//! Anything bigger is precipitated, an ordinary sha2-256 block.

use std::collections::{BTreeMap, BTreeSet};

use crate::block::{Block, IDENTITY, IDENTITY_MAX};
use crate::cid::{AnyCid, BaseCid, CidRef, Cidv1, Cidv1Spec, DAG_CBOR_CODEC, RAW_CODEC};
use crate::dagcbor;
use crate::model::{Ipld, Link};
use crate::multihash::{Multihash, MultihashFunc};

/// The longest tag name: IPIP-0512's limit on identity digests.
pub const MAX_NAME: usize = IDENTITY_MAX;

/// "Targets belong to the given group." With an identity CID for `into`,
/// a simple tag: the targets are tagged with its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    into: Link,
}

/// "Mark a block as collectable." Locally a claim it targets is retracted
/// at once; the tomb itself outlives it so the claim isn't brought back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tomb {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
}

/// "Keep the targets, and what they link to", short of what's `beyond`.
///
/// `beyond` is the frontier where its reach stops, for DAGs too large to
/// hold, left out when empty. What's added is kept unless said otherwise;
/// what nothing kept links to is, in time, collectable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keep {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    /// Sorted by CID bytes and distinct.
    beyond: Vec<Link>,
    /// Which time the targets are kept, from 0, left out when 0: keeping
    /// them again once a keep's been tombed takes a new claim, since a
    /// tomb is forever.
    n: u64,
    /// How many failures it takes to lose what's kept, at least, for what
    /// this keep is the nearest of along a path: left out for whatever the
    /// mesh runs with.
    copies: Option<u64>,
}

/// "The targets, anchors, are `value` as of `at`", in seconds since the
/// epoch, in place of the sets `prev`.
///
/// An anchor is whatever its heads say, the sets that count which no
/// other set replaces, so it's mutable while every claim stays put: what
/// it was is the history. A set with `prev` replaces those sets alone, an
/// empty `prev` none; one without, as older builds made, replaces every
/// set before it by `at` and then the value's multihash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    value: Link,
    at: u64,
    /// The sets this one replaces, sorted by CID bytes and distinct; none
    /// for one made by an older build, which replaces every set before it.
    prev: Option<Vec<Link>>,
    /// Paths under the value it wrote though they hold what they did, as
    /// when a conflict's resolved to its latest version: names joined by
    /// `/`, sorted and distinct.
    wrote: Vec<Vec<u8>>,
    /// The user whose view of the anchors it's for, if not its signer's
    /// own: it counts there if they've given its signer `/anchor/write`.
    for_: Option<Link>,
}

/// "`by` vouches for the targets, claims, as of `at`": `sig` is the key's
/// signature of the sign's own encoding without it. Never dissolved.
///
/// A key's signs are a chain: each names the one it made before as
/// `prev`, left out for its first. A key that's honest has one chain, so
/// a sign that isn't on it, two signs with one `prev`, is a copy of the
/// key at work; and revoking a key can trust a sign and what came before
/// it, which nothing made later can claim to be among.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    by: Link,
    at: u64,
    prev: Option<Link>,
    sig: Vec<u8>,
}

/// "The targets, keys, act for whoever signs this": a certificate, when
/// a user's root key signs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
}

/// "As of `at`, in seconds since the epoch, the targets couldn't be found."
///
/// A report, not a fact about them: a copy may yet turn up, or the same bytes
/// be made again, and then that's that, with nothing to retract. Until then,
/// it's why there's no point asking everyone for them again and again, why
/// what they're under can be kept without them, and what's to be looked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    at: u64,
}

/// "The targets hold the commands `add`, and no longer `del`, on `on`,
/// after the grants `prev`."
///
/// Targets are users, machines or roles; `on` is an anchor or role, or
/// the mesh when it's left out; `prev` is empty for a mesh's first.
///
/// Grants are one history per mesh, by `prev`, as an anchor's sets are,
/// so taking away has a place in it, which a tomb wouldn't. A command is
/// a lower case path from `/`, and covers the longer ones under it (see
/// `covers`). `stands` names, for a `del` of `/anchor/write`, the
/// targets' last sets on `on` that still count. Never dissolved: a grant
/// is an entry in a history, linked to by the grants after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    on: Option<Link>,
    /// Sorted and distinct, as `del` is, and in only one of them.
    add: Vec<String>,
    del: Vec<String>,
    /// Sorted by CID bytes and distinct, as `prev` is.
    stands: Vec<Link>,
    prev: Vec<Link>,
    /// When what it gives goes, in seconds since the epoch, by each
    /// machine's clock: only for a grant that gives, and takes nothing.
    until: Option<u64>,
}

/// "As of `at`, in milliseconds since the epoch, the target, an anchor,
/// is answered live by the node `node`, as its service `service`."
///
/// A route, not a program: which socket a service is, and as whom it
/// runs, is said only in that node's own configuration, so a serve claim
/// can't make any node run anything. `persist` says the server's states
/// are kept as sets. It counts as a set of the anchor would, for the view
/// `for_` names or its signer's own, and the latest that counts wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serve {
    /// The one anchor.
    target: Vec<Link>,
    node: Vec<u8>,
    service: String,
    persist: bool,
    at: u64,
    for_: Option<Link>,
}

/// "The targets are the same, read through the lens `as_`": with none,
/// as each codec's data model, otherwise as the ADL it names reads them
/// (see `same`).
///
/// An equivalence, so claims of one lens join: a target is the same as
/// whatever's the same as what it is. At least two targets, so it's never
/// dissolved. A lens is a name, so far; one that isn't known is kept, and
/// says nothing this can check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Same {
    /// Sorted by CID bytes and distinct, at least two.
    target: Vec<Link>,
    as_: Option<String>,
}

/// "The targets, and whatever they link to, however deep, are anyone's to
/// have."
///
/// In `serve` mode, they're given to whoever asks for them by CID; in
/// `announce`, the targets alone are announced as being here too, as
/// Kubo's `roots` strategy announces.
///
/// A mode is a name, so one this doesn't know is kept, and makes nothing
/// public. Like a keep, `n` counts which time the targets are made public,
/// since a tomb is forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    mode: String,
    /// Left out when 0.
    n: u64,
}

/// "The device whose key is among the targets goes by `name`."
///
/// A label for people, never what anything's let in by: whatever a device
/// is called, it's its key that's trusted. Its targets are the device's key
/// and its certificates, which every member holds, so a name reaches every
/// member, and no one else. A device names itself, by its hostname unless
/// told otherwise, and any device of the user may name another, so two
/// machines of one hostname can be told apart. Like a keep, `n` counts
/// which time it's named, since a tomb is forever: the name that counts
/// with the greatest `n` is the one it goes by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// Sorted by CID bytes and distinct.
    target: Vec<Link>,
    called: String,
    /// Left out when 0.
    n: u64,
}

/// Any claim this understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Group(Group),
    Keep(Keep),
    Set(Set),
    Tomb(Tomb),
    Sign(Sign),
    Device(Device),
    Lost(Lost),
    Grant(Grant),
    Serve(Serve),
    Same(Same),
    Public(Public),
    Name(Name),
}

/// Sort links by their bytes and drop repeats, making them a set.
fn set(links: impl IntoIterator<Item = Link>) -> Vec<Link> {
    let set: BTreeMap<Vec<u8>, Link> = links.into_iter().map(|link| (link.to_bytes(), link)).collect();
    set.into_values().collect()
}

fn links(links: &[Link]) -> Ipld {
    Ipld::List(links.iter().cloned().map(Ipld::Link).collect())
}

impl Group {
    /// A group of the targets, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>, into: Link) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, into })
    }

    pub fn target(&self) -> &[Link] { &self.target }

    /// What the targets belong to: the schema's `into`.
    pub const fn group(&self) -> &Link { &self.into }
}

impl Keep {
    /// A keep of the targets, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>) -> Option<Self> {
        Self::bounded(target, [])
    }

    /// A keep of the targets short of a frontier, if there are any.
    pub fn bounded(target: impl IntoIterator<Item = Link>, beyond: impl IntoIterator<Item = Link>) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, beyond: set(beyond), n: 0, copies: None })
    }

    /// The same keep, but the `n`th time.
    #[must_use]
    pub const fn again(mut self, n: u64) -> Self {
        self.n = n;
        self
    }

    pub const fn n(&self) -> u64 { self.n }

    /// The same keep, asking for `copies` failures to lose what it keeps,
    /// or whatever the mesh runs with; at least 1.
    #[must_use]
    pub fn with_copies(mut self, copies: Option<u64>) -> Self {
        self.copies = copies.filter(|&copies| copies > 0);
        self
    }

    pub const fn copies(&self) -> Option<u64> { self.copies }

    pub fn target(&self) -> &[Link] { &self.target }

    /// Where the keep's reach stops: what's linked to but not kept.
    pub fn beyond(&self) -> &[Link] { &self.beyond }
}

impl Set {
    /// A set of the anchors, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>, value: Link, at: u64) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, value, at, prev: None, wrote: Vec::new(), for_: None })
    }

    /// The same set, for this user's view of its anchors, or with none,
    /// its signer's own.
    #[must_use]
    pub fn for_view(mut self, owner: Option<Link>) -> Self {
        self.for_ = owner;
        self
    }

    /// Whose view of its anchors it's for, if not its signer's own.
    pub const fn owner(&self) -> Option<&Link> { self.for_.as_ref() }

    /// The same set, replacing the sets `prev`, empty for none, or, if
    /// none, every set before it, as an older build's.
    #[must_use]
    pub fn after(mut self, prev: Option<Vec<Link>>) -> Self {
        self.prev = prev.map(set);
        self
    }

    /// The same set, saying it wrote these paths, names joined by `/`.
    #[must_use]
    pub fn wrote(mut self, paths: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let paths: BTreeSet<Vec<u8>> = paths.into_iter().collect();
        self.wrote = paths.into_iter().collect();
        self
    }

    /// The paths it says it wrote, names joined by `/`.
    pub fn written(&self) -> &[Vec<u8>] { &self.wrote }

    /// The sets this replaces, if it says.
    pub fn prev(&self) -> Option<&[Link]> { self.prev.as_deref() }

    pub fn target(&self) -> &[Link] { &self.target }

    pub const fn value(&self) -> &Link { &self.value }

    pub const fn at(&self) -> u64 { self.at }
}

impl Tomb {
    /// A tomb for the targets, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target })
    }

    pub fn target(&self) -> &[Link] { &self.target }
}

impl Sign {
    /// A key's signature of claims, as of `at`, after its sign `prev`, if
    /// there are any claims.
    pub fn new(key: &crate::keys::Key, claims: impl IntoIterator<Item = Link>, prev: Option<Link>, at: u64) -> Option<Self> {
        let mut sign = Self::from_parts(claims, key.id(), at, prev, Vec::new())?;
        sign.sig = key.sign(&sign.message());
        Some(sign)
    }

    /// What's signed: the sign's encoding without the signature.
    fn message(&self) -> Vec<u8> {
        let mut map = self.fields();
        map.remove("sig");
        dagcbor::to_vec(&Ipld::Map(map)).unwrap_or_default()
    }

    fn fields(&self) -> BTreeMap<String, Ipld> {
        let mut map = BTreeMap::from([
            ("at".to_owned(), Ipld::Integer(self.at.into())),
            ("by".to_owned(), Ipld::Link(self.by.clone())),
            ("claim".to_owned(), Ipld::String("sign".to_owned())),
            ("sig".to_owned(), Ipld::Bytes(self.sig.clone())),
            ("target".to_owned(), links(&self.target)),
        ]);
        if let Some(prev) = &self.prev {
            map.insert("prev".to_owned(), Ipld::Link(prev.clone()));
        }
        map
    }

    /// A sign with the given parts, as stored, checked or not, if it signs
    /// any claims.
    pub fn from_parts(target: impl IntoIterator<Item = Link>, by: Link, at: u64, prev: Option<Link>, sig: Vec<u8>) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, by, at, prev, sig })
    }

    /// Whether the signature is `by`'s.
    pub fn verify(&self) -> bool {
        crate::keys::verify(&self.by, &self.message(), &self.sig)
    }

    /// The claims signed.
    pub fn signs(&self) -> &[Link] { &self.target }

    pub const fn by(&self) -> &Link { &self.by }

    pub const fn at(&self) -> u64 { self.at }

    /// The sign its key made before, if any.
    pub const fn prev(&self) -> Option<&Link> { self.prev.as_ref() }

    pub fn sig(&self) -> &[u8] { &self.sig }
}

impl Device {
    /// A certificate for the targets, if there are any and they're all keys.
    pub fn new(target: impl IntoIterator<Item = Link>) -> Option<Self> {
        let target = set(target);
        (!target.is_empty() && target.iter().all(crate::keys::is_key)).then_some(Self { target })
    }

    pub fn target(&self) -> &[Link] { &self.target }
}

impl Serve {
    /// A binding of an anchor to a node's service, if the service is named.
    pub fn new(anchor: Link, node: Vec<u8>, service: String, persist: bool, at: u64) -> Option<Self> {
        (!service.is_empty() && !node.is_empty()).then_some(Self { target: vec![anchor], node, service, persist, at, for_: None })
    }

    /// The same binding, for this user's view of the anchor, or with none,
    /// its signer's own.
    #[must_use]
    pub fn for_view(mut self, owner: Option<Link>) -> Self {
        self.for_ = owner;
        self
    }

    pub fn target(&self) -> &[Link] { &self.target }

    /// The anchor served.
    pub fn anchor(&self) -> Option<&Link> { self.target.first() }

    /// The serving node's peer ID, as bytes.
    pub fn node(&self) -> &[u8] { &self.node }

    pub fn service(&self) -> &str { &self.service }

    pub const fn persist(&self) -> bool { self.persist }

    pub const fn at(&self) -> u64 { self.at }

    pub const fn owner(&self) -> Option<&Link> { self.for_.as_ref() }
}

impl Same {
    /// None unless there are two targets or more, and the lens, if any,
    /// is named.
    pub fn new(target: impl IntoIterator<Item = Link>, lens: Option<String>) -> Option<Self> {
        let target = set(target);
        (target.len() >= 2 && lens.as_ref().is_none_or(|lens| !lens.is_empty())).then_some(Self { target, as_: lens })
    }

    pub fn target(&self) -> &[Link] { &self.target }

    /// How the targets are read; none for each codec's data model.
    pub fn lens(&self) -> Option<&str> { self.as_.as_deref() }
}

impl Public {
    /// Given to whoever asks by CID, and the targets announced.
    pub const ANNOUNCE: &str = "announce";
    /// Given to whoever asks by CID, never announced.
    pub const SERVE: &str = "serve";

    /// The targets made public in a mode, if there are any, and the mode's
    /// named.
    pub fn new(target: impl IntoIterator<Item = Link>, mode: impl Into<String>) -> Option<Self> {
        let (target, mode) = (set(target), mode.into());
        (!target.is_empty() && !mode.is_empty()).then_some(Self { target, mode, n: 0 })
    }

    /// The same, but the `n`th time.
    #[must_use]
    pub const fn again(mut self, n: u64) -> Self {
        self.n = n;
        self
    }

    pub fn target(&self) -> &[Link] { &self.target }

    pub fn mode(&self) -> &str { &self.mode }

    pub const fn n(&self) -> u64 { self.n }
}

impl Name {
    /// The longest a name may be, in characters.
    pub const LONGEST: usize = 64;

    /// The targets named, if there are any and the name's fit to show: not
    /// empty, not padded, no longer than `LONGEST`, and nothing that isn't
    /// printed, such as tabs and newlines, which would break up a listing.
    pub fn new(target: impl IntoIterator<Item = Link>, name: impl Into<String>) -> Option<Self> {
        let (target, name) = (set(target), name.into());
        let fit = !name.is_empty() && name.trim() == name && name.chars().count() <= Self::LONGEST && !name.chars().any(char::is_control);
        (!target.is_empty() && fit).then_some(Self { target, called: name, n: 0 })
    }

    /// The same, but the `n`th time.
    #[must_use]
    pub const fn again(mut self, n: u64) -> Self {
        self.n = n;
        self
    }

    pub fn target(&self) -> &[Link] { &self.target }

    pub fn name(&self) -> &str { &self.called }

    pub const fn n(&self) -> u64 { self.n }
}

impl Lost {
    /// A report of the targets lost, if there are any.
    pub fn new(target: impl IntoIterator<Item = Link>, at: u64) -> Option<Self> {
        let target = set(target);
        (!target.is_empty()).then_some(Self { target, at })
    }

    pub fn target(&self) -> &[Link] { &self.target }

    pub const fn at(&self) -> u64 { self.at }
}

/// A serve claim's fields, taken from its map.
/// A public claim's mode and time from its map, taken out of it.
fn parse_public(map: &mut BTreeMap<String, Ipld>, target: Vec<Link>) -> Option<Public> {
    let Ipld::String(mode) = map.remove("mode")? else {
        return None;
    };
    let n = match map.remove("n") {
        Some(Ipld::Integer(n)) => u64::try_from(n).ok().filter(|&n| n > 0)?,
        Some(_) => return None,
        None => 0,
    };
    Some(Public::new(target, mode)?.again(n))
}

/// A name claim's name and time from its map, taken out of it.
fn parse_name(map: &mut BTreeMap<String, Ipld>, target: Vec<Link>) -> Option<Name> {
    let Ipld::String(name) = map.remove("name")? else {
        return None;
    };
    let n = match map.remove("n") {
        Some(Ipld::Integer(n)) => u64::try_from(n).ok().filter(|&n| n > 0)?,
        Some(_) => return None,
        None => 0,
    };
    Some(Name::new(target, name)?.again(n))
}

fn parse_serve(map: &mut BTreeMap<String, Ipld>, target: &[Link]) -> Option<Serve> {
    let (Ipld::Bytes(node), Ipld::String(service), Ipld::Integer(at)) = (map.remove("node")?, map.remove("service")?, map.remove("at")?) else {
        return None;
    };
    let persist = match map.remove("persist") {
        Some(Ipld::Bool(true)) => true,
        None => false,
        Some(_) => return None,
    };
    let owner = match map.remove("for") {
        Some(Ipld::Link(owner)) => Some(owner),
        Some(_) => return None,
        None => None,
    };
    let [anchor] = target else {
        return None;
    };
    Some(Serve::new(anchor.clone(), node, service, persist, u64::try_from(at).ok()?)?.for_view(owner))
}

/// Whether a string is a command: `/`, or lower case names, of letters,
/// digits and `-`, each after a `/`.
pub fn is_command(command: &str) -> bool {
    command == "/" || command.strip_prefix('/').is_some_and(|rest| {
        rest.split('/').all(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    })
}

/// Whether holding one command allows another: it's the same, or a path
/// the other is under (`/anchor` covers `/anchor/write`, not
/// `/anchors`), and `/` covers everything.
pub fn covers(held: &str, command: &str) -> bool {
    held == "/" || held == command || command.strip_prefix(held).is_some_and(|rest| rest.starts_with('/'))
}

/// Sorted, distinct commands, if they're all commands.
fn commands(commands: impl IntoIterator<Item = String>) -> Option<Vec<String>> {
    let set: BTreeSet<String> = commands.into_iter().collect();
    set.iter().all(|command| is_command(command)).then(|| set.into_iter().collect())
}

impl Grant {
    /// A grant to the targets, on an anchor or role or the mesh, after
    /// the grants `prev`, if there are targets, commands are commands, and
    /// something's given or taken away, and nothing given overlaps
    /// (covers, or is covered by) anything taken away, so each grant means
    /// one thing. `stands` is only for taking `/anchor/write` away.
    pub fn new(
        target: impl IntoIterator<Item = Link>,
        on: Option<Link>,
        add: impl IntoIterator<Item = String>,
        del: impl IntoIterator<Item = String>,
        stands: impl IntoIterator<Item = Link>,
        prev: impl IntoIterator<Item = Link>,
    ) -> Option<Self> {
        let (target, add, del, stands) = (set(target), commands(add)?, commands(del)?, set(stands));
        (!target.is_empty() && (!add.is_empty() || !del.is_empty())).then_some(())?;
        (!add.iter().any(|given| del.iter().any(|taken| covers(given, taken) || covers(taken, given)))).then_some(())?;
        (stands.is_empty() || del.iter().any(|command| covers(command, "/anchor/write"))).then_some(())?;
        Some(Self { target, on, add, del, stands, prev: set(prev), until: None })
    }

    /// What it gives goes at a time, in seconds since the epoch: None, if
    /// it takes anything away, which lasts.
    pub fn until(mut self, until: Option<u64>) -> Option<Self> {
        (until.is_none() || self.del.is_empty()).then_some(())?;
        self.until = until;
        Some(self)
    }

    /// When what it gives goes, if it does.
    pub const fn expires(&self) -> Option<u64> { self.until }

    /// Whether what it gives still holds at a time.
    pub fn lasts(&self, now: u64) -> bool {
        self.until.is_none_or(|until| now < until)
    }

    pub fn target(&self) -> &[Link] { &self.target }

    /// The anchor or role it's about; none for the mesh.
    pub const fn on(&self) -> Option<&Link> { self.on.as_ref() }

    /// The commands given.
    pub fn add(&self) -> &[String] { &self.add }

    /// The commands taken away.
    pub fn del(&self) -> &[String] { &self.del }

    /// The targets' last sets that still count, taking `/anchor/write` away.
    pub fn stands(&self) -> &[Link] { &self.stands }

    /// The grants its signer had seen last; none for a mesh's first.
    pub fn prev(&self) -> &[Link] { &self.prev }
}

impl Claim {
    pub fn target(&self) -> &[Link] {
        match self {
            Self::Group(group) => group.target(),
            Self::Keep(keep) => keep.target(),
            Self::Set(set) => set.target(),
            Self::Tomb(tomb) => tomb.target(),
            Self::Sign(sign) => sign.signs(),
            Self::Device(device) => device.target(),
            Self::Lost(lost) => lost.target(),
            Self::Grant(grant) => grant.target(),
            Self::Serve(serve) => serve.target(),
            Self::Same(same) => same.target(),
            Self::Public(public) => public.target(),
            Self::Name(name) => name.target(),
        }
    }

    /// The claim's type, as its `claim` key says.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Group(_) => "group",
            Self::Keep(_) => "keep",
            Self::Set(_) => "set",
            Self::Tomb(_) => "tomb",
            Self::Sign(_) => "sign",
            Self::Device(_) => "device",
            Self::Lost(_) => "lost",
            Self::Grant(_) => "grant",
            Self::Serve(_) => "serve",
            Self::Same(_) => "same",
            Self::Public(_) => "public",
            Self::Name(_) => "name",
        }
    }

    fn to_ipld(&self) -> Ipld {
        let (kind, mut map) = match self {
            Self::Group(group) => ("group", BTreeMap::from([("into".to_owned(), Ipld::Link(group.into.clone()))])),
            Self::Keep(keep) => {
                let mut map = BTreeMap::new();
                if !keep.beyond.is_empty() {
                    map.insert("beyond".to_owned(), links(&keep.beyond));
                }
                if keep.n > 0 {
                    map.insert("n".to_owned(), Ipld::Integer(keep.n.into()));
                }
                if let Some(copies) = keep.copies {
                    map.insert("copies".to_owned(), Ipld::Integer(copies.into()));
                }
                ("keep", map)
            },
            Self::Set(set) => {
                let mut map = BTreeMap::from([
                    ("value".to_owned(), Ipld::Link(set.value.clone())),
                    ("at".to_owned(), Ipld::Integer(set.at.into())),
                ]);
                if let Some(prev) = &set.prev {
                    map.insert("prev".to_owned(), links(prev));
                }
                if !set.wrote.is_empty() {
                    map.insert("wrote".to_owned(), Ipld::List(set.wrote.iter().cloned().map(Ipld::Bytes).collect()));
                }
                if let Some(owner) = &set.for_ {
                    map.insert("for".to_owned(), Ipld::Link(owner.clone()));
                }
                ("set", map)
            },
            Self::Tomb(_) => ("tomb", BTreeMap::new()),
            Self::Sign(sign) => return Ipld::Map(sign.fields()),
            Self::Device(_) => ("device", BTreeMap::new()),
            Self::Lost(lost) => ("lost", BTreeMap::from([("at".to_owned(), Ipld::Integer(lost.at.into()))])),
            Self::Grant(grant) => {
                let strings = |commands: &[String]| Ipld::List(commands.iter().cloned().map(Ipld::String).collect());
                let mut map = BTreeMap::from([("prev".to_owned(), links(&grant.prev))]);
                if let Some(on) = &grant.on {
                    map.insert("on".to_owned(), Ipld::Link(on.clone()));
                }
                if !grant.add.is_empty() {
                    map.insert("add".to_owned(), strings(&grant.add));
                }
                if !grant.del.is_empty() {
                    map.insert("del".to_owned(), strings(&grant.del));
                }
                if !grant.stands.is_empty() {
                    map.insert("stands".to_owned(), links(&grant.stands));
                }
                if let Some(until) = grant.until {
                    map.insert("until".to_owned(), Ipld::Integer(until.into()));
                }
                ("grant", map)
            },
            Self::Serve(serve) => {
                let mut map = BTreeMap::from([
                    ("node".to_owned(), Ipld::Bytes(serve.node.clone())),
                    ("service".to_owned(), Ipld::String(serve.service.clone())),
                    ("at".to_owned(), Ipld::Integer(serve.at.into())),
                ]);
                if serve.persist {
                    map.insert("persist".to_owned(), Ipld::Bool(true));
                }
                if let Some(owner) = &serve.for_ {
                    map.insert("for".to_owned(), Ipld::Link(owner.clone()));
                }
                ("serve", map)
            },
            Self::Same(same) => {
                let mut map = BTreeMap::new();
                if let Some(lens) = &same.as_ {
                    map.insert("as".to_owned(), Ipld::String(lens.clone()));
                }
                ("same", map)
            },
            Self::Public(public) => {
                let mut map = BTreeMap::from([("mode".to_owned(), Ipld::String(public.mode.clone()))]);
                if public.n > 0 {
                    map.insert("n".to_owned(), Ipld::Integer(public.n.into()));
                }
                ("public", map)
            },
            Self::Name(name) => {
                let mut map = BTreeMap::from([("name".to_owned(), Ipld::String(name.called.clone()))]);
                if name.n > 0 {
                    map.insert("n".to_owned(), Ipld::Integer(name.n.into()));
                }
                ("name", map)
            },
        };
        map.insert("claim".to_owned(), Ipld::String(kind.to_owned()));
        map.insert("target".to_owned(), links(self.target()));
        Ipld::Map(map)
    }

    fn encode(&self) -> Vec<u8> {
        dagcbor::to_vec(&self.to_ipld()).unwrap_or_default()
    }

    /// Whether the claim is dissolved: one target, and small enough to be
    /// its own CID. A keep with a frontier never is, so a dissolved keep
    /// is always of all of its target.
    pub fn dissolves(&self) -> bool {
        let bounded = matches!(self, Self::Keep(keep) if !keep.beyond.is_empty());
        !bounded && !matches!(self, Self::Sign(_) | Self::Grant(_) | Self::Serve(_)) && self.target().len() == 1 && self.encode().len() <= IDENTITY_MAX
    }

    /// The claim as a dag-cbor block: an identity block if it dissolves,
    /// otherwise hashed.
    pub fn block(&self) -> Block {
        let data = self.encode();
        if self.dissolves()
            && let Some(block) = Block::identity(DAG_CBOR_CODEC, data.clone().into())
        {
            return block;
        }
        Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, MultihashFunc::Sha2_256), data.into())
    }

    /// The claim's CID, as `block` would make it.
    pub fn cid(&self) -> Link {
        AnyCid::V1(self.block().cid().clone())
    }

    /// The claim a dag-cbor block's bytes are, if they're exactly one:
    /// canonical, with a set of targets and nothing else.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let Ipld::Map(mut map) = dagcbor::from_slice(data).ok()? else {
            return None;
        };
        let Ipld::String(kind) = map.remove("claim")? else {
            return None;
        };
        let Ipld::List(target) = map.remove("target")? else {
            return None;
        };
        let target = link_list(target)?;
        let claim = match kind.as_str() {
            "group" => {
                let Ipld::Link(into) = map.remove("into")? else {
                    return None;
                };
                Self::Group(Group::new(target.clone(), into)?)
            },
            "keep" => {
                let beyond = match map.remove("beyond") {
                    Some(Ipld::List(beyond)) if !beyond.is_empty() => link_list(beyond)?,
                    Some(_) => return None,
                    None => Vec::new(),
                };
                let n = match map.remove("n") {
                    Some(Ipld::Integer(n)) => u64::try_from(n).ok().filter(|&n| n > 0)?,
                    Some(_) => return None,
                    None => 0,
                };
                let copies = match map.remove("copies") {
                    Some(Ipld::Integer(copies)) => Some(u64::try_from(copies).ok().filter(|&copies| copies > 0)?),
                    Some(_) => return None,
                    None => None,
                };
                Self::Keep(Keep::bounded(target.clone(), beyond)?.again(n).with_copies(copies))
            },
            "set" => {
                let (Ipld::Link(value), Ipld::Integer(at)) = (map.remove("value")?, map.remove("at")?) else {
                    return None;
                };
                let prev = match map.remove("prev") {
                    Some(Ipld::List(prev)) => Some(link_list(prev)?),
                    Some(_) => return None,
                    None => None,
                };
                let wrote = match map.remove("wrote") {
                    Some(Ipld::List(wrote)) if !wrote.is_empty() => wrote.into_iter()
                        .map(|path| match path {
                            Ipld::Bytes(path) => Some(path),
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>()?,
                    Some(_) => return None,
                    None => Vec::new(),
                };
                let owner = match map.remove("for") {
                    Some(Ipld::Link(owner)) => Some(owner),
                    Some(_) => return None,
                    None => None,
                };
                Self::Set(Set::new(target.clone(), value, u64::try_from(at).ok()?)?.after(prev).wrote(wrote).for_view(owner))
            },
            "tomb" => Self::Tomb(Tomb::new(target.clone())?),
            "lost" => {
                let Ipld::Integer(at) = map.remove("at")? else {
                    return None;
                };
                Self::Lost(Lost::new(target.clone(), u64::try_from(at).ok()?)?)
            },
            "sign" => {
                let (Ipld::Link(by), Ipld::Integer(at), Ipld::Bytes(sig)) = (map.remove("by")?, map.remove("at")?, map.remove("sig")?) else {
                    return None;
                };
                let prev = match map.remove("prev") {
                    Some(Ipld::Link(prev)) => Some(prev),
                    Some(_) => return None,
                    None => None,
                };
                Self::Sign(Sign::from_parts(target.clone(), by, u64::try_from(at).ok()?, prev, sig)?)
            },
            "device" => Self::Device(Device::new(target.clone())?),
            "grant" => Self::Grant(parse_grant(&mut map, target.clone())?),
            "serve" => Self::Serve(parse_serve(&mut map, &target)?),
            "same" => {
                let lens = match map.remove("as") {
                    Some(Ipld::String(lens)) => Some(lens),
                    Some(_) => return None,
                    None => None,
                };
                Self::Same(Same::new(target.clone(), lens)?)
            },
            "public" => Self::Public(parse_public(&mut map, target.clone())?),
            "name" => Self::Name(parse_name(&mut map, target.clone())?),
            _ => return None,
        };
        // Nothing else, sorted and distinct already, and canonical dag-cbor
        (map.is_empty() && claim.target() == target && claim.encode() == data).then_some(claim)
    }
}

/// A grant's fields but its type and targets, taken from its map.
fn parse_grant(map: &mut BTreeMap<String, Ipld>, target: Vec<Link>) -> Option<Grant> {
    let mut list = |name: &str| match map.remove(name) {
        Some(Ipld::List(list)) if !list.is_empty() => Some(Some(list)),
        Some(_) => None,
        None => Some(None),
    };
    let strings = |list: Option<Vec<Ipld>>| {
        list.unwrap_or_default().into_iter()
            .map(|command| match command {
                Ipld::String(command) => Some(command),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
    };
    let (add, del) = (strings(list("add")?)?, strings(list("del")?)?);
    let stands = link_list(list("stands")?.unwrap_or_default())?;
    let Ipld::List(prev) = map.remove("prev")? else {
        return None;
    };
    let on = match map.remove("on") {
        Some(Ipld::Link(on)) => Some(on),
        Some(_) => return None,
        None => None,
    };
    let until = match map.remove("until") {
        Some(Ipld::Integer(until)) => Some(u64::try_from(until).ok()?),
        Some(_) => return None,
        None => None,
    };
    Grant::new(target, on, add, del, stands, link_list(prev)?)?.until(until)
}

fn link_list(list: Vec<Ipld>) -> Option<Vec<Link>> {
    list.into_iter()
        .map(|link| match link {
            Ipld::Link(link) => Some(link),
            _ => None,
        })
        .collect()
}

/// A new anchor: an identity CID of 16 random bytes, marked as an anchor.
pub fn anchor() -> std::io::Result<Link> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(std::io::Error::other)?;
    anchor_of(nonce)
}

/// A user's root anchor, the top of what they've named: the anchor whose
/// nonce is a hash of their key, so every device of theirs finds the same
/// one, and no claim need say which it is.
pub fn root_anchor(key: &Link) -> std::io::Result<Link> {
    use sha2::Digest as _;
    let hash = sha2::Sha256::new().chain_update(b"holokeep root anchor\0").chain_update(key.to_bytes()).finalize();
    anchor_of(hash.first_chunk::<16>().copied().unwrap_or_default())
}

/// An anchor's nonce, if it's an anchor and not a view of one.
pub fn anchor_nonce(anchor: &Link) -> Option<[u8; 16]> {
    match parse_anchor(anchor)? {
        (nonce, None) => Some(nonce),
        _ => None,
    }
}

/// The anchor with this nonce.
pub fn anchor_of(nonce: [u8; 16]) -> std::io::Result<Link> {
    let value = Ipld::Map(BTreeMap::from([("anchor".to_owned(), Ipld::Bytes(nonce.to_vec()))]));
    let data = dagcbor::to_vec(&value).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    Block::identity(DAG_CBOR_CODEC, data.into())
        .map(|block| AnyCid::V1(block.cid().clone()))
        .ok_or_else(|| std::io::Error::other("an anchor too large to be an identity"))
}

/// Whether a CID is an anchor, or a user's view of one (see `view`).
pub fn is_anchor(cid: &Link) -> bool {
    parse_anchor(cid).is_some()
}

/// An anchor's nonce, and whose view of it the CID is, if it's a view.
fn parse_anchor(cid: &Link) -> Option<([u8; 16], Option<Link>)> {
    (cid.codec() == DAG_CBOR_CODEC && cid.hashcode() == IDENTITY).then_some(())?;
    let Ok(Ipld::Map(mut map)) = dagcbor::from_slice(cid.digest_ref()) else {
        return None;
    };
    let Some(Ipld::Bytes(nonce)) = map.remove("anchor") else {
        return None;
    };
    let nonce: [u8; 16] = nonce.try_into().ok()?;
    match (map.remove("of"), map.is_empty()) {
        (None, true) => Some((nonce, None)),
        (Some(Ipld::Link(owner)), true) if owner.codec() == 0x72 => Some((nonce, Some(owner))),
        _ => None,
    }
}

/// A user's view of an anchor, as a CID of its own, an anchor too.
///
/// It's the identity CID of `{"anchor": <its nonce>, "of": <user>}`. What
/// it is is what counts in their view of the anchor, which whoever they've
/// given `/anchor/read` may see, and whoever they've given `/anchor/write`
/// may set. None if the anchor's already a view, or isn't an anchor.
pub fn view(anchor: &Link, owner: &Link) -> Option<Link> {
    let (nonce, None) = parse_anchor(anchor)? else {
        return None;
    };
    let value = Ipld::Map(BTreeMap::from([("anchor".to_owned(), Ipld::Bytes(nonce.to_vec())), ("of".to_owned(), Ipld::Link(owner.clone()))]));
    let data = dagcbor::to_vec(&value).ok()?;
    Block::identity(DAG_CBOR_CODEC, data.into()).map(|block| AnyCid::V1(block.cid().clone()))
}

/// The anchor a view is of, and whose view it is, if the CID is a view.
pub fn viewed(cid: &Link) -> Option<(Link, Link)> {
    let (nonce, Some(owner)) = parse_anchor(cid)? else {
        return None;
    };
    Some((anchor_of(nonce).ok()?, owner))
}

/// The anchor a symlink's target is, if it's `/anchors/<anchor>`: one
/// to the anchor itself, not into it, which the mount shows as the anchor
/// and which references it.
pub fn anchor_target(target: &[u8]) -> Option<Link> {
    let name = target.strip_prefix(b"/anchors/")?;
    let name = name.strip_suffix(b"/").unwrap_or(name);
    std::str::from_utf8(name).ok()?.parse::<Link>().ok().filter(is_anchor)
}

/// The CID of a simple tag: its name, as a raw identity CID.
pub fn tag(name: &str) -> Option<Link> {
    (!name.is_empty()).then_some(())?;
    Block::identity(RAW_CODEC, name.as_bytes().into()).map(|block| AnyCid::V1(block.cid().clone()))
}

/// A simple tag's name, if the CID is one.
pub fn tag_name(cid: &Link) -> Option<&str> {
    (cid.codec() == RAW_CODEC && cid.hashcode() == IDENTITY).then_some(())?;
    std::str::from_utf8(cid.digest_ref()).ok()
}

/// The claim an identity CID is, if it's a dissolved one.
pub fn dissolved(cid: &Link) -> Option<Claim> {
    (cid.codec() == DAG_CBOR_CODEC && cid.hashcode() == IDENTITY).then_some(())?;
    Claim::parse(cid.digest_ref()).filter(Claim::dissolves)
}

/// A dissolved claim's CID from its bytes.
pub fn dissolved_cid(data: &[u8]) -> Option<Link> {
    let hash = Multihash::try_wrap(IDENTITY, data).ok()?;
    Some(AnyCid::V1(Cidv1::new(DAG_CBOR_CODEC, hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(data: &[u8]) -> Link {
        AnyCid::V1(Block::hash(Cidv1Spec::default(), data.into()).cid().clone())
    }

    fn group(target: &[Link], name: &str) -> Claim {
        Claim::Group(Group::new(target.iter().cloned(), tag(name).expect("tag")).expect("group"))
    }

    #[test]
    fn a_grant_round_trips_and_is_never_dissolved() {
        let user = crate::keys::Key::generate().expect("key").id();
        let cmds = |list: &[&str]| list.iter().map(|&c| c.to_owned()).collect::<Vec<_>>();
        let first = Grant::new([user.clone()], None, cmds(&["/"]), [], [], []).expect("grant");
        let claim = Claim::Grant(first);
        assert!(!claim.dissolves(), "a grant is an entry in a history");
        assert_eq!(Claim::parse(claim.block().data()), Some(claim.clone()));
        let next = Grant::new([user.clone(), cid(b"m")], Some(cid(b"a")), cmds(&["/mesh/user", "/anchor/read"]), cmds(&["/anchor/write"]), [cid(b"s")], [claim.cid()])
            .expect("grant");
        assert_eq!(next.add(), ["/anchor/read", "/mesh/user"], "sorted");
        let next = Claim::Grant(next);
        assert_eq!(Claim::parse(next.block().data()), Some(next));
        // Nothing given or taken, both at once, not commands, or stands without writes taken away
        assert!(Grant::new([user.clone()], None, [], [], [], []).is_none());
        assert!(Grant::new([user.clone()], None, cmds(&["/mesh"]), cmds(&["/mesh"]), [], []).is_none());
        // Nor anything given overlapping anything taken away, either way
        assert!(Grant::new([user.clone()], None, cmds(&["/mesh"]), cmds(&["/mesh/machine"]), [], []).is_none());
        assert!(Grant::new([user.clone()], None, cmds(&["/mesh/user"]), cmds(&["/mesh"]), [], []).is_none());
        assert!(Grant::new([user.clone()], None, cmds(&["/mesh/user"]), cmds(&["/mesh/machine"]), [], []).is_some());
        assert!(Grant::new([user.clone()], None, cmds(&["/Mesh"]), [], [], []).is_none());
        assert!(Grant::new([user.clone()], None, cmds(&["/mesh/"]), [], [], []).is_none());
        assert!(Grant::new([user], None, [], cmds(&["/anchor/read"]), [cid(b"s")], []).is_none());
    }

    #[test]
    fn a_grant_may_give_till_a_time() {
        let user = crate::keys::Key::generate().expect("key").id();
        let read = || vec!["/anchor/read".to_owned()];
        let lasting = Grant::new([user.clone()], Some(cid(b"a")), read(), [], [], []).expect("grant");
        let brief = lasting.clone().until(Some(1_800_000_000)).expect("until");
        assert!(lasting.lasts(u64::MAX) && brief.lasts(1_799_999_999) && !brief.lasts(1_800_000_000));
        assert_eq!(brief.expires(), Some(1_800_000_000));
        let (lasting, brief) = (Claim::Grant(lasting), Claim::Grant(brief));
        assert_eq!(Claim::parse(brief.block().data()), Some(brief.clone()));
        assert_ne!(lasting.cid(), brief.cid());
        assert_eq!(Claim::parse(lasting.block().data()), Some(lasting), "no until, as before");
        // Taking away lasts
        assert!(Grant::new([user], Some(cid(b"a")), [], read(), [], []).expect("grant").until(Some(1)).is_none());
    }

    #[test]
    fn a_public_claim_names_its_mode_and_counts_again() {
        let (a, b) = (cid(b"a"), cid(b"b"));
        assert!(Public::new([], Public::ANNOUNCE).is_none());
        assert!(Public::new([a.clone()], "").is_none(), "a mode has a name");
        let announced = Claim::Public(Public::new([a.clone()], Public::ANNOUNCE).expect("public"));
        let served = Claim::Public(Public::new([a.clone()], Public::SERVE).expect("public"));
        let again = Claim::Public(Public::new([a.clone()], Public::ANNOUNCE).expect("public").again(1));
        let both = Claim::Public(Public::new([b, a], "pigeons").expect("a mode not known is kept"));
        for claim in [&announced, &served, &again, &both] {
            assert_eq!(Claim::parse(claim.block().data()).as_ref(), Some(claim));
        }
        assert!(announced.dissolves(), "one target, small");
        assert_ne!(announced.cid(), served.cid());
        assert_ne!(announced.cid(), again.cid());
        assert_eq!(Claim::Public(Public::new([cid(b"a")], Public::ANNOUNCE).expect("public").again(0)).cid(), announced.cid(), "0 is left out");
    }

    #[test]
    fn a_name_claim_is_fit_to_show_and_counts_again() {
        let (key, cert) = (cid(b"key"), cid(b"cert"));
        for unfit in ["", " theseus", "theseus\n", "the\tseus", &"x".repeat(Name::LONGEST + 1)] {
            assert!(Name::new([key.clone()], unfit).is_none(), "{unfit:?}");
        }
        assert!(Name::new([], "theseus").is_none());
        let named = Claim::Name(Name::new([key.clone(), cert.clone()], "theseus").expect("name"));
        let again = Claim::Name(Name::new([cert, key.clone()], "theseus 2").expect("name").again(1));
        let wide = Claim::Name(Name::new([key], "テセウス").expect("any script"));
        for claim in [&named, &again, &wide] {
            assert_eq!(Claim::parse(claim.block().data()).as_ref(), Some(claim));
        }
        assert_ne!(named.cid(), again.cid());
    }

    #[test]
    fn a_same_claim_names_its_lens_and_is_never_dissolved() {
        let (a, b) = (cid(b"a"), cid(b"b"));
        // One target is nothing to say, and a lens has a name
        assert!(Same::new([a.clone(), a.clone()], None).is_none());
        assert!(Same::new([a.clone(), b.clone()], Some(String::new())).is_none());
        let plain = Claim::Same(Same::new([b.clone(), a.clone()], None).expect("same"));
        let unixfs = Claim::Same(Same::new([a.clone(), b.clone()], Some("unixfs".to_owned())).expect("same"));
        assert_eq!(plain.target(), Same::new([a, b], None).expect("same").target(), "a set");
        for claim in [plain.clone(), unixfs.clone()] {
            assert!(!claim.dissolves());
            assert_eq!(Claim::parse(claim.block().data()), Some(claim));
        }
        assert_ne!(plain.cid(), unixfs.cid());
        let Ipld::Map(map) = plain.to_ipld() else { panic!("a map") };
        assert!(!map.contains_key("as"), "no lens is each codec's data model");
    }

    #[test]
    fn commands_cover_the_paths_under_them() {
        assert!(covers("/", "/mesh/user"));
        assert!(covers("/mesh", "/mesh/user"));
        assert!(covers("/mesh/user", "/mesh/user"));
        assert!(!covers("/mesh", "/meshes"));
        assert!(!covers("/mesh/user", "/mesh"));
        assert!(is_command("/") && is_command("/anchor/write") && !is_command("anchor") && !is_command("//"));
    }

    #[test]
    fn a_lost_claim_says_when() {
        let serve = Claim::Serve(Serve::new(cid(b"anchor"), b"peer".to_vec(), "notes".into(), true, 1_793_750_400_000).expect("serve").for_view(Some(cid(b"owner"))));
        assert_eq!(Claim::parse(serve.block().data()), Some(serve.clone()));
        assert!(!serve.dissolves(), "a route, kept whole");
        let bare = Claim::Serve(Serve::new(cid(b"anchor"), b"peer".to_vec(), "notes".into(), false, 1).expect("serve"));
        assert_eq!(Claim::parse(bare.block().data()), Some(bare));
        assert!(Serve::new(cid(b"anchor"), b"peer".to_vec(), String::new(), false, 1).is_none(), "a service has a name");
        assert!(Serve::new(cid(b"anchor"), Vec::new(), "notes".into(), false, 1).is_none(), "and a node");
        let lost = Claim::Lost(Lost::new([cid(b"a")], 1_793_750_400).expect("lost"));
        assert!(lost.dissolves());
        assert_eq!(Claim::parse(lost.block().data()), Some(lost.clone()));
        assert_eq!(lost.kind(), "lost");
        assert_ne!(lost.cid(), Claim::Lost(Lost::new([cid(b"a")], 1_793_750_401).expect("lost")).cid(), "each time's a claim of its own");
        assert!(Lost::new([], 1).is_none());
    }

    #[test]
    fn tags_are_identity_cids() {
        let music = tag("music").expect("tag");
        assert_eq!(tag_name(&music), Some("music"));
        // As Kubo inlines it: `ipfs add --inline --raw-leaves`
        assert_eq!(music.to_string(), "bafkqablnovzwsyy");
        assert_eq!(tag(""), None);
        assert!(tag(&"x".repeat(MAX_NAME)).is_some());
        assert_eq!(tag(&"x".repeat(MAX_NAME + 1)), None);
        assert_eq!(tag_name(&cid(b"music")), None);
    }

    #[test]
    fn targets_are_a_set() {
        let (a, b) = (cid(b"a"), cid(b"b"));
        let one = group(&[b.clone(), a.clone(), b.clone()], "t");
        let other = group(&[a, b], "t");
        assert_eq!(one.block(), other.block());
        assert_eq!(one.target().len(), 2);
        assert_eq!(Group::new([], tag("t").expect("tag")), None);
        assert_eq!(Tomb::new([]), None);
    }

    #[test]
    fn small_claims_dissolve() {
        let single = group(&[cid(b"a")], "music");
        assert!(single.dissolves());
        let block = single.block();
        assert_eq!(block.cid().hashcode(), IDENTITY);
        assert_eq!(dissolved(&single.cid()), Some(single.clone()));
        // A tomb for it still fits, though it holds the whole claim
        let tomb = Claim::Tomb(Tomb::new([single.cid()]).expect("tomb"));
        assert!(tomb.dissolves(), "{} bytes", tomb.encode().len());
        assert_eq!(dissolved(&tomb.cid()), Some(tomb));

        // Two targets, or a name too long to fit, are hashed
        let pair = group(&[cid(b"a"), cid(b"b")], "music");
        assert!(!pair.dissolves());
        assert_eq!(pair.block().cid().hashcode(), 0x12);
        let long = group(&[cid(b"a")], &"x".repeat(100));
        assert!(!long.dissolves());
        assert_eq!(dissolved(&long.cid()), None);
    }

    #[test]
    fn signs_cover_many_claims_and_name_the_one_before() {
        let key = crate::keys::Key::generate().expect("key");
        let (a, b) = (cid(b"a"), cid(b"b"));
        let first = Sign::new(&key, [b.clone(), a.clone(), b.clone()], None, 1).expect("sign");
        assert_eq!(first.signs(), set([a.clone(), b]).as_slice());
        let first = Claim::Sign(first);
        let second = Sign::new(&key, [a], Some(first.cid()), 2).expect("sign");
        for sign in [first, Claim::Sign(second.clone())] {
            let parsed = Claim::parse(sign.block().data()).expect("parse");
            assert!(matches!(&parsed, Claim::Sign(parsed) if parsed.verify()));
            assert_eq!(parsed, sign);
        }
        assert!(second.prev().is_some());
        assert!(Sign::new(&key, [], None, 3).is_none());
    }

    #[test]
    fn parses_only_canonical_claims() {
        let claim = group(&[cid(b"a"), cid(b"b")], "t");
        assert_eq!(Claim::parse(claim.block().data()), Some(claim.clone()));
        let tomb = Claim::Tomb(Tomb::new([cid(b"a")]).expect("tomb"));
        assert_eq!(Claim::parse(tomb.block().data()), Some(tomb));

        let with = |key: &str, value: Ipld| {
            let Ipld::Map(mut map) = claim.to_ipld() else { panic!("a claim is a map") };
            map.insert(key.to_owned(), value);
            dagcbor::to_vec(&Ipld::Map(map)).expect("encode")
        };
        for (label, data) in [
            ("unsorted", with("target", links(&claim.target().iter().rev().cloned().collect::<Vec<_>>()))),
            ("repeated", with("target", links(&[cid(b"a"), cid(b"a")]))),
            ("empty", with("target", links(&[]))),
            ("unknown claim", with("claim", Ipld::String("same".into()))),
            ("an extra key", with("when", Ipld::String("now".into()))),
            ("not a link", with("into", Ipld::String("t".into()))),
            ("a tomb with into", with("claim", Ipld::String("tomb".into()))),
        ] {
            assert_eq!(Claim::parse(&data), None, "{label}");
        }
    }

    #[test]
    fn keeps_round_trip_and_dissolve() {
        let keep = Claim::Keep(Keep::new([cid(b"b"), cid(b"a"), cid(b"a")]).expect("keep"));
        assert_eq!(keep.target().len(), 2, "a set");
        assert!(!keep.dissolves(), "two targets");
        assert_eq!(Claim::parse(keep.block().data()), Some(keep));
        let one = Claim::Keep(Keep::new([cid(b"a")]).expect("keep"));
        assert!(one.dissolves());
        assert_eq!(dissolved(&one.cid()), Some(one));
        assert!(Keep::new([]).is_none());
    }

    #[test]
    fn frontiers_bound_keeps_and_never_dissolve() {
        let keep = Keep::bounded([cid(b"a")], [cid(b"z"), cid(b"y"), cid(b"z")]).expect("keep");
        assert_eq!(keep.beyond().len(), 2, "a set");
        let bounded = Claim::Keep(keep);
        assert!(!bounded.dissolves(), "a dissolved keep is of everything");
        assert_eq!(bounded.cid().hashcode(), 0x12);
        assert_eq!(Claim::parse(bounded.block().data()), Some(bounded));
        // No frontier is no field, so it's the same claim as an unbounded keep
        assert_eq!(Claim::Keep(Keep::bounded([cid(b"a")], []).expect("keep")).cid(), Claim::Keep(Keep::new([cid(b"a")]).expect("keep")).cid());
        // An empty frontier isn't canonical
        let empty = dagcbor::to_vec(&Ipld::Map(BTreeMap::from([
            ("beyond".to_owned(), Ipld::List(Vec::new())),
            ("claim".to_owned(), Ipld::String("keep".into())),
            ("target".to_owned(), Ipld::List(vec![Ipld::Link(cid(b"a"))])),
        ])))
        .expect("encode");
        assert_eq!(Claim::parse(&empty), None);
    }

    #[test]
    fn sets_round_trip_and_dissolve() {
        let anchor = super::anchor().expect("anchor");
        let set = Claim::Set(Set::new([anchor], cid(b"v"), 1_800_000_000).expect("set"));
        assert!(set.dissolves(), "an anchor and a value fit");
        assert_eq!(dissolved(&set.cid()), Some(set.clone()));
        assert_eq!(Claim::parse(set.block().data()), Some(set));
        assert!(Set::new([], cid(b"v"), 0).is_none());
    }

    #[test]
    fn a_set_for_another_users_view_says_so() {
        let anchor = super::anchor().expect("anchor");
        let owner = crate::keys::Key::generate().expect("key").id();
        let set = Claim::Set(Set::new([anchor.clone()], cid(b"v"), 1).expect("set").after(Some(Vec::new())).for_view(Some(owner.clone())));
        let Claim::Set(parsed) = Claim::parse(set.block().data()).expect("parses") else { panic!("a set") };
        assert_eq!(parsed.owner(), Some(&owner));
        assert_ne!(set.cid(), Claim::Set(Set::new([anchor], cid(b"v"), 1).expect("set").after(Some(Vec::new()))).cid());
    }

    #[test]
    fn a_view_of_an_anchor_is_an_anchor_naming_both() {
        let anchor = super::anchor().expect("anchor");
        let owner = crate::keys::Key::generate().expect("key").id();
        let view = super::view(&anchor, &owner).expect("a view");
        assert!(super::is_anchor(&view) && view != anchor);
        assert_eq!(super::viewed(&view), Some((anchor.clone(), owner.clone())));
        assert_eq!(super::viewed(&anchor), None);
        assert_eq!(super::view(&view, &owner), None, "not a view of a view");
        assert_eq!(super::view(&anchor, &owner), Some(view), "the same every time");
        assert!(super::view(&cid(b"x"), &owner).is_none());
    }

    #[test]
    fn sets_say_what_they_wrote_only_when_they_did() {
        let anchor = super::anchor().expect("anchor");
        let plain = Claim::Set(Set::new([anchor.clone()], cid(b"v"), 1).expect("set").after(Some(Vec::new())));
        let wrote = Claim::Set(Set::new([anchor], cid(b"v"), 1).expect("set").after(Some(Vec::new())).wrote([b"b/page".to_vec(), b"a".to_vec(), b"a".to_vec()]));
        assert!(!Claim::Set(Set::new([super::anchor().expect("anchor")], cid(b"v"), 1).expect("set").wrote([])).encode().windows(5).any(|w| w == b"wrote"), "left out when empty");
        assert_ne!(plain.cid(), wrote.cid());
        let Claim::Set(set) = Claim::parse(wrote.block().data()).expect("parses") else { panic!("a set") };
        assert_eq!(set.written(), [b"a".to_vec(), b"b/page".to_vec()], "sorted and distinct");
        assert_eq!(dissolved(&wrote.cid()).or_else(|| Claim::parse(wrote.block().data())), Some(wrote));
    }

    #[test]
    fn keeps_again_are_new_claims() {
        let first = Claim::Keep(Keep::new([cid(b"a")]).expect("keep"));
        let again = Claim::Keep(Keep::new([cid(b"a")]).expect("keep").again(1));
        assert_ne!(first.cid(), again.cid());
        assert!(again.dissolves());
        assert_eq!(dissolved(&again.cid()), Some(again));
        assert_eq!(Claim::Keep(Keep::new([cid(b"a")]).expect("keep").again(0)).cid(), first.cid(), "0 is left out");

        // How many copies, left out for the mesh's own
        let two = Claim::Keep(Keep::new([cid(b"a")]).expect("keep").with_copies(Some(2)));
        assert_ne!(two.cid(), first.cid());
        assert_eq!(Claim::parse(two.block().data()), Some(two.clone()), "round trips");
        assert_eq!(Claim::Keep(Keep::new([cid(b"a")]).expect("keep").with_copies(None)).cid(), first.cid());
        assert_eq!(Claim::Keep(Keep::new([cid(b"a")]).expect("keep").with_copies(Some(0))).cid(), first.cid(), "0 isn't a count yet");
        assert!(two.dissolves(), "small still");
    }

    #[test]
    fn a_set_says_which_sets_it_replaces_or_that_its_an_older_builds() {
        let anchor = anchor().expect("anchor");
        let old = Set::new([anchor.clone()], cid(b"v"), 1).expect("set");
        let none = old.clone().after(Some(Vec::new()));
        let after = old.clone().after(Some(vec![cid(b"b"), cid(b"a"), cid(b"a")]));
        let cids: Vec<_> = [&old, &none, &after].iter().map(|set| Claim::Set((*set).clone()).cid()).collect();
        assert!(cids[0] != cids[1] && cids[1] != cids[2] && cids[0] != cids[2], "no prev, an empty one, and some, are three claims");
        for set in [old, none, after] {
            let claim = Claim::Set(set.clone());
            assert_eq!(Claim::parse(claim.block().data()), Some(claim), "round trips");
        }
        let set = Set::new([anchor], cid(b"v"), 1).expect("set").after(Some(vec![cid(b"b"), cid(b"a"), cid(b"b")]));
        let prev = set.prev().expect("prev");
        assert_eq!(prev.len(), 2, "distinct");
        assert!(prev.windows(2).all(|pair| pair.first().map(Link::to_bytes) < pair.last().map(Link::to_bytes)), "sorted by CID bytes");
    }
}
