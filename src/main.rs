use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};


use holokeep::{car, claim, dag, export, health, links};
use holokeep::chunker::ChunkerType;
use holokeep::dag::{BalancedLayout, BlockSink, NullSink};
use holokeep::import::Importer;
use holokeep::model::Link;
use holokeep::cid::{BaseCid, CidRef};
use holokeep::store::{Compact, Copying, InPlace, Outcome, RefIndex, Catalog};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The repo to use [default: ~/.holokeep]
    #[arg(long, global = true, env = "HOLOKEEP_REPO")]
    repo: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Add a file or directory as UnixFS, like `ipfs add` with the
    /// unixfs-v1-2025 profile. Use "-" for stdin.
    Add {
        path: PathBuf,
        /// Only compute CIDs, storing nothing (`ipfs add --only-hash`)
        #[arg(short = 'n', long)]
        only_hash: bool,
        /// Include files and directories starting with "."
        #[arg(short = 'H', long)]
        hidden: bool,
        /// Only print the root CID
        #[arg(short, long)]
        quiet: bool,
        /// Chunking algorithm, only size-[bytes] is supported
        #[arg(short = 's', long, default_value = "size-1048576")]
        chunker: String,
        /// Maximum links per file node
        #[arg(long, default_value_t = dag::FILE_WIDTH)]
        max_file_links: usize,
        /// Keep files' contents where they are rather than copying them
        /// into the repo, like Kubo's filestore. The blocks are only
        /// readable while the files are unchanged.
        #[arg(long, conflicts_with = "only_hash")]
        nocopy: bool,
        /// Don't keep what's added: without a keep, what nothing kept links
        /// to may in time be collected
        #[arg(long)]
        no_keep: bool,
    },
    /// Write a file's contents to stdout, like `ipfs cat`
    Cat {
        cid: Link,
    },
    /// Write a file, directory or symlink out, like `ipfs get`
    Get {
        cid: Link,
        /// Where to write it [default: the CID]
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List the CIDs a block links to, like `ipfs refs`, or with --back,
    /// the CIDs of every block in the repo which links to it
    Refs {
        cid: Link,
        /// Blocks linking to this one, rather than those it links to
        #[arg(long)]
        back: bool,
    },
    /// Tag blocks, and find them by their tags
    #[command(subcommand)]
    Tag(TagCommand),
    /// Keep blocks and what they link to, which `hk add` does for what it
    /// adds, or stop
    #[command(subcommand)]
    Keep(KeepCommand),
    /// Say what's been lost, for what can't be found anywhere
    #[command(subcommand)]
    Lost(LostCommand),
    /// Say blocks are the same, read through a lens, and find what is: a
    /// file however it's chunked, a directory basic or a HAMT, a value in
    /// dag-cbor or dag-json, by any hash function
    #[command(subcommand)]
    Same(SameCommand),
    /// Make things anyone's to have: given to whoever asks for them by CID,
    /// and announced, or not. Everything else is private
    #[command(subcommand)]
    Public(PublicCommand),
    /// Keep things with friends, encrypted: in this account's vault, which
    /// joins their protected meshes
    #[command(subcommand)]
    Protect(ProtectCommand),
    /// Share by capability: a DAG sealed, which whoever holds its
    /// capability can read, and whoever holds only the ciphertext can't
    #[command(subcommand)]
    Cap(CapCommand),
    /// Paths of the soup as the mount shows them, from outside it: what's
    /// at one, and unlinking or promoting it in one set. A path's one
    /// under a running mount, or else of the soup itself: a name the root
    /// has, or anchors/<anchor>/…
    #[command(subcommand)]
    Fs(FsCommand),
    /// Print the account this acts for: the host's uid, the key the repo
    /// signs with for it, and its user, if it's in a mesh. In a repo
    /// another user owns, `hk keep` and `hk tag` act for an account of
    /// your own, through its running node
    Whoami,
    /// Work with anchors: empty identities, which are whatever they were
    /// last set to
    #[command(subcommand)]
    Anchor(AnchorCommand),
    /// The user's devices: the nodes its root key certified
    #[command(subcommand)]
    Device(DeviceCommand),
    /// Work with raw blocks
    #[command(subcommand)]
    Block(BlockCommand),
    /// Work with whole DAGs
    #[command(subcommand)]
    Dag(DagCommand),
    /// Work with git repositories' objects, as `git-raw` blocks
    #[command(subcommand)]
    Git(GitCommand),
    /// Work with the repo itself
    #[command(subcommand)]
    Repo(RepoCommand),
    /// Keep copies of blocks on other volumes, such as other drives
    #[command(subcommand)]
    Volume(VolumeCommand),
    /// The repo's configuration, `config.toml` in its directory: what its
    /// nodes are tuned to and what they mount, so a service runs with no
    /// flags
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Link this repo's machines into a private mesh
    #[cfg(feature = "net")]
    Node(NodeArgs),
    /// Serve anchors live, from a node's services over 9P2000.L, rather
    /// than from blocks: see the wiki's Servers page. Only the route is
    /// said here; what a service is, a node's own config says
    #[cfg(feature = "net")]
    #[command(subcommand)]
    Serve(ServeCommand),
    /// Mount the soup as a filesystem until interrupted: the root anchor's
    /// names, beside cid/<cid>, anchors/<anchor> and tags/<tag>/<cid>.
    /// What's written to an anchor is committed, setting it, once it's
    /// closed or synced and quiet a second, less often if it's written to
    /// often; a directory made at the top is a new anchor, and a link to
    /// an anchor mounts it.
    #[cfg(feature = "fuse")]
    Mount {
        /// An empty directory to mount it on [default: the one `[[mount]]`
        /// of `config.toml`, as it says]
        dir: Option<PathBuf>,
        /// Anchors too are read-only
        #[arg(long)]
        read_only: bool,
    },
}

#[cfg(feature = "net")]
#[derive(clap::Args, Debug)]
struct NodeArgs {
    /// Which of the meshes this node is in: each a swarm of its own, under
    /// its own key, for one of the host's accounts
    #[arg(long, global = true, default_value = holokeep::net::mesh::MAIN)]
    mesh: String,
    #[command(subcommand)]
    command: NodeCommand,
}

#[cfg(feature = "net")]
#[derive(Subcommand, Debug)]
enum NodeCommand {
    /// Print this node's peer id, for another node to invite
    Id {
        /// Print instead the key this repo signs with for one of its
        /// accounts, by uid, for an invite's --device: a host user's, or
        /// an unused number for a user this machine hosts who has no login
        /// here
        #[arg(long)]
        account: Option<u32>,
    },
    /// Let a machine into the mesh, printing a ticket for it to join with.
    /// The ticket holds the mesh's key: keep it secret
    Invite {
        peer: String,
        /// The key to certify as the user's device, by peer ID, if it isn't
        /// the peer's own: an account's on a shared host (`hk whoami`)
        #[arg(long)]
        device: Option<String>,
        /// Whose user certifies the machine, by uid [default: yours]. Of the
        /// main mesh, another account is served by this node too, a user
        /// sharing it, made now if it has none; a new mesh is its
        #[arg(long)]
        account: Option<u32>,
        /// Make a new mesh protected: a friend's, whose vault this node
        /// holds, encrypted, for an account of its own; --device names the
        /// vault (`hk protect id` on the friend's machine)
        #[arg(long)]
        protected: bool,
        /// The most a friend's vault may have here (bytes, or with K, M,
        /// G, T) [default: no limit]
        #[arg(long, value_parser = holokeep::net::daemon::parse_size)]
        quota: Option<u64>,
        /// Let in a client instead: a device of the user, by its peer ID
        /// (`hk node id` in its repo), which is no member, connecting where
        /// members listen for clients (`hk node run --clients`), seeing and
        /// saying only what the user may. With grants, it's given
        /// /mesh/client, which every member serving the user lets in;
        /// without, this node alone. Its ticket holds no mesh key
        #[arg(long, conflicts_with_all = ["device", "protected", "quota"])]
        client: bool,
        /// Let in a visitor instead: a key that's no user of the mesh, by
        /// its peer ID (`hk node id` in its directory), which a user here
        /// shares views of anchors with (`hk anchor share <anchor> <peer>
        /// read`, or `write`), reading and setting those and nothing else,
        /// as a thin client (`hk node join --thin`) where members listen
        /// for clients, signing its sets with its own key. Nothing's
        /// certified: what's shared with it is all it's let in for, till
        /// it's unshared
        #[arg(long, conflicts_with_all = ["device", "protected", "quota", "client"])]
        visitor: bool,
    },
    /// Join a mesh with a ticket from a node already in it
    Join {
        ticket: String,
        /// Which account joins, by uid [default: yours]: of the main mesh,
        /// another account, served by this node too, as a device of the
        /// user the ticket's for
        #[arg(long)]
        account: Option<u32>,
        /// Join as a thin client, with a client's ticket: this directory,
        /// --repo, holds no repo, just this key and the ticket, and `hk`
        /// commands here ask the member, reading, writing, keeping,
        /// tagging and setting anchors through it
        #[arg(long, conflicts_with = "account")]
        thin: bool,
    },
    /// List the meshes this node is in, and whose each is
    Meshes,
    /// Print a systemd user unit running this node, and the main mesh's
    /// mounts, as a service: save it as
    /// `~/.config/systemd/user/<name>.service`, then `systemctl --user
    /// enable --now <name>`. Its flags are `config.toml`'s to say
    Service,
    /// Run this node in the mesh until interrupted or terminated, and keep
    /// the main mesh's mounts while it runs. Each flag says over the
    /// repo's `config.toml` (see `hk config`), which says over the
    /// defaults
    Run(RunArgs),
    /// Let go now of every copy here the mesh can spare, short of space or
    /// not
    Trim,
    /// Have the running node condemn everything here nothing keeps now,
    /// ask members whether they keep it, and let go of what's due
    Collect,
    /// Have the running node look for what's been lost now, rather than
    /// when it next would, and report what no member has. See `hk lost ls`
    ScanLost,
    /// No longer take a peer for a member, as one that's gone for good: it
    /// holds up nothing now, and members saying it is one aren't heeded, so
    /// say so on each node. Inviting it lets it back in. To stop what its key
    /// signs counting, `hk device revoke` too
    Forget { peer: libp2p::PeerId },
    /// List the mesh's members, and which are connected
    Peers,
    /// Give and take away what users and machines may do in the mesh. Once
    /// the mesh has grants, its machines are those given /mesh/machine, its
    /// users those given /mesh/user
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// How the running node is: connected members, blocks, and the
    /// trickle's pace
    Status,
    /// How far each connected member's clock is from this machine's, and
    /// the round trip it was measured over: advisory, as nothing's judged
    /// by it
    Clocks,
    /// Have the running node audit every block now, not a few at a time:
    /// advertise those short of the copies it runs with, or of these, and
    /// copy them to other members
    Audit {
        #[arg(short, long)]
        copies: Option<usize>,
    },
}

#[cfg(feature = "net")]
#[derive(Subcommand, Debug)]
enum GrantCommand {
    /// Keep who's in the mesh as grants from now on: a first grant, which
    /// the user's root key signs, making them its founder, then grants of
    /// /mesh/machine to every member and /mesh/user to every other user
    /// served. The first invite of a new mesh does this itself
    Init,
    /// Give a user or machine, by peer ID, commands: /mesh/user,
    /// /mesh/machine, /mesh/grant (to give what one holds), or /mesh for an
    /// operator
    Add {
        who: String,
        #[arg(required = true)]
        commands: Vec<String>,
    },
    /// Take commands away from a user or machine, by peer ID; and from
    /// those they gave them to, unless someone else did too
    Rm {
        who: String,
        #[arg(required = true)]
        commands: Vec<String>,
    },
    /// List who holds what: the founder first, holding everything
    Ls,
}

#[derive(Subcommand, Debug)]
enum VolumeCommand {
    /// Add a directory as a volume, attached whenever it's found there
    Add {
        name: String,
        path: PathBuf,
        /// Make it a database file, holding structure in the forms the
        /// repo's own does, rather than a flatfs directory
        #[arg(long)]
        sqlite: bool,
    },
    /// List the volumes the repo knows of, attached or not
    Ls,
    /// Copy blocks until it would take this many failures to lose each,
    /// counting volumes' risks, where attached volumes allow
    Replicate {
        #[arg(short, long, default_value_t = 2)]
        copies: usize,
    },
    /// Say what volumes risk together, beyond the disks and machines
    /// found: a building, a person, a cloud account
    #[command(subcommand)]
    Risk(RiskCommand),
    /// Copy blocks to a volume, wherever it is, such as to carry them to
    /// another machine: the DAGs under these CIDs, or every block
    Copy {
        name: String,
        cids: Vec<Link>,
    },
}

#[derive(Subcommand, Debug)]
enum RiskCommand {
    /// Say a volume shares these risks with whichever others do
    Add {
        name: String,
        risks: Vec<String>,
    },
    /// Unsay risks of a volume
    Rm {
        name: String,
        risks: Vec<String>,
    },
    /// List every volume's risks, found or said
    Ls,
}

#[derive(Subcommand, Debug)]
enum BlockCommand {
    /// Write a block's bytes to stdout, like `ipfs block get`
    Get {
        cid: Link,
    },
    /// Say where each block's copies are, here and on other members, what
    /// each risks, and how many failures it would take to lose them all,
    /// against how many its keeps say it should
    Where {
        #[arg(required = true)]
        cids: Vec<Link>,
        #[command(flatten)]
        ask: AskArgs,
    },
}

/// Whether to ask other members what they hold, rather than going by
/// what they've been seen holding (sightings) alone.
#[derive(clap::Args, Debug, Clone, Copy)]
struct AskArgs {
    /// Ask each connected member, through the running node, about what it
    /// hasn't been seen holding lately
    #[arg(long)]
    ask: bool,
    /// Ask each connected member about everything, whatever it's been seen
    /// holding
    #[arg(long, conflicts_with = "ask")]
    ask_all: bool,
}

impl AskArgs {
    const fn any(self) -> bool {
        self.ask || self.ask_all
    }
}

#[derive(Subcommand, Debug)]
enum SameCommand {
    /// Say blocks are the same, once they're checked to be, printing the
    /// claim. What isn't here is fetched, but for raw blocks beside others,
    /// checked by their multihashes, as a kept file's whole one
    Add {
        /// What they're read as: `unixfs` for what the UnixFS ADL reads, a
        /// file's contents (a raw block's a file of its bytes), a
        /// directory's entries or a symlink's target; or `data`, each
        /// codec's data model
        #[arg(long = "as", default_value = "data")]
        lens: String,
        #[arg(required = true, num_args = 2..)]
        cids: Vec<Link>,
    },
    /// Take back saying two blocks are the same, printing the tombs. What
    /// else says so, by way of other blocks, stands
    Rm {
        #[arg(long = "as", default_value = "data")]
        lens: String,
        a: Link,
        b: Link,
    },
    /// List what's the same as a block, a line each: the lens, and its CID
    Ls { cid: Link },
}

#[derive(Subcommand, Debug)]
enum PublicCommand {
    /// Make blocks, and whatever they link to, anyone's to have, printing
    /// each claim. An anchor is public as it is now, and what it mounts;
    /// a tag, as what it tags is now
    Add {
        /// Give them to whoever asks by CID, but never announce them;
        /// otherwise the blocks named are announced too
        #[arg(long)]
        serve: bool,
        /// A tag to make public, by name, as many as wanted
        #[arg(long)]
        tag: Vec<String>,
        #[arg(required_unless_present = "tag")]
        cids: Vec<Link>,
    },
    /// Make a block private again, in whatever mode it was made public,
    /// printing the tombs. What it links to stays public if something else
    /// public does too
    Rm { cid: Link },
    /// List what's been made public, a line each: the mode, and the CID,
    /// or `tag <name>` for a tag
    Ls,
    /// Say whether a block's anyone's to have, as what's public here,
    /// whichever account made it so, reaches it: `public` or `private`
    Check { cid: Link },
}

/// A lens as `hk same` takes it: `data` is none, each codec's data model.
fn lens_named(lens: &str) -> Option<&str> {
    (lens != holokeep::same::named(None)).then_some(lens)
}

#[derive(Subcommand, Debug)]
enum LostCommand {
    /// Look for what was here and still matters, without anyone having let
    /// go of it, asking the running node's members, and report what none
    /// of them has. With members away, only says what it's still to ask
    Scan {
        /// Say what would be reported, and report nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Report blocks lost, as you know better than a scan: printing the claim
    /// for each, unless it's here or reported already
    Add {
        #[arg(required = true)]
        cids: Vec<Link>,
    },
    /// Take back reports of blocks lost, printing the tombs
    Rm {
        #[arg(required = true)]
        cids: Vec<Link>,
    },
    /// List what's reported lost and isn't here, and as of when, in seconds
    /// since the epoch. Whatever's turned up since isn't listed
    Ls,
}

#[derive(Subcommand, Debug)]
enum KeepCommand {
    /// Keep DAGs, printing the claim keeping each. All of each must be
    /// here, or fetched through the running node
    Add {
        #[arg(required = true)]
        cids: Vec<Link>,
        /// Keep as much as can be had, stopping where blocks can't: the
        /// keep's frontier, for DAGs too large to hold
        #[arg(long)]
        shallow: bool,
        /// How many failures it should take to lose what this is the
        /// nearest keep of, rather than the copies the mesh runs with: 1
        /// for what's easily made again, more for what matters most
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        copies: Option<u64>,
    },
    /// Stop keeping blocks, printing the tombs which retract their keeps
    Rm {
        #[arg(required = true)]
        cids: Vec<Link>,
    },
    /// List what's kept
    Ls,
}

#[cfg(feature = "net")]
#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Where to listen [default: port 4011 for the main mesh, any
    /// other port for another]
    #[arg(long)]
    listen: Option<String>,
    /// Copy blocks to other members until it would take this many
    /// failures to lose each, counting risks, auditing a few at a time
    /// [default: 2]
    #[arg(short, long)]
    copies: Option<usize>,
    /// When free space falls below this, let go of copies the mesh can
    /// spare (bytes, or with K, M, G, T) [default: 2G]
    #[arg(long, value_parser = holokeep::net::daemon::parse_size)]
    low_water: Option<u64>,
    /// ...until it's back above this; nor take others' copies past it
    /// [default: 4G]
    #[arg(long, value_parser = holokeep::net::daemon::parse_size)]
    high_water: Option<u64>,
    /// The most to keep here: past it, let go of copies the mesh can spare
    /// and hand others to members with room, until a tenth under it; nor
    /// take others' copies past that [default: no most]
    #[arg(long, value_parser = holokeep::net::daemon::parse_size)]
    target: Option<u64>,
    /// Don't collect garbage. Otherwise leaves nothing keeps are let go
    /// of a week after they're condemned, once every member's said it
    /// doesn't keep them
    #[arg(long)]
    no_collect: bool,
    /// Don't look once a day for what's gone without being let go of,
    /// reporting what no member has as lost, as `hk lost scan` does
    #[arg(long)]
    no_lost_scan: bool,
    /// Let the host's other users connect, to keep and tag things here
    /// as accounts of their own, which this repo signs for with keys of
    /// their own (the repo's directory must let them reach the socket)
    #[arg(long)]
    shared: bool,
    /// Listen for clients too, those `hk node invite --client` let in,
    /// here [default: port 4012]. Clients connect without the mesh's
    /// key, so this is open to anyone who can reach it, though only
    /// the clients' keys get in
    #[arg(long, num_args = 0..=1, default_missing_value = holokeep::net::daemon::LISTEN_CLIENTS)]
    clients: Option<String>,
    /// Open a door too, here [default: port 4013]: where anyone, in no
    /// mesh, may read the sealed anchors this repo holds by capability
    /// (`hk cap import --from`), proving for each block they know its
    /// keys, and nothing else. It's a swarm of its own, apart from the
    /// mesh's, which no one let in there reaches
    #[arg(long, num_args = 0..=1, default_missing_value = holokeep::net::daemon::LISTEN_DOOR)]
    door: Option<String>,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum ConfigCommand {
    /// Print where the configuration is, whether or not it's there yet
    Path,
    /// Print the configuration as it's understood, or why it isn't
    Show,
}

#[derive(Subcommand, Debug)]
enum FsCommand {
    /// Say what's at each path: its CID and what it is, the anchor it's
    /// in and where (if any: one under `cid/` or `tags/` is in none until
    /// it's through a mount point), the anchor a mount point names, its
    /// tags, what's said to be the same as it (`hk same`), and whether it's
    /// public (`hk public`)
    Stat {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Say too how safe what's at each path is, as `hk dag health`
        /// does: where the copies of its blocks are, and how many failures
        /// it would take to lose them
        #[arg(long)]
        copies: bool,
        /// With --copies, implied
        #[command(flatten)]
        ask: AskArgs,
    },
    /// Unlink each path from the anchor naming it, a directory whole, in
    /// one set for each anchor, reading nothing under it. What it held is
    /// collected only once nothing else keeps or references it
    Rm {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Make what's at a path an anchor of its own, mounted where it was,
    /// so it's versioned, kept and shared on its own; print the anchor
    Anchor { path: PathBuf },
    /// List each version of what's at a path, oldest first: each set of
    /// the anchor naming it that changed it, when, by whom, and what it
    /// was then, which `hk cat` reads. A mount point's is its anchor's
    /// whole history. A file moved within the anchor is a removal and an
    /// addition
    Log { path: PathBuf },
}

#[derive(Subcommand, Debug)]
enum CapCommand {
    /// Seal the DAG under a CID with a fresh read key, write its
    /// ciphertext to a `CARv1`, and print a capability that reads it.
    /// Whoever has the capability can read all of it, and the CAR alone
    /// says only how many blocks there are, to a size class
    Export {
        cid: Link,
        /// Where to write the ciphertext
        output: PathBuf,
    },
    /// Publish what an anchor is now, sealed: what's changed of its tree
    /// since it was last published, and a head naming it, in a sealed
    /// anchor of its own whose owner key, derived from this account's
    /// vault, signs it. The vault keeps it, and the running node publishes
    /// it again as the anchor changes, till it's unpublished. Every anchor
    /// mounted in it is published too, for its readers to read. Print a
    /// capability that reads it as it is whenever it's read, the same each
    /// time
    Publish {
        /// The anchor, or a path of the soup that's one or a mount point
        /// of one (see `hk fs`). A folder that's neither is made an anchor
        /// of its own first, mounted where it was, as `hk fs anchor` does
        anchor: PathBuf,
        /// Write everything published of it, every head, to a `CARv1` too,
        /// for someone to read from nothing
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Say in the capability where a holder's door is, as a multiaddr
        /// ending in its peer ID (`hk node run --door` there), for readers
        /// to go to; as many as there are
        #[arg(long)]
        at: Vec<String>,
    },
    /// Stop publishing an anchor: the vault lets go of what's published of
    /// it, which is collected in time wherever it's held, and whoever has
    /// its capability reads its last head till then
    Unpublish { anchor: PathBuf },
    /// List the anchors published, each with its capability
    Ls,
    /// Read a capability's DAG into the repo, unsealing and checking every
    /// block, and print its root: a snapshot's, or a sealed anchor's latest
    /// head's. From a CAR of its ciphertext, or from a holder's door, where
    /// it's let in by proving it has the capability
    Import {
        capability: String,
        /// CARs of its ciphertext, read as one
        car: Vec<PathBuf>,
        /// A holder's door, as a multiaddr ending in its peer ID [default:
        /// those the capability says]
        #[arg(long, conflicts_with = "car")]
        from: Vec<String>,
    },
    /// Let a new writer write a published anchor: a writer key of its own,
    /// which the sealed anchor's owner key gives write, as the mesh's grants
    /// do on the anchor itself, if the mesh has grants. Print a capability
    /// that writes it, and reads it
    Grant {
        /// The anchor, or a path of the soup that's one or a mount point
        /// of one (see `hk fs`)
        anchor: PathBuf,
        /// Say in the capability where a holder's door is (see `hk cap
        /// publish --at`)
        #[arg(long)]
        at: Vec<String>,
    },
    /// Change a published anchor's read key: whoever has a capability with
    /// the old one reads nothing new, though what they've read they keep.
    /// What's unchanged keeps its ciphertext. Print a capability with the
    /// new key, for whoever's still to read it; writers need new
    /// capabilities too (`hk cap grant`)
    Rekey {
        anchor: PathBuf,
        #[arg(long)]
        at: Vec<String>,
    },
    /// Seal a published anchor again whole, under its read key, keeping
    /// nothing sealed under an old one. With --forget, let go of all that
    /// was published of it before too, so the old ciphertext's collected
    /// in time: its writers and readers go on, but its past can't be read
    /// back
    Reseal {
        anchor: PathBuf,
        #[arg(long)]
        forget: bool,
    },
    /// Let a new reader read a published anchor: a reader key of its own,
    /// whose box in the anchor's keyring has its read key, so it goes on
    /// reading as the read key changes, till it's taken away (`hk cap
    /// unread`). Print its capability
    Reader {
        anchor: PathBuf,
        #[arg(long)]
        at: Vec<String>,
    },
    /// List a published anchor's readers, by public key
    Readers { anchor: PathBuf },
    /// Take read away from a reader: a new read key, boxed to every other
    /// reader. Whoever has a capability with a read key in it needs a new
    /// one, as after `hk cap rekey`
    Unread {
        anchor: PathBuf,
        /// The reader, by public key, as `hk cap readers` lists it
        reader: String,
    },
    /// List who may write a published anchor, by key: this account's
    /// machines and capabilities' writers, whether each still may, and if
    /// not, how many of its sets stand
    Writers {
        /// The anchor, or a path of the soup that's one or a mount point
        anchor: PathBuf,
    },
    /// Take write on a published anchor away from a writer, as `hk cap
    /// writers` lists it: what it's written stands, and nothing after
    Revoke {
        anchor: PathBuf,
        /// The writer, by peer ID
        writer: String,
    },
    /// Take in what writers wrote of anchors this account publishes, from
    /// CARs `hk cap write` wrote: each anchor's set as they wrote it, and
    /// published again. A running node takes in what reaches it by itself
    Take {
        car: Vec<PathBuf>,
    },
    /// Write a sealed anchor with a write capability: a tree here, after
    /// its latest head, read from a CAR or at a holder's door. What's sealed
    /// of it, the head, and the writer's signs go to the first door that
    /// takes them, for the owner's node to take in, or to a `CARv1`
    Write {
        capability: String,
        /// What the anchor is to be: a tree here
        root: Link,
        /// Write it to a CAR, here, rather than to a holder's door
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// CARs of its ciphertext, read as one, to read its latest head from
        car: Vec<PathBuf>,
        /// A holder's door to read its latest head at, and write to [default:
        /// those the capability says]
        #[arg(long, conflicts_with = "car")]
        from: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ProtectCommand {
    /// Print the vault's key, by peer ID, for a friend to invite it with
    /// (`hk node invite --protected --device`)
    Id,
    /// Encrypt a DAG, all of which must be here, into the vault, keeping a
    /// manifest of it, which friends' nodes keep too; prints the manifest
    Add { cid: Link },
    /// List what the vault keeps: each manifest, and the root it protects
    Ls,
    /// Bring a DAG back from its manifest, fetching what isn't here
    /// through the vault's protected meshes, and keep it; prints its root
    Restore { manifest: Link },
    /// Protect the soup: publish the root anchor, and every anchor mounted
    /// in it, sealed, for no one but this account to read, kept current by
    /// the node as it changes and held by friends holding the vault
    Soup,
    /// Read back every anchor the vault publishes, after recovering it with
    /// the passphrase: fetch what it keeps through its protected meshes,
    /// and set each anchor that's nothing here to what it is sealed. Prints
    /// each anchor, its value, and whether it was set
    Recover,
}

#[derive(Subcommand, Debug)]
enum DeviceCommand {
    /// Print the user's root key, then each device by peer ID, whether
    /// it counts, and whether its chain of signs forks, a copy of its key
    /// having signed
    List,
    /// Print a device's signs, in the order they came: CID, the sign
    /// before it, when it says, and how many claims it signs
    Log {
        peer: String,
        /// And under each, a tab in: each claim's CID, its kind, its targets,
        /// and `alone` if nothing else authorized makes it count, `shared`
        /// if something does, or `retracted`
        #[arg(long)]
        claims: bool,
    },
    /// Become a device of the user whose root key's here, sealed, with their
    /// passphrase, as brought by `hk dag export --sealed-root`, when there's
    /// no device left to invite this one. What they've said counts here
    /// then. Their other devices stay certified until they're revoked
    Restore,
    /// Revoke a device, with the user's passphrase. What it alone signed
    /// up to `--until` is signed again here, so it still counts; nothing
    /// else it signed does, and it says what that is and asks first. What
    /// keeps the user's sealed root and root anchor is always signed again
    Revoke {
        peer: String,
        /// One of its signs, to trust it and those before it in its chain,
        /// or seconds since the epoch, to trust its signs until then if
        /// its chain doesn't fork. A sign for each chain, if it forks
        /// [default: now]
        #[arg(long)]
        until: Vec<String>,
        /// Say what would stop counting, and revoke nothing
        #[arg(long)]
        dry_run: bool,
        /// Go ahead though claims would stop counting, without asking
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AnchorCommand {
    /// Make a new anchor, printing it
    New,
    /// Say an anchor is a DAG now, which must all be here or fetched
    /// through the running node; prints the set
    Set {
        anchor: Link,
        cid: Link,
        /// Fetch none of it now: what isn't here is fetched as it's read,
        /// through `hk mount`. Like `keep --shallow`, what a keep of the
        /// anchor reaches may then not all be here
        #[arg(long)]
        lazy: bool,
    },
    /// Print what an anchor is now, then every value it's had, oldest
    /// first, with when
    Show { anchor: Link },
    /// Forget what an anchor was before a time, seconds since the epoch as
    /// `show` prints it, printing what that lets go of. What only those
    /// versions refer to is then collected in time, deleted files and
    /// anchors nothing else names among them. History's kept until this says
    Forget {
        anchor: Link,
        /// Forget the versions from before this
        #[arg(long)]
        before: u64,
        /// Say which versions, and forget nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Print this account's root anchor, the top of `hk mount`, and what
    /// it is now
    Root,
    /// Let a user of the mesh, by peer ID, read or write your view of an
    /// anchor, or one you've been let pass on (a view, as `view` prints
    /// it): `read`, `write`, `grant` (to pass on what they hold), or `all`.
    /// What they set counts in your view; their own view of it is apart
    #[cfg(feature = "net")]
    Share {
        anchor: Link,
        who: String,
        #[arg(required = true)]
        commands: Vec<String>,
        /// For only so long, by each machine's clock: `90s`, `30m`, `12h`,
        /// `7d` or `2w`. Then it's gone, and what they passed on with it;
        /// what they set till then still counts
        #[arg(long = "for", value_name = "DURATION", value_parser = parse_lasting)]
        lasting: Option<u64>,
    },
    /// Take back what a user may do with your view of an anchor; and from
    /// those they passed it on to, unless someone else did too. Taking
    /// write away, what they set before still counts, and nothing after
    #[cfg(feature = "net")]
    Unshare {
        anchor: Link,
        who: String,
        #[arg(required = true)]
        commands: Vec<String>,
    },
    /// List who may read and write views of anchors, yours and those
    /// shared with you, or one anchor's
    #[cfg(feature = "net")]
    Shared { anchor: Option<Link> },
    /// Print a user's view of an anchor, by their peer ID, as an anchor of
    /// its own: what to show or mount (`ln -s /anchors/<view>` in the
    /// mount) to see what they've shared, or set it if they let you
    View { anchor: Link, owner: String },
}

#[derive(Subcommand, Debug)]
enum TagCommand {
    /// Tag blocks with a name, printing the claim tagging each
    Add {
        name: String,
        #[arg(required = true)]
        cids: Vec<Link>,
    },
    /// Untag blocks, printing the tombs which retract their claims
    Rm {
        name: String,
        #[arg(required = true)]
        cids: Vec<Link>,
    },
    /// List a block's tags
    Ls {
        cid: Link,
    },
    /// List the blocks with a tag
    Find {
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum DagCommand {
    /// Import the blocks of CAR files (v1 or v2), like `ipfs dag import`.
    /// Use "-" for stdin.
    Import {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Write the DAG under a CID to a `CARv1`, like `ipfs dag export`, which
    /// claims about it are left out of, unless they're asked for
    Export {
        cid: Link,
        /// With the claims about it after it, tags, keeps and so on, dissolved
        /// or not, with their signatures and what makes those count, and
        /// following anchors to what they are: the rest of what it is here.
        /// These say what you've kept and tagged, and signed with which keys
        #[arg(long)]
        claims: bool,
        /// With all that anchors have been, as far as it's here, not only
        /// what they are now
        #[arg(long, requires = "claims")]
        history: bool,
        /// With the user's root key, sealed with their passphrase, so a repo
        /// with no devices left can become the user again (`hk device
        /// restore`). Whoever has this file can try passphrases offline, as
        /// long as they like, so its passphrase is all that protects the user
        #[arg(long, requires = "claims")]
        sealed_root: bool,
        /// Where to write it [default: stdout]
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Fetch whatever of the DAG under a CID isn't here from other members
    /// of the mesh, through the running node
    #[cfg(feature = "net")]
    Fetch {
        cid: Link,
    },
    /// Say how safe the DAG under a CID is: of its blocks, how many failures
    /// it would take to lose the least safe, which are short of what their
    /// keeps say, and which one failure loses, and of what. Following
    /// anchors and keeps as keeping does, and walking nothing that isn't here
    Health {
        cid: Link,
        #[command(flatten)]
        ask: AskArgs,
    },
}

#[derive(Subcommand, Debug)]
enum GitCommand {
    /// Import every object of a git repository, loose or packed, as a
    /// `git-raw` block named by its git SHA-1, keeping what its refs name.
    /// Prints each ref's CID and name
    Import {
        /// The repository: a working tree, its `.git`, or a bare one
        #[arg(default_value = ".", value_name = "REPOSITORY")]
        git: PathBuf,
        /// Don't keep what the refs name
        #[arg(long)]
        no_keep: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RepoCommand {
    /// How many blocks each volume holds, in each form, and each database's
    /// bytes on disk and free pages
    Stat,
    /// Rebuild the block index from the stores
    Reindex,
    /// Give each database's free pages back to the filesystem. Prints each
    /// one's volume, bytes before, bytes after, and what became of it
    Compact {
        /// Only say what would be done: bytes after are the most it'd have
        #[arg(long)]
        dry_run: bool,
        /// Compact even a database big enough that writers might give up
        /// waiting for it; for when nothing else is writing to it
        #[arg(long)]
        long: bool,
    },
}

/// Print a line to stdout, like `println!`, except that a reader which has
/// stopped reading (`hk ls | head`) isn't an error: the command carries on
/// and finishes what it was doing, just without saying so.
macro_rules! out {
    ($($arg:tt)*) => { say(format_args!($($arg)*)) };
}

/// The first failure writing to stdout other than a closed pipe, such as a
/// full disk, which the command fails with once it's done
static UNSAID: std::sync::OnceLock<io::Error> = std::sync::OnceLock::new();

fn say(line: std::fmt::Arguments) {
    let mut stdout = io::stdout().lock();
    if let Err(e) = stdout.write_fmt(line).and_then(|()| stdout.write_all(b"\n"))
        && e.kind() != io::ErrorKind::BrokenPipe
    {
        let _ = UNSAID.set(e);
    }
}

fn main() {
    let result = run(Args::parse()).and_then(|()| {
        UNSAID.get().map_or(Ok(()), |e| Err(anyhow::anyhow!("writing to stdout: {e}")))
    });
    if let Err(e) = result {
        // Streaming into a closed pipe (`hk cat big | head`) ends quietly
        if e.chain().any(|cause| cause.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)) {
            return;
        }
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn repo_dir(repo: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match repo {
        Some(dir) => Ok(dir),
        None => Ok(PathBuf::from(std::env::var_os("HOME").context("no HOME, so use --repo")?).join(".holokeep")),
    }
}

/// Fetch what isn't here of a DAG about to be read, if the node's running
/// to fetch it. What can't be is reported by the reading.
// Without the mesh there's nothing to fetch through
#[cfg_attr(not(feature = "net"), allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn))]
fn fetch_first(repo: Option<&PathBuf>, cid: &Link) -> anyhow::Result<()> {
    #[cfg(feature = "net")]
    {
        let dir = repo_dir(repo.cloned())?;
        if let Some((_, missing)) = holokeep::net::daemon::fetch(&holokeep::net::mesh::Place::main(&dir), cid)?
            && !missing.is_empty()
        {
            eprintln!("warning: {} blocks aren't here or on any connected member", missing.len());
        }
    }
    #[cfg(not(feature = "net"))]
    let _ = (repo, cid);
    Ok(())
}

/// Have a repo fetch blocks it wants through its running node, if there is one.
#[cfg(feature = "net")]
fn fetch_through_node(repo: &mut Catalog, dir: &Path) {
    use holokeep::net::{daemon, mesh::Place};
    let place = Place::main(dir);
    repo.fetch_through(std::sync::Arc::new(move |cids: &[Link]| daemon::fetch_blocks(&place, cids).is_ok_and(|fetched| fetched.is_some())));
}

#[cfg(not(feature = "net"))]
#[allow(clippy::missing_const_for_fn)]
fn fetch_through_node(_: &mut Catalog, _: &Path) {}

/// Refuse a block another of the host's accounts has here, but this one
/// doesn't: it's as good as not here.
/// The repo, having fetched what's under a CID through its running node,
/// if there is one, and made sure it's this account's to read. A whole
/// file's CID, which isn't a block, is the layout it's said to be the
/// same as (see `export::Fetch::same_file`), which is what's fetched,
/// whether here or members say so, and must be this account's: knowing a
/// file's whole CID isn't reading it.
fn fetched(repo: Option<PathBuf>, cid: &Link) -> anyhow::Result<Catalog> {
    fetch_first(repo.as_ref(), cid)?;
    let repo = open_repo(repo)?;
    let layout = export::Fetch::same_file(&repo, cid)?.unwrap_or_else(|| cid.clone());
    in_repo(&repo, &layout)?;
    Ok(repo)
}

fn in_repo(repo: &Catalog, cid: &Link) -> anyhow::Result<()> {
    anyhow::ensure!(repo.visible(cid.multihash())?, "block {cid} not found");
    Ok(())
}

/// Whether the repo is another of the host's users', so this one's to ask
/// its running node to act for it, rather than open it.
fn foreign(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let me = rustix::process::getuid().as_raw();
    me != 0 && std::fs::metadata(dir.join("blocks.db")).is_ok_and(|meta| meta.uid() != me)
}

/// Ask the running node of a repo another user owns to act for this one,
/// printing what it answers.
#[cfg(feature = "net")]
fn as_account(dir: &Path, words: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(!words.iter().any(|word| word.contains(['\t', '\n'])), "what an account asks can't have tabs or newlines in it");
    let lines = holokeep::net::daemon::ask(&holokeep::net::mesh::Place::main(dir), &format!("as\t{}", words.join("\t")))?
        .context("this repo is another user's, and its node isn't running to act for you: its owner can `hk node run --shared`")?;
    for line in lines {
        if let Some(error) = line.strip_prefix("error: ") {
            anyhow::bail!("{error}");
        }
        out!("{line}");
    }
    Ok(())
}

#[cfg(not(feature = "net"))]
fn as_account(_: &Path, _: &[String]) -> anyhow::Result<()> {
    anyhow::bail!("this repo is another user's, and this hk has no node to ask to act for you")
}

/// `hk tag`, in a repo of one's own, or one another user owns.
fn tag_here_or_there(repo: Option<PathBuf>, command: TagCommand) -> anyhow::Result<()> {
    let dir = repo_dir(repo)?;
    if foreign(&dir) {
        return as_account(&dir, &tag_words(command));
    }
    tag(open_repo(Some(dir))?, command)
}

/// `hk keep`, in a repo of one's own, or one another user owns.
fn keep_here_or_there(repo: Option<PathBuf>, command: KeepCommand) -> anyhow::Result<()> {
    let dir = repo_dir(repo)?;
    if foreign(&dir) {
        if let KeepCommand::Add { cids, .. } = &command {
            for cid in cids {
                fetch_first(Some(&dir), cid)?;
            }
        }
        return as_account(&dir, &keep_words(command));
    }
    keep(Some(&dir), open_repo(Some(dir.clone()))?, command)
}

fn protect(dir: &Path, command: ProtectCommand) -> anyhow::Result<()> {
    use holokeep::vault;
    let me = rustix::process::getuid().as_raw();
    match command {
        ProtectCommand::Id => out!("{}", holokeep::keys::peer_id(&vault::Vault::open(dir, me)?.key().id())),
        ProtectCommand::Add { cid } => {
            let mut repo = Catalog::open_repo(dir)?;
            out!("{}", vault::protect(&mut repo, dir, &cid)?);
            seal_vault(&mut repo, dir)?;
        },
        ProtectCommand::Soup => {
            let mut repo = Catalog::open_repo(dir)?;
            let root = repo.root_anchor()?.context("this account has no root anchor yet")?;
            let value = repo.anchor_value(&root)?.with_context(|| format!("the root anchor, {root}, is nothing yet"))?;
            fetch_first(Some(&dir.to_path_buf()), &value)?;
            let vault = vault::Vault::open(dir, me)?;
            let publications = holokeep::cap::publish_mounted(&mut repo, &vault, &root, &value)?;
            seal_vault(&mut repo, dir)?;
            eprintln!("protected the root anchor and {} anchors mounted in it: no one but this account reads them, and the node keeps them current", publications.len().saturating_sub(1));
            out!("{root}");
        },
        ProtectCommand::Recover => {
            let mut repo = Catalog::open_repo(dir)?;
            let vault = vault::Vault::open(dir, me)?;
            #[cfg(feature = "net")]
            for cid in holokeep::cap::vault_keeps(&mut repo, &vault)? {
                fetch_protected(dir, me, &cid)?;
            }
            let recovered = holokeep::cap::recover(&mut repo, &vault)?;
            for recovered in &recovered {
                let outcome = match recovered.outcome {
                    holokeep::cap::Recovery::Set => "set",
                    holokeep::cap::Recovery::Already => "already",
                    holokeep::cap::Recovery::Otherwise => "otherwise here: left be",
                };
                out!("{}\t{}\t{outcome}", recovered.anchor, recovered.value);
            }
            anyhow::ensure!(!recovered.is_empty(), "the vault publishes nothing here: is it recovered, and are its friends' nodes reachable?");
        },
        ProtectCommand::Ls => {
            let mut repo = Catalog::open_repo(dir)?;
            for (manifest, root) in vault::list(&mut repo, dir)? {
                out!("{manifest}\t{root}");
            }
        },
        ProtectCommand::Restore { manifest } => {
            #[cfg(feature = "net")]
            fetch_protected(dir, me, &manifest)?;
            let mut repo = Catalog::open_repo(dir)?;
            let (root, blocks) = vault::restore(&mut repo, dir, &manifest)?;
            eprintln!("restored {blocks} blocks");
            out!("{root}");
        },
    }
    Ok(())
}

/// Fetch a DAG of the vault's that isn't all here through its protected
/// meshes, the first that has it all.
#[cfg(feature = "net")]
fn fetch_protected(dir: &Path, me: u32, cid: &Link) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    let uid = holokeep::vault::vault_of(me);
    for (name, _) in daemon::members(&mesh::Place::main(dir))?.meshes()?.into_iter().filter(|&(_, account)| account == uid) {
        if let Some((_, missing)) = daemon::fetch(&mesh::Place::new(dir, &name), cid)?
            && missing.is_empty()
        {
            break;
        }
    }
    Ok(())
}

/// Seal the vault with the user's passphrase, if it isn't yet, to go where
/// it does, so the passphrase alone recovers it.
fn seal_vault(repo: &mut Catalog, dir: &Path) -> anyhow::Result<()> {
    if holokeep::vault::is_sealed(repo, dir)? {
        return Ok(());
    }
    let passphrase = if repo.user()?.is_some() {
        let passphrase = passphrase(false)?;
        repo.root(passphrase.as_bytes()).context("the vault is sealed with the user's passphrase")?;
        passphrase
    } else {
        passphrase(true)?
    };
    holokeep::vault::seal(repo, dir, passphrase.as_bytes(), holokeep::keys::Cost::RECOMMENDED)?;
    eprintln!("sealed the vault with the passphrase: friends holding it hold what it takes to recover it");
    Ok(())
}

fn whoami(repo: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = repo_dir(repo)?;
    if foreign(&dir) {
        return as_account(&dir, &["whoami".to_owned()]);
    }
    for line in holokeep::account::answer(&mut open_repo(Some(dir))?, "whoami") {
        out!("{line}");
    }
    Ok(())
}

fn tag_words(command: TagCommand) -> Vec<String> {
    let cids = |cids: Vec<Link>| cids.into_iter().map(|cid| cid.to_string());
    match command {
        TagCommand::Add { name, cids: list } => ["tag".to_owned(), "add".to_owned(), name].into_iter().chain(cids(list)).collect(),
        TagCommand::Rm { name, cids: list } => ["tag".to_owned(), "rm".to_owned(), name].into_iter().chain(cids(list)).collect(),
        TagCommand::Ls { cid } => vec!["tag".to_owned(), "ls".to_owned(), cid.to_string()],
        TagCommand::Find { name } => vec!["tag".to_owned(), "find".to_owned(), name],
    }
}

fn keep_words(command: KeepCommand) -> Vec<String> {
    let cids = |cids: Vec<Link>| cids.into_iter().map(|cid| cid.to_string());
    match command {
        KeepCommand::Add { cids: list, shallow, copies } => ["keep", "add"]
            .into_iter()
            .chain(shallow.then_some("--shallow"))
            .map(str::to_owned)
            .chain(copies.map(|copies| format!("--copies={copies}")))
            .chain(cids(list))
            .collect(),
        KeepCommand::Rm { cids: list } => ["keep".to_owned(), "rm".to_owned()].into_iter().chain(cids(list)).collect(),
        KeepCommand::Ls => vec!["keep".to_owned(), "ls".to_owned()],
    }
}

fn open_repo(repo: Option<PathBuf>) -> anyhow::Result<Catalog> {
    let dir = repo_dir(repo)?;
    Catalog::open_repo(&dir).with_context(|| format!("opening repo {}", dir.display()))
}

/// What `hk add` imports with.
fn importer(chunker: &str, max_file_links: usize, hidden: bool) -> anyhow::Result<Importer> {
    let Some(ChunkerType::Size(chunk_size)) = ChunkerType::parse(chunker) else {
        anyhow::bail!("unsupported chunker {chunker:?}, expected size-[bytes]");
    };
    if chunk_size == 0 || max_file_links < 2 {
        anyhow::bail!("chunk size must be positive and max-file-links at least 2");
    }
    Ok(Importer {
        chunk_size,
        layout: BalancedLayout { width: max_file_links },
        hidden,
        ..Importer::default()
    })
}

/// Make a directory a thin client, of the member a client's ticket is from.
#[cfg(feature = "net")]
fn thin_join(place: &holokeep::net::mesh::Place, ticket: &str) -> anyhow::Result<()> {
    anyhow::ensure!(place.is_main(), "clients are of the main mesh");
    let ticket = holokeep::net::thin::join(&place.repo, ticket)?;
    let (user, visiting) = ticket.user.as_ref().map_or_else(|| (String::new(), true), |(user, blocks)| (holokeep::keys::peer_id(user), blocks.is_empty()));
    if visiting {
        eprintln!("visiting {} now, to read what user {user} shares with this key: `hk anchor shared` with --repo {} lists it", ticket.inviter, place.repo.display());
    } else {
        eprintln!("a thin client of {} now, as a device of user {user}: hk commands with --repo {} ask it", ticket.inviter, place.repo.display());
    }
    Ok(())
}

/// A thin client's commands, each asking its member: those which need no
/// repo of their own.
#[cfg(feature = "net")]
fn thin(dir: &Path, command: Command) -> anyhow::Result<()> {
    use holokeep::net::thin::{Blocking, Sink};
    let connect = || Blocking::connect(dir).context("reaching the member");
    let ask = |client: &Blocking, words: &[&str]| -> anyhow::Result<()> {
        for line in client.ask(words.iter().map(|word| (*word).to_owned()).collect())? {
            out!("{line}");
        }
        Ok(())
    };
    match command {
        Command::Node(NodeArgs { mesh, command: NodeCommand::Id { account: None } }) if mesh == holokeep::net::mesh::MAIN => {
            out!("{}", holokeep::net::mesh::node_key(dir)?.public().to_peer_id());
        },
        Command::Node(NodeArgs { mesh, command: NodeCommand::Join { ticket, thin: true, .. } }) => thin_join(&holokeep::net::mesh::Place::new(dir, &mesh), &ticket)?,
        Command::Whoami => {
            let client = connect()?;
            out!("member\t{}", client.member());
            ask(&client, &["whoami"])?;
        },
        Command::Add { path, only_hash, hidden, quiet, chunker, max_file_links, nocopy: false, no_keep } => {
            let importer = importer(&chunker, max_file_links, hidden)?;
            if only_hash {
                return add(&importer, &path, quiet, &mut NullSink).map(drop);
            }
            let client = connect()?;
            let mut sink = Sink::new(&client);
            let root = add(&importer, &path, quiet, &mut sink)?;
            sink.finish()?;
            // A visitor keeps nothing: what it sets is the owner's to keep
            if !no_keep && !client.is_visitor() {
                client.ask(vec!["keep".to_owned(), "add".to_owned(), root.to_string()])?;
            }
        },
        Command::Cat { cid } => {
            let mut out = io::BufWriter::new(io::stdout().lock());
            export::cat(&connect()?, &cid, &mut out)?;
            out.flush()?;
        },
        Command::Get { cid, output } => {
            let dest = output.unwrap_or_else(|| PathBuf::from(cid.to_string()));
            export::get(&connect()?, &cid, &dest).with_context(|| format!("writing {}", dest.display()))?;
        },
        Command::Block(BlockCommand::Get { cid }) => {
            let block = connect()?.get(std::slice::from_ref(&cid))?.into_iter().next().with_context(|| format!("block {cid} not found"))?;
            io::stdout().lock().write_all(block.data())?;
        },
        Command::Keep(KeepCommand::Add { copies: Some(_), .. }) => anyhow::bail!("how many copies to keep is the member's to say"),
        Command::Keep(command) => ask(&connect()?, &keep_words(command).iter().map(String::as_str).collect::<Vec<_>>())?,
        Command::Tag(command) => ask(&connect()?, &tag_words(command).iter().map(String::as_str).collect::<Vec<_>>())?,
        Command::Anchor(AnchorCommand::Shared { anchor: None }) => ask(&connect()?, &["shared"])?,
        Command::Anchor(AnchorCommand::New) => ask(&connect()?, &["anchor", "new"])?,
        Command::Anchor(AnchorCommand::Root) => ask(&connect()?, &["anchor", "root"])?,
        Command::Anchor(AnchorCommand::Show { anchor }) => ask(&connect()?, &["anchor", "show", &anchor.to_string()])?,
        // A visitor passes on what it may as itself
        Command::Anchor(AnchorCommand::Share { anchor, who, commands, lasting }) if holokeep::net::thin::visitor_ticket(dir)?.is_some() => {
            out!("{}", connect()?.share_own(&anchor, &key_named(&who)?, &anchor_commands(&commands)?, &[], ending(lasting))?);
        },
        Command::Anchor(AnchorCommand::Unshare { anchor, who, commands }) if holokeep::net::thin::visitor_ticket(dir)?.is_some() => {
            out!("{}", connect()?.share_own(&anchor, &key_named(&who)?, &[], &anchor_commands(&commands)?, None)?);
        },
        Command::Node(NodeArgs { command: NodeCommand::Invite { visitor: true, .. }, .. }) if holokeep::net::thin::visitor_ticket(dir)?.is_some() => {
            out!("{}", holokeep::net::thin::visitor_ticket(dir)?.unwrap_or_default());
            eprintln!("note: it's this visitor's own ticket, naming no one: it lets in whoever the owner's shares, and those passed on, say may read");
        },
        Command::Anchor(AnchorCommand::Set { anchor, cid, lazy }) => {
            let client = connect()?;
            if client.is_visitor() {
                out!("{}", client.set_own(&anchor, &cid)?);
                return Ok(());
            }
            let (anchor, cid) = (anchor.to_string(), cid.to_string());
            ask(&client, &if lazy { vec!["anchor", "set", "--lazy", &anchor, &cid] } else { vec!["anchor", "set", &anchor, &cid] })?;
        },
        _ => anyhow::bail!("this is a thin client, with no repo: it reads, adds, keeps, tags and sets anchors through its member, and no more"),
    }
    Ok(())
}

fn run(args: Args) -> anyhow::Result<()> {
    #[cfg(feature = "net")]
    if let Ok(dir) = repo_dir(args.repo.clone())
        && holokeep::net::thin::is_thin(&dir)
    {
        return thin(&dir, args.command);
    }
    match args.command {
        Command::Add { path, only_hash, hidden, quiet, chunker, max_file_links, nocopy, no_keep } => {
            let importer = importer(&chunker, max_file_links, hidden)?;
            if only_hash {
                return add(&importer, &path, quiet, &mut NullSink).map(drop);
            }
            open_repo(args.repo)?.batch_breathing(|repo| {
                // What's imported in place is mounted on an anchor, which is
                // what's kept, so it's kept through its changes
                let kept = if nocopy && path != Path::new("-") {
                    let canonical = std::fs::canonicalize(&path).with_context(|| format!("adding {}", path.display()))?;
                    let base = canonical.parent().unwrap_or_else(|| Path::new("")).to_owned();
                    let mut report = |p: &Path, link: &dag::DagLink| {
                        if !quiet {
                            out!("added {} {}", link.cid, p.strip_prefix(&base).unwrap_or(p).display());
                        }
                    };
                    let (mount, root) = repo.import_mounted(&importer, &path, &mut report)?;
                    if quiet {
                        out!("{root}");
                    } else {
                        eprintln!("mounted on {}", mount.anchor);
                    }
                    mount.anchor
                } else if nocopy {
                    add(&importer, &path, quiet, &mut InPlace::new(repo))?
                } else {
                    add(&importer, &path, quiet, &mut Copying::new(repo))?
                };
                if !no_keep {
                    repo.keep(&kept)?;
                }
                anyhow::Ok(())
            })
        },
        Command::Cat { cid } => {
            let repo = fetched(args.repo, &cid)?;
            let mut out = io::BufWriter::new(io::stdout().lock());
            export::cat(&repo, &cid, &mut out)?;
            Ok(out.flush()?)
        },
        Command::Get { cid, output } => {
            let repo = fetched(args.repo, &cid)?;
            let dest = output.unwrap_or_else(|| PathBuf::from(cid.to_string()));
            export::get(&repo, &cid, &dest).with_context(|| format!("writing {}", dest.display()))
        },
        Command::Refs { cid, back } => refs(&open_repo(args.repo)?, &cid, back),
        Command::Dag(command) => dag(args.repo, command),
        Command::Git(GitCommand::Import { git, no_keep }) => git_import(args.repo, &git, no_keep),
        Command::Tag(command) => tag_here_or_there(args.repo, command),
        Command::Keep(command) => keep_here_or_there(args.repo, command),
        Command::Lost(command) => lost(args.repo, command),
        Command::Same(command) => same(args.repo, command),
        Command::Public(command) => public(args.repo, command),
        Command::Whoami => whoami(args.repo),
        Command::Protect(command) => protect(&repo_dir(args.repo)?, command),
        Command::Cap(command) => cap(args.repo, command),
        Command::Fs(command) => soup_fs(args.repo, command),
        Command::Device(command) => device(&repo_dir(args.repo.clone())?, command),
        Command::Anchor(command) => anchor(args.repo.as_ref(), open_repo(args.repo.clone())?, command),
        Command::Block(command) => block(args.repo, command),
        Command::Repo(RepoCommand::Stat) => {
            let repo = open_repo(args.repo)?;
            for (volume, form, blocks) in repo.stats()? {
                out!("{volume}\t{form}\t{blocks}");
            }
            for space in repo.space()? {
                out!("{}\tbytes\t{}", space.volume, space.bytes);
                out!("{}\tfree-bytes\t{}", space.volume, space.free);
            }
            Ok(())
        },
        Command::Repo(RepoCommand::Compact { dry_run, long }) => compact(&open_repo(args.repo)?, Compact { dry_run, long }),
        Command::Repo(RepoCommand::Reindex) => {
            let blocks = open_repo(args.repo)?.reindex()?;
            out!("indexed {blocks} blocks");
            Ok(())
        },
        Command::Volume(command) => volume(open_repo(args.repo)?, command),
        #[cfg(feature = "fuse")]
        Command::Mount { dir: Some(dir), read_only } => mount(repo_dir(args.repo)?, &dir, read_only),
        #[cfg(feature = "fuse")]
        Command::Mount { dir: None, read_only } => mount_configured(repo_dir(args.repo)?, read_only),
        Command::Config(command) => config(&repo_dir(args.repo)?, command),
        #[cfg(feature = "net")]
        Command::Node(NodeArgs { mesh, command }) => node(&holokeep::net::mesh::Place::new(&repo_dir(args.repo)?, &mesh), command),
        #[cfg(feature = "net")]
        Command::Serve(command) => serve(&repo_dir(args.repo)?, command),
    }
}

/// Have a running node take up changes to its mesh, saying if it has to
/// be restarted to, having been running alone, and returning whether.
#[cfg(feature = "net")]
fn reload(place: &holokeep::net::mesh::Place) -> anyhow::Result<()> {
    let joined = holokeep::net::daemon::ask(place, "reload")?.is_some_and(|lines| lines.iter().any(|line| line == "joined"));
    if joined {
        eprintln!("the running node, which was in no mesh, is in this one now");
    }
    Ok(())
}

/// Mount the soup where the config's one mount says.
#[cfg(feature = "fuse")]
fn mount_configured(repo: PathBuf, read_only: bool) -> anyhow::Result<()> {
    let config = holokeep::config::Config::load(&repo)?;
    let [only] = config.mount.as_slice() else {
        anyhow::bail!("name a directory to mount on: config.toml has {} mounts, not one", config.mount.len());
    };
    mount(repo, &only.dir(), read_only || only.read_only)
}

fn config(repo: &Path, command: ConfigCommand) -> anyhow::Result<()> {
    match command {
        ConfigCommand::Path => out!("{}", repo.join(holokeep::config::FILE).display()),
        ConfigCommand::Show => {
            let config = holokeep::config::Config::load(repo)?;
            if config == holokeep::config::Config::default() {
                eprintln!("nothing's configured: the defaults throughout");
            }
            out!("{}", toml::to_string(&config)?.trim_end());
        },
    }
    Ok(())
}

/// Mount the soup at `dir`, as this repo's owner sees it, until
/// interrupted.
#[cfg(feature = "fuse")]
fn mount(repo: PathBuf, dir: &Path, read_only: bool) -> anyhow::Result<()> {
    anyhow::ensure!(!foreign(&repo), "this repo is another user's: only its owner can mount it");
    // Opened here first so a repo that won't open says so before mounting
    drop(Catalog::open_repo(&repo).with_context(|| format!("opening repo {}", repo.display()))?);
    #[cfg(feature = "net")]
    let fetcher: Option<holokeep::mount::Fetcher> = {
        let place = holokeep::net::mesh::Place::main(&repo);
        Some(Box::new(move |cids: &[Link]| matches!(holokeep::net::daemon::fetch_blocks(&place, cids), Ok(Some(_)))))
    };
    #[cfg(not(feature = "net"))]
    let fetcher = None;
    let work = repo.join("work");
    // Anchors this node serves are reached through its services
    #[cfg(feature = "net")]
    let node = holokeep::net::mesh::node_key(&repo).ok().map(|key| (repo.clone(), key.public().to_peer_id().to_bytes()));
    let soup = holokeep::mount::Soup::new(Box::new(move || Catalog::open_repo(&repo)), fetcher);
    #[cfg(feature = "net")]
    let soup = match node {
        Some((repo, node)) => soup.serving(repo, node),
        None => soup,
    };
    let soup = if read_only { soup } else { soup.writable(work) };
    eprintln!("mounted on {}; interrupt to unmount", dir.display());
    holokeep::mount::mount(soup, dir).with_context(|| format!("mounting on {}", dir.display()))
}

/// The passphrase of the user's root key: `HK_PASSPHRASE` if it's set,
/// otherwise asked for, twice if it's a new one.
fn passphrase(new: bool) -> anyhow::Result<zeroize::Zeroizing<String>> {
    if let Ok(passphrase) = std::env::var("HK_PASSPHRASE") {
        return Ok(passphrase.into());
    }
    let ask = |prompt| rpassword::prompt_password(prompt).map(zeroize::Zeroizing::new);
    let passphrase = ask(if new { "a new passphrase for this mesh's user: " } else { "passphrase of this mesh's user: " })?;
    anyhow::ensure!(!passphrase.is_empty(), "the passphrase can't be empty");
    if new {
        anyhow::ensure!(*ask("again: ")? == *passphrase, "those didn't match");
    }
    Ok(passphrase)
}

/// The user's root key, unsealed: or, where it was kept unsealed, as it
/// was before there were seals, sealed now and the file removed.
fn root_key(repo: &Catalog, dir: &Path) -> anyhow::Result<holokeep::keys::Key> {
    use holokeep::keys::{Cost, Key, USER_KEY};
    let file = dir.join(USER_KEY);
    if let Some(root) = Key::load(&file)?
        && repo.user()?.as_ref() == Some(&root.id())
        && repo.seals()?.is_empty()
    {
        eprintln!("sealing the user's root key, which was kept unsealed in {}", file.display());
        repo.seal(&root, passphrase(true)?.as_bytes(), Cost::RECOMMENDED)?;
        std::fs::remove_file(&file)?;
        return Ok(root);
    }
    Ok(repo.root(passphrase(false)?.as_bytes())?)
}

/// The blocks a ticket brings a joiner: every certificate and revocation,
/// signed, and the user's root key sealed, with what keeps it.
#[cfg(feature = "net")]
fn user_blocks(repo: &Catalog) -> anyhow::Result<Vec<Vec<u8>>> {
    let seals: Vec<Link> = repo.seals()?.into_iter().map(|(cid, _)| cid).collect();
    let keys: Vec<Vec<u8>> = repo.devices()?.iter().map(|(device, _)| device.multihash().to_bytes())
        .chain(seals.iter().map(|cid| cid.multihash().to_bytes()))
        .collect();
    let about = holokeep::net::structure::backrefs(repo, keys.iter().map(Vec::as_slice))?;
    seals.iter().chain(&about)
        .map(|cid| Ok(repo.get_block(cid)?.with_context(|| format!("{cid} went missing"))?.into_data().into_vec()))
        .collect()
}

/// Become a device of the user a ticket's for: put what the ticket brings,
/// and make its root key this repo's user, in place of any other. What
/// this node signed before counts as the user's, since the ticket
/// certifies it.
#[cfg(feature = "net")]
fn join_user(dir: &Path, uid: u32, user: &Link, blocks: &[Vec<u8>]) -> anyhow::Result<()> {
    use holokeep::cid::{CidVersion, Cidv1Spec, DAG_CBOR_CODEC};
    let mut repo = Catalog::open_repo(dir)?;
    repo.act_for(uid, holokeep::keys::account_key(dir, uid)?)?;
    let me = repo.signer().context("no key to sign with")?.id();
    repo.batch(|repo| {
        for data in blocks {
            let block = claim::Claim::parse(data).map_or_else(
                || holokeep::block::Block::hash(Cidv1Spec::new(DAG_CBOR_CODEC, holokeep::multihash::MultihashFunc::Sha2_256), data.clone().into()),
                |claim| claim.block(),
            );
            repo.put_block(&block, CidVersion::V1)?;
        }
        // What this repo named joins what the user names
        repo.join_user(user)?;
        anyhow::ensure!(repo.claims().is_some_and(|claims| claims.authorized(&me).unwrap_or(false)), "the ticket doesn't certify this node");
        Ok(())
    })?;
    // A root key kept unsealed, from before there were seals, is no one's
    let own = dir.join(holokeep::keys::USER_KEY);
    if own.exists() {
        std::fs::rename(&own, own.with_extension("key.before-join"))?;
    }
    Ok(())
}

/// Let a machine into a mesh, printing its ticket: certifying it as a
/// device of the mesh's user, made now if the mesh is new.
#[cfg(feature = "net")]
fn invite(place: &holokeep::net::mesh::Place, peer: &str, device: Option<&str>, account: Option<u32>) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    let dir = place.repo.as_path();
    let peer: libp2p::PeerId = peer.parse().context("not a peer id")?;
    let me = mesh::node_key(dir)?.public().to_peer_id();
    anyhow::ensure!(peer != me, "that's this node");
    let members = daemon::members(place)?;
    let uid = mesh_account(&members, account)?;
    let swarm_key = mesh::ensure_swarm_key(&place.dir())?;
    members.add(&peer)?;
    let mut list = members.list()?;
    // The joiner's certificate, which the user's root key signs: the
    // first invite makes the user, and so the mesh
    let device = holokeep::keys::from_peer_id(device.unwrap_or(&peer.to_string())).context("not an ed25519 peer")?;
    let mut repo = Catalog::open_repo(dir)?;
    repo.act_for(uid, holokeep::keys::account_key(dir, uid)?)?;
    let root = if repo.user()?.is_some() {
        root_key(&repo, dir)?
    } else {
        let passphrase = passphrase(true)?;
        let root = repo.batch(|repo| repo.found_user(passphrase.as_bytes(), holokeep::keys::Cost::RECOMMENDED))?;
        eprintln!("made a user for this mesh, {}: its root key is sealed with the passphrase, in the mesh", holokeep::keys::peer_id(&root.id()));
        root
    };
    repo.batch(|repo| repo.certify(&root, &device))?;
    let grants = invite_grants(place, uid, &root, &peer)?;
    let user = root.id();
    let blocks = user_blocks(&repo)?;
    // A running node hears of the new member, or, if it was alone, joins
    // the mesh it's in now; then where it listens is what the ticket says
    reload(place)?;
    let listening = daemon::ask(place, "listeners")?.unwrap_or_default();
    list.insert(me, listening.iter().filter_map(|addr| addr.parse().ok()).collect());
    out!("{}", mesh::Ticket { swarm_key: Some(swarm_key), client: false, inviter: me, members: list, user: Some((user, blocks)), protected: false, sealed: Vec::new(), held: Vec::new(), grants }.encode());
    if listening.is_empty() {
        eprintln!("note: this node isn't running, so the ticket says nowhere to find it; it'll be found on the LAN, or start `hk node run` and invite again");
    }
    Ok(())
}

/// The blocks a client's ticket brings it: every certificate and
/// revocation of its user, signed. Not the user's root key, even sealed: a
/// client only signs.
#[cfg(feature = "net")]
fn client_blocks(repo: &Catalog) -> anyhow::Result<Vec<Vec<u8>>> {
    let keys: Vec<Vec<u8>> = repo.devices()?.iter().map(|(device, _)| device.multihash().to_bytes()).collect();
    let about = holokeep::net::structure::backrefs(repo, keys.iter().map(Vec::as_slice))?;
    about.iter()
        .map(|cid| Ok(repo.get_block(cid)?.with_context(|| format!("{cid} went missing"))?.into_data().into_vec()))
        .collect()
}

/// Let a client in: certify its key as a device of an account's user, and
/// print its ticket, which says where this node listens for clients.
#[cfg(feature = "net")]
fn invite_client(place: &holokeep::net::mesh::Place, peer: &str, account: Option<u32>) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    anyhow::ensure!(place.is_main(), "clients are of the main mesh");
    let dir = place.repo.as_path();
    let peer: libp2p::PeerId = peer.parse().context("not a peer id")?;
    let me = mesh::node_key(dir)?.public().to_peer_id();
    anyhow::ensure!(peer != me, "that's this node");
    let members = daemon::members(place)?;
    anyhow::ensure!(members.client_of()?.is_none(), "this node is a client, which has no clients");
    anyhow::ensure!(!members.contains(&peer)?, "{peer} is a member of the mesh, not a client");
    let home = rustix::process::getuid().as_raw();
    let uid = account.unwrap_or(home);
    anyhow::ensure!(uid == home || members.others()?.contains(&uid), "uid {uid} isn't an account this node serves");
    let device = holokeep::keys::from_peer_id(&peer.to_string()).context("not an ed25519 peer")?;
    let mut repo = Catalog::open_repo(dir)?;
    repo.act_for(uid, holokeep::keys::account_key(dir, uid)?)?;
    let user = repo.user()?.context("the account has no user yet, so is in no mesh: invite a machine first")?;
    let root = root_key(&repo, dir)?;
    repo.batch(|repo| repo.certify(&root, &device))?;
    members.add_client(&peer, uid)?;
    // With grants, every member serving the user lets it in, as they say
    let grants = match members.genesis()? {
        Some(genesis) => {
            let mut owner = Catalog::open_repo(dir)?;
            let state = owner.grant_state(&genesis)?.context("the mesh's grants aren't here")?;
            if !state.holders().iter().any(|(who, held)| *who == device && held.iter().any(|command| command == holokeep::grants::CLIENT)) {
                owner.batch(|owner| owner.grant(&genesis, std::slice::from_ref(&device), &[holokeep::grants::CLIENT.to_owned()], &[]))?;
            }
            Some(grant_blocks(&owner, &genesis)?)
        },
        None => None,
    };
    let blocks = client_blocks(&repo)?;
    reload(place)?;
    // Where it may connect: this node, and others serving the user that
    // listen for clients too
    let mut listening: std::collections::BTreeMap<libp2p::PeerId, Vec<libp2p::Multiaddr>> = std::collections::BTreeMap::new();
    for line in daemon::ask(place, &format!("clients-at {uid}"))?.unwrap_or_default() {
        if let Some((member, addr)) = line.split_once('\t')
            && let (Ok(member), Ok(addr)) = (member.parse(), addr.parse())
        {
            listening.entry(member).or_default().push(addr);
        }
    }
    if !listening.contains_key(&me) {
        eprintln!("note: this node isn't listening for clients, so the ticket says nowhere to find it: start `hk node run --clients` and invite again");
    }
    listening.entry(me).or_default();
    let members = listening;
    out!("{}", mesh::Ticket { swarm_key: None, client: true, inviter: me, members, user: Some((user, blocks)), protected: false, sealed: Vec::new(), held: Vec::new(), grants }.encode());
    Ok(())
}

/// Print a ticket for a visitor: where members serving an account's user
/// listen for clients. What it may read, the user's shares say.
#[cfg(feature = "net")]
fn invite_visitor(place: &holokeep::net::mesh::Place, peer: &str, account: Option<u32>) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    anyhow::ensure!(place.is_main(), "visitors are of the main mesh");
    let dir = place.repo.as_path();
    let peer: libp2p::PeerId = peer.parse().context("not a peer id")?;
    let key = holokeep::keys::from_peer_id(&peer.to_string()).context("not an ed25519 peer")?;
    let me = mesh::node_key(dir)?.public().to_peer_id();
    let members = daemon::members(place)?;
    anyhow::ensure!(members.client_of()?.is_none(), "this node is a client, which has no visitors");
    let genesis = members.genesis()?.context("the mesh has no grants, so nothing's shared: `hk node grant init` first")?;
    let home = rustix::process::getuid().as_raw();
    let uid = account.unwrap_or(home);
    anyhow::ensure!(uid == home || members.others()?.contains(&uid), "uid {uid} isn't an account this node serves");
    let mut repo = Catalog::open_repo(dir)?;
    repo.act_for(uid, holokeep::keys::account_key(dir, uid)?)?;
    let user = repo.user()?.context("the account has no user yet, so shares nothing")?;
    let state = repo.grant_state(&genesis)?.context("the mesh's grants aren't here")?;
    anyhow::ensure!(!state.holds(&key, holokeep::grants::USER), "{peer} is a user of the mesh: share with it as one");
    if !state.shares().iter().any(|share| share.user == key && share.owner == user && !share.held.is_empty()) {
        eprintln!("note: nothing's shared with {peer} yet: `hk anchor share <anchor> {peer} read`, and it's let in");
    }
    let mut listening: std::collections::BTreeMap<libp2p::PeerId, Vec<libp2p::Multiaddr>> = std::collections::BTreeMap::new();
    for line in daemon::ask(place, &format!("clients-at {uid}"))?.unwrap_or_default() {
        if let Some((member, addr)) = line.split_once('\t')
            && let (Ok(member), Ok(addr)) = (member.parse(), addr.parse())
        {
            listening.entry(member).or_default().push(addr);
        }
    }
    if !listening.contains_key(&me) {
        eprintln!("note: this node isn't listening for clients, so the ticket says nowhere to find it: start `hk node run --clients` and invite again");
    }
    listening.entry(me).or_default();
    out!("{}", mesh::Ticket { swarm_key: None, client: true, inviter: me, members: listening, user: Some((user, Vec::new())), protected: false, sealed: Vec::new(), held: Vec::new(), grants: None }.encode());
    Ok(())
}

/// Become a client of the member a ticket's from: a device of its user,
/// connecting to it alone.
#[cfg(feature = "net")]
fn join_client(place: &holokeep::net::mesh::Place, ticket: &holokeep::net::mesh::Ticket) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    anyhow::ensure!(place.is_main(), "clients are of the main mesh");
    let dir = place.repo.as_path();
    anyhow::ensure!(mesh::swarm_key(dir)?.is_none(), "this node is a machine of a mesh: a client is a repo of its own, with --repo");
    let (user, blocks) = ticket.user.as_ref().context("not a ticket: a client's says whose device it is")?;
    let uid = rustix::process::getuid().as_raw();
    may_join(dir, uid, user)?;
    let members = daemon::members(place)?;
    if let Some(had) = members.client_of()? {
        anyhow::ensure!(had == ticket.inviter, "this node is a client of {had}");
    }
    if let Some((genesis, blocks)) = &ticket.grants {
        join_grants(place, genesis, blocks)?;
    }
    join_user(dir, uid, user, blocks)?;
    members.merge(&ticket.members)?;
    members.set_client_of(&ticket.inviter)?;
    reload(place)?;
    eprintln!("a client of {} now, as a device of user {}; `hk node run` to connect", ticket.inviter, holokeep::keys::peer_id(user));
    Ok(())
}

/// Recover this account's vault from what a friend holding it kept sealed,
/// with the passphrase, and its user's root key with it: this repo's user
/// again, certifying this node, and kept sealed here again too.
#[cfg(feature = "net")]
fn recover(dir: &Path, me: u32, sealed: &[Vec<u8>]) -> anyhow::Result<()> {
    eprintln!("the friend holds your vault, sealed: recovering it");
    let passphrase = passphrase(false)?;
    let recovered = holokeep::vault::recover(dir, me, sealed, passphrase.as_bytes())?;
    eprintln!("recovered vault {}", holokeep::keys::peer_id(&recovered.vault.key().id()));
    let Some(root) = recovered.root else {
        return Ok(());
    };
    let mut repo = Catalog::open_repo(dir)?;
    if repo.user()?.is_some() {
        return Ok(());
    }
    let device = repo.signer().context("no key to sign with")?.id();
    repo.batch(|repo| {
        repo.set_user(&root.id())?;
        repo.certify(&root, &device)?;
        for data in sealed {
            if holokeep::keys::Sealed::parse(data).is_some_and(|sealed| sealed.what().is_none() && *sealed.key() == root.id()) {
                let block = holokeep::block::Block::hash(
                    holokeep::cid::Cidv1Spec::new(holokeep::cid::DAG_CBOR_CODEC, holokeep::multihash::MultihashFunc::Sha2_256),
                    data.clone().into(),
                );
                repo.put_block(&block, holokeep::cid::CidVersion::V1)?;
                repo.keep(&holokeep::cid::AnyCid::V1(block.cid().clone()))?;
            }
        }
        anyhow::Ok(())
    })?;
    eprintln!("recovered user {}, which certifies this node", holokeep::keys::peer_id(&root.id()));
    Ok(())
}

/// Let a friend's machine into a protected mesh, which holds their vault
/// here for an internal account of its own, whose user is the vault's key:
/// what the vault keeps, this node keeps for it, up to its quota.
#[cfg(feature = "net")]
fn invite_friend(place: &holokeep::net::mesh::Place, peer: &str, vault: &str, quota: Option<u64>) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    anyhow::ensure!(!place.is_main(), "the main mesh is the owner's: give a protected one a --mesh of its own");
    let dir = place.repo.as_path();
    let peer: libp2p::PeerId = peer.parse().context("not a peer id")?;
    let me = mesh::node_key(dir)?.public().to_peer_id();
    anyhow::ensure!(peer != me, "that's this node");
    let vault = holokeep::keys::from_peer_id(vault).context("--device isn't an ed25519 peer ID")?;
    let members = daemon::members(place)?;
    if members.account()?.is_none() {
        // The next internal account for a friend
        let next = members.meshes()?.iter().map(|&(_, uid)| uid).filter(|&uid| uid >= FRIENDS).max().map_or(FRIENDS, |uid| uid.saturating_add(1));
        members.set_account(next)?;
        members.set_protected(quota)?;
        let repo = Catalog::open_repo(dir)?;
        repo.claims().context("this repo keeps no claims")?.set_user(next, &vault)?;
    }
    anyhow::ensure!(members.protected()?.is_some(), "mesh {} isn't protected", place.mesh);
    // What the vault keeps here already, for a machine of theirs that's
    // lost everything else to recover from
    let (mut sealed, mut held) = (Vec::new(), Vec::new());
    let uid = members.account()?.context("a protected mesh with no account")?;
    let mut repo = Catalog::open_repo(dir)?;
    repo.act_for(uid, holokeep::keys::account_key(dir, uid)?)?;
    for cid in repo.held()? {
        if cid.codec() == holokeep::cid::DAG_CBOR_CODEC
            && let Some(block) = repo.get_block(&cid)?
            && holokeep::keys::Sealed::parse(block.data()).is_some()
        {
            sealed.push(block.data().to_vec());
        }
    }
    for cid in repo.claims().context("this repo keeps no claims")?.keeps()? {
        if repo.get_block(&cid)?.is_none_or(|block| holokeep::keys::Sealed::parse(block.data()).is_none()) {
            held.push(cid);
        }
    }
    drop(repo);
    let swarm_key = mesh::ensure_swarm_key(&place.dir())?;
    members.add(&peer)?;
    let mut list = members.list()?;
    reload(place)?;
    let listening = daemon::ask(place, "listeners")?.unwrap_or_default();
    list.insert(me, listening.iter().filter_map(|addr| addr.parse().ok()).collect());
    out!("{}", mesh::Ticket { swarm_key: Some(swarm_key), client: false, inviter: me, members: list, user: None, protected: true, sealed, held, grants: None }.encode());
    Ok(())
}

/// Where the internal accounts for friends' vaults start.
#[cfg(feature = "net")]
const FRIENDS: u32 = 0xC000_0000;

/// The account a mesh is for, by uid: the main one's owner's, unless
/// it's said, and a new one's whoever's said, or the owner's, recorded.
/// Another account said of the main mesh is served by it too, a user
/// sharing this machine.
#[cfg(feature = "net")]
fn mesh_account(members: &holokeep::net::mesh::Members, said: Option<u32>) -> anyhow::Result<u32> {
    let (uid, new) = mesh_uid(members, said)?;
    if new {
        if members.mesh() == holokeep::net::mesh::MAIN {
            members.serve(uid)?;
        } else {
            members.set_account(uid)?;
        }
    }
    Ok(uid)
}

/// The account a mesh is for, by uid, and whether it's new to the mesh.
#[cfg(feature = "net")]
fn mesh_uid(members: &holokeep::net::mesh::Members, said: Option<u32>) -> anyhow::Result<(u32, bool)> {
    let me = rustix::process::getuid().as_raw();
    if members.mesh() == holokeep::net::mesh::MAIN {
        return Ok(match said {
            Some(uid) if uid != me => (uid, !members.others()?.contains(&uid)),
            _ => (me, false),
        });
    }
    if let Some(uid) = members.account()? {
        anyhow::ensure!(said.is_none_or(|said| said == uid), "mesh {} is uid {uid}'s", members.mesh());
        return Ok((uid, false));
    }
    Ok((said.unwrap_or(me), true))
}

/// Refuse to make an account another user's device when it's a device of
/// a user with others: an account has one user, and another mesh's is
/// another account's.
#[cfg(feature = "net")]
fn may_join(dir: &Path, uid: u32, user: &Link) -> anyhow::Result<()> {
    let mut repo = Catalog::open_repo(dir)?;
    repo.act_for(uid, holokeep::keys::account_key(dir, uid)?)?;
    if let Some(had) = repo.user()?
        && had != *user
        && repo.devices()?.len() > 1
    {
        anyhow::bail!("uid {uid}'s user is {}, which has other devices; join another user's mesh with --mesh and --account", holokeep::keys::peer_id(&had));
    }
    Ok(())
}

#[cfg(feature = "net")]
/// List the members, and which the running node's connected to.
fn peers(place: &holokeep::net::mesh::Place) -> anyhow::Result<()> {
    use holokeep::net::daemon;
    if let Some(lines) = daemon::ask(place, "peers")? {
        for line in &lines {
            out!("{line}");
        }
    } else {
        eprintln!("this node isn't running; members it knows of:");
        for (peer, addrs) in daemon::members(place)?.list()? {
            let addrs: Vec<String> = addrs.iter().map(ToString::to_string).collect();
            out!("{peer}\t-\t{}\t-", addrs.join(" "));
        }
    }
    Ok(())
}

/// Join a mesh with a ticket, as a machine of it, or as a client of the
/// member that made it.
#[cfg(feature = "net")]
fn join(place: &holokeep::net::mesh::Place, ticket: &str, account: Option<u32>) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    let dir = place.repo.as_path();
    let mut ticket = mesh::Ticket::decode(ticket)?;
    if ticket.client {
        anyhow::ensure!(account.is_none(), "a client acts for its repo's owner: make it a repo of its own, with --repo");
        return join_client(place, &ticket);
    }
    let swarm_key = ticket.swarm_key.context("not a ticket: a member's has the mesh's key")?;
    let me = mesh::node_key(dir)?.public().to_peer_id();
    anyhow::ensure!(ticket.members.remove(&me).is_some(), "the ticket isn't for this node, {me}");
    let members = daemon::members(place)?;
    anyhow::ensure!(members.client_of()?.is_none(), "this node is a client: a machine of a mesh is a repo of its own, with --repo");
    // A protected mesh holds this account's vault, and nothing else
    let account = if ticket.protected {
        anyhow::ensure!(!place.is_main() && account.is_none(), "a protected mesh holds your vault: join it with a --mesh of its own");
        let me = rustix::process::getuid().as_raw();
        let uid = holokeep::vault::vault_of(me);
        if !ticket.sealed.is_empty() && !dir.join("accounts").join(format!("{uid}.key")).exists() {
            recover(dir, me, &ticket.sealed)?;
        }
        Some(holokeep::vault::Vault::open(dir, me)?.uid())
    } else {
        account
    };
    let (uid, _) = mesh_uid(&members, account)?;
    if let Some((user, _)) = &ticket.user {
        may_join(dir, uid, user)?;
    }
    mesh::set_swarm_key(&place.dir(), swarm_key)?;
    let uid = mesh_account(&members, account)?;
    members.merge(&ticket.members)?;
    if let Some((genesis, blocks)) = &ticket.grants {
        join_grants(place, genesis, blocks)?;
    }
    if let Some((user, blocks)) = &ticket.user {
        join_user(dir, uid, user, blocks)?;
    }
    reload(place)?;
    let mesh = if place.is_main() { String::new() } else { format!(" --mesh {}", place.mesh) };
    eprintln!("joined the mesh of {}; `hk node run{mesh}` to connect", ticket.inviter);
    if !ticket.held.is_empty() {
        eprintln!("it holds {} of your vault's manifests; once it's running, restore each with `hk protect restore`:", ticket.held.len());
        for cid in &ticket.held {
            out!("{cid}");
        }
    }
    Ok(())
}

#[cfg(feature = "net")]
fn node(place: &holokeep::net::mesh::Place, command: NodeCommand) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    anyhow::ensure!(mesh::Place::valid(&place.mesh), "a mesh's name is letters, digits, - and _");
    let dir = place.repo.as_path();
    match command {
        NodeCommand::Id { account: None } => out!("{}", mesh::node_key(dir)?.public().to_peer_id()),
        NodeCommand::Id { account: Some(uid) } => out!("{}", holokeep::keys::peer_id(&holokeep::keys::account_key(dir, uid)?.id())),
        NodeCommand::Service => node_service(place)?,
        NodeCommand::Meshes => {
            let members = daemon::members(place)?;
            if mesh::swarm_key(dir)?.is_some() {
                out!("{}\t{}", mesh::MAIN, rustix::process::getuid().as_raw());
            }
            for (name, uid) in members.meshes()? {
                out!("{name}\t{uid}");
            }
        },
        NodeCommand::Invite { peer, account, client: true, .. } => invite_client(place, &peer, account)?,
        NodeCommand::Invite { peer, account, visitor: true, .. } => invite_visitor(place, &peer, account)?,
        NodeCommand::Invite { peer, device, account, protected: false, quota: None, .. } => invite(place, &peer, device.as_deref(), account)?,
        NodeCommand::Invite { peer, device, account: None, protected: true, quota, .. } => {
            invite_friend(place, &peer, device.as_deref().context("a protected mesh holds a friend's vault: name it with --device")?, quota)?;
        },
        NodeCommand::Invite { .. } => anyhow::bail!("--quota is for a protected mesh, which is a friend's, not an account's"),
        NodeCommand::Join { ticket, thin: true, .. } => thin_join(place, &ticket)?,
        NodeCommand::Join { ticket, account, thin: false } => join(place, &ticket, account)?,
        NodeCommand::Run(args) => node_run(place, args)?,
        NodeCommand::Collect => {
            let report = daemon::collect(place)?.context("this node isn't running: start `hk node run`")?;
            out!(
                "condemned {}, pardoned {}, let go of {}, freeing {} bytes",
                report.condemned, report.pardoned, report.collected, report.freed,
            );
        },
        NodeCommand::Forget { peer } => daemon::forget(place, &peer)?,
        NodeCommand::ScanLost => drop(daemon::ask(place, "scan-lost")?.context("this node isn't running: start `hk node run`")?),
        NodeCommand::Trim => {
            let report = daemon::trim(place)?.context("this node isn't running: start `hk node run`")?;
            out!("let go of {} of {} spare blocks, freeing {} bytes", report.dropped, report.considered, report.freed);
        },
        NodeCommand::Clocks => {
            for line in &daemon::ask(place, "clocks")?.context("this node isn't running: start `hk node run`")? {
                out!("{line}");
            }
        },
        NodeCommand::Status => {
            let lines = daemon::ask(place, "status")?.context("this node isn't running: start `hk node run`")?;
            for line in &lines {
                out!("{line}");
            }
        },
        NodeCommand::Audit { copies } => {
            let report = daemon::audit(place, copies)?.context("this node isn't running: start `hk node run`")?;
            out!("advertised {}, copied {}", report.advertised, report.copied);
            if report.short > 0 {
                eprintln!("{} blocks are still short, with no connected member to raise them", report.short);
            }
        },
        NodeCommand::Peers => peers(place)?,
        NodeCommand::Grant { command } => grant(place, command)?,
    }
    Ok(())
}

/// Run a node, tuned as the flags say, over the config, and keep the
/// config's mounts while it runs, if it's the main mesh's.
#[cfg(feature = "net")]
fn node_run(place: &holokeep::net::mesh::Place, args: RunArgs) -> anyhow::Result<()> {
    use holokeep::net::daemon;
    let RunArgs { listen, copies, low_water, high_water, target, no_collect, no_lost_scan, shared, clients, door } = args;
    let config = holokeep::config::Config::load(&place.repo)?;
    let tuned = config.node(&place.mesh);
    let listen = listen.or(tuned.listen).unwrap_or_else(|| if place.is_main() { daemon::LISTEN } else { "/ip4/0.0.0.0/tcp/0" }.to_owned());
    let clients = clients.or_else(|| tuned.clients.and_then(|clients| clients.at(daemon::LISTEN_CLIENTS)));
    let door = door.or_else(|| tuned.door.and_then(|door| door.at(daemon::LISTEN_DOOR)));
    anyhow::ensure!(clients.is_none() || place.is_main(), "clients are of the main mesh");
    let listen = daemon::Listen {
        members: listen.parse().context("not a multiaddr")?,
        clients: clients.map(|addr| addr.parse()).transpose().context("not a multiaddr")?,
    };
    if let Some(door) = door {
        holokeep::net::door::open(&place.repo, &holokeep::net::mesh::node_key(&place.repo)?, door.parse().context("not a multiaddr")?)?;
    }
    let copies = copies.or(tuned.copies).unwrap_or(2);
    let marks = holokeep::net::trim::Watermarks::new(low_water.or(tuned.low_water).unwrap_or(2 << 30), high_water.or(tuned.high_water).unwrap_or(4 << 30)).with_target(target.or(tuned.target));
    let collect = !no_collect && tuned.collect.unwrap_or(true);
    let lost_scan = !no_lost_scan && tuned.lost_scan.unwrap_or(true);
    let shared = shared || tuned.shared.unwrap_or(false);
    #[cfg(feature = "fuse")]
    let mounts = if place.is_main() { Some(holokeep::mounts::Mounts::start(&place.repo, &config.mount)?) } else { None };
    #[cfg(not(feature = "fuse"))]
    if !config.mount.is_empty() {
        eprintln!("this build has no mount, so the config's mounts aren't kept");
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let ran = runtime.block_on(daemon::run(place, listen, copies, marks, collect, lost_scan, shared));
    #[cfg(feature = "fuse")]
    if let Some(mounts) = mounts {
        mounts.stop();
    }
    ran?;
    Ok(())
}

/// Print a systemd user unit running a node.
#[cfg(feature = "net")]
fn node_service(place: &holokeep::net::mesh::Place) -> anyhow::Result<()> {
    let program = std::env::current_exe()?;
    let mesh = if place.is_main() { String::new() } else { format!(" --mesh {}", place.mesh) };
    let repo = std::path::absolute(&place.repo)?;
    out!("[Unit]");
    out!("Description=holokeep node{}, of {}", if place.is_main() { String::new() } else { format!(" in mesh {}", place.mesh) }, repo.display());
    out!("");
    out!("[Service]");
    out!("ExecStart={} node run --repo {}{mesh}", program.display(), repo.display());
    out!("Restart=on-failure");
    out!("RestartSec=5");
    // The node's to stop its mounts, which it interrupts to unmount
    out!("KillMode=mixed");
    out!("TimeoutStopSec=30");
    out!("");
    out!("[Install]");
    out!("WantedBy=default.target");
    Ok(())
}

/// A user's or machine's key, by peer ID or CID.
fn key_named(text: &str) -> anyhow::Result<Link> {
    holokeep::keys::from_peer_id(text)
        .or_else(|| text.parse::<Link>().ok().filter(holokeep::keys::is_key))
        .with_context(|| format!("not a key, by peer ID or CID: {text}"))
}

#[cfg(feature = "net")]
#[derive(Subcommand, Debug)]
enum ServeCommand {
    /// Say an anchor is served by a node's service, this node's unless
    /// another's named; prints the claim
    Add {
        anchor: Link,
        /// The service's name in the serving node's `[[serve]]` config
        service: String,
        /// The serving node, by peer ID [default: this one]
        #[arg(long)]
        node: Option<libp2p::PeerId>,
        /// Keep the server's states as sets, but for what it marks QTTMP
        #[arg(long)]
        persist: bool,
    },
    /// Say an anchor's no longer served; prints the tombs
    Rm { anchor: Link },
    /// Print who serves an anchor, if anyone
    Show { anchor: Link },
}

#[cfg(feature = "net")]
fn serve(dir: &Path, command: ServeCommand) -> anyhow::Result<()> {
    let repo = open_repo(Some(dir.to_path_buf()))?;
    match command {
        ServeCommand::Add { anchor, service, node, persist } => {
            let node = match node {
                Some(node) => node,
                None => holokeep::net::mesh::node_key(dir)?.public().to_peer_id(),
            };
            out!("{}", repo.serve_anchor(&anchor, &node.to_bytes(), &service, persist)?);
        },
        ServeCommand::Rm { anchor } => {
            for tomb in repo.unserve_anchor(&anchor)? {
                out!("{tomb}");
            }
        },
        ServeCommand::Show { anchor } => match repo.serving(&anchor)? {
            Some(serving) => {
                let node = libp2p::PeerId::from_bytes(serving.node()).map_or_else(|_| "an unreadable peer ID".to_owned(), |peer| peer.to_string());
                out!("node\t{node}");
                out!("service\t{}", serving.service());
                out!("persist\t{}", if serving.persist() { "yes" } else { "no" });
                out!("since\t{}", serving.at() / 1000);
            },
            None => out!("not served"),
        },
    }
    Ok(())
}

/// A peer's key.
#[cfg(feature = "net")]
fn peer_key(peer: &libp2p::PeerId) -> anyhow::Result<Link> {
    holokeep::keys::from_peer_id(&peer.to_string()).with_context(|| format!("{peer} isn't an ed25519 key"))
}

/// Give a mesh grants, founded by its owner's user with their root key:
/// every member is given /mesh/machine, and every other account's user
/// served /mesh/user. Returns the first grant.
#[cfg(feature = "net")]
fn found_grants(place: &holokeep::net::mesh::Place, repo: &mut Catalog, root: &holokeep::keys::Key) -> anyhow::Result<Link> {
    use holokeep::grants::{MACHINE, USER};
    let members = holokeep::net::daemon::members(place)?;
    anyhow::ensure!(members.genesis()?.is_none(), "this mesh has grants already");
    anyhow::ensure!(repo.user()?.as_ref() == Some(&root.id()), "the mesh's grants are founded by its owner's user");
    let me = holokeep::net::mesh::node_key(&place.repo)?.public().to_peer_id();
    let mut machines = vec![peer_key(&me)?];
    for peer in members.list()?.into_keys() {
        machines.push(peer_key(&peer)?);
    }
    let mut users = Vec::new();
    if let Some(claims) = repo.claims() {
        for uid in members.others()? {
            users.extend(claims.account(uid)?.and_then(|account| account.user));
        }
    }
    let genesis = repo.batch(|repo| {
        let genesis = repo.found_grants(root)?;
        repo.grant(&genesis, &machines, &[MACHINE.to_owned()], &[])?;
        if !users.is_empty() {
            repo.grant(&genesis, &users, &[USER.to_owned()], &[])?;
        }
        anyhow::Ok(genesis)
    })?;
    members.set_genesis(&genesis)?;
    eprintln!("who's in this mesh is kept as grants from now on, founded by {}", holokeep::keys::peer_id(&root.id()));
    Ok(genesis)
}

/// The mesh's first grant, and every grant with what makes it count, as
/// a ticket brings them.
#[cfg(feature = "net")]
fn grant_blocks(repo: &Catalog, genesis: &Link) -> anyhow::Result<(Link, Vec<Vec<u8>>)> {
    let state = repo.grant_state(genesis)?.context("the mesh's grants aren't here")?;
    let grants: Vec<Link> = state.grants().cloned().collect();
    Ok((genesis.clone(), repo.grant_blocks(&grants, &[])?.into_iter().map(|(_, data)| data).collect()))
}

/// What an invite gives, on a mesh with grants, or the first invite of
/// the owner's account makes it: the machine, /mesh/machine; the user of
/// an account another than the owner's, /mesh/user. Returns the grants,
/// for the ticket, if there are any.
#[cfg(feature = "net")]
fn invite_grants(place: &holokeep::net::mesh::Place, uid: u32, root: &holokeep::keys::Key, peer: &libp2p::PeerId) -> anyhow::Result<Option<(Link, Vec<Vec<u8>>)>> {
    use holokeep::grants::{MACHINE, USER};
    if !place.is_main() {
        return Ok(None);
    }
    let mut owner = Catalog::open_repo(&place.repo)?;
    let members = holokeep::net::daemon::members(place)?;
    let genesis = match members.genesis()? {
        Some(genesis) => genesis,
        None if uid == owner.uid() => found_grants(place, &mut owner, root)?,
        None => return Ok(None),
    };
    let state = owner.grant_state(&genesis)?.context("the mesh's grants aren't here")?;
    let machine = peer_key(peer)?;
    owner.batch(|owner| {
        if !state.holds(&machine, MACHINE) {
            owner.grant(&genesis, std::slice::from_ref(&machine), &[MACHINE.to_owned()], &[])?;
        }
        if uid != owner.uid() && !state.holds(&root.id(), USER) {
            owner.grant(&genesis, &[root.id()], &[USER.to_owned()], &[])?;
        }
        anyhow::Ok(())
    })?;
    grant_blocks(&owner, &genesis).map(Some)
}

/// Put what a ticket brings of a mesh's grants, which say who's in it.
#[cfg(feature = "net")]
fn join_grants(place: &holokeep::net::mesh::Place, genesis: &Link, blocks: &[Vec<u8>]) -> anyhow::Result<()> {
    let members = holokeep::net::daemon::members(place)?;
    if let Some(had) = members.genesis()? {
        anyhow::ensure!(had == *genesis, "this node's mesh has other grants: join another with --mesh");
    }
    let mut repo = Catalog::open_repo(&place.repo)?;
    repo.batch(|repo| {
        for data in blocks {
            let claim = claim::Claim::parse(data).context("a ticket's grants are claims")?;
            repo.put_block(&claim.block(), holokeep::cid::CidVersion::V1)?;
        }
        anyhow::Ok(())
    })?;
    anyhow::ensure!(repo.grant_state(genesis)?.is_some(), "the ticket's grants aren't a mesh's");
    members.set_genesis(genesis)?;
    Ok(())
}

/// Give and take away what users and machines may do in the main mesh,
/// as its owner's user, or list who holds what.
#[cfg(feature = "net")]
fn grant(place: &holokeep::net::mesh::Place, command: GrantCommand) -> anyhow::Result<()> {
    anyhow::ensure!(place.is_main(), "only the main mesh has grants");
    let members = holokeep::net::daemon::members(place)?;
    let mut repo = Catalog::open_repo(&place.repo)?;
    if matches!(command, GrantCommand::Init) {
        anyhow::ensure!(members.genesis()?.is_none(), "this mesh has grants already");
        anyhow::ensure!(repo.user()?.is_some(), "this repo has no user yet: the first invite makes one, and the mesh's grants");
        let root = root_key(&repo, &place.repo)?;
        found_grants(place, &mut repo, &root)?;
        return reload(place);
    }
    let genesis = members.genesis()?.context("this mesh has no grants: `hk node grant init` to keep who's in it as grants")?;
    let commands = |commands: Vec<String>| -> anyhow::Result<Vec<String>> {
        for command in &commands {
            anyhow::ensure!(claim::is_command(command), "not a command: {command} (lower case names, each after a /)");
        }
        Ok(commands)
    };
    match command {
        GrantCommand::Init => {},
        GrantCommand::Add { who, commands: given } => {
            out!("{}", repo.grant(&genesis, &[key_named(&who)?], &commands(given)?, &[])?);
            reload(place)?;
        },
        GrantCommand::Rm { who, commands: taken } => {
            out!("{}", repo.grant(&genesis, &[key_named(&who)?], &[], &commands(taken)?)?);
            reload(place)?;
        },
        GrantCommand::Ls => {
            let state = repo.grant_state(&genesis)?.context("the mesh's first grant isn't here")?;
            out!("{}\t/", holokeep::keys::peer_id(state.founder()));
            for (who, held) in state.holders() {
                if who != *state.founder() {
                    out!("{}\t{}", holokeep::keys::peer_id(&who), if held.is_empty() { "-".to_owned() } else { held.join(" ") });
                }
            }
            if !state.waiting().is_empty() {
                eprintln!("{} grants wait for grants before them that aren't here yet", state.waiting().len());
            }
        },
    }
    Ok(())
}

fn volume(mut repo: Catalog, command: VolumeCommand) -> anyhow::Result<()> {
    match command {
        VolumeCommand::Add { name, path, sqlite } => {
            let path = std::path::absolute(&path)?;
            let others = if sqlite { repo.add_sqlite_volume(&name, &path)? } else { repo.add_volume(&name, &path)? };
            for (other, risks) in others {
                eprintln!("warning: {name} shares risks with {other} ({}): one failure there loses copies on both", risks.join(", "));
            }
        },
        VolumeCommand::Ls => {
            for volume in repo.volume_list()? {
                let label: String = volume.label.iter().fold(String::new(), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                });
                let path = volume.path.map(|path| path.display().to_string()).unwrap_or_default();
                let state = if volume.attached { "attached" } else { "detached" };
                out!("{}\t{}\t{label}\t{state}\t{}\t{path}", volume.name, volume.kind, volume.blocks);
            }
        },
        VolumeCommand::Replicate { copies } => {
            let report = repo.batch(|repo| repo.replicate(copies))?;
            out!("copied {} blocks and {} dissolved claims", report.copied, report.claims);
            if !report.short.is_empty() {
                eprintln!("{} blocks would take fewer than {copies} failures to lose; attach volumes which risk less in common", report.short.len());
            }
        },
        VolumeCommand::Risk(RiskCommand::Add { name, risks }) => {
            for risk in risks {
                repo.add_risk(&name, &risk)?;
            }
        },
        VolumeCommand::Risk(RiskCommand::Rm { name, risks }) => {
            for risk in risks {
                repo.remove_risk(&name, &risk)?;
            }
        },
        VolumeCommand::Risk(RiskCommand::Ls) => {
            for (name, risk, found) in repo.risk_list()? {
                out!("{name}\t{risk}\t{}", if found { "found" } else { "said" });
            }
        },
        VolumeCommand::Copy { name, cids } => {
            let report = repo.batch(|repo| repo.copy_to(&name, &cids))?;
            out!("copied {} blocks and {} dissolved claims", report.copied, report.claims);
            if !report.unreadable.is_empty() {
                eprintln!("{} blocks couldn't be read to be copied", report.unreadable.len());
            }
        },
    }
    Ok(())
}

fn device(dir: &Path, command: DeviceCommand) -> anyhow::Result<()> {
    use holokeep::keys::{self, Key};
    let mut repo = Catalog::open_repo(dir)?;
    match command {
        DeviceCommand::List => {
            let user = repo.user()?.context("this repo has no user: it makes one when it invites a node to its mesh")?;
            let sealed = if repo.seals()?.is_empty() { "\tno sealed root here" } else { "" };
            out!("user\t{}{sealed}", keys::peer_id(&user));
            let me = repo.signer().map(Key::id);
            for (device, ok) in repo.devices()? {
                let this = if me.as_ref() == Some(&device) { "\tthis node" } else { "" };
                let forked = if repo.forks(&device)?.is_empty() { "" } else { "\tforked" };
                out!("{}\t{}{forked}{this}", keys::peer_id(&device), if ok { "certified" } else { "revoked" });
            }
        },
        DeviceCommand::Restore => {
            let user = repo.batch(|repo| repo.restore_user(passphrase(false)?.as_bytes()).map_err(anyhow::Error::from))?;
            out!("user\t{}", keys::peer_id(&user));
        },
        DeviceCommand::Log { peer, claims } => {
            let device = keys::from_peer_id(&peer).context("not an ed25519 peer ID")?;
            for signed in repo.claims().context("this repo keeps no claims")?.signs_by(&device)? {
                let prev = signed.prev.map_or_else(|| "-".to_owned(), |prev| prev.to_string());
                out!("{}\t{prev}\t{}\t{}", signed.sign, signed.at, signed.claims);
                if claims {
                    for claim in repo.signed_in(&device, &signed.sign)? {
                        let what = claim.claim.as_ref().map_or_else(|| "not here\t-".to_owned(), describe_claim);
                        let state = if claim.retracted { "retracted" } else if claim.alone { "alone" } else { "shared" };
                        out!("\t{}\t{what}\t{state}", claim.cid);
                    }
                }
            }
            for fork in repo.forks(&device)? {
                eprintln!("forks at {}", fork.map_or_else(|| "its start".to_owned(), |fork| fork.to_string()));
            }
        },
        DeviceCommand::Revoke { peer, until, dry_run, yes } => revoke_device(dir, &repo, &peer, &until, dry_run, yes)?,
    }
    Ok(())
}

/// A claim's kind and targets, tab-separated.
fn describe_claim(claim: &claim::Claim) -> String {
    let targets: Vec<String> = claim.target().iter().map(ToString::to_string).collect();
    format!("{}\t{}", claim.kind(), targets.join(" "))
}

/// Revoke a device, saying first what'd stop counting.
fn revoke_device(dir: &Path, repo: &Catalog, peer: &str, until: &[String], dry_run: bool, yes: bool) -> anyhow::Result<()> {
    use holokeep::keys;
    let device = keys::from_peer_id(peer).context("not an ed25519 peer ID")?;
    anyhow::ensure!(repo.signer().is_some_and(|key| key.id() != device), "a node can't revoke itself");
    let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    let mut trusted = Vec::new();
    if until.is_empty() {
        trusted.extend(repo.cutoff_at(&device, now())?);
    }
    for until in until {
        match until.parse::<u64>() {
            Ok(at) => trusted.extend(repo.cutoff_at(&device, at)?),
            Err(_) => trusted.push(until.parse::<Link>().context("--until is neither a sign nor a time")?),
        }
    }
    let costs = repo.revocation_costs(&device, &trusted)?;
    if dry_run {
        for claim in &costs {
            out!("{}\t{}", claim.cid(), describe_claim(claim));
        }
        eprintln!("{} claims would stop counting", costs.len());
        return Ok(());
    }
    if !costs.is_empty() {
        eprintln!("{} claims would stop counting, signed by {peer} alone:", costs.len());
        for claim in &costs {
            eprintln!("  {}\t{}", claim.cid(), describe_claim(claim));
        }
        if !yes {
            use std::io::IsTerminal as _;
            anyhow::ensure!(io::stdin().is_terminal(), "not revoking: --yes to go ahead, or --until to trust what signed them");
            eprint!("revoke it all the same? [y/N] ");
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            anyhow::ensure!(matches!(answer.trim(), "y" | "Y" | "yes"), "not revoking");
        }
    }
    let root = root_key(repo, dir)?;
    let mut repo = Catalog::open_repo(dir)?;
    let resigned = repo.batch(|repo| repo.revoke_trusting(&root, &device, &trusted))?;
    out!("revoked {peer}; signed {resigned} of its claims again");
    Ok(())
}

/// A duration, in seconds: a number and a unit, `s`, `m`, `h`, `d` or `w`.
#[cfg(feature = "net")]
fn parse_lasting(text: &str) -> Result<u64, String> {
    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().map_err(|_| format!("not a duration: {text} (as 90s, 30m, 12h, 7d or 2w)"))?;
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return Err(format!("not a unit of time: {unit:?} (s, m, h, d or w)")),
    };
    number.checked_mul(scale).filter(|&secs| secs > 0).ok_or_else(|| format!("not a duration: {text}"))
}

/// When something lasting so long from now ends, in seconds since the
/// epoch.
#[cfg(feature = "net")]
fn ending(lasting: Option<u64>) -> Option<u64> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    lasting.map(|secs| now.saturating_add(secs))
}

/// How long till a time, in seconds since the epoch, roughly: in its
/// largest two units.
#[cfg(feature = "net")]
fn left(until: u64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    let secs = until.saturating_sub(now);
    let parts = [(secs / 86_400, "d"), (secs / 3600 % 24, "h"), (secs / 60 % 60, "m"), (secs % 60, "s")];
    let shown: Vec<String> = parts.iter().skip_while(|(n, _)| *n == 0).take(2).filter(|(n, _)| *n > 0).map(|(n, unit)| format!("{n}{unit}")).collect();
    if shown.is_empty() { "0s".to_owned() } else { shown.join(" ") }
}

/// Commands on an anchor, by name or in full.
#[cfg(feature = "net")]
fn anchor_commands(commands: &[String]) -> anyhow::Result<Vec<String>> {
    use holokeep::grants::{ANCHOR, ANCHOR_GRANT, READ, WRITE};
    commands
        .iter()
        .map(|command| match command.as_str() {
            "read" => Ok(READ.to_owned()),
            "write" => Ok(WRITE.to_owned()),
            "grant" => Ok(ANCHOR_GRANT.to_owned()),
            "all" => Ok(ANCHOR.to_owned()),
            other if claim::is_command(other) && claim::covers(ANCHOR, other) => Ok(other.to_owned()),
            other => Err(anyhow::anyhow!("not a command on an anchor: {other} (read, write, grant, all, or one under /anchor)")),
        })
        .collect()
}

/// Give or take away what a user may do with a view of an anchor: the
/// acting user's own, or one they may pass on. Giving, `until` says till
/// when, if it's not for good. Taking write away, the user's latest sets
/// in the view stand.
#[cfg(feature = "net")]
fn share(dir: Option<&PathBuf>, repo: &Catalog, anchor: &Link, who: &str, commands: &[String], give: bool, until: Option<u64>) -> anyhow::Result<()> {
    use holokeep::grants::WRITE;
    anyhow::ensure!(holokeep::claim::is_anchor(anchor), "{anchor} isn't an anchor");
    let place = holokeep::net::mesh::Place::main(&repo_dir(dir.cloned())?);
    let genesis = holokeep::net::daemon::members(&place)?.genesis()?.context("the mesh has no grants: `hk node grant init` first")?;
    let commands = anchor_commands(commands)?;
    let who = key_named(who)?;
    let cid = if give {
        repo.grant_on_until(&genesis, anchor, std::slice::from_ref(&who), &commands, &[], &[], until)?
    } else {
        let stands = if commands.iter().any(|command| claim::covers(command, WRITE)) {
            let view = holokeep::claim::viewed(anchor).map_or_else(|| repo.user().ok().flatten().and_then(|me| holokeep::claim::view(anchor, &me)), |_| Some(anchor.clone()));
            view.map(|view| repo.latest_sets_by(&view, &who)).transpose()?.unwrap_or_default()
        } else {
            Vec::new()
        };
        repo.grant_on(&genesis, anchor, std::slice::from_ref(&who), &[], &commands, &stands)?
    };
    out!("{cid}");
    reload(&place)
}

/// Add a file or directory, returning its root.
fn add(importer: &Importer, path: &Path, quiet: bool, sink: &mut impl BlockSink) -> anyhow::Result<Link> {
    if path == Path::new("-") {
        let root = importer.add_file(std::io::stdin().lock(), sink)?;
        out!("{}", root.cid);
        return Ok(root.cid.into());
    }

    // Report paths relative to the parent, like Kubo
    let base = path.parent().unwrap_or_else(|| Path::new(""));
    let mut report = |p: &Path, link: &dag::DagLink| {
        if !quiet {
            let rel = p.strip_prefix(base).unwrap_or(p);
            out!("added {} {}", link.cid, rel.display());
        }
    };
    let Some(root) = importer.add_path(path, sink, &mut report)? else {
        anyhow::bail!("unsupported file type: {}", path.display());
    };
    if quiet {
        out!("{}", root.cid);
    }
    Ok(root.cid.into())
}

/// A block's links, or the blocks linking to it.
fn refs(repo: &Catalog, cid: &Link, back: bool) -> anyhow::Result<()> {
    if back {
        let mut out = io::BufWriter::new(io::stdout().lock());
        for source in repo.backrefs(cid.multihash())? {
            for cid in repo.cids(source.as_ref())? {
                writeln!(out, "{cid}")?;
            }
        }
        Ok(out.flush()?)
    }
    else {
        let block = repo.get_block(cid)?.with_context(|| format!("block {cid} not found"))?;
        let mut out = io::BufWriter::new(io::stdout().lock());
        for link in links::links(cid.codec(), block.data())? {
            writeln!(out, "{link}")?;
        }
        Ok(out.flush()?)
    }
}

/// Import, export or fetch whole DAGs.
fn compact(repo: &Catalog, compact: Compact) -> anyhow::Result<()> {
    // What the database holds that a kept file would, as big, moved out
    // first, so what it took is free to give back
    if !compact.dry_run {
        let done = repo.rehome(u64::MAX)?;
        if done.files > 0 {
            eprintln!("kept {} files whole, {} bytes out of the database", done.files, done.bytes);
        }
    }
    let mut refused = Vec::new();
    repo.compact(compact, &mut |done| {
        let outcome = match done.outcome {
            Outcome::AlreadyCompact => "already compact".to_owned(),
            Outcome::WouldCompact => "would compact".to_owned(),
            Outcome::Compacted { took, wal_left: false } => format!("compacted in {:.2}s", took.as_secs_f64()),
            Outcome::Compacted { took, wal_left: true } => format!("compacted in {:.2}s, its WAL not emptied since a reader's still on it; compact again, or it goes once nothing has it open", took.as_secs_f64()),
            Outcome::TooLong => "refused: big enough that writers might give up waiting for it".to_owned(),
            Outcome::NoRoom { needed, available } => format!("refused: needs {needed} bytes for its WAL, {available} left"),
        };
        out!("{}\t{}\t{}\t{outcome}", done.volume, done.before, done.after);
        if done.outcome.refused() {
            refused.push((done.volume.clone(), done.outcome));
        }
    })?;
    match refused.iter().find(|(_, outcome)| *outcome == Outcome::TooLong) {
        Some(_) => anyhow::bail!("not all compacted: stop any mount or node using this repo, then use --long"),
        None if !refused.is_empty() => anyhow::bail!("not all compacted: too little disk left"),
        None => Ok(()),
    }
}

fn git_import(repo: Option<PathBuf>, git: &Path, no_keep: bool) -> anyhow::Result<()> {
    use std::collections::{BTreeMap, HashSet};
    let refs = holokeep::git::refs(git)?;
    open_repo(repo)?.batch_breathing(|repo| {
        let mut imported: HashSet<Vec<u8>> = HashSet::new();
        let mut linked: BTreeMap<Vec<u8>, Link> = BTreeMap::new();
        let have = |link: &Link| repo.get_block(link).ok().flatten();
        let count = holokeep::git::objects(git, &have, &mut |object| {
            let block = &object.block;
            linked.extend(holokeep::git::links(block.data())?.into_iter().map(|link| (link.to_bytes(), link)));
            // A pack's delta kept as a delta, where its base is
            let provenance = object.delta.as_ref().map_or(holokeep::dag::Provenance::Unknown, |(base, delta)| {
                holokeep::dag::Provenance::Delta { base: base.multihash(), delta }
            });
            repo.put_block_from(block, holokeep::cid::CidVersion::V1, provenance).map_err(|e| io::Error::other(e.to_string()))?;
            imported.insert(Link::from(block.cid().clone()).to_bytes());
            repo.breathe().map_err(|e| io::Error::other(e.to_string()))?;
            Ok(())
        })?;
        // What's linked to but isn't anywhere here, as a submodule's
        // commits: where the keeps' reach stops
        let mut beyond = Vec::new();
        for (bytes, link) in &linked {
            if !imported.contains(bytes) && repo.get_block(link)?.is_none() {
                beyond.push(link.clone());
            }
        }
        let mut kept: HashSet<Vec<u8>> = HashSet::new();
        for (name, link) in &refs {
            if !no_keep && kept.insert(link.to_bytes()) {
                repo.keep_short_of(link, &beyond)?;
            }
            out!("{link} {name}");
        }
        eprintln!("imported {count} objects{}", if beyond.is_empty() { String::new() } else { format!(", {} linked to from elsewhere", beyond.len()) });
        // What came whole, as loose objects do, kept as deltas on the
        // version after it
        let deltas = repo.git_deltas()?;
        if deltas.deltas > 0 {
            eprintln!("{} kept as deltas on the versions after them", deltas.deltas);
        }
        anyhow::Ok(())
    })
}

fn soup_fs(repo: Option<PathBuf>, command: FsCommand) -> anyhow::Result<()> {
    use holokeep::fs;
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    fetch_through_node(&mut repo, &dir);
    let locate = |repo: &Catalog, path: &Path| -> anyhow::Result<fs::Located> { Ok(fs::locate(repo, &fs::soup_path(path))?) };
    match command {
        FsCommand::Stat { paths, copies, ask } => {
            for (i, path) in paths.iter().enumerate() {
                let located = fs::find(&repo, &fs::soup_path(path))?;
                if i > 0 {
                    out!("");
                }
                if paths.len() > 1 {
                    out!("path\t{}", path.display());
                }
                if let Some(anchor) = &located.anchor {
                    out!("anchor\t{anchor}");
                    if !located.rel.as_os_str().is_empty() {
                        out!("at\t{}", located.rel.display());
                    }
                }
                let Some(cid) = located.at else {
                    out!("cid\tnone: the anchor's nothing yet");
                    continue;
                };
                out!("cid\t{cid}");
                match holokeep::export::stat(&repo, &cid) {
                    Ok(holokeep::export::Kind::Directory) => out!("kind\tdirectory"),
                    Ok(holokeep::export::Kind::File(size)) => out!("kind\tfile, {size} bytes"),
                    Ok(holokeep::export::Kind::Symlink(target)) => out!("kind\tsymlink to {}", String::from_utf8_lossy(&target)),
                    Err(e) => out!("kind\tunknown: {e}"),
                }
                if let Some(mounted) = fs::mount_point(&repo, &cid).unwrap_or_default() {
                    out!("mounts\t{mounted}");
                    out!("which is\t{}", repo.anchor_value(&mounted)?.map_or_else(|| "nothing yet".to_owned(), |value| value.to_string()));
                }
                if let Some(claims) = repo.claims() {
                    let tags: Vec<String> = claims.tags(cid.multihash())?.iter().map(|tag| claim::tag_name(tag).map_or_else(|| tag.to_string(), ToOwned::to_owned)).collect();
                    if !tags.is_empty() {
                        out!("tags\t{}", tags.join(" "));
                    }
                }
                for (lens, same) in repo.same_as(&cid)? {
                    for other in same {
                        out!("same as\t{other}, as {}", holokeep::same::named(lens.as_deref()));
                    }
                }
                if repo.is_public(&cid)? {
                    out!("public\tanyone's to have");
                }
                if copies || ask.any() {
                    dag_health(&repo, &dir, &cid, ask)?;
                }
            }
        },
        FsCommand::Rm { paths } => {
            let located = paths.iter().map(|path| locate(&repo, path)).collect::<anyhow::Result<Vec<_>>>()?;
            for (anchor, value) in fs::remove(&mut repo, &located)? {
                eprintln!("{anchor} is {value} now");
            }
        },
        FsCommand::Anchor { path } => {
            let located = locate(&repo, &path)?;
            out!("{}", fs::promote(&mut repo, &located)?);
        },
        FsCommand::Log { path } => {
            let (anchor, rel) = fs::logged(&repo, &fs::soup_path(&path))?;
            out!("anchor\t{anchor}");
            if !rel.as_os_str().is_empty() {
                out!("in\t{}", rel.display());
            }
            let versions = fs::log(&repo, &anchor, &rel)?;
            let now = health::now();
            for version in &versions {
                let (cid, size) = match &version.was {
                    fs::Was::There(cid, size) => (cid.to_string(), size.map_or_else(|| "-".to_owned(), health::bytes)),
                    fs::Was::Absent | fs::Was::NotHere => ("-".to_owned(), "-".to_owned()),
                };
                let by: Vec<String> = version.by.iter().map(holokeep::keys::peer_id).collect();
                let by = if by.is_empty() { "unsigned".to_owned() } else { by.join(",") };
                let at = i64::try_from(version.at).unwrap_or(i64::MAX);
                out!("{}\t{}\t{}\t{cid}\t{size}\tby {by}\tset {}{}", version.at, health::ago(at, now), version.change.word(), version.set, if version.head { "\thead" } else { "" });
            }
            if versions.is_empty() {
                eprintln!("no version of it: nothing's been there");
            }
        },
    }
    Ok(())
}

/// What's known of the copies other members hold of these blocks, from
/// the running node, asking as said; with the copies wanted where no keep
/// says, and whether copies here count.
fn copies_known(dir: &Path, cids: &[Link], ask: AskArgs) -> anyhow::Result<(health::Known, usize, bool)> {
    let copies = holokeep::config::Config::load(dir)?.node("main").copies.unwrap_or(2);
    #[cfg(feature = "net")]
    {
        use holokeep::net::check::Asking;
        let place = holokeep::net::mesh::Place::main(dir);
        let asking = if ask.ask_all { Asking::All } else if ask.ask { Asking::Unsighted } else { Asking::No };
        if let Some(said) = holokeep::net::daemon::copies(&place, cids, asking)? {
            return Ok((said.known, said.copies, said.own));
        }
        anyhow::ensure!(!ask.any(), "asking members needs the running node: start `hk node run`");
        let own = holokeep::net::daemon::members(&place)?.client_of()?.is_none();
        Ok((health::Known::default(), copies, own))
    }
    #[cfg(not(feature = "net"))]
    {
        let _ = cids;
        anyhow::ensure!(!ask.any(), "asking members needs hk built with the net feature");
        Ok((health::Known::default(), copies, true))
    }
}

/// Say who was asked, and who didn't answer, or that nothing's known of
/// other members.
fn say_asked(known: &health::Known, ask: AskArgs) {
    if !known.node {
        out!("elsewhere\tunknown: the node isn't running, so only what's here is counted");
    }
    else if ask.any() && known.connected == 0 {
        out!("asked\tno one: no member keeping this account's blocks is connected");
    }
    if !known.asked.is_empty() {
        out!("asked\t{}", known.asked.iter().cloned().collect::<Vec<_>>().join(" "));
    }
    if !known.unanswered.is_empty() {
        out!("unanswered\t{}", known.unanswered.iter().cloned().collect::<Vec<_>>().join(" "));
    }
}

fn block(repo: Option<PathBuf>, command: BlockCommand) -> anyhow::Result<()> {
    match command {
        BlockCommand::Where { cids, ask } => {
            let dir = repo_dir(repo)?;
            block_where(&open_repo(Some(dir.clone()))?, &dir, &cids, ask)
        },
        BlockCommand::Get { cid } => {
            let repo = open_repo(repo)?;
            in_repo(&repo, &cid)?;
            let block = repo.get_block(&cid)?.with_context(|| format!("block {cid} not found"))?;
            Ok(io::stdout().lock().write_all(block.data())?)
        },
    }
}

/// `hk block where`: each block's copies, and how safe it is.
fn block_where(repo: &Catalog, dir: &Path, cids: &[Link], ask: AskArgs) -> anyhow::Result<()> {
    let (known, copies, own) = copies_known(dir, cids, ask)?;
    let now = health::now();
    for (i, cid) in cids.iter().enumerate() {
        if i > 0 {
            out!("");
        }
        let health = health::Health::of(repo, cid, None, &known, own, copies)?;
        out!("cid\t{cid}");
        if !own {
            out!("here\tnot counted: this node is a client, whose copies are a cache");
        }
        else if health.here.is_empty() {
            out!("here\tnone");
        }
        for replica in &health.here {
            out!("here\t{}", replica.risks.join(" "));
        }
        for copy in &health.elsewhere {
            out!("{}\t{}\t{}", copy.peer, health::ago(copy.seen, now), copy.replica.risks.join(" "));
        }
        out!("target\t{}, {}", health.target, if health.kept { "as its keeps say" } else { "the mesh's" });
        match health.tolerance {
            0 => out!("tolerance\t0: no copy is known"),
            1 if !health.shared.is_empty() => out!("tolerance\t1: every copy is lost if any of {} fails", health.shared.join(" ")),
            n => out!("tolerance\t{n}"),
        }
    }
    if !cids.is_empty() {
        say_asked(&known, ask);
    }
    Ok(())
}

/// `hk dag health`: how safe the DAG under a CID is.
fn dag_health(repo: &Catalog, dir: &Path, root: &Link, ask: AskArgs) -> anyhow::Result<()> {
    let mut blocks = Vec::new();
    repo.walk_under(root, &mut |cid, size, _| {
        blocks.push((cid.clone(), size));
        Ok(())
    })?;
    let cids: Vec<Link> = blocks.iter().map(|(cid, _)| cid.clone()).collect();
    let (known, copies, own) = copies_known(dir, &cids, ask)?;
    let mut summary = health::Summary::default();
    for (cid, size) in &blocks {
        summary.add(&health::Health::of(repo, cid, *size, &known, own, copies)?, own);
    }
    let some = |(count, bytes): (usize, u64)| format!("{count} block{}, {}", if count == 1 { "" } else { "s" }, health::bytes(bytes));
    let such_as = |example: &Option<Link>| example.as_ref().map_or_else(String::new, |cid| format!(", such as {cid}"));
    out!("blocks\t{}", some((summary.blocks, summary.bytes)));
    if let Some((least, most)) = summary.targets {
        out!("target\t{}", if least == most { least.to_string() } else { format!("{least} to {most}") });
    }
    if let (Some(least), Some(most)) = (summary.least, summary.most) {
        out!("tolerance\t{}", if least == most { least.to_string() } else { format!("least {least}, most {most}") });
    }
    let (short, short_bytes, example) = &summary.short;
    if *short == 0 {
        out!("short\tnone");
    }
    else {
        out!("short\t{} below target{}", some((*short, *short_bytes)), such_as(example));
    }
    if own && summary.not_here.0 > 0 {
        out!("not here\t{}, and nothing under them is walked", some(summary.not_here));
    }
    if summary.none.0 > 0 {
        let (count, bytes, example) = &summary.none;
        out!("no copy\t{}{}", some((*count, *bytes)), such_as(example));
    }
    let mut one_risk: Vec<(&Vec<String>, &(usize, u64))> = summary.one_risk.iter().collect();
    one_risk.sort_by(|a, b| b.1.cmp(a.1));
    for (risks, &counted) in one_risk {
        out!("one failure\t{}, lost if any of {} fails", some(counted), risks.join(" "));
    }
    say_asked(&known, ask);
    Ok(())
}

/// The anchor a CID or a path of the soup names: one, or a mount point of
/// one (see `hk fs`).
fn anchor_named(repo: &Catalog, named: &Path) -> anyhow::Result<Link> {
    if let Some(anchor) = named.to_str().and_then(|text| text.parse::<Link>().ok()) {
        return Ok(anchor);
    }
    let located = holokeep::fs::locate(repo, &holokeep::fs::soup_path(named))?;
    match located.at.as_ref().map(|at| holokeep::fs::mount_point(repo, at)).transpose()?.flatten() {
        Some(mounted) => Ok(mounted),
        None if located.rel.as_os_str().is_empty() => Ok(located.anchor),
        None => anyhow::bail!("{} isn't an anchor, nor a mount point of one: make it one with `hk fs anchor`", named.display()),
    }
}

/// The anchor a CID or a path of the soup names, as `anchor_named` finds
/// it, or else, for a folder that's no anchor, a new one it's made, set
/// to it and mounted where it was (see `hk fs anchor`).
fn anchor_or_folder(repo: &mut Catalog, named: &Path) -> anyhow::Result<Link> {
    if let Ok(anchor) = anchor_named(repo, named) {
        return Ok(anchor);
    }
    let located = holokeep::fs::locate(repo, &holokeep::fs::soup_path(named))?;
    let at = located.at.clone().with_context(|| format!("{}: nothing's there", named.display()))?;
    anyhow::ensure!(matches!(holokeep::export::stat(repo, &at)?, holokeep::export::Kind::Directory), "{} isn't a folder, an anchor, nor a mount point of one", named.display());
    let anchor = holokeep::fs::promote(repo, &located)?;
    eprintln!("{} is an anchor of its own now, {anchor}, mounted where it was", named.display());
    Ok(anchor)
}

/// Read what a capability names from the first holder's door that has
/// it, and isn't behind the head read before: those given, or else those
/// it says.
#[cfg(feature = "net")]
fn read_at_doors(repo: &Catalog, capability: &holokeep::cap::Capability, from: Vec<String>, remembered: &dyn Fn(&Link) -> Vec<Vec<u8>>) -> anyhow::Result<holokeep::cap::Reading> {
    use holokeep::cap::{self, Capability};
    let doors = if from.is_empty() {
        capability.live().map(|live| live.at.clone()).unwrap_or_default()
    } else {
        from
    };
    anyhow::ensure!(!doors.is_empty(), "say where to read it from: a CAR, or a holder's door with --from");
    let mut errors = Vec::new();
    for door in doors {
        let read = || -> anyhow::Result<cap::Reading> {
            let reader = holokeep::net::door::Reader::connect(&door.parse().context("not a multiaddr")?)?;
            Ok(match (capability, capability.live()) {
                (_, Some(live)) => cap::read_into(repo, &reader, live, remembered)?,
                (Capability::Snapshot(snapshot), None) => cap::Reading { plain: snapshot.plain.clone(), blocks: cap::unseal(&reader, snapshot)?, heads: Vec::new(), mounts: Vec::new(), base: None, forked: 0 },
                _ => anyhow::bail!("a capability of nothing to read"),
            })
        };
        match read() {
            Ok(read) => return Ok(read),
            Err(e) => errors.push(format!("{door}: {e}")),
        }
    }
    anyhow::bail!("no door had it: {}", errors.join("; "))
}

#[cfg(not(feature = "net"))]
fn read_at_doors(_: &Catalog, _: &holokeep::cap::Capability, _: Vec<String>, _: &dyn Fn(&Link) -> Vec<Vec<u8>>) -> anyhow::Result<holokeep::cap::Reading> {
    anyhow::bail!("this hk reads from a CAR alone: it's built without networking")
}

fn cap(repo: Option<PathBuf>, command: CapCommand) -> anyhow::Result<()> {
    use holokeep::cap::{self, Capability, Snapshot};
    match command {
        CapCommand::Export { cid, output } => {
            fetch_first(repo.as_ref(), &cid)?;
            let repo = open_repo(repo)?;
            let read = cap::fresh_key()?;
            let sealed = cap::seal(&repo, &cid, &read)?;
            // Written aside and renamed, so a failed export leaves nothing
            let dir = output.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
            let mut file = io::BufWriter::new(tempfile::NamedTempFile::new_in(dir)?);
            car::write_blocks(&mut file, std::slice::from_ref(&sealed.root), &sealed.blocks)?;
            file.into_inner().map_err(io::IntoInnerError::into_error)?.persist(&output)?;
            eprintln!("sealed {} blocks: whoever has this capability can read all of it", sealed.blocks.len());
            out!("{}", Capability::Snapshot(Snapshot::new(sealed.root, cid, read)).encode());
            Ok(())
        },
        CapCommand::Publish { anchor, output, at } => {
            let dir = repo_dir(repo)?;
            let mut repo = open_repo(Some(dir.clone()))?;
            let anchor = anchor_or_folder(&mut repo, &anchor)?;
            let value = repo.anchor_value(&anchor)?.with_context(|| format!("{anchor} is nothing yet"))?;
            fetch_first(Some(&dir), &value)?;
            let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
            let published = cap::Published::current(&mut repo, &vault, &anchor)?;
            let publications = cap::publish_mounted(&mut repo, &vault, &anchor, &value)?;
            if let Some(output) = output {
                let mut blocks = Vec::new();
                let mut seen = std::collections::HashSet::new();
                for (_, publication) in &publications {
                    blocks.extend(cap::published_blocks(&repo, &publication.manifest)?.into_iter().filter(|block| seen.insert(block.cid().to_string())));
                }
                let roots: Vec<Link> = publications.first().map(|(_, publication)| publication.set.clone()).into_iter().collect();
                let parent = output.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
                let mut file = io::BufWriter::new(tempfile::NamedTempFile::new_in(parent)?);
                car::write_blocks(&mut file, &roots, &blocks)?;
                file.into_inner().map_err(io::IntoInnerError::into_error)?.persist(&output)?;
            }
            for (i, (anchor, publication)) in publications.iter().enumerate() {
                let what = if i == 0 { String::new() } else { ", mounted in it".to_owned() };
                if publication.fresh {
                    eprintln!("published {anchor}{what} as it is now: whoever has its capability can read it as it is whenever they read it");
                } else {
                    eprintln!("{anchor}{what} is published as it is already");
                }
            }
            let capability = match published.capability() {
                Capability::Live(live) => Capability::Live(live.at(at)),
                other => other,
            };
            out!("{}", capability.encode());
            Ok(())
        },
        CapCommand::Unpublish { anchor } => {
            let dir = repo_dir(repo)?;
            let mut repo = open_repo(Some(dir.clone()))?;
            let anchor = anchor_named(&repo, &anchor)?;
            let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
            let published = cap::Published::current(&mut repo, &vault, &anchor)?;
            anyhow::ensure!(cap::unpublish(&mut repo, &vault, &published)?, "{anchor} isn't published");
            eprintln!("{anchor} is published no more: what's published of it is collected in time");
            Ok(())
        },
        CapCommand::Ls => {
            let dir = repo_dir(repo)?;
            let mut repo = open_repo(Some(dir.clone()))?;
            let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
            for (anchor, _) in cap::published(&mut repo, &vault)? {
                out!("{anchor}\t{}", cap::Published::current(&mut repo, &vault, &anchor)?.capability().encode());
            }
            Ok(())
        },
        CapCommand::Import { capability, car, from } => cap_import(repo, &capability, &car, from),
        CapCommand::Grant { anchor, at } => cap_grant(repo, &anchor, at),
        CapCommand::Take { car } => cap_take(repo, &car),
        CapCommand::Writers { anchor } => cap_writers(repo, &anchor),
        command @ (CapCommand::Rekey { .. } | CapCommand::Reseal { .. }) => cap_keys(repo, command),
        command @ (CapCommand::Reader { .. } | CapCommand::Readers { .. } | CapCommand::Unread { .. }) => cap_readers(repo, command),
        CapCommand::Revoke { anchor, writer } => cap_revoke(repo, &anchor, &writer),
        CapCommand::Write { capability, root, output, car, from } => cap_write(repo, &capability, &root, output.as_deref(), &car, from),
    }
}

/// Give a capability's writer key write on the plaintext anchor too, as a
/// visitor, so what it writes counts in the owner's view once it's taken
/// in: if the mesh has grants; with none, any set counts.
#[cfg(feature = "net")]
fn grant_plaintext_write(dir: &Path, repo: &Catalog, anchor: &Link, writer: &Link) -> anyhow::Result<()> {
    let place = holokeep::net::mesh::Place::main(dir);
    let Some(genesis) = holokeep::net::daemon::members(&place)?.genesis()? else {
        return Ok(());
    };
    repo.grant_on(&genesis, anchor, std::slice::from_ref(writer), &[holokeep::grants::WRITE.to_owned()], &[], &[])?;
    reload(&place)
}

#[cfg(not(feature = "net"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn, reason = "the same as with networking, which can fail")]
fn grant_plaintext_write(_: &Path, _: &Catalog, _: &Link, _: &Link) -> anyhow::Result<()> {
    Ok(())
}

/// Write a head a writer wrote at the first holder's door that takes it.
#[cfg(feature = "net")]
fn write_at_doors(live: &holokeep::cap::Live, written: &holokeep::cap::Written, doors: Vec<String>) -> anyhow::Result<()> {
    anyhow::ensure!(!doors.is_empty(), "say where to write it: a holder's door with --from, or a CAR with -o");
    let mut errors = Vec::new();
    for door in doors {
        let write = || -> anyhow::Result<()> {
            let reader = holokeep::net::door::Reader::connect(&door.parse().context("not a multiaddr")?)?;
            Ok(reader.write(&live.view, &written.set, &written.sign, &written.blocks)?)
        };
        match write() {
            Ok(()) => return Ok(()),
            Err(e) => errors.push(format!("{door}: {e}")),
        }
    }
    anyhow::bail!("no door took it: {}", errors.join("; "))
}

#[cfg(not(feature = "net"))]
fn write_at_doors(_: &holokeep::cap::Live, _: &holokeep::cap::Written, _: Vec<String>) -> anyhow::Result<()> {
    anyhow::bail!("this hk writes to a CAR alone: it's built without networking")
}

/// What reads a sealed anchor, for a reader's capability: the read key
/// out of its box in the latest keyring, from CARs, or at a holder's door
/// (those given, or else those it says).
fn reader_live(reader: &holokeep::cap::ReaderCap, car: &[PathBuf], from: &[String]) -> anyhow::Result<holokeep::cap::Live> {
    if !car.is_empty() {
        let held = held_of(car)?;
        return Ok(holokeep::cap::open_keyring(&reader.view, reader.seed(), held.all())?.at(reader.at.clone()));
    }
    let doors = if from.is_empty() { reader.at.clone() } else { from.to_vec() };
    anyhow::ensure!(!doors.is_empty(), "say where to read it from: a CAR, or a holder's door with --from");
    let mut errors = Vec::new();
    for door in &doors {
        match keyring_at(door, reader) {
            Ok(live) => return Ok(live.at(reader.at.clone())),
            Err(e) => errors.push(format!("{door}: {e}")),
        }
    }
    anyhow::bail!("no door had its keyring: {}", errors.join("; "))
}

/// A reader's read key, out of its box in the keyring at a door.
#[cfg(feature = "net")]
fn keyring_at(door: &str, reader: &holokeep::cap::ReaderCap) -> anyhow::Result<holokeep::cap::Live> {
    let at = holokeep::net::door::Reader::connect(&door.parse().context("not a multiaddr")?)?;
    let blocks = at.keyring(&reader.view)?;
    Ok(holokeep::cap::open_keyring(&reader.view, reader.seed(), blocks.iter().map(|(_, data)| data.as_slice()))?)
}

#[cfg(not(feature = "net"))]
fn keyring_at(_: &str, _: &holokeep::cap::ReaderCap) -> anyhow::Result<holokeep::cap::Live> {
    anyhow::bail!("this hk reads from a CAR alone: it's built without networking")
}

/// Every block of some CARs, held as one.
fn held_of(cars: &[PathBuf]) -> anyhow::Result<holokeep::cap::Held> {
    let mut held = holokeep::cap::Held::default();
    for car in cars {
        held.add_car(io::BufReader::new(std::fs::File::open(car).with_context(|| format!("opening {}", car.display()))?))?;
    }
    Ok(held)
}

/// `hk cap take`: take in what writers wrote, from CARs, and publish
/// what's taken in again.
fn cap_take(repo: Option<PathBuf>, car: &[PathBuf]) -> anyhow::Result<()> {
    use holokeep::cap;
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let held = held_of(car)?;
    repo.batch_breathing(|repo| {
        for block in held.blocks() {
            repo.put_block(&block, holokeep::cid::CidVersion::V1)?;
        }
        Ok::<_, anyhow::Error>(())
    })?;
    let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
    let taken = cap::take_in(&mut repo, &vault)?;
    for taken in &taken {
        out!("{}\t{}", taken.anchor, taken.set);
        let value = repo.anchor_value(&taken.anchor)?.with_context(|| format!("{} is nothing", taken.anchor))?;
        cap::publish_mounted(&mut repo, &vault, &taken.anchor, &value)?;
    }
    anyhow::ensure!(!taken.is_empty(), "nothing in them a writer wrote of an anchor this account publishes, that isn't here already");
    Ok(())
}

/// Take write on the plaintext anchor away from a capability's writer
/// key too, if the mesh has grants: its latest sets there stand.
#[cfg(feature = "net")]
fn take_plaintext_write(dir: &Path, repo: &Catalog, anchor: &Link, writer: &Link) -> anyhow::Result<()> {
    let place = holokeep::net::mesh::Place::main(dir);
    let Some(genesis) = holokeep::net::daemon::members(&place)?.genesis()? else {
        return Ok(());
    };
    let Some(state) = repo.grant_state(&genesis)? else {
        return Ok(());
    };
    let Some(me) = repo.user()? else {
        return Ok(());
    };
    if !state.holds_on(&me, anchor, writer, holokeep::grants::WRITE) {
        return Ok(());
    }
    let view = holokeep::claim::view(anchor, &me).context("no view of the anchor")?;
    let stands = repo.latest_sets_by(&view, writer)?;
    repo.grant_on(&genesis, anchor, std::slice::from_ref(writer), &[], &[holokeep::grants::WRITE.to_owned()], &stands)?;
    reload(&place)
}

#[cfg(not(feature = "net"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn, reason = "the same as with networking, which can fail")]
fn take_plaintext_write(_: &Path, _: &Catalog, _: &Link, _: &Link) -> anyhow::Result<()> {
    Ok(())
}

/// `hk cap grant`: mint a writer for a published anchor, and print its
/// capability.
fn cap_grant(repo: Option<PathBuf>, anchor: &Path, at: Vec<String>) -> anyhow::Result<()> {
    use holokeep::cap::{self, Capability};
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let anchor = anchor_named(&repo, anchor)?;
    let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
    let published = cap::Published::current(&mut repo, &vault, &anchor)?;
    let seed = cap::add_writer(&mut repo, &vault, &published)?;
    let Capability::Write(write) = published.write_capability(seed, repo.user()?) else {
        anyhow::bail!("not a write capability");
    };
    grant_plaintext_write(&dir, &repo, &anchor, &write.writer().id())?;
    let write = cap::Write::new(write.live.clone().at(at), write.seed(), write.of.clone(), write.owner);
    eprintln!("whoever has this capability can write {anchor} and read it, till their write's taken away");
    out!("{}", Capability::Write(write).encode());
    Ok(())
}

/// `hk cap reader`, `readers` and `unread`: a published anchor's readers.
fn cap_readers(repo: Option<PathBuf>, command: CapCommand) -> anyhow::Result<()> {
    use holokeep::cap;
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
    let reader_id = |public: &[u8; 32]| multibase::encode(multibase::Base::Base32Lower, public);
    match command {
        CapCommand::Reader { anchor, at } => {
            let anchor = anchor_named(&repo, &anchor)?;
            let (published, seed) = cap::add_reader(&mut repo, &vault, &anchor)?;
            let capability = match published.reader_capability(seed) {
                cap::Capability::Reader(reader) => cap::Capability::Reader(reader.at(at)),
                other => other,
            };
            eprintln!("whoever has this capability reads {anchor}, as its read key changes, till their read's taken away");
            out!("{}", capability.encode());
        },
        CapCommand::Readers { anchor } => {
            let anchor = anchor_named(&repo, &anchor)?;
            for reader in cap::Published::current(&mut repo, &vault, &anchor)?.readers {
                out!("{}", reader_id(&reader));
            }
        },
        CapCommand::Unread { anchor, reader } => {
            let anchor = anchor_named(&repo, &anchor)?;
            let (_, bytes) = multibase::decode(&reader).context("not a reader's public key")?;
            let reader = <[u8; 32]>::try_from(bytes.as_slice()).ok().context("not a reader's public key")?;
            let published = cap::remove_reader(&mut repo, &vault, &anchor, &reader)?;
            eprintln!("{} reads {anchor} no more: its read key's new, epoch {}, boxed to its {} other readers", reader_id(&reader), published.epoch, published.readers.len());
        },
        _ => anyhow::bail!("not a command on readers"),
    }
    Ok(())
}

/// `hk cap rekey` and `reseal`: a published anchor's read key, and what's
/// sealed under it.
fn cap_keys(repo: Option<PathBuf>, command: CapCommand) -> anyhow::Result<()> {
    use holokeep::cap::{self, Capability};
    match command {
        CapCommand::Rekey { anchor, at } => {
            let dir = repo_dir(repo)?;
            let mut repo = open_repo(Some(dir.clone()))?;
            let anchor = anchor_named(&repo, &anchor)?;
            let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
            let published = cap::rekey(&mut repo, &vault, &anchor)?;
            eprintln!("{anchor} has a new read key, its epoch {}: older capabilities read nothing new", published.epoch);
            let capability = match published.capability() {
                Capability::Live(live) => Capability::Live(live.at(at)),
                other => other,
            };
            out!("{}", capability.encode());
            Ok(())
        },
        CapCommand::Reseal { anchor, forget } => {
            let dir = repo_dir(repo)?;
            let mut repo = open_repo(Some(dir.clone()))?;
            let anchor = anchor_named(&repo, &anchor)?;
            let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
            let publication = cap::reseal(&mut repo, &vault, &anchor, forget)?;
            if forget {
                eprintln!("sealed {anchor} again whole, and let go of what was published of it before: {}", publication.manifest);
            } else {
                eprintln!("sealed {anchor} again whole: {}", publication.manifest);
            }
            Ok(())
        },
        _ => anyhow::bail!("not a command on read keys"),
    }
}

/// `hk cap writers`: list who may write a published anchor.
fn cap_writers(repo: Option<PathBuf>, anchor: &Path) -> anyhow::Result<()> {
    use holokeep::cap;
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let anchor = anchor_named(&repo, anchor)?;
    let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
    let published = cap::Published::current(&mut repo, &vault, &anchor)?;
    for writer in cap::writers(&repo, &vault, &published)? {
        let may = if writer.writes { "writes".to_owned() } else { format!("taken away, {} sets stand", writer.stands.len()) };
        let whose = if writer.this_machine { "\tthis machine" } else { "" };
        out!("{}\t{may}{whose}", holokeep::keys::peer_id(&writer.key));
    }
    Ok(())
}

/// `hk cap revoke`: take a writer's write on a published anchor away.
fn cap_revoke(repo: Option<PathBuf>, anchor: &Path, writer: &str) -> anyhow::Result<()> {
    use holokeep::cap;
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let anchor = anchor_named(&repo, anchor)?;
    let writer = key_named(writer)?;
    let vault = holokeep::vault::Vault::open(&dir, repo.uid())?;
    let published = cap::Published::current(&mut repo, &vault, &anchor)?;
    let stands = cap::take_write(&mut repo, &vault, &published, &writer)?;
    take_plaintext_write(&dir, &repo, &anchor, &writer)?;
    eprintln!("{} may write {anchor} no more: {} of its sets stand, and nothing after", holokeep::keys::peer_id(&writer), stands.len());
    Ok(())
}

/// `hk cap write`: write a sealed anchor with a write capability, after
/// its latest head, read from a CAR or at holders' doors, into a CAR.
fn cap_write(repo: Option<PathBuf>, capability: &str, root: &Link, output: Option<&Path>, car: &[PathBuf], from: Vec<String>) -> anyhow::Result<()> {
    use holokeep::cap::{self, Capability};
    let capability = Capability::decode(capability)?;
    let Capability::Write(write) = &capability else {
        anyhow::bail!("that capability reads, but doesn't write");
    };
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let uid = repo.uid();
    let remembered = |view: &Link| cap::Remembered::of(&dir, uid, view).claims().unwrap_or_default();
    let doors = if from.is_empty() { write.live.at.clone() } else { from };
    let reading = if car.is_empty() {
        read_at_doors(&repo, &capability, doors.clone(), &remembered)?
    } else {
        cap::read_into(&repo, &held_of(car)?, &write.live, &remembered)?
    };
    let base = reading.base.context("nothing to write after")?;
    let written = cap::write(&mut repo, write, &base, root)?;
    match output {
        Some(output) => {
            let parent = output.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
            let mut file = io::BufWriter::new(tempfile::NamedTempFile::new_in(parent)?);
            car::write_blocks(&mut file, &[written.set_cid()], &written.all())?;
            file.into_inner().map_err(io::IntoInnerError::into_error)?.persist(output)?;
        },
        None => write_at_doors(&write.live, &written, doors)?,
    }
    eprintln!("wrote {} as {root}, after the head {}: {} blocks", write.of, base.set, written.blocks.len().saturating_add(2));
    out!("{}", written.set_cid());
    Ok(())
}

/// `hk cap import`: read what a capability names, from a CAR or at
/// holders' doors, into the repo, remembering each head read.
fn cap_import(repo: Option<PathBuf>, capability: &str, car: &[PathBuf], from: Vec<String>) -> anyhow::Result<()> {
    use holokeep::cap::{self, Capability};
    let capability = match Capability::decode(capability)? {
        Capability::Reader(reader) => Capability::Live(reader_live(&reader, car, &from)?),
        other => other,
    };
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let uid = repo.uid();
    let remembered = |view: &Link| cap::Remembered::of(&dir, uid, view).claims().unwrap_or_else(|e| {
        eprintln!("forgetting what was read of {view} before: {e}");
        Vec::new()
    });
    let reading = if car.is_empty() {
        read_at_doors(&repo, &capability, from, &remembered)?
    } else {
        let held = held_of(car)?;
        match &capability {
            Capability::Snapshot(snapshot) => cap::Reading { plain: snapshot.plain.clone(), blocks: cap::unseal(&held, snapshot)?, heads: Vec::new(), mounts: Vec::new(), base: None, forked: 0 },
            Capability::Live(live) | Capability::Write(cap::Write { live, .. }) => cap::read_into(&repo, &held, live, &remembered)?,
            Capability::Reader(_) => anyhow::bail!("a reader's capability, its keyring unopened"),
        }
    };
    let cap::Reading { plain, blocks, heads, mounts, forked, .. } = reading;
    if forked > 0 {
        eprintln!("merged {} heads, forked: as the owner's machines will, once they take them in", forked.saturating_add(1));
    }
    repo.batch_breathing(|repo| {
        for block in &blocks {
            repo.put_block(block, holokeep::cid::CidVersion::V1)?;
        }
        Ok::<_, anyhow::Error>(())
    })?;
    // Only once it's all here: each head's remembered as read
    for (view, head) in &heads {
        cap::Remembered::of(&dir, uid, view).remember(head)?;
    }
    eprintln!("unsealed {} blocks", blocks.len());
    out!("root {plain}");
    for mounted in &mounts {
        match &mounted.read {
            Ok(plain) => out!("mount {}\t{plain}", mounted.path),
            Err(e) => eprintln!("{} is a mount point of {}, not read: {e}", mounted.path, mounted.view),
        }
    }
    Ok(())
}

fn dag(repo: Option<PathBuf>, command: DagCommand) -> anyhow::Result<()> {
    match command {
        #[cfg(feature = "net")]
        DagCommand::Fetch { cid } => {
            let dir = repo_dir(repo)?;
            let (fetched, missing) = holokeep::net::daemon::fetch(&holokeep::net::mesh::Place::main(&dir), &cid)?.context("this node isn't running: start `hk node run`")?;
            out!("fetched {fetched}");
            for cid in &missing {
                out!("missing {cid}");
            }
            anyhow::ensure!(missing.is_empty(), "{} blocks aren't here or on any connected member", missing.len());
            Ok(())
        },
        DagCommand::Health { cid, ask } => {
            let dir = repo_dir(repo)?;
            dag_health(&open_repo(Some(dir.clone()))?, &dir, &cid, ask)
        },
        DagCommand::Import { paths } => {
            open_repo(repo)?.batch_breathing(|repo| {
                for path in paths {
                    let reader: Box<dyn io::Read> = if path == Path::new("-") {
                        Box::new(io::stdin())
                    }
                    else {
                        Box::new(std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?)
                    };
                    let (roots, blocks) = car::import(io::BufReader::new(reader), repo)
                        .with_context(|| format!("importing {}", path.display()))?;
                    for root in roots {
                        let present = if repo.get_block(&root)?.is_some() { "" } else { " (not in the CAR)" };
                        out!("root {root}{present}");
                    }
                    eprintln!("imported {blocks} blocks from {}", path.display());
                }
                Ok(())
            })
        },
        DagCommand::Export { cid, claims, history, sealed_root, output } => {
            fetch_first(repo.as_ref(), &cid)?;
            let dir = repo_dir(repo)?;
            let mut repo = open_repo(Some(dir.clone()))?;
            // What it reaches through anchors isn't what fetching the root
            // fetches, so it's fetched as it's reached
            if claims {
                fetch_through_node(&mut repo, &dir);
            }
            let export = |out: &mut dyn io::Write| -> io::Result<()> {
                let exported = if claims { car::export_with_claims(&repo, &cid, car::WithClaims { history, sealed_root }, &mut { out }) } else { car::export_noting(&repo, &cid, &mut { out }) }?;
                if exported.left_out > 0 {
                    eprintln!("left out {} claims about this: --claims to take them", exported.left_out);
                }
                if claims {
                    eprintln!("wrote {} blocks and {} claims", exported.blocks, exported.claims);
                }
                if exported.unreadable > 0 {
                    eprintln!("{} blocks of older versions, or reported lost, aren't here, so aren't there", exported.unreadable);
                }
                if exported.sealed > 0 {
                    eprintln!("the root key's in there, sealed: keep this file as safe as its passphrase is strong");
                }
                Ok(())
            };
            if let Some(path) = output {
                // Written aside and renamed, so a failed export leaves nothing
                let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
                let mut file = io::BufWriter::new(tempfile::NamedTempFile::new_in(dir)?);
                export(&mut file)?;
                file.into_inner().map_err(io::IntoInnerError::into_error)?.persist(&path)?;
            }
            else {
                let mut out = io::BufWriter::new(io::stdout().lock());
                export(&mut out)?;
                out.flush()?;
            }
            Ok(())
        },
    }
}

fn tag_cid(name: &str) -> anyhow::Result<Link> {
    claim::tag(name).with_context(|| format!("a tag name must be 1 to {} bytes", claim::MAX_NAME))
}

/// Tag blocks or find them by tag.
/// Make sure all of each DAG is here, fetching what isn't if the node's
/// running: a keep is only added by a node holding everything it links
/// to, so its copy outlives anything collecting it elsewhere meanwhile.
/// Returns each DAG's frontier: what's still missing, if `shallow`.
fn hold_all(dir: Option<&PathBuf>, repo: &Catalog, cids: &[Link], shallow: bool) -> anyhow::Result<Vec<Vec<Link>>> {
    let mut frontiers = Vec::new();
    for cid in cids {
        if repo.missing_under(cid)?.is_empty() {
            frontiers.push(Vec::new());
            continue;
        }
        fetch_first(dir, cid)?;
        let missing = repo.missing_under(cid)?;
        anyhow::ensure!(!missing.contains(cid), "{cid} isn't here or on any connected member");
        // What's lost isn't to be waited for: it's as far as it can be kept
        if !shallow && missing.iter().all(|block| repo.lost_at(block).is_ok_and(|at| at.is_some())) {
            eprintln!("keeping {cid} short of {} blocks reported lost", missing.len());
            frontiers.push(missing);
            continue;
        }
        if shallow {
            if !missing.is_empty() {
                eprintln!("keeping {cid} short of {} blocks which couldn't be had", missing.len());
            }
            frontiers.push(missing);
            continue;
        }
        if let Some(first) = missing.first() {
            anyhow::bail!(
                "{} blocks under {cid} aren't here or on any connected member, {first} among them; a keep needs all of what it keeps{}",
                missing.len(),
                if cfg!(feature = "net") { " (is `hk node run` running? or keep it --shallow)" } else { " (or keep it --shallow)" },
            );
        }
        frontiers.push(Vec::new());
    }
    Ok(frontiers)
}

fn anchor(dir: Option<&PathBuf>, mut repo: Catalog, command: AnchorCommand) -> anyhow::Result<()> {
    match command {
        AnchorCommand::New => out!("{}", repo.new_anchor()?),
        AnchorCommand::View { anchor, owner } => {
            let view = holokeep::claim::view(&anchor, &key_named(&owner)?).with_context(|| format!("{anchor} isn't an anchor, or is a view already"))?;
            out!("{view}");
        },
        #[cfg(feature = "net")]
        AnchorCommand::Share { anchor, who, commands, lasting } => share(dir, &repo, &anchor, &who, &commands, true, ending(lasting))?,
        #[cfg(feature = "net")]
        AnchorCommand::Unshare { anchor, who, commands } => share(dir, &repo, &anchor, &who, &commands, false, None)?,
        #[cfg(feature = "net")]
        AnchorCommand::Shared { anchor } => {
            let place = holokeep::net::mesh::Place::main(&repo_dir(dir.cloned())?);
            let genesis = holokeep::net::daemon::members(&place)?.genesis()?.context("the mesh has no grants, so nothing's shared")?;
            let state = repo.grant_state(&genesis)?.context("the mesh's first grant isn't here")?;
            let me = repo.user()?;
            let only = anchor.map(|anchor| holokeep::claim::viewed(&anchor).map_or(anchor, |(of, _)| of));
            for share in state.shares() {
                let mine = me.as_ref().is_some_and(|me| *me == share.owner || *me == share.user);
                if !mine || only.as_ref().is_some_and(|only| *only != share.anchor) {
                    continue;
                }
                let stands = if share.stands.is_empty() { String::new() } else { format!("\t{} sets of theirs stand", share.stands.len()) };
                let until = share.until.map(|until| format!("\tuntil {until} ({} from now)", left(until))).unwrap_or_default();
                out!("{}\t{}\t{}\t{}{stands}{until}", holokeep::keys::peer_id(&share.owner), share.anchor, holokeep::keys::peer_id(&share.user), share.held.join(" "));
            }
        },
        AnchorCommand::Set { anchor, cid, lazy } => {
            anyhow::ensure!(holokeep::claim::is_anchor(&anchor), "{anchor} isn't an anchor");
            if !lazy {
                hold_all(dir, &repo, std::slice::from_ref(&cid), false)?;
            }
            let set = repo.batch(|repo| repo.set_anchor(&anchor, &cid))?;
            out!("{set}");
        },
        AnchorCommand::Root => {
            let root = repo.root_anchor()?.ok_or_else(|| anyhow::anyhow!("this account has no key yet, so no root anchor"))?;
            out!("{root}");
            match repo.anchor_value(&root)? {
                Some(value) => out!("{value}"),
                None => out!("unset"),
            }
        },
        AnchorCommand::Forget { anchor, before, dry_run } => {
            anyhow::ensure!(holokeep::claim::is_anchor(&anchor), "{anchor} isn't an anchor");
            let versions = repo.versions_before(&anchor, before)?;
            if !dry_run && let Some(tomb) = repo.forget_versions(&anchor, &versions)? {
                eprintln!("forgotten by {tomb}: what only they refer to goes once it's been condemned a week, with every member's say");
            }
            for (_, value, at, _) in versions {
                out!("{at}\t{value}");
            }
        },
        AnchorCommand::Show { anchor } => {
            anyhow::ensure!(holokeep::claim::is_anchor(&anchor), "{anchor} isn't an anchor");
            match repo.anchor_value(&anchor)? {
                Some(value) => out!("{value}"),
                None => out!("unset"),
            }
            let heads = repo.anchor_heads(&anchor)?;
            if heads.len() > 1 {
                eprintln!("forked: that's {} heads merged, till it's set again:", heads.len());
                for (set, value, at) in heads {
                    eprintln!("  {at}\t{value}\tby {set}");
                }
            }
            if let Some(view) = repo.anchor_view(&anchor)?
                && view.state.in_conflict().next().is_some()
            {
                eprintln!("in conflict, till one's changed (the mount shows each version beside it):");
                for (path, versions) in view.state.in_conflict() {
                    let path: Vec<String> = path.iter().map(|name| String::from_utf8_lossy(name).into_owned()).collect();
                    let versions: Vec<String> = versions.iter().rev().map(|version| format!("{} ({})", version.cid, version.tag())).collect();
                    eprintln!("  {}\t{}", path.join("/"), versions.join(", "));
                }
            }
            for (at, value) in repo.anchor_history(&anchor)? {
                out!("{at}\t{value}");
            }
        },
    }
    Ok(())
}

/// Whichever of these no member has, by asking them, and how many members
/// were away to ask.
#[cfg(feature = "net")]
fn with_no_member(dir: &Path, blocks: Vec<Link>) -> anyhow::Result<(Vec<Link>, usize)> {
    use holokeep::net::{daemon, mesh::Place};
    let place = Place::main(dir);
    let Some(peers) = daemon::ask(&place, "peers")? else {
        anyhow::ensure!(daemon::members(&place)?.list()?.is_empty(), "this repo has members to ask: start `hk node run`");
        return Ok((blocks, 0));
    };
    let away = peers.iter().filter(|line| !line.contains("connected")).count();
    if blocks.is_empty() {
        return Ok((blocks, away));
    }
    let (_, missing) = daemon::fetch_blocks(&place, &blocks)?.context("the node stopped")?;
    let missing: std::collections::HashSet<String> = missing.into_iter().collect();
    Ok((blocks.into_iter().filter(|cid| missing.contains(&cid.to_string())).collect(), away))
}

#[cfg(not(feature = "net"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
fn with_no_member(_: &Path, blocks: Vec<Link>) -> anyhow::Result<(Vec<Link>, usize)> {
    Ok((blocks, 0))
}

fn same(repo: Option<PathBuf>, command: SameCommand) -> anyhow::Result<()> {
    let repo = open_repo(repo)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    match command {
        SameCommand::Add { lens, cids } => writeln!(out, "{}", repo.say_same(&cids, lens_named(&lens))?)?,
        SameCommand::Rm { lens, a, b } => {
            let tombs = repo.unsay_same(&a, &b, lens_named(&lens))?;
            if tombs.is_empty() {
                anyhow::bail!("nothing here says {a} and {b} are the same as {lens}");
            }
            for tomb in tombs {
                writeln!(out, "{tomb}")?;
            }
        },
        SameCommand::Ls { cid } => {
            for (lens, same) in repo.same_as(&cid)? {
                for other in same {
                    writeln!(out, "{}\t{other}", holokeep::same::named(lens.as_deref()))?;
                }
            }
        },
    }
    Ok(out.flush()?)
}

fn public(repo: Option<PathBuf>, command: PublicCommand) -> anyhow::Result<()> {
    use holokeep::claim::Public;
    let mut repo = open_repo(repo)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    match command {
        PublicCommand::Add { serve, tag, mut cids } => {
            let mode = if serve { Public::SERVE } else { Public::ANNOUNCE };
            for name in &tag {
                cids.push(tag_cid(name)?);
            }
            repo.batch(|repo| {
                for cid in &cids {
                    writeln!(out, "{}", repo.publish(cid, mode)?)?;
                }
                anyhow::Ok(())
            })?;
        },
        PublicCommand::Rm { cid } => {
            let tombs = repo.unpublish(&cid)?;
            if tombs.is_empty() {
                anyhow::bail!("{cid} wasn't made public here");
            }
            for tomb in tombs {
                writeln!(out, "{tomb}")?;
            }
        },
        PublicCommand::Ls => {
            for (mode, root) in repo.public_roots()? {
                match claim::tag_name(&root) {
                    Some(tag) => writeln!(out, "{mode}\ttag {tag}")?,
                    None => writeln!(out, "{mode}\t{root}")?,
                }
            }
        },
        PublicCommand::Check { cid } => writeln!(out, "{}", if repo.is_public(&cid)? { "public" } else { "private" })?,
    }
    Ok(out.flush()?)
}

fn lost(repo: Option<PathBuf>, command: LostCommand) -> anyhow::Result<()> {
    use holokeep::store::BlockIndex as _;
    let dir = repo_dir(repo)?;
    let mut repo = open_repo(Some(dir.clone()))?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    match command {
        LostCommand::Scan { dry_run } => {
            let candidates = repo.lost_candidates()?;
            let (lost, away) = with_no_member(&dir, candidates)?;
            // Fetched since it was looked for, it's not
            let lost: Vec<Link> = lost.into_iter().filter(|cid| !repo.has(cid.multihash()).unwrap_or(true)).collect();
            if away > 0 {
                eprintln!("{} blocks may be with the {away} members away, so none is reported", lost.len());
            } else if !dry_run {
                repo.batch(|repo| {
                    for cid in &lost {
                        repo.report_lost(cid)?;
                    }
                    anyhow::Ok(())
                })?;
            }
            for cid in &lost {
                writeln!(out, "{cid}")?;
            }
        },
        LostCommand::Add { cids } => repo.batch(|repo| {
            for cid in &cids {
                if let Some(claim) = repo.report_lost(cid)? {
                    writeln!(out, "{claim}")?;
                }
            }
            anyhow::Ok(())
        })?,
        LostCommand::Rm { cids } => repo.batch(|repo| {
            for cid in &cids {
                for tomb in repo.unreport_lost(cid)? {
                    writeln!(out, "{tomb}")?;
                }
            }
            anyhow::Ok(())
        })?,
        LostCommand::Ls => {
            for (cid, at) in repo.lost_blocks()? {
                writeln!(out, "{cid}\t{at}")?;
            }
        },
    }
    Ok(out.flush()?)
}

fn keep(dir: Option<&PathBuf>, mut repo: Catalog, command: KeepCommand) -> anyhow::Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    match command {
        KeepCommand::Add { cids, shallow, copies } => {
            let frontiers = hold_all(dir, &repo, &cids, shallow)?;
            repo.batch(|repo| {
                for (cid, beyond) in cids.iter().zip(&frontiers) {
                    writeln!(out, "{}", repo.keep_as(cid, beyond, copies)?)?;
                }
                anyhow::Ok(())
            })?;
        },
        KeepCommand::Rm { cids } => repo.batch(|repo| {
            for cid in cids {
                for tomb in repo.unkeep(&cid)? {
                    writeln!(out, "{tomb}")?;
                }
            }
            anyhow::Ok(())
        })?,
        KeepCommand::Ls => {
            for cid in repo.claims().context("this repo keeps no claims")?.keeps()? {
                writeln!(out, "{cid}")?;
            }
        },
    }
    Ok(out.flush()?)
}

fn tag(mut repo: Catalog, command: TagCommand) -> anyhow::Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    match command {
        TagCommand::Add { name, cids } => {
            let tag = tag_cid(&name)?;
            repo.batch(|repo| {
                for cid in cids {
                    writeln!(out, "{}", repo.tag(&cid, &tag)?)?;
                }
                anyhow::Ok(())
            })?;
        },
        TagCommand::Rm { name, cids } => {
            let tag = tag_cid(&name)?;
            repo.batch(|repo| {
                for cid in cids {
                    for tomb in repo.untag(&cid, &tag)? {
                        writeln!(out, "{tomb}")?;
                    }
                }
                anyhow::Ok(())
            })?;
        },
        TagCommand::Ls { cid } => {
            let claims = repo.claims().context("this repo keeps no claims")?;
            for tag in claims.tags(cid.multihash())? {
                match claim::tag_name(&tag) {
                    Some(name) => writeln!(out, "{name}")?,
                    None => writeln!(out, "{tag}")?,
                }
            }
        },
        TagCommand::Find { name } => {
            let claims = repo.claims().context("this repo keeps no claims")?;
            for cid in claims.tagged(tag_cid(&name)?.multihash())? {
                writeln!(out, "{cid}")?;
            }
        },
    }
    Ok(out.flush()?)
}
