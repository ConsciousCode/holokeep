use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};


use holokeep::{car, claim, dag, export, links};
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
    /// Keep things with friends, encrypted: in this account's vault, which
    /// joins their protected meshes
    #[command(subcommand)]
    Protect(ProtectCommand),
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
    /// Link this repo's machines into a private mesh
    #[cfg(feature = "net")]
    Node(NodeArgs),
    /// Mount the soup as a filesystem until interrupted: the root anchor's
    /// names, beside cid/<cid>, anchors/<anchor> and tags/<tag>/<cid>.
    /// What's written to an anchor is committed, setting it, once it's
    /// closed or synced and quiet a second, less often if it's written to
    /// often; a directory made at the top is a new anchor, and a link to
    /// an anchor mounts it.
    #[cfg(feature = "fuse")]
    Mount {
        /// An empty directory to mount it on
        dir: PathBuf,
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
    },
    /// Join a mesh with a ticket from a node already in it
    Join {
        ticket: String,
        /// Which account joins, by uid [default: yours]: of the main mesh,
        /// another account, served by this node too, as a device of the
        /// user the ticket's for
        #[arg(long)]
        account: Option<u32>,
    },
    /// List the meshes this node is in, and whose each is
    Meshes,
    /// Run this node in the mesh until interrupted
    Run {
        /// Where to listen [default: port 4011 for the main mesh, any
        /// other port for another]
        #[arg(long)]
        listen: Option<String>,
        /// Copy blocks to other members until it would take this many
        /// failures to lose each, counting risks, auditing a few at a time
        #[arg(short, long, default_value_t = 2)]
        copies: usize,
        /// When free space falls below this, let go of copies the mesh can
        /// spare (bytes, or with K, M, G, T)
        #[arg(long, default_value = "2G", value_parser = holokeep::net::daemon::parse_size)]
        low_water: u64,
        /// ...until it's back above this; nor take others' copies past it
        #[arg(long, default_value = "4G", value_parser = holokeep::net::daemon::parse_size)]
        high_water: u64,
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
    },
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
            // The vault, sealed with the user's passphrase, goes where it does,
            // so the passphrase alone recovers it
            if !vault::is_sealed(&mut repo, dir)? {
                let passphrase = if repo.user()?.is_some() {
                    let passphrase = passphrase(false)?;
                    repo.root(passphrase.as_bytes()).context("the vault is sealed with the user's passphrase")?;
                    passphrase
                } else {
                    passphrase(true)?
                };
                vault::seal(&mut repo, dir, passphrase.as_bytes(), holokeep::keys::Cost::RECOMMENDED)?;
                eprintln!("sealed the vault with the passphrase: friends holding it hold what it takes to recover it");
            }
        },
        ProtectCommand::Ls => {
            let mut repo = Catalog::open_repo(dir)?;
            for (manifest, root) in vault::list(&mut repo, dir)? {
                out!("{manifest}\t{root}");
            }
        },
        ProtectCommand::Restore { manifest } => {
            #[cfg(feature = "net")]
            {
                use holokeep::net::{daemon, mesh};
                let uid = vault::vault_of(me);
                for (name, _) in daemon::members(&mesh::Place::main(dir))?.meshes()?.into_iter().filter(|&(_, account)| account == uid) {
                    if let Some((_, missing)) = daemon::fetch(&mesh::Place::new(dir, &name), &manifest)?
                        && missing.is_empty()
                    {
                        break;
                    }
                }
            }
            let mut repo = Catalog::open_repo(dir)?;
            let (root, blocks) = vault::restore(&mut repo, dir, &manifest)?;
            eprintln!("restored {blocks} blocks");
            out!("{root}");
        },
    }
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

fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Add { path, only_hash, hidden, quiet, chunker, max_file_links, nocopy, no_keep } => {
            let Some(ChunkerType::Size(chunk_size)) = ChunkerType::parse(&chunker) else {
                anyhow::bail!("unsupported chunker {chunker:?}, expected size-[bytes]");
            };
            if chunk_size == 0 || max_file_links < 2 {
                anyhow::bail!("chunk size must be positive and max-file-links at least 2");
            }
            let importer = Importer {
                chunk_size,
                layout: BalancedLayout { width: max_file_links },
                hidden,
                ..Importer::default()
            };
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
            fetch_first(args.repo.as_ref(), &cid)?;
            let repo = open_repo(args.repo)?;
            in_repo(&repo, &cid)?;
            let mut out = io::BufWriter::new(io::stdout().lock());
            export::cat(&repo, &cid, &mut out)?;
            Ok(out.flush()?)
        },
        Command::Get { cid, output } => {
            fetch_first(args.repo.as_ref(), &cid)?;
            let repo = open_repo(args.repo)?;
            in_repo(&repo, &cid)?;
            let dest = output.unwrap_or_else(|| PathBuf::from(cid.to_string()));
            export::get(&repo, &cid, &dest).with_context(|| format!("writing {}", dest.display()))
        },
        Command::Refs { cid, back } => refs(&open_repo(args.repo)?, &cid, back),
        Command::Dag(command) => dag(args.repo, command),
        Command::Git(GitCommand::Import { git, no_keep }) => git_import(args.repo, &git, no_keep),
        Command::Tag(command) => tag_here_or_there(args.repo, command),
        Command::Keep(command) => keep_here_or_there(args.repo, command),
        Command::Lost(command) => lost(args.repo, command),
        Command::Whoami => whoami(args.repo),
        Command::Protect(command) => protect(&repo_dir(args.repo)?, command),
        Command::Device(command) => device(&repo_dir(args.repo.clone())?, command),
        Command::Anchor(command) => anchor(args.repo.as_ref(), open_repo(args.repo.clone())?, command),
        Command::Block(BlockCommand::Get { cid }) => {
            let repo = open_repo(args.repo)?;
            in_repo(&repo, &cid)?;
            let block = repo.get_block(&cid)?.with_context(|| format!("block {cid} not found"))?;
            Ok(io::stdout().lock().write_all(block.data())?)
        },
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
        Command::Mount { dir, read_only } => mount(repo_dir(args.repo)?, &dir, read_only),
        #[cfg(feature = "net")]
        Command::Node(NodeArgs { mesh, command }) => node(&holokeep::net::mesh::Place::new(&repo_dir(args.repo)?, &mesh), command),
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
    let soup = holokeep::mount::Soup::new(Box::new(move || Catalog::open_repo(&repo)), fetcher);
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
    out!("{}", mesh::Ticket { swarm_key, inviter: me, members: list, user: Some((user, blocks)), protected: false, sealed: Vec::new(), held: Vec::new(), grants }.encode());
    if listening.is_empty() {
        eprintln!("note: this node isn't running, so the ticket says nowhere to find it; it'll be found on the LAN, or start `hk node run` and invite again");
    }
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
    out!("{}", mesh::Ticket { swarm_key, inviter: me, members: list, user: None, protected: true, sealed, held, grants: None }.encode());
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

#[cfg(feature = "net")]
fn node(place: &holokeep::net::mesh::Place, command: NodeCommand) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    anyhow::ensure!(mesh::Place::valid(&place.mesh), "a mesh's name is letters, digits, - and _");
    let dir = place.repo.as_path();
    match command {
        NodeCommand::Id { account: None } => out!("{}", mesh::node_key(dir)?.public().to_peer_id()),
        NodeCommand::Id { account: Some(uid) } => out!("{}", holokeep::keys::peer_id(&holokeep::keys::account_key(dir, uid)?.id())),
        NodeCommand::Meshes => {
            let members = daemon::members(place)?;
            if mesh::swarm_key(dir)?.is_some() {
                out!("{}\t{}", mesh::MAIN, rustix::process::getuid().as_raw());
            }
            for (name, uid) in members.meshes()? {
                out!("{name}\t{uid}");
            }
        },
        NodeCommand::Invite { peer, device, account, protected: false, quota: None } => invite(place, &peer, device.as_deref(), account)?,
        NodeCommand::Invite { peer, device, account: None, protected: true, quota } => {
            invite_friend(place, &peer, device.as_deref().context("a protected mesh holds a friend's vault: name it with --device")?, quota)?;
        },
        NodeCommand::Invite { .. } => anyhow::bail!("--quota is for a protected mesh, which is a friend's, not an account's"),
        NodeCommand::Join { ticket, account } => {
            let mut ticket = mesh::Ticket::decode(&ticket)?;
            let me = mesh::node_key(dir)?.public().to_peer_id();
            anyhow::ensure!(ticket.members.remove(&me).is_some(), "the ticket isn't for this node, {me}");
            let members = daemon::members(place)?;
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
            mesh::set_swarm_key(&place.dir(), ticket.swarm_key)?;
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
        },
        NodeCommand::Run { listen, copies, low_water, high_water, no_collect, no_lost_scan, shared } => {
            let listen = listen.as_deref().unwrap_or_else(|| if place.is_main() { daemon::LISTEN } else { "/ip4/0.0.0.0/tcp/0" });
            let listen = listen.parse().context("not a multiaddr")?;
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(daemon::run(place, listen, copies, (low_water, high_water), !no_collect, !no_lost_scan, shared))?;
        },
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

/// A user's or machine's key, by peer ID or CID.
#[cfg(feature = "net")]
fn key_named(text: &str) -> anyhow::Result<Link> {
    holokeep::keys::from_peer_id(text)
        .or_else(|| text.parse::<Link>().ok().filter(holokeep::keys::is_key))
        .with_context(|| format!("not a key, by peer ID or CID: {text}"))
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
    Ok((genesis.clone(), repo.grant_blocks(&grants)?.into_iter().map(|(_, data)| data).collect()))
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
