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
use holokeep::store::{Copying, InPlace, RefIndex, Catalog};

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
    /// Work with the repo itself
    #[command(subcommand)]
    Repo(RepoCommand),
    /// Keep copies of blocks on other volumes, such as other drives
    #[command(subcommand)]
    Volume(VolumeCommand),
    /// Link this repo's machines into a private mesh
    #[cfg(feature = "net")]
    Node(NodeArgs),
    /// Mount the soup as a read-only filesystem until interrupted:
    /// cid/<cid>, anchors/<anchor> and tags/<tag>/<cid>
    #[cfg(feature = "fuse")]
    Mount {
        /// An empty directory to mount it on
        dir: PathBuf,
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
        /// Print instead the key this repo signs with for one of the host's
        /// accounts, by uid, for an invite's --device
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
        /// Whose mesh a new one is, by uid [default: yours]
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
        /// Whose mesh it is, by uid, for one other than the main one
        /// [default: yours]
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
    /// List the mesh's members, and which are connected
    Peers,
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
    Log { peer: String },
    /// Revoke a device, with the user's passphrase. What it alone signed
    /// up to `--until` is signed again here, so it still counts; nothing
    /// else it signed does
    Revoke {
        peer: String,
        /// One of its signs, to trust it and those before it in its chain,
        /// or seconds since the epoch, to trust its signs until then if
        /// its chain doesn't fork [default: now]
        #[arg(long)]
        until: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AnchorCommand {
    /// Make a new anchor, printing it
    New,
    /// Say an anchor is a DAG now, which must all be here or fetched
    /// through the running node; prints the set
    Set { anchor: Link, cid: Link },
    /// Print what an anchor is now, then every value it's had, oldest
    /// first, with when
    Show { anchor: Link },
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
    /// Write the DAG under a CID to a `CARv1`, like `ipfs dag export`
    Export {
        cid: Link,
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
enum RepoCommand {
    /// How many blocks each volume holds, in each form
    Stat,
    /// Rebuild the block index from the stores
    Reindex,
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
        KeepCommand::Add { cids: list, shallow } => ["keep", "add"].into_iter().chain(shallow.then_some("--shallow")).map(str::to_owned).chain(cids(list)).collect(),
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
            open_repo(args.repo)?.batch(|repo| {
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
        Command::Tag(command) => tag_here_or_there(args.repo, command),
        Command::Keep(command) => keep_here_or_there(args.repo, command),
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
            for (volume, form, blocks) in open_repo(args.repo)?.stats()? {
                out!("{volume}\t{form}\t{blocks}");
            }
            Ok(())
        },
        Command::Repo(RepoCommand::Reindex) => {
            let blocks = open_repo(args.repo)?.reindex()?;
            out!("indexed {blocks} blocks");
            Ok(())
        },
        Command::Volume(command) => volume(open_repo(args.repo)?, command),
        #[cfg(feature = "fuse")]
        Command::Mount { dir } => mount(repo_dir(args.repo)?, &dir),
        #[cfg(feature = "net")]
        Command::Node(NodeArgs { mesh, command }) => node(&holokeep::net::mesh::Place::new(&repo_dir(args.repo)?, &mesh), command),
    }
}

/// Mount the soup at `dir`, as this repo's owner sees it, until
/// interrupted.
#[cfg(feature = "fuse")]
fn mount(repo: PathBuf, dir: &Path) -> anyhow::Result<()> {
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
    let soup = holokeep::mount::Soup::new(Box::new(move || Catalog::open_repo(&repo)), fetcher);
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
        repo.set_user(user)?;
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
    // Where this node listens, if it's running
    let listening = daemon::ask(place, "listeners")?.unwrap_or_default();
    list.insert(me, listening.iter().filter_map(|addr| addr.parse().ok()).collect());
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
    let user = root.id();
    let blocks = user_blocks(&repo)?;
    daemon::ask(place, "reload")?;
    out!("{}", mesh::Ticket { swarm_key, inviter: me, members: list, user: Some((user, blocks)), protected: false, sealed: Vec::new(), held: Vec::new() }.encode());
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
    let listening = daemon::ask(place, "listeners")?.unwrap_or_default();
    list.insert(me, listening.iter().filter_map(|addr| addr.parse().ok()).collect());
    daemon::ask(place, "reload")?;
    out!("{}", mesh::Ticket { swarm_key, inviter: me, members: list, user: None, protected: true, sealed, held }.encode());
    Ok(())
}

/// Where the internal accounts for friends' vaults start.
#[cfg(feature = "net")]
const FRIENDS: u32 = 0xC000_0000;

/// The account a mesh is for, by uid: the main one's owner's, unless
/// it's said, and a new one's whoever's said, or the owner's, recorded.
#[cfg(feature = "net")]
fn mesh_account(members: &holokeep::net::mesh::Members, said: Option<u32>) -> anyhow::Result<u32> {
    let (uid, new) = mesh_uid(members, said)?;
    if new {
        members.set_account(uid)?;
    }
    Ok(uid)
}

/// The account a mesh is for, by uid, and whether the mesh is new.
#[cfg(feature = "net")]
fn mesh_uid(members: &holokeep::net::mesh::Members, said: Option<u32>) -> anyhow::Result<(u32, bool)> {
    let me = rustix::process::getuid().as_raw();
    if members.mesh() == holokeep::net::mesh::MAIN {
        anyhow::ensure!(said.is_none_or(|uid| uid == me), "the main mesh is the owner's: give another --mesh for another account");
        return Ok((me, false));
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
            if let Some((user, blocks)) = &ticket.user {
                join_user(dir, uid, user, blocks)?;
            }
            daemon::ask(place, "reload")?;
            let mesh = if place.is_main() { String::new() } else { format!(" --mesh {}", place.mesh) };
            eprintln!("joined the mesh of {}; `hk node run{mesh}` to connect", ticket.inviter);
            if !ticket.held.is_empty() {
                eprintln!("it holds {} of your vault's manifests; once it's running, restore each with `hk protect restore`:", ticket.held.len());
                for cid in &ticket.held {
                    out!("{cid}");
                }
            }
        },
        NodeCommand::Run { listen, copies, low_water, high_water, no_collect, shared } => {
            let listen = listen.as_deref().unwrap_or_else(|| if place.is_main() { daemon::LISTEN } else { "/ip4/0.0.0.0/tcp/0" });
            let listen = listen.parse().context("not a multiaddr")?;
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(daemon::run(place, listen, copies, (low_water, high_water), !no_collect, shared))?;
        },
        NodeCommand::Collect => {
            let report = daemon::collect(place)?.context("this node isn't running: start `hk node run`")?;
            out!(
                "condemned {}, pardoned {}, let go of {}, freeing {} bytes",
                report.condemned, report.pardoned, report.collected, report.freed,
            );
        },
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
        NodeCommand::Peers => if let Some(lines) = daemon::ask(place, "peers")? {
            for line in &lines {
                out!("{line}");
            }
        } else {
            eprintln!("this node isn't running; members it knows of:");
            for (peer, addrs) in daemon::members(place)?.list()? {
                let addrs: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                out!("{peer}\t-\t{}", addrs.join(" "));
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
        DeviceCommand::Log { peer } => {
            let device = keys::from_peer_id(&peer).context("not an ed25519 peer ID")?;
            for signed in repo.claims().context("this repo keeps no claims")?.signs_by(&device)? {
                let prev = signed.prev.map_or_else(|| "-".to_owned(), |prev| prev.to_string());
                out!("{}\t{prev}\t{}\t{}", signed.sign, signed.at, signed.claims);
            }
            for fork in repo.forks(&device)? {
                eprintln!("forks at {}", fork.map_or_else(|| "its start".to_owned(), |fork| fork.to_string()));
            }
        },
        DeviceCommand::Revoke { peer, until } => {
            let device = keys::from_peer_id(&peer).context("not an ed25519 peer ID")?;
            anyhow::ensure!(repo.signer().is_some_and(|key| key.id() != device), "a node can't revoke itself");
            let cutoff = match until.as_deref().map(str::parse::<u64>) {
                Some(Ok(at)) => repo.cutoff_at(&device, at)?,
                Some(Err(_)) => Some(until.as_deref().unwrap_or_default().parse::<Link>().context("--until is neither a CID nor a time")?),
                None => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
                    repo.cutoff_at(&device, now)?
                },
            };
            let root = root_key(&repo, dir)?;
            let resigned = repo.batch(|repo| repo.revoke(&root, &device, cutoff.as_ref()))?;
            out!("revoked {peer}; signed {resigned} of its claims again");
        },
    }
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
            open_repo(repo)?.batch(|repo| {
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
        DagCommand::Export { cid, output } => {
            fetch_first(repo.as_ref(), &cid)?;
            let repo = open_repo(repo)?;
            if let Some(path) = output {
                // Written aside and renamed, so a failed export leaves nothing
                let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
                let mut file = io::BufWriter::new(tempfile::NamedTempFile::new_in(dir)?);
                car::export(&repo, &cid, &mut file)?;
                file.into_inner().map_err(io::IntoInnerError::into_error)?.persist(&path)?;
            }
            else {
                let mut out = io::BufWriter::new(io::stdout().lock());
                car::export(&repo, &cid, &mut out)?;
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
        AnchorCommand::Set { anchor, cid } => {
            anyhow::ensure!(holokeep::claim::is_anchor(&anchor), "{anchor} isn't an anchor");
            hold_all(dir, &repo, std::slice::from_ref(&cid), false)?;
            let set = repo.batch(|repo| repo.set_anchor(&anchor, &cid))?;
            out!("{set}");
        },
        AnchorCommand::Show { anchor } => {
            anyhow::ensure!(holokeep::claim::is_anchor(&anchor), "{anchor} isn't an anchor");
            match repo.anchor_value(&anchor)? {
                Some(value) => out!("{value}"),
                None => out!("unset"),
            }
            for (at, value) in repo.anchor_history(&anchor)? {
                out!("{at}\t{value}");
            }
        },
    }
    Ok(())
}

fn keep(dir: Option<&PathBuf>, mut repo: Catalog, command: KeepCommand) -> anyhow::Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    match command {
        KeepCommand::Add { cids, shallow } => {
            let frontiers = hold_all(dir, &repo, &cids, shallow)?;
            repo.batch(|repo| {
                for (cid, beyond) in cids.iter().zip(&frontiers) {
                    writeln!(out, "{}", repo.keep_short_of(cid, beyond)?)?;
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
