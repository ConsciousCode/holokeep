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
    /// Work with anchors: empty identities, which are whatever they were
    /// last set to
    #[command(subcommand)]
    Anchor(AnchorCommand),
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
    #[command(subcommand)]
    Node(NodeCommand),
}

#[cfg(feature = "net")]
#[derive(Subcommand, Debug)]
enum NodeCommand {
    /// Print this node's peer id, for another node to invite
    Id,
    /// Let a machine into the mesh, printing a ticket for it to join with.
    /// The ticket holds the mesh's key: keep it secret
    Invite {
        peer: String,
    },
    /// Join a mesh with a ticket from a node already in it
    Join {
        ticket: String,
    },
    /// Run this node in the mesh until interrupted
    Run {
        #[arg(long, default_value = holokeep::net::daemon::LISTEN)]
        listen: String,
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

fn main() {
    if let Err(e) = run(Args::parse()) {
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
fn fetch_first(repo: &Option<PathBuf>, cid: &Link) -> anyhow::Result<()> {
    #[cfg(feature = "net")]
    {
        let dir = repo_dir(repo.clone())?;
        if let Some((_, missing)) = holokeep::net::daemon::fetch(&dir, cid)?
            && !missing.is_empty()
        {
            eprintln!("warning: {} blocks aren't here or on any connected member", missing.len());
        }
    }
    #[cfg(not(feature = "net"))]
    let _ = (repo, cid);
    Ok(())
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
                            println!("added {} {}", link.cid, p.strip_prefix(&base).unwrap_or(p).display());
                        }
                    };
                    let (mount, root) = repo.import_mounted(&importer, &path, &mut report)?;
                    if quiet {
                        println!("{root}");
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
            fetch_first(&args.repo, &cid)?;
            let repo = open_repo(args.repo)?;
            let mut out = io::BufWriter::new(io::stdout().lock());
            export::cat(&repo, &cid, &mut out)?;
            Ok(out.flush()?)
        },
        Command::Get { cid, output } => {
            fetch_first(&args.repo, &cid)?;
            let repo = open_repo(args.repo)?;
            let dest = output.unwrap_or_else(|| PathBuf::from(cid.to_string()));
            export::get(&repo, &cid, &dest).with_context(|| format!("writing {}", dest.display()))
        },
        Command::Refs { cid, back } => refs(&open_repo(args.repo)?, &cid, back),
        Command::Dag(command) => dag(args.repo, command),
        Command::Tag(command) => tag(open_repo(args.repo)?, command),
        Command::Keep(command) => keep(&args.repo, open_repo(args.repo.clone())?, command),
        Command::Anchor(command) => anchor(&args.repo, open_repo(args.repo.clone())?, command),
        Command::Block(BlockCommand::Get { cid }) => {
            let repo = open_repo(args.repo)?;
            let block = repo.get_block(&cid)?.with_context(|| format!("block {cid} not found"))?;
            Ok(io::stdout().lock().write_all(block.data())?)
        },
        Command::Repo(RepoCommand::Stat) => {
            for (volume, form, blocks) in open_repo(args.repo)?.stats()? {
                println!("{volume}\t{form}\t{blocks}");
            }
            Ok(())
        },
        Command::Repo(RepoCommand::Reindex) => {
            let blocks = open_repo(args.repo)?.reindex()?;
            println!("indexed {blocks} blocks");
            Ok(())
        },
        Command::Volume(command) => volume(open_repo(args.repo)?, command),
        #[cfg(feature = "net")]
        Command::Node(command) => node(&repo_dir(args.repo)?, command),
    }
}

#[cfg(feature = "net")]
fn node(dir: &Path, command: NodeCommand) -> anyhow::Result<()> {
    use holokeep::net::{daemon, mesh};
    match command {
        NodeCommand::Id => println!("{}", mesh::node_key(dir)?.public().to_peer_id()),
        NodeCommand::Invite { peer } => {
            let peer: libp2p::PeerId = peer.parse().context("not a peer id")?;
            let me = mesh::node_key(dir)?.public().to_peer_id();
            anyhow::ensure!(peer != me, "that's this node");
            let swarm_key = mesh::ensure_swarm_key(dir)?;
            let members = daemon::members(dir)?;
            members.add(&peer)?;
            let mut list = members.list()?;
            // Where this node listens, if it's running
            let listening = daemon::ask(dir, "listeners")?.unwrap_or_default();
            list.insert(me, listening.iter().filter_map(|addr| addr.parse().ok()).collect());
            daemon::ask(dir, "reload")?;
            println!("{}", mesh::Ticket { swarm_key, inviter: me, members: list }.encode());
            if listening.is_empty() {
                eprintln!("note: this node isn't running, so the ticket says nowhere to find it; it'll be found on the LAN, or start `hk node run` and invite again");
            }
        },
        NodeCommand::Join { ticket } => {
            let mut ticket = mesh::Ticket::decode(&ticket)?;
            let me = mesh::node_key(dir)?.public().to_peer_id();
            anyhow::ensure!(ticket.members.remove(&me).is_some(), "the ticket isn't for this node, {me}");
            mesh::set_swarm_key(dir, ticket.swarm_key)?;
            daemon::members(dir)?.merge(&ticket.members)?;
            daemon::ask(dir, "reload")?;
            eprintln!("joined the mesh of {}; `hk node run` to connect", ticket.inviter);
        },
        NodeCommand::Run { listen, copies, low_water, high_water, no_collect } => {
            let listen = listen.parse().context("not a multiaddr")?;
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(daemon::run(dir, listen, copies, (low_water, high_water), !no_collect))?;
        },
        NodeCommand::Collect => {
            let report = daemon::collect(dir)?.context("this node isn't running: start `hk node run`")?;
            println!(
                "condemned {}, pardoned {}, let go of {}, freeing {} bytes",
                report.condemned, report.pardoned, report.collected, report.freed,
            );
        },
        NodeCommand::Trim => {
            let report = daemon::trim(dir)?.context("this node isn't running: start `hk node run`")?;
            println!("let go of {} of {} spare blocks, freeing {} bytes", report.dropped, report.considered, report.freed);
        },
        NodeCommand::Status => {
            let lines = daemon::ask(dir, "status")?.context("this node isn't running: start `hk node run`")?;
            lines.iter().for_each(|line| println!("{line}"));
        },
        NodeCommand::Audit { copies } => {
            let report = daemon::audit(dir, copies)?.context("this node isn't running: start `hk node run`")?;
            println!("advertised {}, copied {}", report.advertised, report.copied);
            if report.short > 0 {
                eprintln!("{} blocks are still short, with no connected member to raise them", report.short);
            }
        },
        NodeCommand::Peers => match daemon::ask(dir, "peers")? {
            Some(lines) => lines.iter().for_each(|line| println!("{line}")),
            None => {
                eprintln!("this node isn't running; members it knows of:");
                for (peer, addrs) in daemon::members(dir)?.list()? {
                    let addrs: Vec<String> = addrs.iter().map(ToString::to_string).collect();
                    println!("{peer}\t-\t{}", addrs.join(" "));
                }
            },
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
                println!("{}\t{}\t{label}\t{state}\t{}\t{path}", volume.name, volume.kind, volume.blocks);
            }
        },
        VolumeCommand::Replicate { copies } => {
            let report = repo.batch(|repo| repo.replicate(copies))?;
            println!("copied {} blocks and {} dissolved claims", report.copied, report.claims);
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
                println!("{name}\t{risk}\t{}", if found { "found" } else { "said" });
            }
        },
        VolumeCommand::Copy { name, cids } => {
            let report = repo.batch(|repo| repo.copy_to(&name, &cids))?;
            println!("copied {} blocks and {} dissolved claims", report.copied, report.claims);
            if !report.unreadable.is_empty() {
                eprintln!("{} blocks couldn't be read to be copied", report.unreadable.len());
            }
        },
    }
    Ok(())
}

/// Add a file or directory, returning its root.
fn add(importer: &Importer, path: &Path, quiet: bool, sink: &mut impl BlockSink) -> anyhow::Result<Link> {
    if path == Path::new("-") {
        let root = importer.add_file(std::io::stdin().lock(), sink)?;
        println!("{}", root.cid);
        return Ok(root.cid.into());
    }

    // Report paths relative to the parent, like Kubo
    let base = path.parent().unwrap_or_else(|| Path::new(""));
    let mut report = |p: &Path, link: &dag::DagLink| {
        if !quiet {
            let rel = p.strip_prefix(base).unwrap_or(p);
            println!("added {} {}", link.cid, rel.display());
        }
    };
    let Some(root) = importer.add_path(path, sink, &mut report)? else {
        anyhow::bail!("unsupported file type: {}", path.display());
    };
    if quiet {
        println!("{}", root.cid);
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
            let (fetched, missing) = holokeep::net::daemon::fetch(&dir, &cid)?.context("this node isn't running: start `hk node run`")?;
            println!("fetched {fetched}");
            for cid in &missing {
                println!("missing {cid}");
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
                        println!("root {root}{present}");
                    }
                    eprintln!("imported {blocks} blocks from {}", path.display());
                }
                Ok(())
            })
        },
        DagCommand::Export { cid, output } => {
            fetch_first(&repo, &cid)?;
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
fn hold_all(dir: &Option<PathBuf>, repo: &Catalog, cids: &[Link], shallow: bool) -> anyhow::Result<Vec<Vec<Link>>> {
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

fn anchor(dir: &Option<PathBuf>, mut repo: Catalog, command: AnchorCommand) -> anyhow::Result<()> {
    match command {
        AnchorCommand::New => println!("{}", repo.new_anchor()?),
        AnchorCommand::Set { anchor, cid } => {
            anyhow::ensure!(holokeep::claim::is_anchor(&anchor), "{anchor} isn't an anchor");
            hold_all(dir, &repo, std::slice::from_ref(&cid), false)?;
            let set = repo.batch(|repo| repo.set_anchor(&anchor, &cid))?;
            println!("{set}");
        },
        AnchorCommand::Show { anchor } => {
            anyhow::ensure!(holokeep::claim::is_anchor(&anchor), "{anchor} isn't an anchor");
            match repo.anchor_value(&anchor)? {
                Some(value) => println!("{value}"),
                None => println!("unset"),
            }
            for (at, value) in repo.anchor_history(&anchor)? {
                println!("{at}\t{value}");
            }
        },
    }
    Ok(())
}

fn keep(dir: &Option<PathBuf>, mut repo: Catalog, command: KeepCommand) -> anyhow::Result<()> {
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
