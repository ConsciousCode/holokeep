use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};

mod cid;
mod block;
mod chunker;
mod varint;
mod multihash;
mod pb;
mod unixfs;
mod dag;
mod hamt;
mod import;
mod export;
mod model;
mod store;
#[cfg(test)]
mod codec_fixtures;
#[cfg(test)]
mod differential;
#[cfg(test)]
mod testutil;
// Generic IPLD/serde layer, not needed by the importer yet
//mod dagpb;
mod canon;
//mod ipld;
mod dagcbor;
mod dagjson;
mod serde;

use chunker::ChunkerType;
use dag::{BalancedLayout, BlockSink, NullSink};
use import::Importer;
use model::Link;
use store::{Copying, RoutingStore};

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
    /// Work with raw blocks
    #[command(subcommand)]
    Block(BlockCommand),
    /// Work with the repo itself
    #[command(subcommand)]
    Repo(RepoCommand),
}

#[derive(Subcommand, Debug)]
enum BlockCommand {
    /// Write a block's bytes to stdout, like `ipfs block get`
    Get {
        cid: Link,
    },
}

#[derive(Subcommand, Debug)]
enum RepoCommand {
    /// How many blocks each store holds
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

fn open_repo(repo: Option<PathBuf>) -> anyhow::Result<RoutingStore> {
    let dir = match repo {
        Some(dir) => dir,
        None => PathBuf::from(std::env::var_os("HOME").context("no HOME, so use --repo")?).join(".holokeep"),
    };
    RoutingStore::open_repo(&dir).with_context(|| format!("opening repo {}", dir.display()))
}

fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Add { path, only_hash, hidden, quiet, chunker, max_file_links, nocopy } => {
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
                add(&importer, &path, quiet, &mut NullSink)
            }
            else if nocopy {
                open_repo(args.repo)?.batch(|repo| add(&importer, &path, quiet, repo))
            }
            else {
                open_repo(args.repo)?.batch(|repo| add(&importer, &path, quiet, &mut Copying(repo)))
            }
        },
        Command::Cat { cid } => {
            let repo = open_repo(args.repo)?;
            let mut out = io::BufWriter::new(io::stdout().lock());
            export::cat(&repo, &cid, &mut out)?;
            Ok(out.flush()?)
        },
        Command::Get { cid, output } => {
            let repo = open_repo(args.repo)?;
            let dest = output.unwrap_or_else(|| PathBuf::from(cid.to_string()));
            export::get(&repo, &cid, &dest).with_context(|| format!("writing {}", dest.display()))
        },
        Command::Block(BlockCommand::Get { cid }) => {
            let repo = open_repo(args.repo)?;
            let block = repo.get_block(&cid)?.with_context(|| format!("block {cid} not found"))?;
            Ok(io::stdout().lock().write_all(block.data())?)
        },
        Command::Repo(RepoCommand::Stat) => {
            for (store, blocks) in open_repo(args.repo)?.stats()? {
                println!("{store}\t{blocks}");
            }
            Ok(())
        },
        Command::Repo(RepoCommand::Reindex) => {
            let blocks = open_repo(args.repo)?.reindex()?;
            println!("indexed {blocks} blocks");
            Ok(())
        },
    }
}

fn add(importer: &Importer, path: &Path, quiet: bool, sink: &mut impl BlockSink) -> anyhow::Result<()> {
    if path == Path::new("-") {
        let root = importer.add_file(std::io::stdin().lock(), sink)?;
        println!("{}", root.cid);
        return Ok(());
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
    Ok(())
}
