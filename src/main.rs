use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};

mod cid;
mod car;
mod claim;
mod block;
mod chunker;
mod varint;
mod multihash;
mod pb;
mod unixfs;
mod dag;
mod hamt;
mod import;
mod links;
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
use cid::{BaseCid, CidRef};
use store::{Copying, InPlace, RefIndex, Catalog};

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
    /// Work with raw blocks
    #[command(subcommand)]
    Block(BlockCommand),
    /// Work with whole DAGs
    #[command(subcommand)]
    Dag(DagCommand),
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

fn open_repo(repo: Option<PathBuf>) -> anyhow::Result<Catalog> {
    let dir = match repo {
        Some(dir) => dir,
        None => PathBuf::from(std::env::var_os("HOME").context("no HOME, so use --repo")?).join(".holokeep"),
    };
    Catalog::open_repo(&dir).with_context(|| format!("opening repo {}", dir.display()))
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
                open_repo(args.repo)?.batch(|repo| add(&importer, &path, quiet, &mut InPlace::new(repo)))
            }
            else {
                open_repo(args.repo)?.batch(|repo| add(&importer, &path, quiet, &mut Copying::new(repo)))
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
        Command::Refs { cid, back } => refs(&open_repo(args.repo)?, &cid, back),
        Command::Dag(command) => dag(open_repo(args.repo)?, command),
        Command::Tag(command) => tag(open_repo(args.repo)?, command),
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

/// Import or export CAR files.
fn dag(mut repo: Catalog, command: DagCommand) -> anyhow::Result<()> {
    match command {
        DagCommand::Import { paths } => {
            repo.batch(|repo| {
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
