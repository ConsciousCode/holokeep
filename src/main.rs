use std::path::{Path, PathBuf};

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
mod model;
#[cfg(test)]
mod codec_fixtures;
#[cfg(test)]
mod differential;
// Generic IPLD/serde layer, not needed by the importer yet
//mod dagpb;
mod canon;
//mod ipld;
mod dagcbor;
mod dagjson;
mod serde;

use chunker::ChunkerType;
use dag::{BalancedLayout, NullSink};
use import::Importer;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Hash a file or directory into UnixFS, like `ipfs add --only-hash`
    /// with the unixfs-v1-2025 profile. Use "-" for stdin.
    Add {
        path: PathBuf,
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
    },
}

fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Add { path, hidden, quiet, chunker, max_file_links } => {
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
            add(&importer, &path, quiet)
        }
    }
}

fn add(importer: &Importer, path: &Path, quiet: bool) -> anyhow::Result<()> {
    let mut sink = NullSink;

    if path == Path::new("-") {
        let root = importer.add_file(std::io::stdin().lock(), &mut sink)?;
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
    let Some(root) = importer.add_path(path, &mut sink, &mut report)? else {
        anyhow::bail!("unsupported file type: {}", path.display());
    };
    if quiet {
        println!("{}", root.cid);
    }
    Ok(())
}
