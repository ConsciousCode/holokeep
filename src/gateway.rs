//! A trustless gateway: what's public, over HTTP.
//!
//! As the IPFS trustless gateway spec has it, for whatever can't reach the
//! mesh: a browser, `curl`, any IPFS client. Nothing it sends needs
//! trusting, since the reader checks each block against its CID.
//!
//! - `GET` or `HEAD /ipfs/<cid>?format=raw`, or with `Accept:
//!   application/vnd.ipld.raw`: the block. A whole file's CID, which is no
//!   block, is the file, read through a layout said to be the same.
//! - `?format=car`, or `Accept: application/vnd.ipld.car`: a `CARv1` of
//!   the DAG under it, depth first, each block once; with
//!   `dag-scope=block`, of it alone.
//!
//! Only what's public is served (see `Catalog::is_public`), and what
//! isn't here is fetched through the running node, only if it's public.
//! What's private is answered exactly as what's missing is. Paths under a
//! CID, and anything but those two formats, aren't served.
//!
//! It's HTTP alone, no TLS: it listens on loopback by default, for a
//! reverse proxy in front to give it HTTPS. Each connection has a thread,
//! and a catalog, of its own, so a slow reader holds up no one else, and
//! there are at most `CONNECTIONS` at once.

use std::io::{self, BufRead as _, BufReader, BufWriter, Read as _, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::cid::CidRef as _;
use crate::model::Link;
use crate::store::{BlockIndex as _, Catalog};

/// Where the gateway listens, by default: loopback alone, for a reverse
/// proxy in front.
pub const LISTEN: &str = "127.0.0.1:4014";

/// The most connections served at once; past it, a connection's told to
/// come back later.
const CONNECTIONS: usize = 32;

/// The most a request's line and headers may be.
const HEAD: u64 = 8 * 1024;

/// How long a connection may say nothing before it's closed.
const IDLE: Duration = Duration::from_secs(15);

/// How long writing to a reader may take before it's given up on.
const WRITING: Duration = Duration::from_mins(2);

/// Fetches what's asked through the running node: these blocks, or with
/// `dag`, the whole DAG under the first. Whether it could ask.
pub type Fetcher = Arc<dyn Fn(&[Link], bool) -> bool + Send + Sync>;

/// Serve the repo's public blocks on `addr`, on a thread of its own,
/// fetching what isn't here with `fetch`. Returns where it listens.
///
/// # Errors
///
/// If the repo won't open, or `addr` can't be listened on.
pub fn open(repo: &Path, addr: &str, fetch: Option<Fetcher>) -> io::Result<SocketAddr> {
    // Opened here first, so a repo that won't open says so at once
    drop(Catalog::open_repo(repo).map_err(io::Error::other)?);
    let listener = TcpListener::bind(addr)?;
    let at = listener.local_addr()?;
    let repo = repo.to_path_buf();
    std::thread::Builder::new().name("gateway".to_owned()).spawn(move || serve(&listener, &repo, fetch.as_ref()))?;
    Ok(at)
}

/// Serve connections as they come, each on a thread of its own.
fn serve(listener: &TcpListener, repo: &Path, fetch: Option<&Fetcher>) {
    let serving = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        if serving.load(Ordering::Relaxed) >= CONNECTIONS {
            let _ = respond(&mut stream, &Answer::status(503, "busy: try again soon"), false, false);
            continue;
        }
        serving.fetch_add(1, Ordering::Relaxed);
        let (repo, fetch, done) = (repo.to_path_buf(), fetch.cloned(), serving.clone());
        let spawned = std::thread::Builder::new().name("gateway-connection".to_owned()).spawn(move || {
            let _ = connection(stream, &repo, fetch.as_ref());
            done.fetch_sub(1, Ordering::Relaxed);
        });
        if spawned.is_err() {
            serving.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// A request, as far as the gateway cares.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    head: bool,
    target: String,
    accept: String,
    /// Whether the connection's to be kept open after.
    keep_alive: bool,
}

/// What's said back.
enum Answer {
    /// A body of known length.
    Body { kind: &'static str, data: Vec<u8>, cid: Link },
    /// A file, as a whole CID names it, read through this layout.
    File { cid: Link, layout: Link },
    /// A CAR of the DAG under a CID, or of the block alone.
    Car { cid: Link, whole: bool },
    Status(u16, String),
}

impl Answer {
    fn status(code: u16, why: &str) -> Self {
        Self::Status(code, format!("{why}\n"))
    }
}

/// Serve one connection's requests, one after another, till it's closed
/// or idle.
fn connection(stream: TcpStream, repo: &Path, fetch: Option<&Fetcher>) -> io::Result<()> {
    stream.set_read_timeout(Some(IDLE))?;
    stream.set_write_timeout(Some(WRITING))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = BufWriter::new(stream);
    let mut catalog: Option<Catalog> = None;
    loop {
        let request = match read_request(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                respond(&mut out, &Answer::status(400, &e.to_string()), false, false)?;
                // What's left of the request read and dropped, so closing
                // doesn't reset the connection before the answer's read
                out.get_ref().shutdown(std::net::Shutdown::Write)?;
                out.get_ref().set_read_timeout(Some(Duration::from_secs(1)))?;
                let _ = io::copy(&mut reader.take(HEAD * 8), &mut io::sink());
                return Ok(());
            },
            Err(e) => return Err(e),
        };
        if catalog.is_none() {
            match Catalog::open_repo(repo) {
                Ok(opened) => catalog = Some(opened),
                Err(e) => {
                    respond(&mut out, &Answer::Status(500, format!("the repo won't open: {e}\n")), false, false)?;
                    return Ok(());
                },
            }
        }
        let Some(opened) = catalog.as_ref() else {
            return Ok(());
        };
        let answer = answer(opened, &request, fetch);
        let keep = respond_from(Some(opened), &mut out, &answer, request.head, request.keep_alive)?;
        if !keep {
            return Ok(());
        }
    }
}

/// Read a request's line and headers; none if the connection's closed
/// first. What's no request of this kind is `InvalidData`.
fn read_request(reader: &mut impl io::BufRead) -> io::Result<Option<Request>> {
    let mut limited = reader.take(HEAD);
    let mut line = String::new();
    if limited.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidData, why.to_owned());
    let mut words = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (words.next(), words.next(), words.next()) else {
        return Err(bad("not an HTTP request"));
    };
    let mut request = Request { head: method == "HEAD", target: target.to_owned(), accept: String::new(), keep_alive: version == "HTTP/1.1" };
    if !matches!(method, "GET" | "HEAD") {
        return Err(bad("only GET and HEAD are served"));
    }
    loop {
        let mut header = String::new();
        if limited.read_line(&mut header)? == 0 {
            return Err(bad("the request's headers are too long, or cut short"));
        }
        let header = header.trim_end();
        if header.is_empty() {
            return Ok(Some(request));
        }
        let Some((name, value)) = header.split_once(':') else {
            return Err(bad("a header without a colon"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("accept") {
            request.accept = value.to_ascii_lowercase();
        } else if name.eq_ignore_ascii_case("connection") {
            request.keep_alive = match value.to_ascii_lowercase().as_str() {
                "close" => false,
                "keep-alive" => true,
                _ => request.keep_alive,
            };
        }
    }
}

/// What to say to a request.
fn answer(catalog: &Catalog, request: &Request, fetch: Option<&Fetcher>) -> Answer {
    let (path, query) = request.target.split_once('?').unwrap_or((&request.target, ""));
    let Some(rest) = path.strip_prefix("/ipfs/") else {
        return Answer::status(404, "only /ipfs/<cid> is served");
    };
    let rest = rest.trim_end_matches('/');
    if rest.contains('/') {
        return Answer::status(400, "paths under a CID aren't served: ask for the CID of what's there");
    }
    let Ok(cid) = rest.parse::<Link>() else {
        return Answer::status(400, "not a CID");
    };
    let param = |name: &str| query.split('&').find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='));
    let format = match param("format") {
        Some(format) => format.to_owned(),
        None if request.accept.contains("application/vnd.ipld.raw") => "raw".to_owned(),
        None if request.accept.contains("application/vnd.ipld.car") => "car".to_owned(),
        None => String::new(),
    };
    let whole = match param("dag-scope") {
        None | Some("all" | "entity") => true,
        Some("block") => false,
        Some(_) => return Answer::status(400, "dag-scope is all, entity or block"),
    };
    if !matches!(format.as_str(), "raw" | "car") {
        return Answer::status(406, "only raw blocks (format=raw) and CARs (format=car) are served");
    }
    // Private is as missing: said the same, and nothing's fetched for it
    let missing = || Answer::status(404, "not here, or not public");
    if !catalog.is_public(&cid).unwrap_or(false) {
        return missing();
    }
    let here = |catalog: &Catalog| catalog.has(cid.multihash()).unwrap_or(false);
    if format == "car" {
        if whole
            && let Some(fetch) = fetch
        {
            fetch(std::slice::from_ref(&cid), true);
        } else if !here(catalog)
            && let Some(fetch) = fetch
        {
            fetch(std::slice::from_ref(&cid), false);
        }
        return if here(catalog) { Answer::Car { cid, whole } } else { missing() };
    }
    if !here(catalog)
        && let Some(fetch) = fetch
    {
        fetch(std::slice::from_ref(&cid), false);
    }
    match catalog.get_block(&cid) {
        Ok(Some(block)) => Answer::Body { kind: "application/vnd.ipld.raw", data: block.data().to_vec(), cid },
        // A whole file's CID, which is no block, read through a layout
        _ => match crate::export::Fetch::same_file(catalog, &cid) {
            Ok(Some(layout)) => Answer::File { cid, layout },
            _ => missing(),
        },
    }
}

/// Say an answer that needs nothing of the repo. Whether the connection's
/// kept open.
fn respond(out: &mut impl Write, answer: &Answer, head: bool, keep_alive: bool) -> io::Result<bool> {
    respond_from(None, out, answer, head, keep_alive)
}

/// Say an answer, reading what it streams from the catalog. Whether the
/// connection's kept open: never after what's streamed, whose length isn't
/// said, nor after an error part way.
fn respond_from(catalog: Option<&Catalog>, out: &mut impl Write, answer: &Answer, head: bool, keep_alive: bool) -> io::Result<bool> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    match answer {
        Answer::Status(code, text) => {
            write!(out, "HTTP/1.1 {code} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n", reason(*code), text.len())?;
            if !head {
                out.write_all(text.as_bytes())?;
            }
            out.flush()?;
            Ok(keep_alive)
        },
        Answer::Body { kind, data, cid } => {
            write!(out, "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n{}Connection: {connection}\r\n\r\n", data.len(), immutable(cid, "raw"))?;
            if !head {
                out.write_all(data)?;
            }
            out.flush()?;
            Ok(keep_alive)
        },
        Answer::File { cid, layout } => {
            write!(out, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.ipld.raw\r\n{}Connection: close\r\n\r\n", immutable(cid, "raw"))?;
            if !head && let Some(catalog) = catalog {
                crate::export::cat(catalog, layout, out)?;
            }
            out.flush()?;
            Ok(false)
        },
        Answer::Car { cid, whole } => {
            write!(out, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.ipld.car; version=1; order=dfs; dups=n\r\n{}Connection: close\r\n\r\n", immutable(cid, if *whole { "car" } else { "car-block" }))?;
            if !head && let Some(catalog) = catalog {
                if *whole {
                    crate::car::export(catalog, cid, out)?;
                } else if let Some(block) = catalog.get_block(cid).map_err(io::Error::other)? {
                    crate::car::write_blocks(out, std::slice::from_ref(cid), &[block])?;
                }
            }
            out.flush()?;
            Ok(false)
        },
    }
}

/// The headers saying what's at a CID never changes.
fn immutable(cid: &Link, format: &str) -> String {
    format!("Cache-Control: public, max-age=29030400, immutable\r\nEtag: \"{cid}.{format}\"\r\nX-Content-Type-Options: nosniff\r\nX-Ipfs-Roots: {cid}\r\n")
}

const fn reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        404 => "Not Found",
        406 => "Not Acceptable",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
mod tests;
