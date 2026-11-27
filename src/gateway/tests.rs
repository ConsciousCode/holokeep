use super::*;
use crate::import::Importer;
use crate::store::Copying;
use crate::testutil::Scratch;

/// A status code, headers by lower-cased name, and the body, of an answer
/// read till the connection closes.
type Answered = (u16, Vec<(String, String)>, Vec<u8>);

/// Send a request and read its answer, to the end of the connection.
fn ask(at: SocketAddr, request: &str) -> Answered {
    let mut stream = TcpStream::connect(at).expect("connect");
    stream.write_all(request.as_bytes()).expect("send");
    let mut all = Vec::new();
    stream.read_to_end(&mut all).expect("read");
    parse(&all)
}

fn parse(all: &[u8]) -> Answered {
    let end = all.windows(4).position(|w| w == b"\r\n\r\n").expect("a head");
    let head = String::from_utf8_lossy(all.get(..end).unwrap_or_default()).into_owned();
    let mut lines = head.split("\r\n");
    let code = lines.next().and_then(|line| line.split_whitespace().nth(1)).and_then(|code| code.parse().ok()).expect("status");
    let headers = lines.filter_map(|line| line.split_once(": ")).map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned())).collect();
    (code, headers, all.get(end.saturating_add(4)..).unwrap_or_default().to_vec())
}

fn get(at: SocketAddr, target: &str, accept: &str) -> Answered {
    ask(at, &format!("GET {target} HTTP/1.1\r\nHost: test\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"))
}

fn header<'a>(answered: &'a Answered, name: &str) -> Option<&'a str> {
    answered.1.iter().find(|(header, _)| header == name).map(|(_, value)| value.as_str())
}

/// A repo with a tree made public and a file that isn't, and a gateway
/// serving it: the gateway's address, the tree, a block in it, the big
/// file's whole CID and bytes, and the private file.
fn serving(scratch: &Scratch) -> (SocketAddr, Link, Link, (Link, Vec<u8>), Link) {
    let repo = scratch.path().join("repo");
    let tree = scratch.path().join("tree");
    std::fs::create_dir_all(&tree).expect("mkdir");
    std::fs::write(tree.join("small"), "a small public file").expect("write");
    // Over 64 KiB, of more than one leaf, so kept whole and said the same
    // as its whole CID
    let big: Vec<u8> = (0..300_000u32).map(|i| u8::try_from(i % 251).unwrap_or_default()).collect();
    std::fs::write(tree.join("big"), &big).expect("write");
    std::fs::write(scratch.path().join("private"), "not anyone's").expect("write");
    let mut catalog = Catalog::open_repo(&repo).expect("catalog");
    let importer = Importer { chunk_size: 100_000, ..Importer::default() };
    let root: Link = importer.add_path(&tree, &mut Copying::new(&mut catalog), &mut |_, _| {}).expect("add").expect("root").cid.into();
    let private: Link = importer.add_path(&scratch.path().join("private"), &mut Copying::new(&mut catalog), &mut |_, _| {}).expect("add").expect("file").cid.into();
    catalog.publish(&root, crate::claim::Public::SERVE).expect("publish");
    let small = crate::export::list(&catalog, &root).expect("list").into_iter().find(|entry| entry.name == b"small").expect("small").cid;
    let whole: Link = crate::block::Block::hash(crate::cid::Cidv1Spec::default(), big.clone().into()).cid().clone().into();
    assert!(catalog.is_public(&whole).expect("public"), "the big file's whole CID, by its layout");
    drop(catalog);
    let at = open(&repo, "127.0.0.1:0", None).expect("open");
    (at, root, small, (whole, big), private)
}

#[test]
fn whats_public_is_served_as_the_trustless_gateway_spec_has_it() {
    let scratch = Scratch::new("gateway");
    let (at, root, small, (whole, big), _) = serving(&scratch);

    let block = get(at, &format!("/ipfs/{small}?format=raw"), "*/*");
    assert_eq!((block.0, block.2.as_slice()), (200, b"a small public file".as_slice()));
    assert_eq!(header(&block, "content-type"), Some("application/vnd.ipld.raw"));
    assert!(header(&block, "cache-control").is_some_and(|value| value.contains("immutable")));
    assert_eq!(get(at, &format!("/ipfs/{small}"), "application/vnd.ipld.raw").2, block.2, "by Accept");

    // A whole file's CID is the file
    let file = get(at, &format!("/ipfs/{whole}?format=raw"), "*/*");
    assert_eq!((file.0, file.2.len()), (200, big.len()));
    assert_eq!(file.2, big, "the file, byte for byte");

    // A CAR of the DAG, which reads back as the tree; and of a block alone
    let car = get(at, &format!("/ipfs/{root}?format=car"), "*/*");
    assert_eq!(car.0, 200);
    assert!(header(&car, "content-type").is_some_and(|kind| kind.starts_with("application/vnd.ipld.car")));
    let mut sink = Catalog::open_repo(&scratch.path().join("reader")).expect("catalog");
    let (roots, count) = crate::car::import(std::io::Cursor::new(car.2), &mut sink).expect("a CAR");
    assert_eq!((roots, count > 3), (vec![root.clone()], true));
    let one = get(at, &format!("/ipfs/{root}?format=car&dag-scope=block"), "*/*");
    let mut alone = Catalog::open_repo(&scratch.path().join("alone")).expect("catalog");
    assert_eq!(crate::car::import(std::io::Cursor::new(one.2), &mut alone).expect("a CAR").1, 1);
}

#[test]
fn whats_private_is_answered_as_whats_missing() {
    let scratch = Scratch::new("gateway-private");
    let (at, _, _, _, private) = serving(&scratch);
    let missing: Link = crate::block::Block::hash(crate::cid::Cidv1Spec::default(), b"never here".to_vec().into()).cid().clone().into();
    for format in ["raw", "car"] {
        let (theirs, nothing) = (get(at, &format!("/ipfs/{private}?format={format}"), "*/*"), get(at, &format!("/ipfs/{missing}?format={format}"), "*/*"));
        assert_eq!(theirs.0, 404);
        assert_eq!((theirs.0, theirs.2), (nothing.0, nothing.2), "{format}");
    }
}

#[test]
fn what_isnt_asked_of_it_is_refused() {
    let scratch = Scratch::new("gateway-refused");
    let (at, root, small, _, _) = serving(&scratch);
    assert_eq!(get(at, &format!("/ipfs/{small}"), "text/html").0, 406, "neither format");
    assert_eq!(get(at, &format!("/ipfs/{root}/small?format=raw"), "*/*").0, 400, "a path under it");
    assert_eq!(get(at, "/ipfs/not-a-cid?format=raw", "*/*").0, 400);
    assert_eq!(get(at, "/ipns/whatever", "*/*").0, 404);
    assert_eq!(get(at, &format!("/ipfs/{root}?format=car&dag-scope=sideways"), "*/*").0, 400);
    assert_eq!(ask(at, &format!("POST /ipfs/{small} HTTP/1.1\r\nContent-Length: 0\r\n\r\n")).0, 400);
    assert_eq!(ask(at, "nonsense\r\n\r\n").0, 400);
    let long = format!("GET /ipfs/{small}?format=raw HTTP/1.1\r\nX-Long: {}\r\n\r\n", "x".repeat(10_000));
    assert_eq!(ask(at, &long).0, 400, "headers past the limit");
}

#[test]
fn a_connection_serves_requests_one_after_another_and_head_says_no_body() {
    let scratch = Scratch::new("gateway-keep-alive");
    let (at, _, small, _, _) = serving(&scratch);
    let mut stream = TcpStream::connect(at).expect("connect");
    let head = format!("HEAD /ipfs/{small}?format=raw HTTP/1.1\r\nHost: test\r\n\r\n");
    let get = format!("GET /ipfs/{small}?format=raw HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    stream.write_all(format!("{head}{get}").as_bytes()).expect("send");
    let mut all = Vec::new();
    stream.read_to_end(&mut all).expect("read");
    let first = parse(&all);
    assert_eq!((first.0, header(&first, "content-length")), (200, Some("19")));
    // What follows the first head is the second answer, the first having
    // no body
    let rest = all.get(all.windows(4).position(|w| w == b"\r\n\r\n").expect("head").saturating_add(4)..).unwrap_or_default();
    let second = parse(rest);
    assert_eq!((second.0, second.2.as_slice()), (200, b"a small public file".as_slice()));
}
