use std::io;
use std::time::Duration;

use super::client::{Client, libc_errno};
use super::memfs::{Attached, MemFs, Shared, spawn};
use super::*;

fn every_request() -> Vec<Tmsg> {
    let attr = SetAttr { valid: SETATTR_SIZE | SETATTR_MODE, mode: 0o644, uid: 1, gid: 2, size: 3, atime: (4, 5), mtime: (6, 7) };
    vec![
        Tmsg::Version { msize: MSIZE, version: VERSION.to_vec() },
        Tmsg::Attach { fid: 1, afid: NOFID, uname: b"bafy".to_vec(), aname: b"anchor".to_vec(), n_uname: 1000 },
        Tmsg::Flush { oldtag: 9 },
        Tmsg::Walk { fid: 1, newfid: 2, names: vec![b"a".to_vec(), b"b\xff".to_vec()] },
        Tmsg::Walk { fid: 1, newfid: 2, names: vec![] },
        Tmsg::Clunk { fid: 2 },
        Tmsg::Remove { fid: 2 },
        Tmsg::Statfs { fid: 1 },
        Tmsg::Getattr { fid: 1, mask: GETATTR_BASIC },
        Tmsg::Setattr { fid: 1, attr },
        Tmsg::Lopen { fid: 1, flags: 2 },
        Tmsg::Lcreate { fid: 1, name: b"new".to_vec(), flags: 0o100, mode: 0o644, gid: 0 },
        Tmsg::Read { fid: 1, offset: 1 << 40, count: 4096 },
        Tmsg::Write { fid: 1, offset: 5, data: b"hello".to_vec() },
        Tmsg::Readdir { fid: 1, offset: 3, count: 8192 },
        Tmsg::Fsync { fid: 1, datasync: 1 },
        Tmsg::Mkdir { dfid: 1, name: b"d".to_vec(), mode: 0o755, gid: 0 },
        Tmsg::Symlink { fid: 1, name: b"l".to_vec(), target: b"/x".to_vec(), gid: 0 },
        Tmsg::Readlink { fid: 1 },
        Tmsg::Renameat { olddirfid: 1, oldname: b"a".to_vec(), newdirfid: 2, newname: b"b".to_vec() },
        Tmsg::Unlinkat { dirfid: 1, name: b"a".to_vec(), flags: AT_REMOVEDIR },
    ]
}

fn every_answer() -> Vec<Rmsg> {
    let qid = Qid { kind: QTDIR | QTTMP, version: 7, path: 1 << 50 };
    let attr = Attr { valid: GETATTR_BASIC, qid, mode: 0o40755, size: 9, atime: (1, 2), btime: (3, 4), data_version: 5, ..Attr::default() };
    vec![
        Rmsg::Version { msize: 8192, version: VERSION.to_vec() },
        Rmsg::Lerror { ecode: 2 },
        Rmsg::Attach { qid },
        Rmsg::Flush,
        Rmsg::Walk { qids: vec![qid, Qid::default()] },
        Rmsg::Clunk,
        Rmsg::Remove,
        Rmsg::Statfs(StatFs { bsize: 4096, blocks: 10, namelen: 255, ..StatFs::default() }),
        Rmsg::Getattr(Box::new(attr)),
        Rmsg::Setattr,
        Rmsg::Lopen { qid, iounit: 0 },
        Rmsg::Lcreate { qid, iounit: 4096 },
        Rmsg::Read { data: b"bytes".to_vec() },
        Rmsg::Write { count: 5 },
        Rmsg::Readdir { data: dirents(&[DirEntry { qid, offset: 1, kind: 4, name: b"d".to_vec() }], 100).expect("dirents").0 },
        Rmsg::Fsync,
        Rmsg::Mkdir { qid },
        Rmsg::Symlink { qid },
        Rmsg::Readlink { target: b"/x".to_vec() },
        Rmsg::Renameat,
        Rmsg::Unlinkat,
    ]
}

#[test]
fn every_message_round_trips() {
    for request in every_request() {
        let bytes = request.encode(42).expect("encode");
        assert_eq!(Tmsg::decode(&bytes).expect("decode"), (42, request));
    }
    for answer in every_answer() {
        let bytes = answer.encode(42).expect("encode");
        assert_eq!(Rmsg::decode(&bytes).expect("decode"), (42, answer));
    }
}

#[test]
fn messages_are_as_linux_lays_them_out() {
    // Tversion, tag NOTAG: size, type 100, tag, msize, "9P2000.L"
    let bytes = Tmsg::Version { msize: 8192, version: VERSION.to_vec() }.encode(NOTAG).expect("encode");
    assert_eq!(bytes, b"\x15\x00\x00\x00\x64\xff\xff\x00\x20\x00\x00\x08\x009P2000.L");
    // Rlerror ENOENT
    assert_eq!(Rmsg::Lerror { ecode: 2 }.encode(1).expect("encode"), b"\x0b\x00\x00\x00\x07\x01\x00\x02\x00\x00\x00");
}

#[test]
fn whats_malformed_is_refused() {
    let good = Tmsg::Clunk { fid: 1 }.encode(1).expect("encode");
    assert!(Tmsg::decode(good.get(..good.len() - 1).expect("short")).is_err(), "shorter than its size");
    let mut long = good.clone();
    long.push(0);
    assert!(Tmsg::decode(&long).is_err(), "longer than its size");
    let mut extra = good;
    extra.push(0);
    extra[0] += 1;
    assert!(Tmsg::decode(&extra).is_err(), "bytes left over");
    let unknown = Out::new(30, 5).done().expect("done");
    let error = Tmsg::decode(&unknown).expect_err("unknown");
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

fn served(fs: MemFs) -> (Client, Shared) {
    let shared = Shared::new(fs);
    let stream = spawn(shared.clone());
    (Client::over_unix(stream, Duration::from_millis(500)).expect("connect"), shared)
}

fn errno(result: io::Result<impl std::fmt::Debug>) -> i32 {
    result.expect_err("an error").raw_os_error().expect("an errno")
}

#[test]
fn a_client_walks_reads_and_writes_a_tree() {
    let mut fs = MemFs::new();
    fs.file("notes/today.md", b"hello");
    fs.symlink("link", "notes/today.md");
    let (client, shared) = served(fs);
    let (root, qid) = client.attach(b"bafyuser", b"bafyanchor", 1000).expect("attach");
    assert!(qid.is_dir());
    assert_eq!(shared.lock().attached, [Attached { uname: b"bafyuser".to_vec(), aname: b"bafyanchor".to_vec(), n_uname: 1000 }]);

    // Listing
    let (dir, _) = client.walk(root, &[]).expect("clone");
    client.lopen(dir, 0).expect("open");
    let names: Vec<Vec<u8>> = client.readdir_all(dir).expect("readdir").into_iter().map(|entry| entry.name).collect();
    assert_eq!(names, [b"link".to_vec(), b"notes".to_vec()]);
    client.clunk(dir).expect("clunk");

    // Reading, and writing
    let (file, qids) = client.walk(root, &[b"notes", b"today.md"]).expect("walk");
    assert_eq!(qids.len(), 2);
    assert_eq!(client.getattr(file).expect("getattr").size, 5);
    client.lopen(file, 2).expect("open");
    assert_eq!(client.read(file, 0, 100).expect("read"), b"hello");
    assert_eq!(client.write(file, 5, b", world").expect("write"), 7);
    client.clunk(file).expect("clunk");
    assert_eq!(shared.lock().read("notes/today.md").as_deref(), Some(b"hello, world".as_slice()));

    // Making, renaming and removing
    let (notes, _) = client.walk(root, &[b"notes"]).expect("walk");
    let (new, _) = client.walk(notes, &[]).expect("clone");
    client.lcreate(new, b"new.md", 0o101, 0o644, 0).expect("create");
    client.write(new, 0, b"made").expect("write");
    client.mkdir(notes, b"sub", 0o755, 0).expect("mkdir");
    client.renameat(notes, b"new.md", notes, b"renamed.md").expect("rename");
    assert_eq!(shared.lock().read("notes/renamed.md").as_deref(), Some(b"made".as_slice()));
    assert_eq!(errno(client.unlinkat(notes, b"sub", 0)), libc_errno::EISDIR);
    client.unlinkat(notes, b"sub", AT_REMOVEDIR).expect("rmdir");
    let (link, _) = client.walk(root, &[b"link"]).expect("walk");
    assert_eq!(client.readlink(link).expect("readlink"), b"notes/today.md");

    // What isn't there
    assert_eq!(errno(client.walk(root, &[b"nothing"])), libc_errno::ENOENT);
    assert_eq!(errno(client.walk(root, &[b"notes", b"nothing"])), libc_errno::ENOENT, "part of the way is no walk");
}

#[test]
fn a_slow_answer_times_out_and_the_next_isnt_taken_for_it() {
    let mut fs = MemFs::new();
    fs.file("a", b"aaa");
    let (client, shared) = served(fs);
    let (root, _) = client.attach(b"u", b"", NONUNAME).expect("attach");
    shared.lock().delay = Duration::from_millis(800);
    assert_eq!(errno(client.getattr(root)), libc_errno::ETIMEDOUT);
    // The late answer, then the flush's, arrive while this waits
    shared.lock().delay = Duration::ZERO;
    let (file, _) = client.walk(root, &[b"a"]).expect("walk");
    client.lopen(file, 0).expect("open");
    assert_eq!(client.read(file, 0, 10).expect("read"), b"aaa");
}

#[test]
fn a_connection_gone_fails_everything() {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("pair");
    let server = std::thread::spawn(move || {
        // Agree on the version, then hang up
        let mut stream = theirs;
        let message = read_message(&mut stream, MSIZE).expect("read");
        let (tag, _) = Tmsg::decode(&message).expect("decode");
        write_message(&mut stream, &Rmsg::Version { msize: MSIZE, version: VERSION.to_vec() }.encode(tag).expect("encode")).expect("write");
    });
    let client = Client::over_unix(ours, Duration::from_secs(5)).expect("connect");
    server.join().expect("join");
    assert_eq!(errno(client.attach(b"u", b"", NONUNAME)), libc_errno::ENOTCONN);
    assert!(client.closed());
}

#[test]
fn a_server_of_another_dialect_is_refused() {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("pair");
    std::thread::spawn(move || {
        let mut stream = theirs;
        let message = read_message(&mut stream, MSIZE).expect("read");
        let (tag, _) = Tmsg::decode(&message).expect("decode");
        write_message(&mut stream, &Rmsg::Version { msize: MSIZE, version: b"9P2000".to_vec() }.encode(tag).expect("encode")).expect("write");
    });
    let error = Client::over_unix(ours, Duration::from_secs(5)).expect_err("refused");
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

#[test]
fn a_server_says_what_it_doesnt_serve() {
    let mut fs = Shared::new(MemFs::new());
    let mut input = Vec::new();
    input.extend(Tmsg::Version { msize: 8192, version: VERSION.to_vec() }.encode(NOTAG).expect("encode"));
    input.extend(Out::new(30, 5).done().expect("done"));
    let mut output = Vec::new();
    server::serve(&mut fs, &mut input.as_slice(), &mut output).expect("serve");
    let mut answers = output.as_slice();
    let (_, version) = Rmsg::decode(&read_message(&mut answers, MSIZE).expect("read")).expect("decode");
    assert_eq!(version, Rmsg::Version { msize: 8192, version: VERSION.to_vec() });
    let (tag, unknown) = Rmsg::decode(&read_message(&mut answers, MSIZE).expect("read")).expect("decode");
    assert_eq!((tag, unknown), (5, Rmsg::Lerror { ecode: 95 }));
}

#[test]
fn a_client_connects_to_a_socket_and_sees_what_isnt_to_be_kept() {
    let scratch = crate::testutil::Scratch::new("ninep-socket");
    let mut fs = MemFs::new();
    fs.tmp("handshake", b"once");
    fs.file("kept", b"always");
    let path = scratch.path().join("fs.9p");
    super::memfs::listen(Shared::new(fs), &path).expect("listen");
    let client = Client::connect(&path).expect("connect");
    let (root, _) = client.attach(b"u", b"", NONUNAME).expect("attach");
    let (_, tmp) = client.walk(root, &[b"handshake"]).expect("walk");
    let (_, kept) = client.walk(root, &[b"kept"]).expect("walk");
    assert!(tmp.first().is_some_and(Qid::is_tmp) && !kept.first().is_some_and(Qid::is_tmp));
}

#[test]
fn a_server_hanging_up_fails_whats_asked_after() {
    let scratch = crate::testutil::Scratch::new("ninep-hang-up");
    let path = scratch.path().join("fs.9p");
    let shared = Shared::new(MemFs::new());
    super::memfs::listen(shared.clone(), &path).expect("listen");
    let client = Client::connect(&path).expect("connect");
    let (root, _) = client.attach(b"u", b"", NONUNAME).expect("attach");
    shared.hang_up();
    assert_eq!(errno(client.getattr(root)), libc_errno::ENOTCONN);
}
