//! Services anchors are served from, as a node's own configuration says
//! (see the wiki's Servers page): which are fit to use, and connecting to
//! them.
//!
//! A serve claim only names a service; what it is, a socket speaking
//! 9P2000.L, is in `config.toml`'s `[[serve]]`, and runs as whoever owns
//! that file. So nothing here is believed unless its owner is who this
//! runs as: the configuration, which no one else may write, and the
//! socket, which must be theirs, in a directory no one else may write,
//! so nobody can put another socket in its place. Connecting runs with
//! this process's own credentials, and never on another user's behalf.

use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use crate::config::{self, Config, Service};
use crate::ninep::client::Client;

/// Why a service can't be used.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error("{0}")]
    Unfit(String),
    #[error("no service {0:?} in this node's config")]
    Unknown(String),
    #[error("{0}: {1}")]
    Io(PathBuf, io::Error),
}

/// The user this runs as.
fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Whether a file of configuration may say what runs as `me`: it's theirs
/// and no one else may write it.
pub fn config_fit(path: &Path, uid: u32, mode: u32, me: u32) -> Result<(), String> {
    if uid != me {
        return Err(format!("{} is uid {uid}'s, not this user's ({me}): its services aren't served", path.display()));
    }
    if mode & 0o022 != 0 {
        return Err(format!("{} may be written by others (mode {:o}): its services aren't served", path.display(), mode & 0o7777));
    }
    Ok(())
}

/// Whether a socket may be connected to as `me`'s service: a socket, theirs,
/// in a directory that's theirs or root's which no one else may write.
pub fn socket_fit(path: &Path, socket: Option<(bool, u32)>, dir: (u32, u32), me: u32) -> Result<(), String> {
    let (dir_uid, dir_mode) = dir;
    if dir_uid != me && dir_uid != 0 {
        return Err(format!("{} is in a directory of uid {dir_uid}'s", path.display()));
    }
    if dir_mode & 0o022 != 0 {
        return Err(format!("{} is in a directory others may write (mode {:o})", path.display(), dir_mode & 0o7777));
    }
    match socket {
        None => Err(format!("{} isn't there", path.display())),
        Some((false, _)) => Err(format!("{} isn't a socket", path.display())),
        Some((true, uid)) if uid != me => Err(format!("{} is uid {uid}'s, not this user's ({me})", path.display())),
        Some(_) => Ok(()),
    }
}

/// Where a mount reaches anchors other nodes serve, through the repo's
/// running node.
///
/// In the repo, unless the path's too long for a socket, then in the
/// user's runtime directory, named for the repo; never anywhere others may
/// write, where another socket could be put first.
pub fn relay_socket(repo: &Path) -> Option<PathBuf> {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let path = repo.join("serve.sock");
    if path.as_os_str().len() < 100 {
        return Some(path);
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)?;
    let repo = std::fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    let name = sha2::Sha256::digest(repo.as_os_str().as_encoded_bytes()).iter().take(8).fold(String::new(), |mut name, byte| {
        let _ = write!(name, "{byte:02x}");
        name
    });
    Some(runtime.join(format!("hk-{name}-serve.sock")))
}

/// Connect to the repo's node, to reach an anchor another node serves, if
/// its socket's this user's.
pub fn connect_relay(repo: &Path, anchor: &crate::model::Link, service: &str, node: &str) -> Result<Client, Error> {
    let path = relay_socket(repo).ok_or_else(|| Error::Unfit("no runtime directory for the node's socket".into()))?;
    let meta = std::fs::symlink_metadata(&path).map_err(|e| Error::Io(path.clone(), e))?;
    if !meta.file_type().is_socket() || meta.uid() != me() {
        return Err(Error::Unfit(format!("{} isn't this user's node's socket", path.display())));
    }
    let mut stream = std::os::unix::net::UnixStream::connect(&path).map_err(|e| Error::Io(path.clone(), e))?;
    std::io::Write::write_all(&mut stream, format!("{anchor} {service} {node}\n").as_bytes()).map_err(|e| Error::Io(path.clone(), e))?;
    Client::over_unix(stream, crate::ninep::client::TIMEOUT).map_err(|e| Error::Io(path, e))
}

/// The services a repo's configuration says, if it's fit to say them.
pub fn services(repo: &Path) -> Result<Vec<Service>, Error> {
    let path = repo.join(config::FILE);
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(path, e)),
    };
    let services = Config::load(repo)?.serve;
    if !services.is_empty() {
        config_fit(&path, meta.uid(), meta.mode(), me()).map_err(Error::Unfit)?;
    }
    Ok(services)
}

/// The service by a name, if the configuration's fit to say it.
pub fn service(repo: &Path, name: &str) -> Result<Service, Error> {
    services(repo)?.into_iter().find(|service| service.name == name).ok_or_else(|| Error::Unknown(name.to_owned()))
}

/// Connect to a service, if its socket's fit to.
pub fn connect(service: &Service) -> Result<Client, Error> {
    let stream = connect_raw(service)?;
    Client::over_unix(stream, crate::ninep::client::TIMEOUT).map_err(|e| Error::Io(service.socket(), e))
}

/// Connect to a service's socket, if it's fit to, to speak to it raw.
pub fn connect_raw(service: &Service) -> Result<std::os::unix::net::UnixStream, Error> {
    let path = service.socket();
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    let dir_meta = std::fs::metadata(dir).map_err(|e| Error::Io(dir.to_path_buf(), e))?;
    // None there is a server not running, not one that's unfit
    let meta = std::fs::symlink_metadata(&path).map_err(|e| Error::Io(path.clone(), e))?;
    socket_fit(&path, Some((meta.file_type().is_socket(), meta.uid())), (dir_meta.uid(), dir_meta.mode()), me()).map_err(Error::Unfit)?;
    std::os::unix::net::UnixStream::connect(&path).map_err(|e| Error::Io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_owners_config_says_what_runs_as_them() {
        let path = Path::new("config.toml");
        assert!(config_fit(path, 1000, 0o100_644, 1000).is_ok());
        assert!(config_fit(path, 1000, 0o100_600, 1000).is_ok());
        assert!(config_fit(path, 1001, 0o100_644, 1000).is_err(), "another user's");
        assert!(config_fit(path, 1000, 0o100_664, 1000).is_err(), "the group may write it");
        assert!(config_fit(path, 1000, 0o100_646, 1000).is_err(), "anyone may write it");
        assert!(config_fit(path, 1000, 0o100_644, 0).is_err(), "a user's config says nothing of what runs as root");
    }

    #[test]
    fn only_the_owners_socket_where_no_one_else_may_put_one() {
        let path = Path::new("/run/user/1000/notes.9p");
        assert!(socket_fit(path, Some((true, 1000)), (1000, 0o40_700), 1000).is_ok());
        assert!(socket_fit(path, Some((true, 1000)), (0, 0o40_755), 1000).is_ok(), "in root's directory");
        assert!(socket_fit(path, Some((true, 1001)), (1000, 0o40_700), 1000).is_err(), "another user's socket");
        assert!(socket_fit(path, Some((true, 1000)), (0, 0o41_777), 1000).is_err(), "in /tmp, where anyone may put one");
        assert!(socket_fit(path, Some((true, 1000)), (1001, 0o40_755), 1000).is_err(), "in another user's directory");
        assert!(socket_fit(path, Some((false, 1000)), (1000, 0o40_700), 1000).is_err(), "not a socket");
        assert!(socket_fit(path, None, (1000, 0o40_700), 1000).is_err(), "not there");
    }

    #[test]
    fn a_service_is_connected_to_only_if_fit() {
        let scratch = crate::testutil::Scratch::new("served");
        let repo = scratch.path().join("repo");
        let run = scratch.path().join("run");
        std::fs::create_dir_all(&repo).expect("mkdir");
        std::fs::create_dir_all(&run).expect("mkdir");
        let set_mode = |path: &Path, mode: u32| std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)).expect("chmod");
        set_mode(&run, 0o700);
        let socket = run.join("notes.9p");
        crate::ninep::memfs::listen(crate::ninep::memfs::Shared::default(), &socket).expect("listen");
        std::fs::write(repo.join(config::FILE), format!("[[serve]]\nname = \"notes\"\nsocket = {:?}\n", socket.display().to_string())).expect("write");
        set_mode(&repo.join(config::FILE), 0o644);

        let notes = service(&repo, "notes").expect("service");
        assert_eq!(notes.socket(), socket);
        let client = connect(&notes).expect("connect");
        assert!(client.attach(b"u", b"", crate::ninep::NONUNAME).is_ok());
        assert!(matches!(service(&repo, "other"), Err(Error::Unknown(_))));

        // Where anyone could have put it
        set_mode(&run, 0o777);
        assert!(matches!(connect(&notes), Err(Error::Unfit(_))));
        set_mode(&run, 0o700);
        // Configuration anyone could have written
        set_mode(&repo.join(config::FILE), 0o666);
        assert!(matches!(services(&repo), Err(Error::Unfit(_))));
    }
}
