//! The mounts a running node keeps (`[[mount]]` in `config.toml`).
//!
//! Each is an `hk mount` of its own, so one that fails takes nothing
//! else with it; started again when it ends, sooner the longer it ran,
//! and interrupted, to unmount, when the node stops. A stale mount where one
//! goes, left by one that died, is cleared first; a live one, another's,
//! is left be.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::config::Mount;

/// The least wait before starting a mount again, doubling to `MOST` while
/// it keeps ending within `STEADY`.
const LEAST: Duration = Duration::from_secs(1);
const MOST: Duration = Duration::from_mins(1);
const STEADY: Duration = Duration::from_secs(30);
/// How often a place another mount holds is looked at again.
const LOOK_AGAIN: Duration = Duration::from_secs(30);
/// How long a mount's given to unmount when the node stops.
const UNMOUNTING: Duration = Duration::from_secs(10);

/// The mounts being kept, until `stop`.
pub struct Mounts {
    kept: Vec<Kept>,
}

struct Kept {
    stop: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

impl Mounts {
    /// Keep each of these mounted, of the repo in `repo`, by `hk`, this
    /// program.
    pub fn start(repo: &Path, mounts: &[Mount]) -> io::Result<Self> {
        let program = std::env::current_exe()?;
        let mut kept = Vec::new();
        for mount in mounts {
            let (stop, stopped) = mpsc::channel();
            let keeper = Keeper { program: program.clone(), repo: repo.to_owned(), dir: mount.dir(), read_only: mount.read_only, stopped };
            let thread = std::thread::Builder::new().name(format!("mount {}", mount.dir().display())).spawn(move || keeper.run())?;
            kept.push(Kept { stop, thread });
        }
        Ok(Self { kept })
    }

    /// Unmount each, as an interrupt does, waiting a while for it to.
    pub fn stop(self) {
        for kept in &self.kept {
            let _sent = kept.stop.send(());
        }
        for kept in self.kept {
            drop(kept.thread.join());
        }
    }
}

struct Keeper {
    program: PathBuf,
    repo: PathBuf,
    dir: PathBuf,
    read_only: bool,
    stopped: mpsc::Receiver<()>,
}

impl Keeper {
    fn run(self) {
        let mut wait = LEAST;
        let mut said_held = false;
        loop {
            match place(&self.dir) {
                Place::Held => {
                    if !said_held {
                        eprintln!("{} is mounted already, not by this node: leaving it be", self.dir.display());
                        said_held = true;
                    }
                    if self.sleep(LOOK_AGAIN) {
                        return;
                    }
                    continue;
                },
                Place::Stale => {
                    eprintln!("{} is a mount that died: clearing it", self.dir.display());
                    clear(&self.dir);
                },
                Place::Missing => {
                    if let Err(e) = std::fs::create_dir_all(&self.dir) {
                        eprintln!("can't make {} to mount on: {e}", self.dir.display());
                    }
                },
                Place::Free => {},
            }
            said_held = false;
            let started = Instant::now();
            match self.spawn() {
                Ok(mut child) => {
                    let status = loop {
                        if !matches!(self.stopped.recv_timeout(Duration::from_millis(200)), Err(RecvTimeoutError::Timeout)) {
                            self.reap(&mut child);
                            return;
                        }
                        match child.try_wait() {
                            Ok(None) => {},
                            Ok(Some(status)) => break Ok(status),
                            Err(e) => break Err(e),
                        }
                    };
                    match status {
                        Ok(status) if status.success() => eprintln!("mount on {} ended", self.dir.display()),
                        Ok(status) => eprintln!("mount on {} ended: {status}", self.dir.display()),
                        Err(e) => eprintln!("mount on {}: {e}", self.dir.display()),
                    }
                },
                Err(e) => eprintln!("can't start a mount on {}: {e}", self.dir.display()),
            }
            wait = if started.elapsed() >= STEADY { LEAST } else { wait.saturating_mul(2).min(MOST) };
            if self.sleep(wait) {
                return;
            }
        }
    }

    fn spawn(&self) -> io::Result<Child> {
        let mut command = Command::new(&self.program);
        command.arg("mount").arg("--repo").arg(&self.repo).arg(&self.dir);
        if self.read_only {
            command.arg("--read-only");
        }
        // Its own group, so an interrupt at the terminal is the node's to
        // pass on, and the node's to know isn't the mount failing
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        command.stdin(Stdio::null()).spawn()
    }

    /// Interrupt a mount, to unmount, and wait for it to end, killing it
    /// if it won't.
    fn reap(&self, child: &mut Child) {
        if matches!(child.try_wait(), Ok(None)) {
            interrupt(child.id());
        }
        let deadline = Instant::now().checked_add(UNMOUNTING).unwrap_or_else(Instant::now);
        while Instant::now() < deadline {
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!("mount on {} didn't end when interrupted: killing it", self.dir.display());
        drop(child.kill());
        drop(child.wait());
    }

    /// Wait, unless stopped first: whether stopped.
    fn sleep(&self, wait: Duration) -> bool {
        !matches!(self.stopped.recv_timeout(wait), Err(RecvTimeoutError::Timeout))
    }
}

enum Place {
    Free,
    Missing,
    /// A FUSE mount whose process is gone.
    Stale,
    /// Mounted by someone else.
    Held,
}

fn place(dir: &Path) -> Place {
    match std::fs::metadata(dir) {
        Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => Place::Stale,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Place::Missing,
        _ if crate::fs::mount_points().iter().any(|point| point == dir) => Place::Held,
        _ => Place::Free,
    }
}

/// Unmount a mount whose process is gone, lazily, as its user may.
fn clear(dir: &Path) {
    for program in ["fusermount3", "fusermount"] {
        match Command::new(program).arg("-u").arg("-z").arg(dir).stdin(Stdio::null()).status() {
            Ok(status) if status.success() => return,
            Ok(status) => {
                eprintln!("{program} -u -z {}: {status}", dir.display());
                return;
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => {
                eprintln!("{program}: {e}");
                return;
            },
        }
    }
    eprintln!("no fusermount to clear {} with", dir.display());
}

fn interrupt(pid: u32) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: a signal to a child of this process not yet reaped, so
        // its pid isn't anyone else's
        unsafe {
            libc::kill(pid, libc::SIGINT);
        }
    }
}
