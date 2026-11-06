#!/usr/bin/env bash
# Stress a real mount: writers and readers at once through FUSE, with
# compacts, and the database's write lock held for a while, as a big import
# would. Checks what must always hold, whatever's going on:
#
#   - a file saved by renaming over it reads as one whole version
#   - a big file edited in place never reads as holes (zeros)
#   - nothing asked of the mount fails
#   - every value the anchor's had is whole, as is its file as last written
#
# and says how long the slowest read took while the lock was held. Uses a
# throwaway repo only, and needs FUSE, but not root.
#
#   scripts/mount-stress.sh [seconds]     (HK=path uses that build of hk)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
# KEEP=1 leaves it to look at, as what failed may want looking at
[ -n "${KEEP:-}" ] || trap 'rm -rf "$work"' EXIT
if [ -z "${HK:-}" ]; then
    cargo build --release --quiet --manifest-path "$root/Cargo.toml"
    HK=$root/target/release/hk
fi

python3 -I - "$HK" "$work" "${1:-40}" <<'PY'
import errno, os, random, re, signal, sqlite3, subprocess, sys, threading, time

hk, work, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
repo, mnt, tree = f"{work}/repo", f"{work}/mnt", f"{work}/tree"
env = {**os.environ, "HOLOKEEP_REPO": repo}
os.makedirs(mnt)
os.makedirs(tree)
BIG = 3_000_000
SAVED = [f"saved{i}" for i in range(4)]
BIGS = [f"big{i}" for i in range(3)]
LINES = 800
lock_seconds = 15
failures = []

def fail(what):
    if len(failures) < 40:
        print("FAILED:", what, flush=True)
    failures.append(what)

def saved_content(name, version):
    return f"{name} version {version}\n".encode() * LINES

def check_saved(name, data, where):
    lines = data.split(b"\n")[:-1]
    if len(lines) != LINES or len(set(lines)) != 1 or not lines[0].startswith(name.encode() + b" version "):
        fail(f"{where}: {name} isn't one whole version: {len(data)} bytes, {len(set(lines))} different lines")

for name in SAVED:
    open(f"{tree}/{name}", "wb").write(saved_content(name, 0))
for name in BIGS:
    open(f"{tree}/{name}", "wb").write(bytes([7]) * BIG)
os.makedirs(f"{tree}/still")
open(f"{tree}/still/here", "wb").write(b"unchanged\n")

def run(*args):
    return subprocess.run([hk, *args], env=env, capture_output=True, text=True, check=True).stdout.strip()

first = run("add", "-q", tree).splitlines()[-1]
anchor = run("anchor", "new")
run("anchor", "set", anchor, first)

mount_log = open(f"{work}/mount.log", "wb")
mount = subprocess.Popen([hk, "mount", mnt], env=env, stdout=mount_log, stderr=mount_log,
                         preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
for _ in range(100):
    if os.path.ismount(mnt):
        break
    time.sleep(0.1)
else:
    sys.exit("it never mounted")
soup = f"{mnt}/anchors/{anchor}"

stop = threading.Event()
locked = threading.Event()
# For the second half, writers all pause every so often, long enough for a
# commit to start, then start again, so it's collided with: the first half,
# they don't, and commits that manage it are among writes throughout
go = threading.Event()
go.set()
last = {name: 0 for name in SAVED}
counts = {"saves": 0, "edits": 0, "reads": 0, "history": 0, "compacts": 0, "listings": 0}
slowest = {"read": 0.0, "read in its dir while locked": 0.0, "read of other dir while locked": 0.0, "read of an open file while locked": 0.0, "save while locked": 0.0}
compacts_busy = [0]

def timed(kind, started):
    took = time.time() - started
    slowest[kind] = max(slowest[kind], took)

def saver(name):
    version = 0
    while not stop.is_set():
        go.wait()
        version += 1
        started, during = time.time(), locked.is_set()
        try:
            with open(f"{soup}/.{name}.tmp", "wb") as f:
                f.write(saved_content(name, version))
            os.rename(f"{soup}/.{name}.tmp", f"{soup}/{name}")
            last[name] = version
            counts["saves"] += 1
        except OSError as e:
            fail(f"saving {name}: {e!r}")
        if during:
            timed("save while locked", started)
        time.sleep(random.uniform(0, 0.3))

def editor(name):
    while not stop.is_set():
        go.wait()
        try:
            with open(f"{soup}/{name}", "r+b") as f:
                f.seek(random.randrange(BIG - 8192))
                f.write(bytes([random.randrange(1, 255)]) * 8192)
            counts["edits"] += 1
        except OSError as e:
            fail(f"editing {name}: {e!r}")
        time.sleep(random.uniform(0, 1))

def reader(n):
    rng = random.Random(n)
    while not stop.is_set():
        name = rng.choice(SAVED + BIGS)
        started, during = time.time(), locked.is_set()
        try:
            if name in SAVED:
                with open(f"{soup}/{name}", "rb") as f:
                    check_saved(name, f.read(), "reading")
            else:
                with open(f"{soup}/{name}", "rb") as f:
                    f.seek(rng.randrange(BIG - 200_000))
                    if 0 in f.read(200_000):
                        fail(f"{name} read as holes")
            counts["reads"] += 1
        except OSError as e:
            fail(f"reading {name}: {e!r}")
        timed("read in its dir while locked" if during else "read", started)
        started, during = time.time(), locked.is_set()
        try:
            with open(f"{soup}/still/here", "rb") as f:
                if f.read() != b"unchanged\n":
                    fail("still/here changed")
            os.listdir(f"{soup}/still")
            counts["listings"] += 1
        except OSError as e:
            fail(f"reading still/here: {e!r}")
        if during:
            timed("read of other dir while locked", started)

def open_reader():
    with open(f"{soup}/still/here", "rb") as small, open(f"{soup}/{BIGS[0]}", "rb") as big:
        while not stop.is_set():
            started, during = time.time(), locked.is_set()
            try:
                os.pread(small.fileno(), 100, 0)
                os.pread(big.fileno(), 65536, 0)
            except OSError as e:
                fail(f"reading an open file: {e!r}")
            if during:
                timed("read of an open file while locked", started)
            time.sleep(0.02)

def values():
    with open(f"{work}/mount.log", "rb") as f:
        return re.findall(rb" is (bafy[a-z0-9]+) now", f.read())

def historian():
    rng = random.Random(0)
    while not stop.is_set():
        seen = values()
        if not seen:
            time.sleep(0.2)
            continue
        value = rng.choice(seen).decode()
        name = rng.choice(SAVED)
        try:
            with open(f"{mnt}/cid/{value}/{name}", "rb") as f:
                check_saved(name, f.read(), f"version {value}")
            counts["history"] += 1
        except OSError as e:
            if e.errno != errno.ENOENT:
                fail(f"reading version {value}: {e!r}")
        time.sleep(0.05)

def compactor():
    while not stop.is_set():
        try:
            c = sqlite3.connect(f"{repo}/blocks.db", timeout=30, isolation_level=None)
            c.executescript("CREATE TABLE junk AS WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<2000) SELECT zeroblob(4000) AS b FROM n; DROP TABLE junk;")
            c.close()
        except sqlite3.OperationalError as e:
            fail(f"making something to compact: {e}")
        done = subprocess.run([hk, "repo", "compact"], env=env, capture_output=True, text=True)
        # Beside the lock this holds for longer than a command waits
        if "database is locked" in done.stderr:
            compacts_busy[0] += 1
        elif done.returncode != 0:
            fail(f"compact: {done.stderr.strip()}")
        counts["compacts"] += 1
        time.sleep(0.5)

def pauser():
    rng = random.Random(1)
    time.sleep(seconds / 2)
    while not stop.is_set():
        time.sleep(rng.uniform(2, 4))
        go.clear()
        time.sleep(rng.uniform(1.0, 1.6))
        go.set()

threads = [threading.Thread(target=saver, args=(name,)) for name in SAVED]
threads += [threading.Thread(target=editor, args=(name,)) for name in BIGS]
threads += [threading.Thread(target=reader, args=(n,)) for n in range(4)]
threads += [threading.Thread(target=historian), threading.Thread(target=compactor), threading.Thread(target=pauser), threading.Thread(target=open_reader)]
for thread in threads:
    thread.start()

# Settle, hold the write lock, as a big import would, then go on
time.sleep(max(1.0, (seconds - lock_seconds) / 2))
holder = sqlite3.connect(f"{repo}/blocks.db", timeout=30, isolation_level=None)
holder.execute("BEGIN IMMEDIATE")
locked.set()
time.sleep(lock_seconds)
locked.clear()
holder.execute("COMMIT")
holder.close()
time.sleep(max(1.0, (seconds - lock_seconds) / 2))
stop.set()
for thread in threads:
    thread.join(timeout=180)
    if thread.is_alive():
        fail(f"{thread.name} never finished")

# Let it commit, and end
time.sleep(3)
mount.send_signal(signal.SIGINT)
try:
    mount.wait(timeout=60)
except subprocess.TimeoutExpired:
    fail("the mount didn't stop on being interrupted")
    mount.kill()
mount_log.close()

seen = sorted({value.decode() for value in values()})
for n, value in enumerate(seen):
    out = f"{work}/out-{n}"
    done = subprocess.run([hk, "get", value, "--output", out], env=env, capture_output=True, text=True)
    if done.returncode != 0:
        fail(f"version {value} isn't whole: {done.stderr.strip()}")
        continue
    for name in SAVED:
        check_saved(name, open(f"{out}/{name}", "rb").read(), f"version {value}")
    for name in BIGS:
        if 0 in open(f"{out}/{name}", "rb").read():
            fail(f"version {value}: {name} has holes")
now = subprocess.run([hk, "anchor", "show", anchor], env=env, capture_output=True, text=True).stdout.split()[0]
out = f"{work}/out-now"
subprocess.run([hk, "get", now, "--output", out], env=env, check=True, capture_output=True)
for name, version in last.items():
    if open(f"{out}/{name}", "rb").read() != saved_content(name, version):
        fail(f"{name} isn't version {version}, as last saved")
check = sqlite3.connect(f"{repo}/blocks.db").execute("PRAGMA integrity_check").fetchone()[0]
if check != "ok":
    fail(f"integrity check: {check}")

print(f"{counts['saves']} saves, {counts['edits']} edits, {counts['reads']} reads, {counts['listings']} listings, "
      f"{counts['history']} reads of old versions, {counts['compacts']} compacts ({compacts_busy[0]} beside the lock); {len(seen)} versions whole")
print("slowest: " + ", ".join(f"{kind} {took:.2f}s" for kind, took in slowest.items()))
if failures:
    print(f"{len(failures)} failures")
    sys.exit(1)
print("all held")
PY
