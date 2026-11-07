#!/usr/bin/env bash
# Rename a big file over and over through a real mount while it's open, still
# being copied, and read and written at once: what's read must never be holes,
# and what's written must never be undone by the copy catching up. Uses a
# throwaway repo only, and needs FUSE, but not root.
#
#   scripts/mount-renames.sh [seconds]     (HK=path uses that build of hk)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
base=$(mktemp -d)
trap 'rm -rf "$base"' EXIT
if [ -z "${HK:-}" ]; then
    cargo build --release --quiet --manifest-path "$root/Cargo.toml"
    HK=$root/target/release/hk
fi

python3 -I - "$HK" "$base" "${1:-6}" <<'PY'
import os, random, signal, subprocess, sys, tempfile, threading, time
hk, base = sys.argv[1], sys.argv[2]
work = tempfile.mkdtemp(dir=base)
repo, mnt, tree = f"{work}/repo", f"{work}/mnt", f"{work}/tree"
env = {**os.environ, "HOLOKEEP_REPO": repo}
os.makedirs(mnt); os.makedirs(tree)
SIZE = 400 * 1024 * 1024
PAGE = 4096
def page(i): return bytes([(i % 251) + 1]) * PAGE
with open(f"{tree}/big", "wb") as f:
    for i in range(SIZE // PAGE): f.write(page(i))
run = lambda *a: subprocess.run([hk, *a], env=env, capture_output=True, text=True, check=True).stdout.strip()
out = run("add", "-q", tree).splitlines()[-1]
anchor = run("anchor", "new")
run("anchor", "set", anchor, out)
m = subprocess.Popen([hk, "mount", mnt], env=env, stdout=open(f"{work}/log", "w"), stderr=subprocess.STDOUT, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
for _ in range(100):
    if os.path.ismount(mnt): break
    time.sleep(0.1)
assert os.path.ismount(mnt)
try:
    d = f"{mnt}/anchors/{anchor}"
    n = f"{d}/big"
    fd = os.open(n, os.O_RDWR)
    # direct kernel cache out of the way as far as we can
    stop = threading.Event(); bad = []; reads = [0]; renames = [0]
    written = {}
    def reader():
        r = random.Random()
        while not stop.is_set():
            i = r.randrange(SIZE // PAGE)
            if i in written: continue
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            data = os.pread(fd, PAGE, i * PAGE)
            reads[0] += 1
            if data != page(i) and i not in written:
                bad.append((i, data[:4])); 
    def writer():
        r = random.Random(1)
        while not stop.is_set():
            i = r.randrange(SIZE // PAGE) & ~255 | 7
            written[i] = True
            os.pwrite(fd, b"W" * PAGE, i * PAGE)
            time.sleep(0.01)
    def renamer():
        cur = "big"; k = 0
        while not stop.is_set():
            k += 1; new = f"big{k}"
            os.rename(f"{d}/{cur}", f"{d}/{new}"); cur = new; renames[0] += 1
            time.sleep(0.005)
        names.append(cur)
    names = []
    ts = [threading.Thread(target=f) for f in (reader, reader, reader, writer, renamer)]
    [t.start() for t in ts]
    t0 = time.time()
    time.sleep(float(sys.argv[3]))
    stop.set(); [t.join() for t in ts]
    os.fsync(fd)
    # everything: what was written stays, the rest is the original
    wrong = 0
    for i in range(SIZE // PAGE):
        data = os.pread(fd, PAGE, i * PAGE)
        want = b"W" * PAGE if i in written else page(i)
        if data != want:
            wrong += 1
    os.close(fd)
    print(f"reads {reads[0]} renames {renames[0]} writes {len(written)} bad-during {len(bad)} {bad[:3]} wrong-after {wrong}")
    time.sleep(1)
    errs = open(f"{work}/log").read().splitlines()
    print("log tail:", [l for l in errs if 'rror' in l or "couldn't" in l][:5])
finally:
    m.send_signal(signal.SIGINT); m.wait(timeout=30)
sys.exit(1 if bad or wrong else 0)
PY
