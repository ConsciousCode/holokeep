#!/usr/bin/env bash
# Compare `hk add` against `ipfs add --only-hash` for a batch of generated
# cases, then store each case in a holokeep repo and check `hk get` writes
# it back out identically. Uses throwaway Kubo and holokeep repos, so your
# own ~/.ipfs and ~/.holokeep are never touched.
#
#   scripts/kubo-compare.sh          # quick cases
#   LARGE=1 scripts/kubo-compare.sh  # also >1 GiB files (1024/1025 chunks)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export IPFS_PATH="$work/ipfs"
ipfs init --profile unixfs-v1-2025 --empty-repo >/dev/null
export HOLOKEEP_REPO="$work/holokeep"

cargo build --release --quiet --manifest-path "$root/Cargo.toml"
hk="$root/target/release/hk"

cases="$work/cases"
mkdir -p "$cases"
cd "$cases"

rand() { head -c "$1" /dev/urandom > "$2"; }

## Files around chunk boundaries
: > empty
printf x > one-byte
rand $((1024*1024)) exact-chunk
rand $((1024*1024 + 1)) chunk-plus-one
rand $((3*1024*1024 + 17)) three-chunks

## Directories
mkdir -p empty-dir
mkdir -p tree/a/b/c tree/.hidden-dir tree/ünïcödé
rand 5000 tree/a/file
rand $((2*1024*1024)) tree/a/b/two-chunks
: > tree/a/b/c/empty
printf secret > tree/.hidden
printf inside > tree/.hidden-dir/file
printf hi > "tree/ünïcödé/名前 with spaces"
ln -s a/file tree/rel-link
ln -s /nonexistent/target tree/dangling-link
ln -s ../.. tree/a/b/up-link

## HAMT switch: entries named to make the basic directory block exactly
## 256 KiB, then one byte over. 4853 names of 10 bytes and one of 34/35
## bytes, each linking the same empty file.
for n in 34 35; do
    d="hamt-edge-$n"
    mkdir -p "$d"
    (cd "$d" && seq -f 'f%09g' 1 4853 | xargs touch && touch "$(printf 'z%.0s' $(seq 1 $n))")
done

## Big HAMT with nested shards
mkdir -p hamt-big
(cd hamt-big && seq -f 'entry-%g.txt' 1 20000 | xargs touch)

## Deep balanced trees at a small scale via --chunker/--max-file-links
rand 20000 deep

if [[ -n "${LARGE:-}" ]]; then
    truncate -s $((1024*1024*1024)) chunks-1024
    truncate -s $((1025*1024*1024)) chunks-1025
fi

fail=0
compare() {
    local label=$1; shift
    local want got
    want=$(ipfs add -n -r "$@" | sort)
    got=$("$hk" add -n "$@" | sort)
    if [[ "$want" == "$got" ]]; then
        echo "ok   $label ($(wc -l <<<"$want") entries)"
    else
        echo "FAIL $label"
        diff <(echo "$want") <(echo "$got") | head -20
        fail=1
    fi
}

for f in *; do
    [[ $f == deep ]] && continue
    compare "$f" "$f"
done
compare "tree --hidden" -H tree
for args in "size-64 2" "size-100 3" "size-1000 7" "size-256 174"; do
    set -- $args
    compare "deep -s $1 --max-file-links $2" --chunker="$1" --max-file-links="$2" deep
done

## Store everything and read it back out
out="$work/out"
mkdir -p "$out"
for f in *; do
    root=$("$hk" add -q -H "$f")
    if "$hk" get "$root" -o "$out/$f" && diff -r --no-dereference "$f" "$out/$f" >/dev/null; then
        echo "ok   get $f"
    else
        echo "FAIL get $f"
        diff -r --no-dereference "$f" "$out/$f" | head -10
        fail=1
    fi
done
root=$("$hk" add -q --chunker=size-64 --max-file-links=2 deep)
if "$hk" cat "$root" | cmp -s - deep; then
    echo "ok   cat deep -s size-64 --max-file-links 2"
else
    echo "FAIL cat deep -s size-64 --max-file-links 2"
    fail=1
fi
"$hk" repo stat

## Large blocks and files are kept whole, named as flatfs would (base32upper
## multihash, next-to-last/2), so they check themselves
kept=0
for f in "$HOLOKEEP_REPO"/shards/??/*.data; do
    [ -e "$f" ] || continue
    kept=$((kept + 1))
    key=$(printf '1220%s' "$(sha256sum "$f" | cut -d' ' -f1)" | xxd -r -p | base32 -w0 | tr -d =)
    if [ "$(basename "$f")" != "$key.data" ] || [ "$(basename "$(dirname "$f")")" != "${key: -3:2}" ]; then
        echo "FAIL kept file $f doesn't match its name"
        fail=1
    fi
done
if [ "$kept" -gt 0 ]; then
    echo "ok   $kept kept files match their names"
else
    echo "FAIL nothing was kept whole"
    fail=1
fi

## Keep files in place, in a separate repo, and read them back while unchanged
export HOLOKEEP_REPO="$work/nocopy"
nocopy="$work/nocopy-out"
mkdir -p "$nocopy"
for f in *; do
    root=$("$hk" add -q -H --nocopy "$f")
    if "$hk" get "$root" -o "$nocopy/$f" && diff -r --no-dereference "$f" "$nocopy/$f" >/dev/null; then
        echo "ok   get --nocopy $f"
    else
        echo "FAIL get --nocopy $f"
        fail=1
    fi
done
"$hk" repo stat
if "$hk" repo stat | grep -q '^raw'; then
    echo "FAIL --nocopy copied leaves into the repo"
    fail=1
fi

exit $fail
