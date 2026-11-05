#!/usr/bin/env bash
# Compare `hk git import` against git and Kubo: build a repository with
# loose objects, packs (deltas on offsets, and on names), annotated tags, a
# merged tag and a submodule's commit, import it, then check every object
# is held with git's bytes, under the CID Kubo gives those bytes, linking
# to what Kubo says it links to. Uses throwaway repos only.
#
#   scripts/git-compare.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'gpgconf --kill gpg-agent 2>/dev/null || true; rm -rf "$work"' EXIT

export IPFS_PATH="$work/ipfs"
ipfs init --empty-repo >/dev/null
export HOLOKEEP_REPO="$work/holokeep"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null

# A throwaway OpenPGP key to sign with: go-ipld-git reads OpenPGP
# signatures, not SSH ones
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key t@t ed25519 sign never 2>/dev/null
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.signingkey GIT_CONFIG_VALUE_0=t@t

cargo build --release --quiet --manifest-path "$root/Cargo.toml"
hk="$root/target/release/hk"

# The CID git-raw gives an object by its SHA-1
cid_of() { python3 -c 'import base64,sys; print("b" + base64.b32encode(bytes([1,0x78,0x11,0x14]) + bytes.fromhex(sys.argv[1])).decode().lower().rstrip("="))' "$1"; }

# Every link in dag-json, sorted
kubo_links() { python3 -c '
import json, sys
def walk(v):
    if isinstance(v, dict):
        if set(v) == {"/"} and isinstance(v["/"], str):
            yield v["/"]
        else:
            for x in v.values(): yield from walk(x)
    elif isinstance(v, list):
        for x in v: yield from walk(x)
print("\n".join(sorted(walk(json.load(sys.stdin)))))' | sed '/^$/d'; }

make_repo() {
    local dir=$1
    git init -q -b main "$dir"
    cd "$dir"
    for i in $(seq 1 30); do
        seq 1 $((i * 50)) > numbers.txt
        mkdir -p "dir$((i % 3))"
        echo "file $i" > "dir$((i % 3))/f$i"
        git add -A
        git commit -qm "commit $i"
    done
    git tag -a v1 -m "the first"
    git tag light
    git checkout -qb side HEAD~5
    echo side > side.txt
    git add side.txt
    git commit -qm side
    # Signed, so merging it records a mergetag, and a signed commit
    git tag -s side-tag -m "a tag to merge"
    git checkout -q main
    git merge -q --no-ff --no-edit side-tag
    git commit -qS --allow-empty -m "signed"
    # A submodule's commit, which is in no object here
    git update-index --add --cacheinfo 160000,1234567890123456789012345678901234567890,sub
    git commit -qm "a submodule"
    cd - >/dev/null
}

check_repo() {
    local dir=$1 label=$2
    "$hk" git import "$dir" > "$work/refs" 2>"$work/err" || { cat "$work/err"; exit 1; }
    echo "$label: $(cat "$work/err")"
    local head
    head=$(git -C "$dir" rev-parse HEAD)
    grep -q "^$(cid_of "$head") HEAD$" "$work/refs" || { echo "$label: HEAD isn't $head"; cat "$work/refs"; exit 1; }
    local count=0
    while read -r sha type size; do
        cid=$(cid_of "$sha")
        { printf '%s %s\0' "$type" "$size"; git -C "$dir" cat-file "$type" "$sha"; } > "$work/want"
        "$hk" block get "$cid" > "$work/got" || { echo "$label: $type $sha ($cid) not held"; exit 1; }
        cmp -s "$work/want" "$work/got" || { echo "$label: $type $sha isn't git's bytes"; exit 1; }
        kubo=$(ipfs block put --cid-codec git-raw --mhtype sha1 < "$work/got")
        [ "$kubo" = "$cid" ] || { echo "$label: Kubo names $type $sha $kubo, not $cid"; exit 1; }
        # Kubo's links, from its decoding, since `ipfs refs` would want
        # what they link to here
        ipfs dag get "$cid" | kubo_links > "$work/kubo-links"
        "$hk" refs "$cid" | sort > "$work/hk-links"
        diff "$work/kubo-links" "$work/hk-links" >/dev/null \
            || { echo "$label: $type $sha links differ (Kubo <, hk >):"; diff "$work/kubo-links" "$work/hk-links"; exit 1; }
        count=$((count + 1))
    done < <(git -C "$dir" cat-file --batch-all-objects --batch-check)
    echo "$label: all $count objects match"
}

make_repo "$work/loose"
check_repo "$work/loose" "loose"

make_repo "$work/offsets"
git -C "$work/offsets" repack -adfq
[ -z "$(find "$work/offsets/.git/objects" -path '*/objects/??/*')" ] || { echo "offsets: still loose objects"; exit 1; }
check_repo "$work/offsets" "packed, deltas on offsets"

make_repo "$work/names"
git -C "$work/names" -c repack.useDeltaBaseOffset=false repack -adfq
check_repo "$work/names" "packed, deltas on names"

# Packed and loose together, as a repository is after a few commits
make_repo "$work/both"
git -C "$work/both" repack -adq
echo more >> "$work/both/numbers.txt"
git -C "$work/both" commit -qam more
check_repo "$work/both" "packed and loose"

git -C "$work/loose" cat-file commit HEAD~2 | grep -q '^mergetag ' || { echo "no mergetag made"; exit 1; }
git -C "$work/loose" cat-file commit HEAD~1 | grep -q '^gpgsig ' || { echo "no signed commit made"; exit 1; }
for dir in offsets names; do
    deltas=$(git -C "$work/$dir" verify-pack -v "$work/$dir"/.git/objects/pack/*.idx | awk 'NF == 7' | wc -l)
    [ "$deltas" -gt 0 ] || { echo "$dir: no deltas in the pack"; exit 1; }
    echo "$dir: $deltas deltas"
done
echo "all match"
