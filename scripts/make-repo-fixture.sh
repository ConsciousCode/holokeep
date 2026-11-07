#!/usr/bin/env bash
# Make a repo with this build of hk, as a fixture every later build must
# still open: tests/fixtures/repos/<name>/, with what it should find in
# expect.txt. Make a new one whenever the schema changes, and keep the old.
# Usage: scripts/make-repo-fixture.sh <name>   (eg the date)
set -euo pipefail
name=${1:?usage: $0 <name>}
cd "$(dirname "$0")/.."
cargo build --release --quiet
hk="$PWD/target/release/hk"
out="tests/fixtures/repos/$name"
[ ! -e "$out" ] || { echo "$out exists" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/repo"
h() { "$hk" --repo "$repo" "$@"; }

mkdir -p "$tmp/tree/sub"
printf 'hello from %s\n' "$name" > "$tmp/tree/hello.txt"
# Over 64 KiB, so the shards hold it
head -c 100000 /dev/zero | tr '\0' 'x' > "$tmp/tree/sub/big.txt"
tree=$(h add -q "$tmp/tree")
hello=$(h add -q -n "$tmp/tree/hello.txt")
big=$(h add -q -n "$tmp/tree/sub/big.txt")
h tag add fixture "$hello" >/dev/null
# Wanted once, by a keep nearer it than the tree's
h keep add --copies 1 "$big" >/dev/null
anchor=$(h anchor new)
h anchor set "$anchor" "$tree" >/dev/null
# The root names the anchor, as hk mount would
mkdir "$tmp/top"
ln -s "/anchors/$anchor" "$tmp/top/named"
top=$(h add -q "$tmp/top")
root=$(h anchor root | head -1)
h anchor set "$root" "$top" >/dev/null

# A git repository, packed, so some of its objects are kept as deltas
git init -q "$tmp/git"
for i in 1 2 3; do
    seq 1 $((i * 200)) > "$tmp/git/numbers.txt"
    git -C "$tmp/git" add numbers.txt
    GIT_AUTHOR_NAME=f GIT_AUTHOR_EMAIL=f@f GIT_COMMITTER_NAME=f GIT_COMMITTER_EMAIL=f@f \
        git -C "$tmp/git" commit -qm "$i"
done
git -C "$tmp/git" repack -adfq
git=$(h git import "$tmp/git" 2>/dev/null | awk '$2 == "HEAD" { print $1 }')

# Reported lost: what's never been here, so it stays so
printf 'lost from %s\n' "$name" > "$tmp/lost.txt"
lost=$(h add -q -n "$tmp/lost.txt")
h lost add "$lost" >/dev/null

mkdir -p "$out"
cp -a "$repo/." "$out/"
rm -f "$out"/*.sock
cat > "$out/expect.txt" <<EXPECT
tree $tree
hello $hello
big $big
anchor $anchor
root $root
top $top
copied $big
git $git
lost $lost
EXPECT
echo "made $out"
du -sh "$out"
