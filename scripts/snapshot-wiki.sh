#!/usr/bin/env bash
# Snapshot the wiki, which lives in the soup as the anchor the root names
# `wiki`, into docs/wiki, as a fallback while the soup earns trust.
# Usage: scripts/snapshot-wiki.sh [hk args such as --repo <dir>]
set -euo pipefail
hk=${HK:-hk}
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
root=$("$hk" "$@" anchor root | sed -n 2p)
[ "$root" != unset ] || { echo "the root anchor is unset" >&2; exit 1; }
"$hk" "$@" get "$root" -o "$tmp/root" >/dev/null
target=$(readlink "$tmp/root/wiki") || { echo "the root names no wiki" >&2; exit 1; }
anchor=${target#/anchors/}
value=$("$hk" "$@" anchor show "$anchor" | head -1)
rm -rf docs/wiki
mkdir -p docs
"$hk" "$@" get "$value" -o docs/wiki >/dev/null
# Obsidian's settings and workspace are the reader's, not the wiki's
rm -rf docs/wiki/.obsidian
printf 'wiki anchor %s\nas of       %s\n' "$anchor" "$value" > docs/wiki/.snapshot
echo "docs/wiki is $value"
