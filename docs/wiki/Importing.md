`hk add` turns files and directories into UnixFSv1 DAGs whose CIDs are
identical to Kubo's `ipfs add` under the **`unixfs-v1-2025`** profile.
This is checked against a real Kubo by `scripts/kubo-compare.sh` in the
repository whenever the importer changes.

## Parameters

| Parameter   | Value                                                                             |
| ----------- | --------------------------------------------------------------------------------- |
| CID version | 1                                                                                 |
| Hash        | sha2-256                                                                          |
| Leaves      | raw (`0x55`)                                                                      |
| Chunker     | fixed size, 1 MiB (1048576 bytes)                                                 |
| File layout | balanced, 1024 links per node                                                     |
| Directories | basic, switching to a HAMT once the directory would exceed 256 KiB (IPIP-499)     |
| HAMT        | fanout 256, murmur3-x64-64 of the name, most significant bits first (boxo `hamt`) |
| Metadata    | no mode, no mtime                                                                 |
| Symlinks    | UnixFS symlink nodes, target as data                                              |

A file of one chunk is just its raw leaf. A bigger file is a tree of
dag-pb nodes, each with UnixFS `Data` of type File, `filesize`, and
`blocksizes` for each child, and PBLinks with empty names and `Tsize`
equal to the child's cumulative size. dag-pb fields are written in
Kubo's order: Links before Data.

Directory entries are sorted by name bytes. A link's `Tsize` is the
child's block size plus the sum of its own links' Tsizes.

## Hidden files

By default `hk add` skips names starting with `.`, as Kubo does without
`--hidden`. Overlay mounts import with hidden files included (see
[[Mount]]).

## In place: `--nocopy`

`hk add --nocopy` doesn't copy file contents. Each leaf is recorded as
a range (blob, offset, length) of the file where it was found, and the
file is mounted on an anchor (see [[Anchors and Names]]).
When the file changes, a running node imports it again and moves the
anchor. A range is only served while the file's fingerprint (size,
mtime, inode) still holds; otherwise reads fail as stale rather than
returning wrong bytes.

## Copying

Plain `hk add` copies. A file with more than one leaf and over 64 KiB is
written whole into the shards directory as it's read, and its leaves
become ranges of that copy, so they stay contiguous on disk. Smaller
files are stored block by block.

Source: `src/import.rs`, `src/dag.rs`, `src/hamt.rs`, `src/chunker.rs`, `scripts/kubo-compare.sh`.
