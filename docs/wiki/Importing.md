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

`hk add --nocopy` doesn't copy file contents, like Kubo's filestore. Each
leaf is recorded as a range (blob, offset, length) of the file where it
was found. A range is only served while the file's fingerprint (size,
mtime, inode) still holds; otherwise reads fail as stale rather than
returning wrong bytes. Nothing's watched, and there's no anchor: to
follow a file or directory as it changes, watch it.

## Watched: `hk watch`

`hk watch add <path>` imports a file or directory in place, as
`--nocopy` does, mounts it on an anchor (see [[Anchors and Names]]),
keeps the anchor, and prints it. While the node runs, it watches every
directory in it (inotify), and imports it again when something changes,
moving the anchor. A changed file is noticed by its fingerprint and read
again; a file unchanged since the last import isn't read at all, but
taken for what it was. Newly watched, and when the node starts, it's
imported again once, for what changed while nothing was watching. Where
it's watched is known only to this machine and never enters the soup.

What [[Rules]] say to `skip` isn't imported: the built-in rules skip
downloads under way (`*.part`, `*.crdownload`, `*.download`,
`*.partial`, `*.tmp`), so a download's imported once, when it's renamed
to what it'll be; the root's `.souprules` and any `.souprules` in the
watched directory and below say more, a nearer saying over a farther.

```
hk watch add <path>             # watch it, printing its anchor
hk watch ls                     # path, anchor, root, files, size, how many stale
hk watch ls --files [<path>]    # each file read in place: ok, changed or gone
hk watch rm <path|anchor>       # stop watching, whatever state it's in
```

Stopping leaves the anchor as it was last imported, still kept: what's
read from files where they are stays readable while they're unchanged,
as with `--nocopy`, and members' copies stay where they are.

## Copying

Plain `hk add` copies. A file with more than one leaf and over 64 KiB is
written whole into the shards directory as it's read, and its leaves
become ranges of that copy, so they stay contiguous on disk. Smaller
files are stored block by block.

Source: `src/import.rs`, `src/dag.rs`, `src/hamt.rs`, `src/chunker.rs`, `scripts/kubo-compare.sh`.
