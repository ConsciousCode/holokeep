## Shape

- A **repo** is one node's share of the soup: by default `~/.holokeep`,
  holding `blocks.db` (SQLite), `shards/` (a flatfs directory), keys, and
  `work/` for mount overlays.
- A **volume** is a place bytes are kept: the repo's database, its shards
  directory, or another drive or database added with `hk volume`. Each
  carries a random label in itself (a row, or a `VOLUME` file), so any
  catalog that opens it knows it for the same volume.
- A **form** is how a volume breaks a block down: UnixFS nodes as rows,
  claims as rows, IPLD as JSONB, raw bytes, file ranges.
- The **catalog** indexes a node's volumes: which volume and form hold
  each block (`blocks (block, volume, form)`), and every CID prefix a block
  was put under (`block_cids`).

In LVM terms a volume is a PV, a catalog the VG, and the repository the
LV. Blocks are immutable and relocatable, so moving one is copying it by
multihash and updating placement.

## Interning

Within a database, multihashes are **interned**: `multihashes` holds each
once, and everything else refers to it by integer id. Ids are local and
never cross a trait boundary or the network; multihashes are the
interchange format. Knowing a multihash doesn't mean having the block: a
link to something not yet fetched still gets an id, so "what's linked but
missing" is a plain query.

## Placement

Each put is offered to stores in order, and the first that admits it
keeps it:

1. **UnixFS** (`unixfs_nodes`, `unixfs_links`): dag-pb nodes it can
   rebuild exactly: every link named and sized, no mode or mtime, Kubo's
   field order. HAMT shard names are split into bucket and entry name, so
   the `unixfs_entries` view lists every directory alike.
2. **[[Claims]]** (`claims`, `claim_targets`, and per-type tables): canonical
   claims as rows; dissolved ones with no multihash.
3. **IPLD** (`ipld_blocks`): canonical dag-cbor and dag-json as SQLite
   JSONB in dag-json form, queryable in place
   (`WHERE data ->> '$.name' = …`).
4. **Offsets** (`offset_ranges`): raw leaves as (blob, offset, length)
   ranges of a whole file, kept in the shards or found in place.
5. **Deltas** (`delta_blocks`): [[Git|git objects]], versions of files
   written over through the [[Mount|mount]], and any block put with a
   delta on a block this store already keeps. See below.
6. **Shards** (flatfs): anything over 64 KiB, and whole files. Named by
   multihash in base32 upper with no multibase prefix, sharded
   `next-to-last/2`, as Kubo's flatfs.
7. **Raw** (`raw_blocks`): anything else, as bytes.

**Specialized stores must manifest exact bytes.** A store that keeps rows
must regenerate each block byte for byte, so it admits only [[Blocks and CIDs#Codecs|canonical]]
blocks; anything valid but non-canonical falls through to raw. Every
block is verified against its CID on the way out.

## Deltas

The delta store keeps a block either whole or as a **delta** on another
block it keeps, its **base**: copies from the base's bytes and bytes of
its own, in git's delta format (see `src/delta.rs`), over the whole
blocks' bytes. Each row is zlib-compressed when that makes it smaller.

| Column | Meaning |
|---|---|
| `block` | The block, by interned multihash. |
| `base` | The block it's a delta on, or NULL if it's whole. |
| `depth` | How many deltas reading it applies, at most. |
| `zlib` | Whether `data` is compressed. |
| `data` | The block's bytes, or the delta, as kept. |

- A delta comes with a put, never searched for by the store: a store is
  told where a block's bytes came from (its provenance), and a delta on
  a base is one such. [[Git#Importing|Importing git]] gives each object
  a pack had as a delta that delta, made one between whole blocks. The
  [[Mount|mount]] gives each part of a file written over the part of the
  version before it, which is then made a delta on it, and git objects
  that came whole are made deltas on the same path's next version (see
  [[Git#Storage]]).
- Deltas are found by `delta::encode`, as git's are: the base's 16-byte
  windows indexed by a rolling hash, each match extended both ways, and
  a short match looked past for one that goes further. On the pairs of
  objects ripgrep's pack has as deltas, its deltas are 6% smaller than
  git's, compressed, and found in a third of a second.
- A delta is kept only if its base is in the store, it's shorter than
  the block, applying it makes the block, the chain stays at most 50
  deep, and it doesn't loop back on itself. Otherwise the block is kept
  whole if it's a git object or a version written over, and goes on to
  the next store if not.
- A block kept whole is made a delta when it's put again with one,
  unless whole is smaller, or what's already a delta on it would end up
  more than 50 deep.
- A base let go of first makes each block that's a delta on it whole,
  and what's on those shallower.

## Compacting

A database keeps the pages it frees to use again, as an allocator does,
so its file doesn't shrink. That's usually right: what's freed is likely
needed again. It's worth giving back after something that won't be
repeated, such as importing a repository of loose objects, which writes
them whole and then rewrites them as deltas. So it's only done when
asked:

```
hk repo stat               # each database's bytes and free-bytes
hk repo compact --dry-run  # volume, bytes before, the most after, outcome
hk repo compact            # volume, bytes before, bytes after, outcome
```

It's safe to run beside a mount and a daemon, and does nothing to a
database with no free pages. `VACUUM` rewrites the database through its
WAL: readers carry on, and writers wait. They only wait 10 seconds,
though, so a database with over 256 MiB of pages in use is refused
without `--long`, which says nothing else is writing to it. One whose
filesystem has too little room for the WAL is always refused. A refusal
exits non-zero, after compacting the databases it can. A reader still in
a transaction can keep the WAL from being emptied, which the outcome
says: it goes on the next compact, or once nothing has the database open.

## Transactions

Every database is in WAL mode, so readers don't wait for a writer. But
`SQLite` doesn't wait, however long it's told to, for a transaction that's
already read and now wants to write beside a writer: it fails at once.
So `Db::atomically` takes the write lock before starting, and waits for
it. What usually only reads, like catching up, uses `Db::reading_first`,
which starts without it, so isn't held up; if it needs to write beside a
writer, it's undone and run again, waiting.

## Backreferences

Every block's links are indexed, by multihash, so "what links to this?"
is a query. Stores that keep link rows (UnixFS, IPLD, claims) serve
their own; for others the catalog reads links by codec on put into
`refs`. A mount point's link to its anchor goes into `refs` too, from
whichever store. The `links (source, target)` view is the union.
`hk refs --back <cid>`.

## Catching up between catalogs

Two nodes may share a volume (a USB drive, a network database). Writers
tell other nodes what they wrote over the [[Mesh]]; a catalog opening a
shared volume only has to notice what it wasn't told:

- **flatfs**: by each shard directory's mtime, compared with what it
  recorded when it last listed it (with a 2 s margin for FAT).
- **SQLite**: by a 64-bit **generation**. Triggers stamp a block's row in
  `generations` with one more than the latest whenever it arrives or
  leaves; a catalog keeps the latest generation it has seen per volume
  and reads `WHERE generation > n`. Dissolved claims are stamped in
  `claim_generations`.

Blocks are replicated between volumes, never rows: a copy is a put by
multihash into whatever forms the target supports.

## Schema migration

Each store creates its tables if missing and adds columns it needs after
checking `pragma_table_info`, so opening an older repo upgrades it in
place. A change to what's already in a repo is made once, in one
transaction, and recorded by name in `migrations (name, at)`:

| Migration | Change |
|---|---|
| `mount points link to their anchors` | Index every UnixFS symlink to `/anchors/<anchor>` as a link (in `refs`) to the anchor. |

Source: `src/store.rs`, `src/store/`.
