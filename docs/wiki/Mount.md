`hk mount <dir>` shows the soup as a filesystem over FUSE (pure Rust, via
`fusermount3`), until interrupted. `--read-only` makes anchors read-only
too.

```
<name>/…            what the account's root anchor names
cid/<cid>/…         whatever is at a CID; looked up by name, never listed
anchors/<anchor>/…  what each anchor is now, writable
tags/<tag>/<cid>/…  what's tagged so
```

UnixFS directories are directories, files files, symlinks symlinks
(but mount points, below); a block of any other codec reads as its
bytes. Another account's blocks are
as good as absent. Anchors and tags are looked up again every second, so
the mount follows them.

## The top

The top is the account's root anchor (see
[[Anchors and Names]]), beside `cid`, `anchors` and
`tags`, which hide any root entries of the same name. It's written to as
any anchor, except that **`mkdir` at the top makes a new anchor** (an
empty directory) and names it with a mount point. So does `mkdir`
anywhere that [[Rules]] say to detach what's made.

## Mount points

A symlink to an anchor, `/anchors/<anchor>`, is shown as the anchor
itself (see [[Anchors and Names#Mount points]]), so the root's names are
directories, and tools that won't follow symlinks, such as Obsidian,
see the anchors' contents. `ln -s ~/soup/anchors/<anchor> name` makes
one anywhere writable.

- **Writes** under a mount point go to its anchor; the directory holding
  the mount point doesn't change.
- **Renaming** a mount point renames the link. Moving a file across one
  is between anchors, so `rename` fails with `EXDEV` and `mv` copies.
- **`rmdir`** of a mount point removes the link, whatever the anchor
  holds, as an unmount; the anchor is as it was. `rm -r` removes the
  anchor's contents first, as it would any directory's.
- **Loops**: a mount point whose anchor is above it is shown as the
  symlink.
- `mkdir` must answer with a directory and `symlink` with a symlink, so
  each answers as asked; the kernel sees what's there on its next lookup,
  within a second.

## Inodes

The kernel lets a directory have only one parent, so a directory
reached two ways is two inodes: an anchor at `anchors/<anchor>` and at
each of its mount points, or one directory block at two paths under
`cid/`. A file's block is one inode wherever it's reached, like a hard
link.

## Reading

- Listing a directory fetches no files: sizes come from the directory's
  link `Tsize`s. They're advisory, as a stat's size is.
- A read fetches only the chunks its range covers.
- What isn't here is asked of the running node, which fetches just those
  blocks from members, all of a read's or a listing's at once. So is what
  committing an overlay or merging a fork needs: what's found missing
  inside the commit's transaction is fetched once it's over (the node
  writing it would wait on it), and the commit tried again at once, a
  level of the tree each time.

## Writing: overlays

Writing to an anchor turns it into an **overlay mount**:

- A file opened to write is made in the anchor's work directory
  (`work/<anchor>/` in the repo), at its full size but sparse, and
  **copied as it's used**: the 1 MiB chunks a read or write touches
  first, the rest in the background. A chunk is marked copied before
  anything is written into it, so an interrupted mount resumes cleanly. A
  big file, even one only on another node, can be written immediately.
- What's created goes into the work directory. What the anchor had and no
  longer shows (removed, or renamed away) is recorded as **marks** on its
  paths: gone, or a block already in the soup. Renaming something big
  copies nothing.
- When it's due (see [[#Committing]]), the overlay is imported: the work
  directory in place like any mount, rebuilding only the directories
  over what changed, exactly as the importer builds them. The anchor's
  new value is what `hk add` of the tree as it now is would make (hidden
  files included), and one burst, like an editor's save, is one set.
- Before a work file that's been committed is written to, truncated,
  replaced, moved or removed, the blocks it was imported as in place are
  **moved out**, to be blocks of their own. So every value the anchor has
  had stays whole, while what it is now is stored once, in the work
  directory: history costs only what changed.
- What's moved out goes to the [[Storage#Deltas|delta store]], whole,
  and the version of the same path before it, part by part at the same
  offsets, is made a **delta** on it, as git keeps history: the newest
  version written over is whole, each older one only what it differs
  by. The anchor's history says which version came before; the deltas
  are found by the committer's thread, not the one writing.
- An anchor can be a single file. Editors save by writing a file beside
  it and renaming that over it, so `anchors/` accepts loose files, which
  become the anchor when renamed over it.
- Unmounting commits what's left; mounting again commits what an
  interrupted mount didn't.

## Threads

The filesystem takes eight requests at once, so one that's fetching a
block or waiting for the database doesn't hold up the rest. Anything that
changes something still happens one at a time, and only what reads goes
on beside it. So:

- A file open to read stays what it was when it's replaced, whether or
  not anything of it had reached the work directory.
- A file saved by renaming over it is always there, and always one whole
  version: rename replaces what's there, never removing it first, and the
  inode that was there is told from the one that's there now, so nothing
  read through the old one goes in the page cache among what it held.
- A file opened to write is known to be partial before it's made, so it's
  never read full of holes.
- A file open follows its path: renamed, or with a directory over it
  renamed, it's still what's filled, kept and committed where it now is.
  Replaced or removed, it's at no path and of no anchor, as any unlinked
  file, though whoever has it open can still read all of it, copied as
  it's read, and needn't sync it for the anchor to be committed.
- A commit takes the same lock from seeing nothing's changed until what
  it's committed is known to be in place, without waiting for it, as a
  change could be waiting for the commit's own transaction. If something's
  underway, the commit gives way and tries again. Otherwise that change
  could replace what was being committed with no copy kept.

The kernel takes a directory's lock for a create or rename, so while one
of those waits for the database, new lookups in that directory wait too.
Files already open, and other directories, don't.

`scripts/mount-stress.sh` checks all this through a real mount.

## Committing

An anchor written to is committed when what's written is **whole**,
**quiet** and **paced**:

- **Whole**: no file of it is open and written to since it was last
  synced. A closed file is whole, and an application `fsync`s once what
  it's written is consistent, as a database does after each transaction,
  so a database left open is committed too. Renaming and removing are
  atomic and don't count; a journal's removal doesn't hold a commit back.
- **Quiet**: nothing's been written for 1 s, so a burst is one set; or,
  if it's never quiet, it's been written to for the longer of 5 s and
  its pace.
- **Paced**: its pace has passed since it was last committed.

The pace starts at nothing and steps through 5 s, 30 s, 2 min and 10
min. A commit that comes within twice the pace plus 2 s of the last, or
because the anchor was never quiet, steps it slower; one more than ten
times the pace plus a minute after the last steps it faster. So notes
saved now and then are committed at once, and a database written
continuously settles at every 10 min. The mount says when an anchor's
pace changes.

A file is never committed halfway through being written: if the anchor
is written to while it's being imported, nothing is set, and it's
committed once it's whole again.

## In step with what's set elsewhere

An anchor's work directory says what the anchor was when it was committed,
and it would hide whatever's set elsewhere since, or undo it on the next
commit. So each overlay keeps its **base** in `overlay_bases`: the value its
work directory and marks were last in step with, and the sets saying so. An
overlay from before bases is taken to be over the last set this device signed.

When the anchor's value isn't its base, within about a second, and before
anything's changed in it, so an edit is measured from what the mount showed,
unless a file of it is open to write or not yet committed:

1. What's in the work directory is imported over the **base**. If that's
   changed anything, it's set, replacing the base's sets alone. So it forks
   what's been set since, and [[Anchors and Names#Forks and merges|merging]]
   settles it, a conflict side by side if the same file changed, with the base
   as the common ancestor.
2. The blocks imported in place are moved out, so every version stays whole.
3. The work directory is renamed aside and removed, and its marks forgotten.
4. The base is what the anchor is now.

Each step can start over if the mount ends part way. So the mount shows what
the anchor is, as every other node does. An anchor set by another device while
a file's open to write shows once it's closed.

A commit does the first of those too, whenever the anchor has moved on from its
base, so it never replaces what it didn't see.

Source: `src/mount.rs`, `src/mount/write.rs`, `src/store/overlay.rs`, `src/store.rs` (`preserve_in_place`).
