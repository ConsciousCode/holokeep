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
  blocks from members, all of a read's or a listing's at once.

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
- An anchor can be a single file. Editors save by writing a file beside
  it and renaming that over it, so `anchors/` accepts loose files, which
  become the anchor when renamed over it.
- Unmounting commits what's left; mounting again commits what an
  interrupted mount didn't.

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

Concurrent edits of one anchor from two nodes aren't merged yet: the
later set wins.

Source: `src/mount.rs`, `src/mount/write.rs`, `src/store/overlay.rs`, `src/store.rs` (`preserve_in_place`).
