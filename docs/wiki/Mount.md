# Mount

Back to [Data Soup](Data_Soup.md).

`hk mount <dir>` shows the soup as a filesystem over FUSE (pure Rust, via
`fusermount3`), until interrupted. `--read-only` makes anchors read-only
too.

```
<name>/…            what the account's root anchor names
cid/<cid>/…         whatever is at a CID; looked up by name, never listed
anchors/<anchor>/…  what each anchor is now, writable
tags/<tag>/<cid>/…  what's tagged so
```

UnixFS directories are directories, files files, symlinks symlinks; a
block of any other codec reads as its bytes. Another account's blocks are
as good as absent. Anchors and tags are looked up again every second, so
the mount follows them.

## The top

The top is the account's root anchor (see
[Anchors and names](Anchors_and_Names.md)), beside `cid`, `anchors` and
`tags`, which hide any root entries of the same name. It's written to as
any anchor, except that **`mkdir` at the top makes a new anchor** (an
empty directory) and names it with a symlink to `/anchors/<anchor>`.
Since FUSE requires `mkdir` to answer with a directory, it answers with
the new anchor's; the kernel sees the symlink on its next lookup.

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
- Once nothing of an anchor is open to write and it has been quiet for a
  second, the overlay is imported: the work directory in place like any
  mount, rebuilding only the directories over what changed, exactly as
  the importer builds them. The anchor's new value is what `hk add` of
  the tree as it now is would make (hidden files included), and one
  burst, like an editor's save, is one set.
- An anchor can be a single file. Editors save by writing a file beside
  it and renaming that over it, so `anchors/` accepts loose files, which
  become the anchor when renamed over it.
- Unmounting commits what's left; mounting again commits what an
  interrupted mount didn't.

Concurrent edits of one anchor from two nodes aren't merged yet: the
later set wins.
