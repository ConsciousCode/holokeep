Git objects go into the soup as `git-raw` blocks, one object to a block,
named by git's own SHA-1. A commit, tree or file is then the same thing
in the soup as in git, by the same name, and two clones of a repository
hold the same blocks.

## The codec

A `git-raw` block (codec `0x78`, multihash `sha1`, `0x11`) is a git
object's bytes, uncompressed, header and all:

```
<type> <size>\0<content>
```

where `<type>` is `commit`, `tree`, `blob` or `tag`, and `<size>` is the
content's length in decimal. Its SHA-1 is the object's git name, so the
CID follows from the name alone: the bytes `01 78 11 14` then the SHA-1,
in base32 (`baf4bcf…`). The same block in Kubo (`ipfs block put --cid-codec
git-raw --mhtype sha1`) gets the same CID.

Its links, as go-ipld-git reads them:

| Object | Links |
|---|---|
| blob | none |
| tree | each entry's object, in order, a submodule's commit (mode `160000`) included |
| commit | `tree`, each `parent`, and the `object` of each `mergetag` |
| tag | `object` |

Since every block's links are known, a repository's objects are kept,
fetched, replicated and collected as any DAG is: a keep of a commit
keeps its history.

A submodule's commit is a link to an object in another repository, so
it usually isn't here. Kubo's own decoder (go-ipld-git) reads only
OpenPGP signatures in commits and tags: one signed with SSH fails to
decode there, though its links here are read as any other's.

## Importing

`hk git import [<repository>]` reads every object of a repository (a
working tree, its `.git`, or a bare one): loose objects inflated, and
packs read entry by entry, deltas applied to their bases, whether those
are named by offset or by SHA-1, in the pack or already here. Each object
is checked against its name. It then keeps what each ref names
(`refs/`, `packed-refs` and `HEAD`), one keep per distinct object, and
prints each ref's CID and name. `--no-keep` keeps nothing.

What's linked to but in no object here, as a submodule's commits, is
each keep's `beyond` (see [[Claims#Encoding]]), so the keep doesn't wait on
it.

An object that's a delta in a pack is kept as that delta, in the
[[Storage#Deltas|delta store]], so a packed repository takes about as
much room in the soup as its pack: ripgrep's 6.1 MiB pack, 118 MiB of
objects, is 5.8 MiB of rows. Its blocks are still whole objects to
anything reading them, and are sent whole between nodes.

Not yet: `.git` through [[Mount|hk mount]] as `git-raw` (objects written
there are stored as files, as anything else is); exporting objects back
into a repository; and the `same` claim tying a blob to the UnixFS file
of the same bytes.

Source: `src/git.rs`, `src/git/pack.rs`, `src/main.rs` (`git_import`), `src/store/delta.rs`, `scripts/git-compare.sh`.
