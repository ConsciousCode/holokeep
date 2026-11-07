## Anchors

An **anchor** is a stable identity whose value changes, like a Perkeep
permanode or a git ref. It's a dag-cbor identity CID of

```
{"anchor": <16 random bytes>}
```

so it's named without being stored anywhere, and anyone can tell it's
an anchor from the CID alone. Its value is what its **heads** say (see
[[#Forks and merges]]): usually one, the latest counting `set` claim;
every earlier set is its history. `hk anchor new`,
`hk anchor set <anchor> <cid>`, `hk anchor show <anchor>`.

A `keep` of an anchor keeps everything it's been, until that's forgotten
(`hk anchor forget`; see [[Replication and Retention#Garbage collection]]),
though what it was needn't all be here: only what it is now is fetched
to keep it.

Anchors carry everything mutable:

- **Files imported in place** (`hk add --nocopy`): the path is mounted on
  an anchor. The mount (path and import settings) is known only to the
  node with the file and never enters the soup. A running node watches it
  (inotify on its directory, a sample each tick, and a sweep at start),
  imports it again when it changes, and moves the anchor.
- **Overlay mounts**: anchors written through `hk mount` (see [[Mount]]).
- **Names**: the root anchor, below.

## The root anchor

Each account has a **root anchor**, the top of what it has named and the
top of `hk mount`. It's derived from the key the account acts for (its
user's root key once in a mesh, its device key before):

```
nonce  = sha256("holokeep root anchor\0" || key CID bytes)[0..16]
anchor = identity CID of dag-cbor {"anchor": nonce}
```

So every device of a user finds the same root anchor without any claim
saying which it is. `hk anchor root` prints it and its current value.

The root anchor is **kept**: `hk mount`, starting writable, and making a
user each put a keep of it if there's none that counts. Through it and
its mount points, everything the root names is kept.

The root's value is an ordinary UnixFS directory. Its entries can be
anything, but a directory made at the top of the mount is a **new
anchor**, which the root names with a mount point, a UnixFS symlink:

```
wiki -> /anchors/bafyqagnbmzqw4y3in5zf…
```

A name is bound to an anchor, not to the anchor's value. The root
changes only when a name is added, renamed or removed; each named anchor
keeps its own history. "What was everything like on Tuesday" is answered
by evaluating each anchor's sets as of then, not by one root hash.

### Petnames

Names are local to an account: anchors are global and secure, names are
readable and private. Two users' `wiki`s don't collide. Sharing a named
thing means passing its anchor, which the recipient names however they
like.

### Mount points

A UnixFS symlink whose target is `/anchors/<anchor>` or
`/anchors/<anchor>/<path>`, where `<anchor>` parses as an anchor CID,
refers to that anchor. A symlink to an anchor itself is a **mount
point**: [[Mount|hk mount]] shows it as the anchor, a directory (or file)
of its own wherever it's reached, and what's written under it goes to
that anchor. Outside the mount, as in `hk get`, it's an ordinary
symlink. In the catalog it's a **link** to the anchor, so whatever keeps
or references the mount point does the same for what the anchor is now
(see [[Replication and Retention#Garbage collection]]). A mount point whose anchor is already above it, as an anchor
naming itself or the root, is shown as the symlink instead, so the
mount has no loops.

Any other symlink to an anchor, into it (`/anchors/<anchor>/page.md`),
stays a symlink, shown as an absolute path under wherever the soup is
mounted, so it resolves however deep it sits.

A symlink made in the mount to a path under the mount's `anchors/`, or
through a mount point at the top (`~/soup/wiki/page.md`), is stored in
this form, so links survive mounting elsewhere. Other targets are stored
as given.

### Meshes

Making a mesh (`found_user`) sets the new user's root anchor to whatever
the repo's device root was, so nothing named is lost. A repo *joining* a
mesh (`join_user`) sets the user's root anchor to what it named before
**beside** what it is, with an empty `prev`: a head of its own, which
the other devices' heads merge with, name by name, neither replacing the
other. What it named stays reachable at its old root anchor under
`anchors/` too.

## Forks and merges

A `set` names the sets it replaces as its `prev` (see [[Claims]]); an
empty `prev` replaces none, and a set without one, as older builds
made, replaces every set before it by `at` and then the value's
multihash. An anchor's **heads** are its counting sets no other counting
set replaces. Every set made here names every head it knows as `prev`.

Two devices setting an anchor without seeing each other's set **fork**
it: two heads. Every node computes the same **merge** of the heads from
the same claims, so nothing has to agree on it, and that's what the
anchor is, in the mount and to `hk get`, till it's set again: the next
set, by anyone, names every head, and so says what it is. `hk anchor
show` lists the heads of a forked anchor.

Directories merge three ways, name by name, against the value of the
heads' latest common ancestor (by `prev`, an older build's set coming
after every set before it). With more than one, none coming after another,
as when two devices each go on from the same merge, which no set says, it's
those merged in turn, by these same rules, so what's measured from is what
they saw:

- what changed on one side only is taken, whether changed, added or
  removed;
- what changed the same on every side that changed it is no conflict;
- a directory changed on more than one side is merged in turn;
- anything else changed differently is a **conflict**: the latest
  head's version keeps the name, and each other's is kept beside it as
  `name (conflict <tag>)`, before the extension (`page (conflict
  ab3c2d).md`), the tag being the last six characters of its set's CID;
- a change wins over a removal.

Without a common ancestor, or once its value's been collected, every
name a head has is a change. Anything that isn't every head a directory
is the latest head's value. Merged directories are built as the
importer builds them; each head's value stays referenced while it's a
head.

Source: `src/claim.rs` (`anchor`, `root_anchor`, `Set`), `src/store.rs` (`root_anchor`, `found_user`, `join_user`, `anchor_value`), `src/store/merge.rs`, `src/store/claims.rs` (`anchor_values`), `src/mount.rs`.
