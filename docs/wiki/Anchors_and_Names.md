# Anchors and names

Back to [Data Soup](Data_Soup.md).

## Anchors

An **anchor** is a stable identity whose value changes, like a Perkeep
permanode or a git ref. It's a dag-cbor identity CID of

```
{"anchor": <16 random bytes>}
```

so it's named without being stored anywhere, and anyone can tell it's
an anchor from the CID alone. Its value is whatever its latest counting
`set` claim says (by `at`, then CID bytes); every earlier set is its
history. `hk anchor new`, `hk anchor set <anchor> <cid>`,
`hk anchor show <anchor>`.

A `keep` of an anchor keeps its current value; what a set replaces is
collected after the grace period unless something else keeps it.

Anchors carry everything mutable:

- **Files imported in place** (`hk add --nocopy`): the path is mounted on
  an anchor. The mount (path and import settings) is known only to the
  node with the file and never enters the soup. A running node watches it
  (inotify on its directory, a sample each tick, and a sweep at start),
  imports it again when it changes, and moves the anchor.
- **Overlay mounts**: anchors written through `hk mount` (see [Mount](Mount.md)).
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

The root's value is an ordinary UnixFS directory. Its entries can be
anything, but a directory made at the top of the mount is a **new
anchor**, which the root names with a UnixFS symlink:

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

### Symlink convention

A UnixFS symlink whose target is `/anchors/<anchor>` or
`/anchors/<anchor>/<path>`, where `<anchor>` parses as an anchor CID,
refers to that anchor. Inside `hk mount` it's shown as an absolute path
under wherever the soup is mounted, so it resolves however deep it sits.
A symlink made in the mount to a path under the mount's `anchors/`, or
through one of the root's anchor names (`~/soup/wiki/page.md`), is
stored in this form, so links survive mounting elsewhere. Other targets
are stored as given.

### Meshes

Making a mesh (`found_user`) sets the new user's root anchor to whatever
the repo's device root was, so nothing named is lost. A repo *joining* a
mesh doesn't, since it may not have the mesh's root yet, and setting it
would overwrite the other devices' names. What it named before stays
reachable at its old root anchor under `anchors/`. Merging the two is
future work, alongside merging concurrent edits.
