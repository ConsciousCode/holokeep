**Partly a design.** Snapshots exist (see [[#Snapshots]]), and so do
sealed anchors, read-only: published, kept current, held by friends,
and read from a CAR or at a holder's door by anyone with the capability,
through the anchors mounted in them (see [[#Publishing, as it is now]],
[[#Doors]] and [[#Mount points]]). The rest of this page isn't implemented
yet. It's the plan for
the last part of sharing across the boundary (see [[Sharing#Across the
boundary]]), written down to be argued with before it's built.

A **capability** is a short string that lets whoever holds it read an
anchor, and perhaps write it, from ciphertext anyone may hold. No
member enforces it: holding the keys is the permission, and judging
what counts needs nothing but the anchor's own key. [[Grants]] stay the
mechanism inside the mesh, where members enforce them on plaintext, and
[[Mesh#Visitors|visitors]] the way in through such a member.
Capabilities are for when there's no such member: a friend's protected
mesh holding the ciphertext, a CAR file, a public gateway.

The scheme is a cryptree, after
[Cryptree](https://doi.org/10.1109/SRDS.2006.15) (Grolimund et al.,
2006) and [Peergos](https://book.peergos.org/security/cryptree.html):
a key opens what's under it and nothing above. Peergos gets its
indirection from a map of random labels to blocks, per writer, so that
a parent names a child by label rather than by CID. Holokeep already
has that indirection in its [[Anchors and Names#Mount points|mount
points]], which name an anchor rather than a value, so it draws the
boundary there: every anchor is sealed separately, and a parent names a
sealed anchor and its key. Inside an anchor the sealed tree is an
ordinary Merkle DAG, with keys derived down it.

## Sealed anchors

A plaintext anchor is published as a **sealed anchor**: a new anchor,
owned by a key of its own, in whose view the sealed value is set.

```
owner seed   = derive(secret, "owner", anchor nonce)     an ed25519 seed: the key K
sealed nonce = derive(secret, "nonce", anchor nonce)[0..16]
sealed view  = identity CID of dag-cbor {"anchor": sealed nonce, "of": K}
```

- `derive(k, label, data) = HMAC-SHA256(k, label || 0x00 || data)`, as
  [[Protected Meshes#Vaults|vaults]] derive.
- `secret` is derived from the account's vault secret,
  `derive(vault secret, "capabilities", "")`, so it's kept and recovered
  with it (see [[Protected Meshes#Recovery from the passphrase]]).
- `K` is unrelated to the user's key and to every other anchor's, so a
  holder can't tell whose a sealed anchor is, or that two are the same
  person's.
- **K is the root of trust for the sealed view, alone.** A set counts
  in it if `K` signed it, or a key `K` gave `/anchor/write` by
  [[Grants#Grants on anchors|grants]] signed by `K`, judged as grants on
  anchors are with `K` in the owner's place. Nothing about any mesh
  comes into it: any machine holding the claims can judge which sets
  count. See [[#Judging a sealed view]].
- `K` signs grants, as a user's key does, and little else. Each of the
  owner's machines that publishes has a **writer** key of its own,
  derived from the secret, the anchor nonce and its device key, which
  `K` grants `/anchor/write` once. Each writer's signs are then one
  chain, as [[Keys and Users#Signatures|sign chains]] expect.

## Keys down the tree

A sealed anchor has a 32-byte **read key**, random. Every node of its
tree has a **node key**, derived from its parent's, and the root's from
the read key:

```
root key             = derive(read key, "root", "")
child key, by name:  derive(k_parent, "name", entry name)
child key, by CID:   derive(k_parent, "cid", child plaintext CID bytes)
```

- **A directory entry** derives by name. An edit deep in the tree
  changes the CIDs on the path above it but not their names, so every
  subtree beside the path keeps its keys and its ciphertext. Only the
  path is sealed again, as only the path is written again in plaintext.
- **An unnamed link** derives by CID: a file's chunks and the nodes
  between them, and anything linked to by a block that isn't a UnixFS
  directory. A file is shared whole or not at all.
- **A sharded directory** (a HAMT) keys its shards by CID and its
  entries by name, both from the directory's own key, not the shard's:
  an entry's name is its link's name less the shard's index prefix (2
  hex digits at fanout 256). So an entry keeps its key, and its
  ciphertext, however the HAMT's shards are reshaped around it.
- **An identity CID** isn't sealed: it's in its parent already, and
  stays as it is in `links`.
- **A mount point** doesn't derive: its key is stored in the parent's
  sealed node (see [[#Mount points]]).
- **An entry kept from an earlier read key** doesn't derive either: its
  key is stored in the parent's sealed node (see [[#Revoking]]).

A block is sealed under its node key as a vault block is, in the same
layout (see [[Protected Meshes#Encrypted block format]]), with the node
key in place of the vault secret:

| Label | Use |
|---|---|
| `"key"`, plaintext CID | the XChaCha20-Poly1305 key |
| `"nonce"`, plaintext CID | the first 24 bytes are the nonce |
| `"bat"`, plaintext CID | the block access token |

Sealing is deterministic: the same plaintext at the same place under
the same read key is the same ciphertext, on any machine, every time.
That's what lets machines that never coordinate, and forks that later
merge, converge on the same sealed blocks (see [[#Writing]]).

No key commitment is needed beside the AEAD: a reader always knows the
plaintext CID it expects from the parent before deriving a block's key,
and checks the plaintext against it.

## Sealed nodes

What's encrypted in each sealed block is a dag-cbor map, padded:

| Key | Type | Meaning |
|---|---|---|
| `block` | bytes | The plaintext block, whole. Its CID is checked on unsealing. |
| `links` | `[Link]` | The ciphertext CID of each of the block's links, in the order the block names them. |
| `keys` | `{string: bytes}` | Node keys for entries that don't derive theirs, kept from an earlier read key (omitted if none). |
| `mounts` | `{string: Mount}` | The sealed anchor each mount point among the entries names (omitted if none). |

`links` can't be worked out from `block`: a child's ciphertext CID is
the hash of its sealed bytes, which needs its plaintext, which the
reader has only once it has fetched the child by that CID. Carrying
them keeps the sealed tree an ordinary Merkle DAG, which holders can
check, keep, collect and serve as any other blocks, with no index of
labels as Peergos has.

A file's chunks are sealed nodes too, with only `block`. The plaintext
block is unchanged UnixFS (or whatever it was), so what's unsealed is
exactly the plaintext DAG, CID for CID: sealing is a projection of the
plaintext, not a format of its own.

### Padding

The encoded map is followed by zero bytes up to the next size class:

```
size classes: 256 B, 512 B, 1 KiB, 2 KiB, 4 KiB, then each multiple of 4 KiB
```

No length is stored: dag-cbor delimits itself, so unsealing decodes one
item and requires that everything after it is zero, so each plaintext
has exactly one padded form. Padding is part of the format, as it
changes every ciphertext's size and so its CID: the size class is a
function of the length alone, the same on every machine.

## Mount points

Implemented, but for revoking. A plaintext mount point is a symlink to
`/anchors/<anchor>`, sealed like any block. The parent's `mounts` table
says, for its entry, which sealed anchor it is and how to read it:

| Key | Type | Meaning |
|---|---|---|
| `view` | Link | The sealed view of the anchor mounted. |
| `read` | bytes | Its current read key. |

A HAMT's mount points are in the `mounts` of the shard whose entry each
is, by the entry's name less the index prefix. Entries whose names
aren't UTF-8 aren't sealed as mount points.

- **Sealing.** Publishing seals each mount point as the sealed anchor
  its anchor is published as, `Published::of(secret, anchor)`, so its
  view and read key are derived as any published anchor's. An entry is
  looked at only if its link's `Tsize` is at most 256 bytes, or unsaid,
  and it's dag-pb: a symlink whose target is `/anchors/` and an anchor's
  CID, not a view's. A snapshot (`hk cap export`) seals mount points as
  the symlinks they are, with no `mounts`.
- **Publishing.** Publishing an anchor publishes each anchor a mount
  point names in what's sealed anew, and so on down, each once, loops
  and all; one that's nothing yet isn't. Each is published on its own,
  with its own manifest and capability, listed by `hk cap ls`, and kept
  current by the node as any is. Only what's sealed anew is looked at,
  so a mount point in a directory unchanged since the last head isn't
  published again by publishing what mounts it; it was when it was
  first sealed. Unpublishing one leaves what mounts it naming it: its
  readers read its last head while that's held.
- **Reading.** A reader of the parent reads each mounted anchor too,
  from the same CAR or door, at its own latest head, each sealed view
  once, and remembers each head read (see [[#Remembered heads]]). A
  mounted anchor that can't be read, or is behind, is said so, and the
  rest is read: only the anchor the capability names must be. `hk cap import` prints `mount <path>\t<plaintext root>` for each read, the path
  `/`-separated from the root of the capability's anchor. A capability
  on the mounted anchor reads it and nothing above.

**Sharing a folder makes it an anchor**: `hk cap publish <path>` of a
folder that's neither an anchor nor a mount point makes it one first,
as `hk fs anchor` does (see [[Mount#From outside: `hk fs`]]): the
folder's content becomes a new anchor's value, and the folder a mount
point to it, in one set of the anchor whose folder it was. That's
visible in the owner's tree, but the [[Mount|mount]] shows a mount point
as the directory it was.

A reader learns the plaintext anchor a mount point names, as the
symlink's target, though not whose it is.

Revoking a mounted anchor's readers changes its read key, which
changes the parent's `mounts` entry, so the parent's path to the root
is sealed again. Nothing else is. That comes with revoking (phase 5).

## Heads

The sealed anchor's value at any time is a set in the sealed view, made
by a writer, whose value is a sealed **head block**, in the vault
block layout, keyed by the plaintext set it carries:

```
head key   = derive(read key, "head", inner set CID bytes)
head nonce = derive(read key, "head nonce", inner set CID bytes)[0..24]
```

| Key | Type | Meaning |
|---|---|---|
| `root` | Link | The ciphertext of the anchor's value. |
| `set` | bytes | The plaintext set of the anchor for the owner's view, with that value, its `wrote` and `prev`. |
| `sign` | bytes | Its writer's sign of it. |
| `past` | bytes | The read key before this one, so a reader holding the current one can read the anchor's history (omitted for the first). |

- The sealed set carries no `wrote`, which would say names; the inner
  set does.
- The head block is padded as a sealed node is.
- A machine of the owner's that can unseal a head counts the inner set
  in the owner's plaintext view, as a set by the writer, which the
  owner has let write as a [[Mesh#Visitors|visitor]]. So what's set by
  a write capability reaches the plaintext.
- A machine hosting the owner keeps each sealed anchor current. When the
  plaintext anchor's value changes, it seals the path to each change,
  makes a head, and pushes the ciphertext, with a manifest, to wherever
  the anchor is published, as a vault pushes (see [[Protected Meshes#Manifests]]). Manifests are incremental: each lists what's new
  and links the one before by `next`.

## Capability strings

A capability is dag-cbor in multibase, base32, as a ticket is (see
[[Mesh#Joining]]), starting `hkcap`:

| Key | Type | Meaning |
|---|---|---|
| `view` | Link | The sealed view, which names `K`. Omitted for a snapshot. |
| `root` | Link | A fixed sealed root: a snapshot, with no heads. Omitted otherwise. |
| `plain` | Link | A snapshot's plaintext root, which its root block's key and nonce are derived with. Omitted otherwise, as a head says it. |
| `read` | bytes | The read key. |
| `writer` | bytes | An ed25519 seed `K` has given `/anchor/write`, for a capability that writes (omitted for one that reads). |
| `at` | `[Multiaddr]` | Where some holders of the ciphertext listen (omitted if found otherwise). |

Each write capability has a writer of its own, so each has a sign chain
of its own, and taking one's write away leaves the others'.

## Snapshots

Implemented. A snapshot is a DAG sealed under a fresh random read key,
with no heads, and a capability of `root`, `plain` and `read`:

- `hk cap export <cid> <car>` seals the DAG, fetching what isn't here
  through the node first, writes its sealed blocks to a CARv1 whose root
  is the sealed root, and prints the capability.
- `hk cap import <capability> <car>` unseals every block from the CAR,
  checking each against its plaintext CID and each sealed node's
  padding, puts them in the repo, and prints the plaintext root.

A snapshot can be read at a door too (`--from`), as any sealed blocks
can (see [[#Doors]]). It seals no `mounts` (see [[#Mount points]]), and
`keys` are followed but never written, until revoking makes them.

A test vector: the file `hello, sealed world` (a raw leaf) in a
directory as `hello.txt`, `bafybeig3b3oi7lruke4xl5rd6b5qsi6bmug2x6ltoqhf276doiiirzvcq4`,
sealed under a read key of 32 bytes `0x42`, is two blocks, the file's
`bafkreic2niwyy4jblogxyxnaov4iyrw625y7r6ai6zv3bhlsh2wovsrpxe` and the
directory's, the sealed root,
`bafkreifhyh75rbh3ekfa64angthj2xfmlkd7yesd2vepbtbcemxrac5scy`.

## Publishing, as it is now

Implemented, as the first parts of phase 2:

- `hk cap publish <anchor> [-o <car>]` takes an anchor, or a path of the
  soup that's one or a mount point of one (see `hk fs` on [[Mount]]). It
  seals what's changed of what the anchor is since it was last
  published, makes a head block, and sets the sealed anchor to it,
  signed by `K`. With `-o`, it writes everything published of it, every
  head, to a CARv1 whose root is the latest set. It prints the
  capability, `{read, view}`, the same each time.
- `hk cap unpublish <anchor>` stops: the vault lets go of what's
  published, which is collected in time wherever it's held, and whoever
  has the capability reads the last head till then.
- `hk cap ls` lists the anchors published, each with its capability.
- `hk cap import <capability> [<car>]` reads a sealed anchor's latest
  head from what a CAR holds, or at a holder's door (`--from`, or the
  doors the capability names), unseals its tree into the repo, and prints
  the plaintext root. `hk cap publish --at <multiaddr>` names doors in the
  capability it prints.
- The running node publishes each published anchor again, every 10 s,
  if its value's changed.

### Sealing what's changed

Sealing again walks the new tree beside the last head's, which the
owner can open: in each place, a block whose plaintext CID and key are
the same as before is the same ciphertext, so isn't read or sealed
again, and where a directory's changed, the one before it is opened to
find, by entry name (or a HAMT's shard by its index), what's the same
below. So only the paths to what's changed are sealed, as only they are
written again in plaintext.

### Manifests

What's published is the vault's account's, as what it protects is (see
[[Protected Meshes#Vaults]]). Each publish puts a **manifest**, a
dag-cbor map, which the vault keeps in place of the one before:

| Key | Type | Meaning |
|---|---|---|
| `manifest` | string | `"holokeep-cap-1"` |
| `view` | Link | The sealed view it's of. |
| `blocks` | `[Link]` | What this publish made: the sealed blocks new since the last, the head block, the set and its sign. |
| `parts` | `[Link]` | Further manifests naming the rest, past 1024 (omitted if none). |
| `next` | Link | The manifest before (omitted for the first). |
| `sealed` | bytes | Which plaintext anchor it's of, `{anchor}` in dag-cbor, sealed under `derive(secret, "manifest", "")` as a head block is. |

Every link is plain, so whatever holds the vault keeps all of it, every
head, from one keep, reading nothing. Which anchors the node publishes
again is read from the vault's keeps, unsealing `sealed`, so nothing's
kept about them in the clear.

So a friend's protected mesh holding the vault (see [[Protected
Meshes#Holding for a friend]]) holds what's published as it holds
anything the vault keeps: the node of the user's protected mesh, acting
for the vault, copies it there, and the friend's node keeps it for the
vault's keep. What a holder has is enough to read from: the sets of the
sealed anchor and their signs, by what links to the sealed anchor, and
the rest by CID. Only the user's own node publishes; a protected mesh's,
acting for the vault, doesn't.

### How it differs from the rest of this page, for now

- The read key is derived, `derive(secret, "read", anchor nonce)`, until
  read keys change (see [[#Revoking]]).
- Each of the owner's machines writes with a **writer key** of its own,
  an ed25519 key from the seed `derive(secret, "writer", anchor nonce ||
  device key CID bytes)`, the device key being the catalog's signer (none,
  if it has none). Before its first head, `K` gives it `/anchor/write` on
  the sealed anchor (see [[#Writers' grants]]). A head's set names as
  `prev` every head of the sealed view there is. Publishing what's
  already the one latest head's value sets nothing new.
- A head block is padded and sealed under `derive(read key, "head", "")`
  alone: the 43-byte header with a BAT `derive(head key, "bat", "")`, the
  same for every head, so a reader can prove it knows it before it has
  one, then a 24-byte nonce `derive(head key, "nonce", padded)[0..24]`,
  then XChaCha20-Poly1305 under `derive(head key, "key", "")`, with the
  header as associated data. So the same head seals the same way. It's a
  dag-cbor map:

  | Key | Type | Meaning |
  |---|---|---|
  | `plain` | Link | The plaintext root, which the root block's key and nonce are derived with. |
  | `root` | Link | The sealed root. |
  | `sets` | `[Link]` | The plaintext anchor's sets it's of, by CID, sorted: its heads where it was published (omitted if none). |
  | `set`, `sign` | bytes | For a head a capability's writer made, the plaintext set it carries and its sign (not yet made). |

  `past` comes with revoking.
- A reader judges the sealed view in itself, not by the catalog's views,
  which a repo with no users would let anything count in: a set of the
  sealed anchor, for no other view, signed by `K`, or by a key `K` let
  write and hasn't taken that from (see [[#Writers' grants]]), and which
  no other such set names as `prev`, is a head, and the latest of them
  by `at`, then CID, is read.
- A reader remembers the head it last read of each sealed view (see
  [[#Remembered heads]]), so a holder offering an older head as the
  latest is noticed. It reads from one door at a time, trying the next
  if one fails or is behind.

### Writers' grants

A sealed view's grants are judged as a mesh's are (see [[Grants]]), on
their own: `K` founds a mesh of one, and every other key is a visitor
of it, holding what `K`'s grants on the sealed anchor say.

- The first grant is `{target: [K], add: ["/"], prev: []}`, the same for
  every `K`, so a reader makes it itself; it's held, with `K`'s sign,
  but needn't be sent. A writer's grant gives `/anchor/write` on the
  sealed anchor, after the grants before it, signed by `K`.
- A set counts if `K` signed it, or a key holding `/anchor/write` then,
  or if it's among, or before, the sets a grant taking a writer's write
  away says stand.
- A head's grants go with it: in the manifest, and in what a door
  answers for heads, as claims about the sealed anchor. A catalog
  finds grants by the anchor they're on, not by reference: a hashed
  block's link to an identity CID isn't indexed.
- In a mesh's own grants, those after another first grant, as a sealed
  view's are, are another history, not waiting for anything of the
  mesh's.
- A head read before is taken to count as it did, whatever grants are
  offered with it now (see [[#Remembered heads]]).

### Remembered heads

`hk cap import` keeps the head it read of a sealed view in the reader's
repo, at `heads/<uid>/<sealed view>`: a dag-cbor list of two byte
strings, the set and the sign by `K` that signs it, written aside and
renamed, once everything read is in the repo. It's the reader's alone,
neither shared nor signed.

The next read judges the remembered head with the heads offered, as
one more: a newer head names it as `prev`, or is later, and replaces
it. If it's still the latest and wasn't offered, what's offered is
behind, whether out of date or withholding, and the read fails, "its
latest head is older than one read before", so the next door is tried.
A reader with nothing remembered reads whatever's latest of what's
offered.

## Doors

Implemented. A holder may open a **door** (`hk node run --door [<addr>]`, port 4013 by default): a libp2p swarm of its own, apart from
the mesh's, over TCP with noise and yamux and no private network, as
the node's key, which lets anyone in, to ask `/holokeep/cap/1.0.0` and
nothing else. Whoever's let in there never reaches the mesh's swarm. It
reads the repo through a catalog of its own, on a thread of its own, so
it answers for whatever's held, a friend's vault too.

The name is only that it's where outsiders come in. It isn't a
Solaris door, a call into a server through a path, which the README
suggests as a way to think of servers mounted on anchors.

Requests are serde CBOR:

| Request | Answer |
|---|---|
| `{Heads: {view: CID bytes, at: uint, proof: bytes}}` | The sets of the sealed view's anchor, their signs, and the head blocks they set it to. |
| `{Blocks: {wanted: [[CID bytes, proof]], at: uint}}` | Each block whose proof holds, to about 4 MiB; the rest are asked again. |

The answer is `{blocks: [[CID bytes, data]]}`, nothing for what isn't
proved or held. A proof is that of [[Protected Meshes#Block access
tokens]], over the CID asked for (the sealed view, for heads), the
asker's peer ID, and `at`, which must be within 300 s of the door's
clock:

- **Heads** are given to whoever proves the heads' token,
  `derive(head key, "bat", "")`, checked against the token in a head
  block held: so only to whoever has the read key.
- **Blocks** are given to whoever proves each one's token, checked
  against the token it carries. A reader derives a sealed node's,
  `derive(node key, "bat", plaintext CID)`, as it unseals its parent,
  and asks for each level's blocks at once, 64 to a request. A plaintext
  block carries no token, so is never given.

A reader checks every block it's given against its CID, and judges the
heads as it would from anywhere (see [[#Publishing, as it is now]]).

## Judging a sealed view

Inside a mesh, a view is judged against the mesh's grants: its owner
must be a user, so the mesh's genesis is where all judgement starts,
and a key the mesh never named owns no view (see [[Mesh#Visitors]]).
A sealed view is judged on its own:

- Its grants are those on its anchor signed by `K`, and by whoever `K`
  gave `/anchor/grant`, judged as grants on anchors are, with `K` as
  owner. Every key counts as itself: there's no mesh, so no user to
  have been.
- A set counts if `K` or a key holding `/anchor/write` signed it, and
  its writer's write hadn't been taken away where the set stands, as
  today (see [[Grants#Taking write away]]).

This holds only for views whose owner key a capability names, or which
the owner published: a key with no standing doesn't get a namespace on
a machine by signing things. Which sealed anchors a machine holds at
all is a question of durability, not judgement.

## Reading

A holder of a capability fetches heads for the sealed view from
holders, judges which count, unseals the latest, and walks down,
deriving each node's key from its parent's and its name or CID, and
checking each plaintext against its CID. To ask a holder for a block,
it proves it knows the block's access token (see [[Protected Meshes#Block access tokens]]).

Block access tokens are the holders' policy, not a secret: every holder
and every past reader knows them. They stop an honest holder from
serving ciphertext in bulk to anyone who only knows its CIDs, for
offline attack, and let a friend's machine serve readers without asking
the owner's mesh anything. Holders check them only at the door where
non-members fetch.

Holders can withhold, serving an old head as the latest, or none, but
can't forge one. A reader remembers the head it last read and refuses
an answer older than it (see [[#Remembered heads]]); one asking several
holders at once, and taking the latest any offers, isn't implemented
yet.

## Writing

A write capability's holder writes as any writer of an anchor does: it
sets the plaintext anchor's value, seals the path to each change under
the current read key, and makes a head whose `prev` names the heads it
read. Several writers fork, as plaintext anchors do; nothing is
refused. Holders can't merge sealed heads, so they show the latest, as
an anchor whose heads aren't all directories does (see [[Anchors and Names#Forks and merges]]).

Merging takes the read key, not write: any reader can unseal every head
and their common ancestor and show the merge, without publishing it. A
writer that reads several heads merges them so, and its next head is
the merge with its own edits in it, in one set whose `prev` names every
head it read: never the merge and the edit as two. Two writers merging
the same heads with no edits of their own make the same tree and the
same sealed blocks, each in a set of its own; with edits, they fork
again, and the next writer merges that. Forks converge rather than
accumulate.

Writing takes reading: a writer unseals to merge, and seals under the
current read key. A write needs `prev`, so a blind write can't be a
head; something that only appends events, unread, is a different thing
from an anchor (see [[#Open questions]]).

What's lost, beside a single authority as Peergos has in each user's
home server:

- Atomic commits across anchors. A move between two is an add, then a
  remove, as `mv` across a mount point is (`EXDEV`): a crash between
  them leaves the same blocks in both places, never in neither. A move
  within one anchor is one set, so atomic.
- Writes taken away take effect wherever the grant has arrived, not at
  once. A set a revoked writer made before then stops counting
  wherever the grant reaches, as `stands` says, and a holder keeping
  the grant back can stretch that out.
- Expiry of write runs on each judging machine's clock, and a writer
  says its own `at`, so an expired write is best followed by taking it
  away. An expiry on read means nothing without a new read key.
- If `K` itself leaks, nothing above it can take it back: the owner
  publishes a new sealed anchor, with a new `K`, and hands out new
  capabilities.

## Revoking

A capability can't be taken back, only made useless for what's new:
whoever held the keys can read whatever they fetched.

- **Write.** `K` signs a grant taking `/anchor/write` from the
  capability's writer, naming what of its stands. No key changes: a
  writer never held `K`.
- **Read.** The owner picks a new read key and puts the old one in the
  next head's `past`. What's written afterwards is sealed under the new
  key. Entries unchanged since keep their ciphertext, their node keys
  stored in their parent's `keys`, as they no longer derive. Remaining
  readers get the new key in a sealed box to their key: what a grant of
  `/anchor/read` to a key on a sealed anchor comes to.
- **Everything, at once.** Sealing every entry again under the new key,
  and forgetting the old ciphertext (`hk anchor forget`), is explicit,
  as letting go of the past always is (see [[Replication and Retention]]).
- **The anchor itself.** A revoked reader still knows the sealed view,
  so can watch when heads are made and how big. Cutting that off is a
  new sealed anchor, with a new `K`.

Two machines changing the read key at once make sibling heads, each
with its own; the head merging them names one, and the other in `past`.

## What holders learn

|                                                                 | Holokeep                      | Peergos                          |
| --------------------------------------------------------------- | ----------------------------- | -------------------------------- |
| Block sizes, how many, when they change                         | Yes, to a size class          | Yes, to a size class             |
| How blocks link                                                 | No                            | No, but its label map is public  |
| Who owns a tree                                                 | No                            | Its owner proofs are public      |
| When heads are made, how many writers, the shape of their forks | Yes: sets are in the clear    | No: one signer, compare-and-swap |
| Which writer made each head                                     | A writer's key, not who it is | No                               |
| The grants on the anchor                                        | Yes                           | No                               |
| Which blocks were pushed together                               | Yes, by manifest              | Partly                           |
| That a path went back to earlier content                        | Yes: sealing is deterministic | No                               |

## Phases

In order, each of use alone:

1. **Snapshots.** Done: the sealer, on the vault's block format, with
   sealed nodes, derived keys and padding, and a capability on a fixed
   root with no heads, exported to and read from a CAR. Test vectors.
2. **Sealed anchors, read-only.** Done: owner keys, heads, judging by `K`, sealing what's changed,
   manifests the vault keeps, kept current by the node, held by friends'
   protected meshes, read from a CAR or at a holder's door, and readers
   remembering heads.
3. **Mount points.** Done: sealed `mounts`, publishing what's mounted,
   reading through mount points, making a folder an anchor to share it,
   and capabilities on mounted anchors.
4. **Writing.** Begun: the owner's machines write with writer keys `K`
   lets write, judged by `K`'s grants alone. To come: write capabilities, counting their inner sets through
   the visitor rule, merging on unsealing, and taking write away.
5. **Revoking read.** New read keys, `keys` and `past`, sealed boxes for
   read grants, and sealing everything again when asked.
6. **The vault as a capability**: a sealed root anchor only its owner
   can read, if one scheme for both is wanted.

## Open questions

- **Moves across anchors.** Anchors cut the soup into pieces each with
  its own history, so a move across them is an add and a remove, not
  one event. A compromise, not yet built: the add's inner set says
  where it moved from, and the remove's where to, inside the sealed
  inner set, so holders don't learn that two sealed anchors are
  related. A reader of only one side still sees that it moved; naming
  the other side's plaintext set, not its sealed one, gives them nothing
  to look up, where a sealed set's CID would lead to its sealed view and
  the times and sizes of its heads. Sequencing a file's many moves needn't rest on `at`: an add
  naming, by CID, the set of the source anchor it read is after it by
  construction, so a file's moves chain causally, as a Merkle clock
  does. The cost is a reference from one anchor's history into
  another's: whether it keeps that history (see
  [[Replication and Retention]]), and what it says to whoever can read
  only one side. Something deeper, one history across anchors with no
  cut between them, is a goal, not a design.
- **Blind writes.** Something that only appends, unable to read, such
  as an event or telemetry: not a head, which needs `prev`. Claims are
  already written without reading what they're about, judged where
  they're gathered, so perhaps an anchor's server or door gathers them
  into its heads, recording what it was given as it goes. That needs a
  transport to whoever can read, which holders aren't.

- Head lookups prove the read key, so a reader whose read key's been
  changed can't watch new heads through a door, but one who kept the old
  read key can still be told the old heads.
- Witnesses: holders countersigning when they received a set, so a
  write's time is something other than its writer's word.
- Coarsening `at` in sealed sets, to say less of when the owner works.
- Whether `past` should chain back to the first read key, or a new
  reader see history only from when they were let in.

Source: `src/cap.rs`, `src/vault.rs`, `src/dagcbor.rs`, `src/net/door.rs`, `src/net/node.rs` (`keep_published`), `src/main.rs`.
