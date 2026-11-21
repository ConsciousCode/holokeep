**Partly a design.** Snapshots exist (see [[#Snapshots]]), and so does
publishing a sealed anchor and reading its latest head from a CAR (see
[[#Publishing, as it is now]]). The rest of this page isn't implemented
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

A plaintext mount point is a symlink to `/anchors/<anchor>`, sealed
like any block. The parent's `mounts` table says, for its entry, which
sealed anchor it is and how to read it:

| Key | Type | Meaning |
|---|---|---|
| `view` | Link | The sealed view of the anchor mounted. |
| `read` | bytes | Its current read key. |

So a reader of the parent reads the mounted anchor too, at its own
latest head, and a capability on the mounted anchor reads it and
nothing above. **Sharing a folder makes it an anchor**: the folder's
content becomes a new anchor's value, and the folder a mount point to
it. That's visible in the owner's tree, but the [[Mount|mount]] shows a
mount point as the directory it was.

Revoking a mounted anchor's readers changes its read key, which
changes the parent's `mounts` entry, so the parent's path to the root
is sealed again. Nothing else is.

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

Reading from a holder rather than a CAR waits for a way in for
non-members (see [[#Reading]]). Sealed nodes with `mounts` are refused,
and `keys` are followed but never written, until the phases that make
them.

A test vector: the file `hello, sealed world` (a raw leaf) in a
directory as `hello.txt`, `bafybeig3b3oi7lruke4xl5rd6b5qsi6bmug2x6ltoqhf276doiiirzvcq4`,
sealed under a read key of 32 bytes `0x42`, is two blocks, the file's
`bafkreic2niwyy4jblogxyxnaov4iyrw625y7r6ai6zv3bhlsh2wovsrpxe` and the
directory's, the sealed root,
`bafkreifhyh75rbh3ekfa64angthj2xfmlkd7yesd2vepbtbcemxrac5scy`.

## Publishing, as it is now

Implemented, as the first part of phase 2:

- `hk cap publish <anchor> <car>` takes an anchor, or a path of the soup
  that's one or a mount point of one (see `hk fs` on [[Mount]]). It seals what the anchor is now under the sealed anchor's read
  key, makes a head block, and sets the sealed anchor to it, signed by
  `K`, in the repo. It writes the sealed tree, the head block, the set
  and its sign to a CARv1 whose root is the set, and prints the
  capability, `{read, view}`, which is the same each time.
- `hk cap import <capability> <car>` reads a sealed anchor's latest head
  from what the CAR holds, unseals its tree into the repo, and prints the
  plaintext root.

How it differs from the rest of this page, for now:

- The read key is derived, `derive(secret, "read", anchor nonce)`, until
  read keys change (see [[#Revoking]]).
- `K` signs heads itself, from the one machine whose vault secret it's
  derived from, rather than through writer keys it grants
  `/anchor/write`. Writers come with writing (phase 4). Its sets follow
  one another: each names as `prev` the set its last sign signed.
  Publishing what's already the latest head sets nothing new.
- A head block is `{plain, root}`, the plaintext root, which the root
  block's key and nonce are derived with, and the sealed root, padded
  and sealed under `derive(read key, "head", "")` alone: the 43-byte
  header with a BAT `derive(head key, "bat", padded)`, then a 24-byte
  nonce `derive(head key, "nonce", padded)[0..24]`, then
  XChaCha20-Poly1305 under `derive(head key, "key", "")`, with the header
  as associated data. So the same head seals the same way. `set`,
  `sign` and `past` come with writing and revoking.
- A reader judges the sealed view in itself, not by the catalog's views,
  which a repo with no users would let anything count in: a set of the
  sealed anchor, for no other view, whose sign by `K` verifies, and
  which no other such set names as `prev`, is a head, and the latest of
  them by `at`, then CID, is read.
- It's all written to a CAR, the whole tree each time. Keeping a sealed
  anchor current, pushing it to holders, and reading from them are the
  rest of phase 2.

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
can't forge one. A reader remembers the heads it has seen, refuses an
answer that's neither a descendant of them nor a sibling it can see,
and asks more than one holder.

## Writing

A write capability's holder writes as any writer of an anchor does: it
sets the plaintext anchor's value, seals the path to each change under
the current read key, and makes a head whose `prev` names the heads it
read. Several writers fork, as plaintext anchors do; nothing is
refused. Holders can't merge sealed heads, so they show the latest, as
an anchor whose heads aren't all directories does (see [[Anchors and Names#Forks and merges]]). A writer that reads several heads unseals
them and their common ancestor, merges the plaintext as any anchor's
heads merge, and seals the result when it next writes. Two writers
sealing the same plaintext make the same blocks.

What's lost, beside a single authority as Peergos has in each user's
home server:

- Atomic commits across anchors. A move between two is an add and a
  remove.
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
  as letting go of the past always is (see [[Replication and
  Retention]]).
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
2. **Sealed anchors, read-only.** Begun: owner keys, heads, judging by
   `K`, published to and read from a CAR. To come: keeping a sealed
   anchor current, publishing to a protected mesh with incremental
   manifests, holders answering for heads and checking proofs at the
   door, and readers remembering heads. Writer keys, and judging the
   grants that give them write, come with writing.
3. **Mount points.** Sealed `mounts`, making a folder an anchor to share
   it, and capabilities on mounted anchors.
4. **Writing.** Write capabilities, counting their inner sets through
   the visitor rule, merging on unsealing, and taking write away.
5. **Revoking read.** New read keys, `keys` and `past`, sealed boxes for
   read grants, and sealing everything again when asked.
6. **The vault as a capability**: a sealed root anchor only its owner
   can read, if one scheme for both is wanted.

## Open questions

- How a holder knows who may ask it for heads: a head-lookup token, from
  the read key, would keep a revoked reader from watching, but holders
  would need to check it without the key.
- Witnesses: holders countersigning when they received a set, so a
  write's time is something other than its writer's word.
- Coarsening `at` in sealed sets, to say less of when the owner works.
- Whether `past` should chain back to the first read key, or a new
  reader see history only from when they were let in.

Source: `src/cap.rs`, `src/vault.rs`, `src/dagcbor.rs`, `src/main.rs`.
