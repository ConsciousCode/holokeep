**Not yet implemented: a design.** Nothing on this page exists in the
code. It's the plan for the last part of sharing across the boundary
(see [[Sharing#Across the boundary]]), written down to be argued with
before it's built.

A **capability** is a short string that lets whoever holds it read a
view of an anchor, or a folder in it, and perhaps write it, from
ciphertext anyone may hold. No member enforces it. Holding the key is
the permission, and a holder of the ciphertext learns nothing without
it. [[Grants]] stay the mechanism inside the mesh, and
[[Mesh#Visitors|visitors]] the way in through a member that enforces
them. Capabilities are for when there's no such member: a friend's
protected mesh holding the ciphertext, a CAR file, a public gateway.

The scheme is a cryptree, as in
[Cryptree](https://doi.org/10.1109/SRDS.2006.15) (Grolimund et al.,
2006) and [Peergos](https://book.peergos.org/security/cryptree.html):
a folder's key opens what's under it and nothing above. It differs from
Peergos in deriving keys rather than storing them, as
[[Protected Meshes#Vaults|vaults]] do.

## Keys down the tree

Each node of a shared tree has a 32-byte **node key**. The root's is
the view's **read key**, which is random, and every other node's is
derived from its parent's:

```
derive(k, label, data) = HMAC-SHA256(k, label || 0x00 || data)

child key, by name:  derive(k_parent, "name", salt || entry name)
child key, by CID:   derive(k_parent, "cid", child plaintext CID bytes)
```

- **A named link**, a directory entry, derives by name. An edit deep in
  a tree changes the CIDs on the path above it, but not their names, so
  every subtree beside the path keeps its keys, and with them its
  ciphertext. Only the path is encrypted again.
- **An unnamed link** derives by CID: a file's chunks and the nodes
  between them, and a sharded directory's internal shard nodes, keyed
  under the directory's key. A file is shared whole or not at all, so
  nothing below it needs a key of its own.
- **`salt`** is empty unless the parent's sealed link table (below)
  says otherwise for that entry. A new salt gives the subtree below it
  new keys without touching the keys above, which is how one folder's
  capability is revoked (see [[#Revoking]]).

A block is encrypted under its node key as a vault block is, with the
same layout (see [[Protected Meshes#Encrypted block format]]), but with
the node key in place of the vault secret:

| Label | Use |
|---|---|
| `"key"`, plaintext CID | the XChaCha20-Poly1305 key |
| `"nonce"`, plaintext CID | the first 24 bytes are the nonce |
| `"bat"`, plaintext CID | the block access token |

The same block at the same path encrypts the same way every time, so
publishing again is idempotent, and an unchanged subtree is the same
ciphertext in every version. A block reached by two paths is two
ciphertexts, so no one can tell from ciphertext that two shares hold
the same thing.

## Sealed nodes

A plaintext block's links are CIDs of plaintext, which a holder of the
capability needs to turn into the ciphertext to fetch. So the plaintext
sealed in each encrypted block is a dag-cbor map:

| Key | Type | Meaning |
|---|---|---|
| `block` | bytes | The plaintext block, whole. Its CID is checked on decrypting. |
| `links` | `[Link]` | The ciphertext CID of each of the block's links, in the order the block names them. |
| `salts` | `{string: bytes}` | Salts for entries that have one (omitted if none). |

Links are inside the ciphertext, so a holder of the ciphertext alone
sees raw blocks of some sizes, not how they link. It can't tell which
blocks make up which file, or that a tree is a tree.

## Publishing a view

A view is published as a sequence of sealed **heads**, each naming the
ciphertext of the view's value at the time. A head is found by an
anchor anyone holding the capability can work out, and signed by a key
the capability names:

```
signer seed = derive(write key, "signer", "")      an ed25519 seed
read key    = derive(write key, "read", "")
anchor nonce = sha256(signer public key)[0..16]
```

- The **signer** is an ed25519 key of the published view's own, not the
  owner's, so a holder of the capability doesn't learn whose it is. The
  owner grants it `/anchor/write` on the view, as a
  [[Grants|visitor]], so what's set with it counts there too.
- A **head** is a set claim on the anchor whose nonce is above, signed
  by the signer, whose value is a sealed **head block**: a random
  24-byte nonce, then XChaCha20-Poly1305 under `derive(read key, "head",
  "")` of the dag-cbor map below. Readers follow its `root`. A machine
  of the owner's that can decrypt it may count the plaintext set in the
  owner's view, so what a write capability sets reaches it.

| Key | Type | Meaning |
|---|---|---|
| `root` | Link | The ciphertext of the view's value. |
| `set` | bytes | The plaintext set claim for the view, with that value. |
| `sign` | bytes | The signer's sign of it. |

- The owner's machines keep each published view's write key in the
  account, as the vault keeps its secret, and seal it with the vault
  for recovery (see [[Protected Meshes#Recovery from the passphrase]]).
- A machine hosting the owner keeps the published view current. When
  the view's value changes, it encrypts what's new (the path to each
  change), and makes and signs a head. It pushes the ciphertext and
  heads to wherever the view is published, such as one of the owner's
  protected meshes, as a vault's manifests are, so holders keep all of
  it from one keep.

## Capability strings

A capability is dag-cbor in multibase, base32, as a ticket is (see
[[Mesh#Joining]]), starting `hkcap`:

| Key | Type | Meaning |
|---|---|---|
| `signer` | bytes | The signer's public key, to find and check heads. |
| `read` | bytes | The read key, for a capability on the whole view. |
| `path` | `[string]` | Entry names from the root to the folder shared, and the folder's node key in `read` in place of the view's (omitted for the root). |
| `write` | bytes | The write key, for a capability that writes (omitted for one that reads). |
| `at` | `[Multiaddr]` | Where some holders of the ciphertext listen (omitted if it's to be found otherwise). |

A capability on a folder holds that folder's node key and the path to
it. The path is needed to find the folder in each new head, since it
isn't a fixed CID. Its holder can decrypt each head's root as far as
the link table along `path`, but no further. So they learn the names
on the path, and nothing else above the folder. Whether a folder's
capability should hide even those, by keying heads per folder, is open.

A capability that writes holds the write key, so it can make heads.
The owner's machines count its sets as the signer's, as they do a
visitor's, and so any write capability's sets are one writer's. Telling
apart several writers needs a signer each, so a write capability per
writer.

## Reading

A holder of a capability fetches the latest head for its anchor, checks
it's signed by `signer`, decrypts the root, and walks down, deriving
each node's key from its parent's and its name or CID, and checking
each plaintext against its CID. To ask a holder of ciphertext for a
block, it proves it knows the block's access token (see
[[Protected Meshes#Block access tokens]]): this is the first use of
the proofs. A holder serves a block to anyone with a good proof, and
needs to know nothing else.

What holders can do is withhold: serve an old head as the latest, or
none. They can't forge one. A head says its time, and readers take the
latest they've seen, from any holder.

## Revoking

A capability can't be taken back, only made useless for what's new:
whoever held the key can read whatever they fetched, forever.

- **The whole view.** The owner picks a new write key, so new read
  key, signer and anchor, and publishes the view under them,
  encrypting all of it again. Old heads stop. Holders who should keep
  reading get a new capability.
- **One folder.** The owner gives the folder's entry a new salt in its
  parent's link table, which gives the folder and everything under it
  new keys, encrypted again, and publishes a head. A capability on the
  folder no longer derives what's below, while one on the view still
  does. The view's capability holders need nothing new.
- The old ciphertext is dropped once no head reaches it, as anything
  unkept is (see [[Replication and Retention]]).

Handing the remaining holders new capabilities without asking each one
out of band could be a sealed box to each holder's key, kept where
they'd look, as Peergos does with its sharing folders. That's
undecided.

## What a holder of ciphertext learns

How many blocks there are and their sizes, which change when, how
often heads are made, and that blocks in one push are probably related.
Not names, contents, or how blocks link. Padding blocks to a multiple
of some size, as Peergos does, would hide sizes at a cost in space,
and is open.

## Phases

None of this exists yet. In order:

1. **Snapshots.** Encrypted trees under derived keys, sealed nodes, and
   a capability on a fixed root, with no heads, to export (`hk cap
   export <cid>`) and read from a CAR or a holder. Test vectors.
2. **Published views.** Signers, heads, keeping a published view
   current incrementally, publishing to a protected mesh, holders
   answering for heads and enforcing proofs, and reading by capability
   from outside the mesh.
3. **Writing.** Write capabilities, heads from them counted in the
   owner's view through the visitor rules.
4. **Revoking.** Salts, new write keys, and how remaining holders get
   new capabilities.

## Open questions

- Whether a folder's capability should reveal the names on the path to
  it, or heads be keyed per folder.
- How holders answer "the latest head for this anchor", and whether a
  reader should ask several to guard against one withholding.
- Padding, and to what sizes.
- Whether the vault becomes a capability on the root anchor, so one
  scheme does both.
- Whether XChaCha20-Poly1305, which isn't key-committing, needs a
  commitment beside it, as a capability's keys come from someone else.
