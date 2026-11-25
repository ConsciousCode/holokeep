A **claim** is a small dag-cbor block that says something about other
blocks, its *targets*: that they're tagged, kept, what an anchor is now,
who vouches for them. Claims are how anything mutable or relational is
expressed while every block stays immutable.

## Encoding

A claim is a canonical dag-cbor map with its type inline under the key
`claim`. `target` is a **set**, written as an array sorted by CID bytes
with no duplicates, so equal claims are equal blocks whoever makes them.
A claim with any other key, unsorted targets, or non-canonical encoding
is not a claim; it's stored as ordinary data.

| Type     | Fields (besides `claim`, `target`)                                                                        | Meaning                                                                                                                                                                                                                                                                                                                                                                                 |
| -------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `group`  | `into: Link`                                                                                              | The targets belong to `into`. With a raw identity CID for `into`, a simple tag named by its bytes.                                                                                                                                                                                                                                                                                      |
| `keep`   | `beyond: [Link]` (omitted if empty), `n: int` (omitted if 0), `copies: int` (omitted for the mesh's own)  | Keep the targets and what they link to, stopping at `beyond`. `n` is which time they're kept, since a tomb is forever. `copies`, at least 1, is how many failures it should take to lose what this is the nearest keep of (see [[Replication and Retention#Durability]]).                                                                                                               |
| `set`    | `value: Link`, `at: int`, `prev: [Link]` (omitted by older builds), `wrote: [bytes]` (omitted when empty), `for: Link` (omitted for the signer's own view) | The targets (anchors) are `value` as of `at`, seconds since the epoch, in place of the sets `prev` (an empty list for none). `wrote` lists paths under `value` (names joined by `/`, sorted and distinct) it wrote though they hold what they did, as when a conflict's resolved to its latest version. `for` is the user whose view of the anchors it's for, where it counts if they've let its signer write it (see [[Grants#Grants on anchors]]). See [[Anchors and Names#Forks and merges]] and [[Anchors and Names#Conflicts]]. |
| `tomb`   | none                                                                                                      | Retract the target claims.                                                                                                                                                                                                                                                                                                                                                              |
| `sign`   | `by: Link`, `at: int`, `prev: Link` (omitted for the first), `sig: bytes`                                 | `by` vouches for the target claims. See [[Keys and Users]].                                                                                                                                                                                                                                                                                                                             |
| `device` | none                                                                                                      | The target keys act for whoever signs this: a certificate when a user's root key signs it.                                                                                                                                                                                                                                                                                              |
| `lost`   | `at: int`                                                                                                 | The targets couldn't be found as of `at`, seconds since the epoch. See [[Replication and Retention#Lost blocks]].                                                                                                                                                                                                                                                                       |
| `grant`  | `on: Link` (omitted for the mesh), `add: [string]`, `del: [string]` (each omitted if empty), `stands: [Link]` (omitted if empty), `prev: [Link]`, `until: int` (omitted for good) | The targets hold the commands `add`, till `until` if it says, and no longer `del`, after the grants `prev`. Never dissolved. See [[Grants]]. |
| `same`   | `as: string` (omitted for each codec's data model)                                                        | The targets, two or more, are the same, read through the lens `as`. Never dissolved. See [[#Same]]. |

Examples, in dag-json for readability:

```json
{"claim": "group", "into": {"/": "bafkqablnovzwsyy"}, "target": [{"/": "bafkrei…"}]}   (tagged "music")
{"claim": "set", "at": 1793750400, "target": [{"/": "bafyqag…"}], "value": {"/": "bafybei…"}}
{"claim": "keep", "target": [{"/": "bafybei…"}]}
{"claim": "keep", "copies": 1, "target": [{"/": "bafyqag…"}]}   (made again easily: one copy)
{"at": 1793750400, "claim": "lost", "target": [{"/": "bafkrei…"}]}
{"as": "unixfs", "claim": "same", "target": [{"/": "bafkrei…"}, {"/": "bafybei…"}]}   (a file and its whole multihash)
```

A node of an older build doesn't know `copies`, so it takes such a keep
for ordinary data, not a keep; likewise `lost`, `grant`, and a set with
`for`, and `same`.

Not yet implemented, but planned: `attr` (attributes, with `prev`
history), `derive` (structure derived from the targets).

## Dissolved and precipitated

Claims are meant to be numerous and tiny, often smaller than a hash.
So:

- A claim **dissolves** if it has exactly one target and encodes to at
  most 128 bytes. Its CID is then a dag-cbor *identity* CID: the CID is
  the claim. Anyone can name it without hashing, and a store keeps it as
  rows with no multihash, found by what it says.
- Anything else is **precipitated**: an ordinary sha2-256 dag-cbor block.
- A `sign` never dissolves, and nor does a `keep` with a `beyond`.

A single-target tag named `music` is 80 bytes, and its tomb, which
contains the whole claim, is 109. Tags dissolve with names up to about
70 bytes; their tombs up to about 24.

## Semantics

- **Retraction is whole.** A tomb can't remove one target of a claim of
  fifty. So claims are made one relationship at a time, and a
  multi-target claim is a batch, equivalent to the single claims it
  unions. Retracting one relationship from a batch is a tomb for the
  batch plus single claims for the rest.
- **Tags union.** Claims with the same `into` combine their targets.
- **Sets replace what they name.** An anchor is what its heads say, the
  counting sets no other replaces, merged if there's more than one (see
  [[Anchors and Names#Forks and merges]]). Every set stays, so the
  history is free.
- **A tomb deletes the dissolved claims it targets at once** and keeps
  them from being put again. A precipitated claim it targets stays a
  block until collected, but stops counting.
- **What counts.** Once a repo has a user, a claim only counts when a key
  the user authorized signs it, and a tomb only retracts when it counts.
  Unsigned claims, or those signed by strangers, are kept as data but say
  nothing.
- **Claims travel with their claims.** A claim is sent along with its
  signatures and tombs, and theirs, however deep.

## Same

A CID's codec says how to decode a block, not what it means: a UnixFS
file's root decodes as a dag-pb node, and the file is what the UnixFS ADL
reads from it and the blocks under it. So a `same` claim names how its
targets are read, its **lens**, and says they read the same through it:

| Lens | Reads | So these are the same |
|---|---|---|
| none (`data` to `hk same`) | Each codec's data model: a raw block as its bytes | One value in dag-cbor and dag-json; a raw block and a dag-cbor byte string of its bytes; one block by two hash functions |
| `unixfs` | What the UnixFS ADL does: a file's contents, a raw block as a file of its bytes, a directory's entries (each name's CID), a symlink's target | A file however it's chunked or laid out, and its whole multihash, by any hash function; a directory basic or a HAMT |

- **Checkable.** `hk same add` checks before it says so, reading each
  target through the lens; what isn't here is fetched. A raw target
  beside others is checked by its multihash against what they read as,
  so it needn't be here: a kept file's whole multihash is no block anyone
  can get. Past 64 MiB that's only by sha2-256.
- **An equivalence.** It's symmetric and transitive, so claims of one
  lens join: `hk same ls` lists whatever's the same as a block, or as
  what is, and so on. Lenses don't mix: the same file isn't the same
  dag-pb node. Membership is by CID, not multihash, as one multihash is
  different things to different codecs.
- **A set, and nothing else.** Which member to prefer depends on what
  for (matching Kubo, streaming, what's near), so it's said elsewhere, by
  the node's policy or facts about members, and claims still merge by
  union alone.
- **What isn't `same`.** Similarity isn't transitive: a lossy copy of a
  lossy copy drifts. Renditions of one work (a JPEG of a PNG, a scaled
  copy, a translation) are a `group` of the work, said explicitly.
- **Kept files say so.** A file [[Storage#Placement|kept whole]] is
  said to be the same, through `unixfs`, as the root it was imported
  as, by its whole CID (raw, sha2-256): how DASL and ATproto name a
  blob, and a common denominator any layout can be checked against. A
  repo opening with files kept before says so of each, once, in one
  sign. The repo's own record of which roots a kept file is
  (`shard_roots`) stands apart, so its ranges never hang on a claim.
- **A whole CID reads through a layout.** A raw CID that isn't a block
  here, as a kept file's whole one isn't, is read through a layout a
  `unixfs` claim that counts says it's the same as, one whose root is
  here if any is, else fetched from members as blocks, each checked
  against its own CID: by `hk cat`, `hk get`, and the mount's
  `cid/<cid>`. `hk cat` and `hk get` hash what they write and fail if
  it isn't the whole CID, `get` taking the file away; a read of part of
  it, as the mount's, can't be checked against a whole hash, so takes
  the claim at its signer's word. What's fetched, and must be this
  account's to read, is the layout: knowing a whole CID isn't reading
  it. Members don't yet answer for a whole CID, but have its claims, as
  structure, wherever they hold its root. A lens is a name for now; one not
  known is kept, and says nothing this can check. A lens could later be
  an ADL's code by CID, as WASM.

```
hk same add --as unixfs <cid> <cid>…   # check, then say so
hk same ls <cid>                       # lens and CID of what's the same
hk same rm --as unixfs <a> <b>         # tomb the claims saying both
```

## Backreferences

Every claim is a backreference of what it targets: "which claims are
about this block?" is one lookup. Claims are stored as rows (`claims`,
with targets in one shared `claim_targets` table), and a tag is a row,
not a file. The `tags (target, tag, name)` SQL view names simple tags.

Source: `src/claim.rs`, `src/store/claims.rs`.
