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

| Type | Fields (besides `claim`, `target`) | Meaning |
|---|---|---|
| `group` | `into: Link` | The targets belong to `into`. With a raw identity CID for `into`, a simple tag named by its bytes. |
| `keep` | `beyond: [Link]` (omitted if empty), `n: int` (omitted if 0), `copies: int` (omitted for the mesh's own) | Keep the targets and what they link to, stopping at `beyond`. `n` is which time they're kept, since a tomb is forever. `copies`, at least 1, is how many failures it should take to lose what this is the nearest keep of (see [[Replication and Retention#Durability]]). |
| `set` | `value: Link`, `at: int`, `prev: [Link]` (omitted by older builds) | The targets (anchors) are `value` as of `at`, seconds since the epoch, in place of the sets `prev` (an empty list for none). See [[Anchors and Names#Forks and merges]]. |
| `tomb` | none | Retract the target claims. |
| `sign` | `by: Link`, `at: int`, `prev: Link` (omitted for the first), `sig: bytes` | `by` vouches for the target claims. See [[Keys and Users]]. |
| `device` | none | The target keys act for whoever signs this: a certificate when a user's root key signs it. |
| `lost` | `at: int` | The targets couldn't be found as of `at`, seconds since the epoch. See [[Replication and Retention#Lost blocks]]. |

Examples, in dag-json for readability:

```json
{"claim": "group", "into": {"/": "bafkqablnovzwsyy"}, "target": [{"/": "bafkrei…"}]}   (tagged "music")
{"claim": "set", "at": 1793750400, "target": [{"/": "bafyqag…"}], "value": {"/": "bafybei…"}}
{"claim": "keep", "target": [{"/": "bafybei…"}]}
{"claim": "keep", "copies": 1, "target": [{"/": "bafyqag…"}]}   (made again easily: one copy)
{"at": 1793750400, "claim": "lost", "target": [{"/": "bafkrei…"}]}
```

A node of an older build doesn't know `copies`, so it takes such a keep
for ordinary data, not a keep; likewise `lost`.

Not yet implemented, but planned: `same` (targets are the same bytes
under different hashes), `attr` (attributes, with `prev` history),
`derive` (structure derived from the targets).

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

## Backreferences

Every claim is a backreference of what it targets: "which claims are
about this block?" is one lookup. Claims are stored as rows (`claims`,
with targets in one shared `claim_targets` table), and a tag is a row,
not a file. The `tags (target, tag, name)` SQL view names simple tags.

Source: `src/claim.rs`, `src/store/claims.rs`.
