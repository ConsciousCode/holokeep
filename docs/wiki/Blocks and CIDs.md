## Blocks and multihashes

A block is a finite byte string. Its identity is a **multihash**: a hash
function code, a digest length, and the digest, each length-prefixed by
an unsigned varint (multiformats). Holokeep treats each hash function as
collision-free over everything it stores, so the multihash is the
primary key everywhere.

- Supported functions: SHA-1, SHA-2 (256, 512), SHA-3, BLAKE2b-256,
  murmur3, and `identity` (code `0x00`), where the digest *is* the data.
- Digests are capped at **128 bytes**, IPIP-0512's limit for identity
  multihashes. No real hash function comes close.
- The same bytes under two hash functions are two distinct logical
  objects. Equivalence is a claim (`same`, not yet implemented).

## CIDs

A CID adds a version and a codec to a multihash. The codec says how to
read the bytes; it is *not* part of the block's identity. Stores key by
multihash, and the CID prefixes a block has been seen under are indexed
beside it.

- **CIDv0**: a bare sha2-256 multihash, base58btc (`Qm…`), always dag-pb.
- **CIDv1**: `varint(1) varint(codec) multihash`, usually base32 lower
  with the `b` multibase prefix (`bafy…`).
- A CID's version survives round trips: a link written as v0 stays v0.
- Varints in CIDs and multihashes must be minimal and at most 9 bytes
  (values below 2^63). Protobuf varints in dag-pb are LEB128, read
  leniently, up to 64 bits.

Codecs used:

| Codec | Code | Used for |
|---|---|---|
| raw | `0x55` | File leaves, encrypted blocks, simple tag names. |
| dag-pb | `0x70` | UnixFS files and directories. |
| dag-cbor | `0x71` | Claims, sealed keys, manifests, anchors. |
| dag-json | `0x0129` | Accepted and stored; not produced. |
| libp2p-key | `0x72` | Keys: identity multihash of the protobuf public key. |

## Identity CIDs

An identity CID holds its block inside itself. Holokeep uses them where
the content is tiny and naming it shouldn't need a hash:

- **Simple tags**: a raw identity CID of the tag's UTF-8 name, the same
  CID `ipfs add --inline --raw-leaves` makes of the name.
- **Anchors**: a dag-cbor identity CID of `{"anchor": <16 bytes>}`.
- **Dissolved claims**: a claim of one target that encodes to 128 bytes
  or less (see [[Claims]]).
- **Keys**: a libp2p-key identity CID of the protobuf ed25519 public key
  (`08 01 12 20` then 32 bytes), so a node's key and its peer ID are one.

## Codecs

Every codec goes through one IPLD data model: null, bool, integer
(i128, so dag-cbor's full −2^64 … 2^64−1 range fits), float, string,
bytes, list, map, link. Decoding is strict: duplicate keys, NaN,
indefinite lengths and malformed CIDs are errors. Valid but
non-canonical input (unsorted keys, padded integers, short floats,
whitespace) decodes and is *reported* as non-canonical, because
specialized stores admit only canonical blocks (see [[Storage]]).
Nesting is limited to 256 levels.

- **dag-cbor**: canonical per the IPLD spec: map keys sorted by length then
  bytewise, minimal integers, 64-bit floats, links as tag 42 with a
  leading `0x00`.
- **dag-json**: per spec where implementations disagree. Integral floats
  keep `.0`, big integers stay integers, and only `{"/": string}` and
  `{"/": {"bytes": string}}` are reserved.
- **dag-pb**: its own strict codec for PBNode/PBLink, with UnixFS on top.

All three pass every fixture in `ipld/codec-fixtures`, and dag-cbor and
dag-json are differentially fuzzed against `serde_ipld_dagcbor` and
`serde_ipld_dagjson`.

## CAR files

`hk dag export` writes CARv1, byte-identical to `ipfs dag export`:
depth-first, each block the first time it's reached. `hk dag import`
reads CARv1 and CARv2, verifies every block, bounds sections as go-car
does (8 MiB, headers 32 MiB), and ignores a CARv2 index.

`hk dag export --claims` writes that same CAR, then the claims about what's
in it, each a section of its own, so any reader can read it: a precipitated
claim under its hash, a dissolved one under its identity CID, with the claim
as the block. They're sorted by CID bytes. Which claims:

- those targeting a block written, and what's about those, however deep: their
  signatures and tombs. A dissolved claim that's tombed is gone, so its tomb
  goes for it.
- for each signature, the claims about its key: certificates, and theirs. Not
  the signs before it in its chain.
- what this account can see. Not a set whose value is a block written, which
  is its anchor's, nor the other claims a sign shares its signature with,
  though it names them, so a dissolved one can be read there.

An anchor reached, by a link or a mount point, is followed to what it is now,
so the DAG under an account's root anchor is its whole soup, and its claims
include every set: what it was is still said. `--history` follows it to what
it's been too, passing over and counting what's not here. Claims about what's
not here go too, such as that it's been [[Claims|reported lost]].

A plain `hk dag export` says how many claims it left out, on stderr.

`hk dag import` takes claims as it takes any block. Only a claim signed by a
key the repo's user has authorized counts, so a fresh repo, whose device key
is its own user, keeps them only as data until it joins that user. There's no
restoring a user from a CAR: its root key isn't in one.

Source: `src/multihash.rs`, `src/cid/`, `src/dagcbor.rs`, `src/dagjson.rs`, `src/pb.rs`, `src/car.rs`.
