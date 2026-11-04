# Data Soup

Data soup is a storage model where data has no location. Every object is
named by a hash of its content, kept on whichever drives and machines
happen to hold it, and organized by relationships (tags, anchors, links)
rather than by where it sits. **Holokeep** is one implementation of it,
written in Rust, with the `hk` command.

This wiki documents how Holokeep works, at the level needed to
reimplement it or interoperate with it. It lives in the soup itself, in
an anchor named `wiki` in its author's root, so editing it is using it.
For the reasoning behind the design, and the roadmap, see the README in
the holokeep repository; this wiki is the reference.

## Pages

- [Blocks and CIDs](Blocks_and_CIDs.md): what is stored and how it's named.
- [Importing](Importing.md): files and directories into UnixFS, identical to Kubo.
- [Storage](Storage.md): the catalog, volumes, forms, and how a block is kept.
- [Claims](Claims.md): sidecar blocks that say things about other blocks.
- [Anchors and names](Anchors_and_Names.md): mutable identities, the root anchor, `~/soup`.
- [Keys and users](Keys_and_Users.md): devices, users, signatures, sealing, accounts.
- [Mesh](Mesh.md): joining, transport, and every wire protocol.
- [Replication and retention](Replication_and_Retention.md): copies, risks, trimming, garbage collection.
- [Protected meshes](Protected_Meshes.md): vaults, encryption, recovery.
- [Mount](Mount.md): the FUSE filesystem and writing through it.

## Vocabulary

| Term | Meaning |
|---|---|
| block | An immutable byte string, named by its multihash. |
| CID | A multihash plus a version and codec: how to read a block's bytes. |
| claim | A small dag-cbor block about other blocks (a tag, a keep, a set, a signature). |
| dissolved | A claim small enough to be its own identity CID, stored as rows with no hash. |
| precipitated | A claim stored as an ordinary sha2-256 block. |
| anchor | A stable identity whose value changes, by `set` claims. |
| root anchor | An account's top-level anchor, the top of `hk mount`. |
| repo | Everything one node keeps: its catalog database and volumes (`~/.holokeep`). |
| volume | A place bytes are kept: a SQLite file, a flatfs directory, a drive. |
| form | How a volume breaks a block down: rows, JSONB, raw bytes, file ranges. |
| catalog | A node's index over its volumes. |
| node | One machine running holokeep, named by its ed25519 key (= libp2p peer ID). |
| device | A node's key, certified by a user. |
| user | A root key, sealed with a passphrase, that certifies devices. |
| account | One of the host's users, by uid, within a repo. |
| mesh | The nodes of one user (private) or a vault's holders (protected). |
| vault | An account's internal account for what it encrypts for friends to hold. |
| keep | A claim saying to keep a DAG; what nothing keeps is collected. |
| tomb | A claim retracting other claims. |

## Invariants

- A block is named by the hash of its bytes, and nothing else.
- Blocks never change. Mutability is claims (sets on anchors).
- Whatever goes in comes back out byte for byte, however it's stored.
- Standard CIDs and IPLD throughout: a file gets the same CID as in Kubo.
- Nothing is collected except by the retention rules.
