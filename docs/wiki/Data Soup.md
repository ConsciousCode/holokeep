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

- [[Blocks and CIDs]]: what is stored and how it's named.
- [[Importing]]: files and directories into UnixFS, identical to Kubo.
- [[Storage]]: the catalog, volumes, forms, and how a block is kept.
- [[Claims]]: sidecar blocks that say things about other blocks.
- [[Anchors and Names]]: mutable identities, the root anchor, `~/soup`.
- [[Keys and Users]]: devices, users, signatures, sealing, accounts.
- [[Mesh]]: joining, transport, and every wire protocol.
- [[Replication and Retention]]: copies, risks, trimming, garbage collection.
- [[Protected Meshes]]: vaults, encryption, recovery.
- [[Grants]]: who may do what in a mesh, as a history of claims.
- [[Sharing]]: users sharing machines and data (partly planned).
- [[Mount]]: the FUSE filesystem and writing through it.
- [[Rules]]: `.souprules`, what's made through the mount becomes.
- [[Git]]: git objects as `git-raw` blocks, and importing repositories.
- [[Style Guide]]: how these pages are written.

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
| form | How a volume breaks a block down: rows, JSONB, raw bytes, file ranges, deltas. |
| delta | A block kept as copies from another block's bytes and bytes of its own. |
| catalog | A node's index over its volumes. |
| node | One machine running holokeep, named by its ed25519 key (= libp2p peer ID). |
| device | A node's key, certified by a user. |
| user | A root key, sealed with a passphrase, that certifies devices. |
| account | A user a repo serves, by uid: one of the host's users, or a user with no login there. |
| mesh | Machines serving one or more users, each user's blocks only on machines hosting them (private), or a vault's holders (protected). |
| vault | An account's internal account for what it encrypts for friends to hold. |
| machine | A mesh member, named by `node.key`; trusted by every user of the mesh. In a mesh with grants, one given `/mesh/machine`. Planned to be distinct from devices, see [[Sharing]]. |
| grant | A claim giving or taking away commands in a mesh, after the grants before it; see [[Grants]]. |
| command | What a grant gives, as a path from `/`: `/mesh/user`, `/mesh/machine`, `/mesh/grant`. |
| operator | A user holding `/mesh`; the **founder**, whose first grant names the mesh, holds `/`. |
| client | A device acting for its user through a member machine, not a member itself (planned; local clients exist). |
| role | A set of privileges granted to users and other roles, as in SQL (planned). |
| grant | A claim giving a user or role a privilege on an anchor or the mesh (planned). |
| keep | A claim saying to keep a DAG; what nothing keeps is collected. |
| tomb | A claim retracting other claims. |
| mount point | A symlink to an anchor, which the mount shows as the anchor. |
| rules file | A `.souprules` file, saying what's made below it becomes. |
| git-raw | The codec of git objects as blocks, named by git's SHA-1. |

## Invariants

- A block is named by the hash of its bytes, and nothing else.
- Blocks never change. Mutability is claims (sets on anchors).
- Whatever goes in comes back out byte for byte, however it's stored.
- Standard CIDs and IPLD throughout: a file gets the same CID as in Kubo.
- Nothing is collected except by the retention rules.
