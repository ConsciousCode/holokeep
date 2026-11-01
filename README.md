# Holokeep

Conventional filesystems are incredibly useful. They provide a unified interface for coordinating impossibly heterogeneous data in the form of "files" across multiple systems. However, the cost of this utility is the tyranny of *location*. A file must always "live" somewhere under a rigid ontology communicated by hierarchical directories. Does the album name or the year it was released come first? Where do you put a "School" folder? They must have a unique name even when that name would be meaningless - "Cat.jpg", "Cat (1).jpg", "Cat (1)-backup.jpg", "Cat (1) (1).jpg". Placing a file entails a decision about which drive it exists within, tying its lifetime to the health of the drive itself. There is no formal way to tie a backup to its file, particularly when that file is edited. Given long enough, any filesystem succumbs to entropy and the only choices are to give up or continue pushing the boulder against the gravity of decay.

What if files didn't have a location? They could be pure objects identified by their content found by their intrinsic attributes. They could exist on any of your drives, computers, or even your friends' computers without worry that anything had changed. They could be in multiple locations at once so you don't have to worry about drive failure.

This is **data soup**, a content-addressable storage model where location is not tied to an object's identity or meaning. The name anchors intuition to data as a fluid which flows to fill the shape of its container, its particles roughly fungible at a high level, with larger chunks (files and objects) suspended in it and no identifiable location for anything. Objects are identified by their content and organized through relationships, not paths or hosts. The medium is homeostatic through anti-entropy replication and stochastic garbage collection acting in tension to return to a steady state. Semantics are contextual and relational; applications interpret objects in terms of the local graph of links and descriptors that surround them.

**Holokeep** is a particular implementation of this storage model.

- [Status](#status)
- [Vision](#vision)
- [Principles](#principles)
- [Architecture](#architecture)
  - [Identity](#identity)
  - [Physical: blockstores](#physical-blockstores)
  - [Data model and codecs](#data-model-and-codecs)
  - [Linking: claims](#linking-claims)
  - [Retention](#retention)
  - [Replication and transport](#replication-and-transport)
- [Roadmap](#roadmap)
- [Open questions](#open-questions)
- [Development](#development)

## Status

Holokeep is early. What exists is the content-addressing core, each piece checked against an independent implementation:

- **Import**: `hk add` turns files and directories into UnixFSv1 with CIDs identical to Kubo's `ipfs add` under the `unixfs-v1-2025` profile, including chunked files, nested directories, symlinks and HAMT-sharded directories.
- **CIDs and multihashes**: v0 and v1; SHA-1, SHA-2, SHA-3, BLAKE2b-256 and murmur3 (no identity hash yet).
- **Codecs**: dag-pb, dag-cbor and dag-json, strict and canonical, passing all of [ipld/codec-fixtures](https://github.com/ipld/codec-fixtures) and differential fuzzing against `serde_ipld_dagcbor`/`serde_ipld_dagjson`.
- **Storage and retrieval**: `hk add` stores into a repo where a routing store sorts blocks by structure: UnixFS nodes as rows, dag-cbor and dag-json as queryable JSONB, large blocks and whole files in a flatfs-style sharded directory, file leaves as ranges of whole files kept there (or left in place with `--nocopy`), and everything else as raw bytes. `hk cat`/`hk get` read them back out, checked against the original files.
- **Interchange**: `hk dag export` writes a DAG as a CARv1 byte-for-byte identical to `ipfs dag export`, and `hk dag import` reads CARv1 and CARv2 files, Kubo's included, verifying every block. Legacy CIDv0 DAGs round-trip unchanged.

Nodes can join a private mesh (`hk node`) and fetch blocks from each other, so any file in the repo can be read from any running node, and they keep each other's blocks replicated, counting the risks each copy shares, so a block isn't one disk failure from being lost; see the [roadmap](#roadmap) for what isn't done.

## Vision

- **Short-term**: Treat my data like a tiny data lake without having to know "where" anything is and without ever having to configure replication or redundancy. From any node in the network, all files are accessible even if they don't "live" with that node. I just add 5 computers to my network and they automatically figure out which hard drives get which blobs to maintain a default 3x replication. It needs to be robust to changing network topologies so I can keep my laptop as part of it even as it connects and disconnects. Compare this to other distributed filesystems like Ceph where nodes are expected to be always-on and NFS where data lives in one server.
- **Mid-term**: Imports act as a local cache of external data repositories and applications to eventually support the long-term vision where those applications provide the blocks directly without needing an import step.
- **Long-term**: Re-imagine the internet as one enormous global filesystem that everyone is a part of. Personal files are invisible to everyone unless shared, and there's a shift in applications from storing user data in proprietary servers to storing data within the user's own data sectors with BAT-style permissions. Compare this to DNS/HTTP: DNS decentralizes authority over *names*, data soup decentralizes authority over *state*.

Hardware becomes like a hermit crab's shell: discard the old, move into the new, renovate, and grow into it. Adding a machine to a mesh makes it yours; it receives your identity.

### Use cases

- Personal archive
- Stochastic replication
- Social data sharing
- Distributed application hosting
- General transport via anchor mounts: mount arbitrary RPC servers on anchors to be serviced by nodes, à la 9P. This could let you access a node's local filesystem and facilities through the DAG.

### Prior art

- **[Perkeep](https://perkeep.org/doc/)**: archival object focus, importing, blob server abstractions, permanodes (anchors).
- **[IPFS/IPLD](https://ipld.io/docs/)**: protocols, formats, CIDs, libp2p plumbing.
- **[Nayuki's tag-based file organization](https://www.nayuki.io/page/designing-better-file-organization-around-tags-not-hierarchies)**: backreference indexing, tagging as the core organizational principle, tables as a compact representation of object classes.
- **[Peergos](https://book.peergos.org/)**: BATs for hierarchical access control via semi-trusted nodes.

More reading is collected in [RESEARCH.md](RESEARCH.md).

## Principles

### Invariants

What Holokeep guarantees, whatever the configuration.

- **Identity is content.** A block is named by the hash of its bytes, nothing else. Location, ownership and meaning are never part of identity.
- **Immutability.** Blocks never change; mutability is layered on top through claims.
- **No silent loss.** A block is only collected under the [retention](#retention) rules, never because of where it happens to be stored.
- **Round-trip fidelity.** Whatever bytes go in come back out exactly, however a blockstore chooses to represent them.
- **Ecosystem compatibility.** Holokeep produces and accepts standard CIDs and IPLD blocks; the public IPFS network is a subset of the repository.

### Defaults

What happens unless configured otherwise.

- **Private and user-owned.** Imported blocks are private and never announced publicly unless shared.
- **Replicated.** Objects are stochastically replicated within the private mesh, 3x by default.
- **Scales either way.** Works with however many, or few, nodes you add.
- **Kubo-compatible import.** Files import with Kubo's `unixfs-v1-2025` profile, so the same file gets the same CID in Holokeep and in IPFS.

### Design stances

The opinions which shape the design.

- **Location-free.** Objects "live" in multiple possibly remote locations but can be accessed from anywhere within the mesh without the user knowing where they are.
- **Relational, not hierarchical.** Organization is through tags, attributes and backreferences; hierarchy is available where it's actually wanted.
- **Consume the universe, import everything.** It can take any data you throw at it and sort the mess later.
- **Privacy needs exactly one of permissioned or cryptographic security.** The private tier is permissioned, the protected tier is cryptographic, the public tier is neither.
- **Trust is an optimization.** Trusted peers skip work (verification, encryption) that untrusted ones require.
- **AP, not CP.** A partitioned node is indistinguishable from a dead one, so every mutable structure must be merge-shaped: read-your-writes on the local node, eventual consistency everywhere else, convergence via anti-entropy.
- **Waste no bytes.** Storage is shaped by what blocks *are*: a tag is a row, not a file in a sharded directory.

### Non-goals

Not a blockchain. Not Byzantine-fault-tolerant against malicious mesh members. Not a POSIX filesystem. Not low-latency block storage. No availability guarantee during total partition.

## Architecture

The system is layered:

- **Physical**: Each node has one or more blockstores mapping multihashes to blocks. These are dumb by design and do not track user ownership.
- **Logical**: Nodes track which blocks each user owns in their repository ("repo") and make a best effort to restrict access to the blocks users actually control. Users are coordinated by DID and their documents, authenticated by public key.
- **Linking**: Within a user's repo, indexes track which blocks reference which, the basis of mutable anchoring, tagging and collections. At any given moment these indexes might be incomplete or spread across multiple nodes, but a node tries to aggregate the totality of any given block's indexes within its blockstores.
- **Transport**: Private, protected and public tiers of peer-to-peer replication; see [replication and transport](#replication-and-transport).

### Identity

A block is a finite sequence of bytes. Blocks are addressed by multihashes, where each multihash encodes a choice of hash function and a digest of the block's bytes. For any fixed hash function, the system treats the hash as injective over all blocks it will store so that, operationally, each multihash acts as its primary key and hash collisions are treated as impossible for all practical purposes.

Two multihashes may, by design, refer to the same block (for example, when using different hash functions) and Holokeep makes the opinionated assertion that these constitute distinct logical objects, even if they share physical storage. Equivalence between different multihashes with the same preimage is deferred to the relational layer (`Same` claims).

A CID adds a version and a codec to the multihash: a claim about how to interpret the bytes, not part of their identity. Blockstores key by multihash, as Kubo's does, and the CID prefixes a block has been seen with are indexed alongside it. References are by multihash too, so a link written as CIDv0 and one written as CIDv1 are backreferences to the same block.

Within a database, multihashes are **interned**: one table holds each multihash once, and everything else (placement, CID prefixes, stores' rows, link targets) refers to it by integer id. Knowing a multihash doesn't mean having its block: a link to something not yet fetched still gets an id, so "what's linked but missing" is a plain query.

Design decisions:

- `Multihash<D>` is generic over its digest storage (fixed arrays, inline buffers, boxed slices) rather than the ecosystem's `Multihash<usize>`, and `AnyCid` preserves a CID's version through round trips.
- **Ids are local; multihashes are the interchange format.** An interned id means nothing outside its database, so ids never cross a trait boundary or the network, and each database pays for its own copy of the multihashes it knows. Assuming every store is a local SQLite database that could be attached to the others is what broke the original prototype: repos have to scale to distant stores.
- Digests are capped at 128 bytes, the limit IPIP-0512 sets for identity multihashes; no real hash function comes close.
- Varints follow two specs. Protobuf (dag-pb) varints are LEB128 up to 64 bits, read leniently. Multiformats varints (CIDs, multihashes) must be minimal and at most 9 bytes, so codes and lengths stop at 2^63 - 1; `varint::read_minimal` enforces this, as the ecosystem's `cid` crate does. A CID with a larger code can be constructed but won't decode again; no real codec comes close.

### Physical: blockstores

Following Nayuki's "externalized relational database", where *a file corresponds to a database row and its schema to which table the row belongs in*, blockstores are **specialized**: each may restrict which blocks it accepts and represent them however suits their structure. A generic store accepts arbitrary bytes; a tag store accepts only tag claims and keeps them as literal rows in a table, rather than blobs in a sharded directory with ad-hoc indexing on top.

This is a more granular take on Perkeep's blob servers, leaning into Rust's trait-oriented style. Rather than one blob server interface, capabilities are separate traits, and a store implements whichever it can:

| Trait | Capability |
|---|---|
| `BlockIndex` | Does the store have a block, and enumerate what it has |
| `BlockSource` | Get a block's bytes |
| `BlockStore` | Put a block, optionally saying where its bytes came from |
| `RefIndex` | Which blocks reference a given block (backreferences) |

…and a zoo of extensions to come. A read-only archive is a `BlockSource` and `BlockIndex` without `BlockStore`; an index rebuilt from other stores is a `RefIndex` with no blocks at all.

**Where blocks live is separate from how they're kept.** A *repository* is one logical whole spread over one or more *nodes*, whole computers in the p2p network, each an access point onto all of it with no main one. A node's *catalog* indexes its *volumes*: places bytes are kept (a SQLite file, a flatfs directory, a drive, a cloud bucket). A volume holds one or more logical blockstores, each in a *form*, how it breaks a block down: UnixFS nodes as rows, claims as rows, IPLD as JSONB, raw bytes, file ranges. In LVM terms a volume is a PV, a node's catalog over its volumes the VG, and the repository the LV; forms are filesystem formats. Most of LVM's complexity goes away, since every block is immutable and relocatable: moving one is copying it by multihash and updating placement.

- *Structure in the catalog, bulk in volumes.* Everything but raw leaves (UnixFS nodes, claims, IPLD) is small, and it's what's queried, so the catalog's own database is a volume holding it; other volumes mostly hold leaves and whole files. A node makes a best effort to know every backreference to the blocks it holds, which this makes possible even while the bytes are on a drive that isn't plugged in. One blockstore can be both catalog and volume, as the repo's database is.
- *Volumes are shareable*, unlike most, so each carries a stable random label in itself (a row in its database, a `VOLUME` file in its directory), and any catalog opening it knows it for the same volume. Placement is many-to-many, so a block can be on several volumes, and any readable copy serves it.
- *Blocks are replicated, never rows.* Copying to another volume is a put by multihash, which that volume breaks down into whatever forms it supports (a flatfs directory only raw). No device syncs another's rows, so rows never have to agree across schemas, interning or versions.
- *Catching up without a log.* Writers tell the other nodes what they wrote, the same best-effort path backreferences take; a catalog opening a shared volume only has to notice what it wasn't told. A flatfs directory does that by its shards' mtimes, which change whenever a blob is added or removed: the catalog records each shard's mtime when it lists it, and on opening lists again only those whose mtime is anything else, which catches deletes too. It compares the writer's own timestamps rather than its own clock, so machines whose clocks disagree don't matter, and a shard changed within two seconds of being listed (FAT's mtime granularity) is listed again next time regardless. A SQLite volume keeps a 64-bit generation instead: triggers on each form's table stamp a block's row in `generations` with one more than the latest whenever it arrives or leaves, so whatever writes to the database is stamped, another node or a hand-written `DELETE`. The catalog keeps the latest generation it's seen per volume, and what's changed is `WHERE generation > n`. It's a row per block rather than a log of changes, and a block that leaves keeps its row, marked gone, so readers see it go. Dissolved claims have no multihash, so they're stamped by their rows in `claim_generations`, from the same generations; one leaves only by being tombed, and readers learn that from the tomb, stamped like any other claim. The volume carries `block_cids` for its blocks too, so a catalog catching up can read links even of blocks kept as raw bytes, and it keeps a copy of whatever structure (UnixFS nodes, claims, IPLD) arrives, so it's queried locally, and a tomb takes effect.
- *Durability is counted in shared risks.* Each volume has a set of risks, anything whose failure takes every volume sharing it. Some are found where it's mounted: each physical disk under its filesystem (`disk:`), found through sysfs past partitions, LVM, RAID and encryption, by WWID or serial number, which stay the same wherever a drive is plugged in, with a mirror's disks as one risk since it takes both; the machine (`host:`, by machine id) for disks inside it rather than on USB; and for a filesystem on no disk, its mount source (`nfs4:server:/data`). Device numbers wouldn't do (a USB drive's changes between mounts), and neither they nor filesystem UUIDs know that two filesystems on one disk fail together. The rest can't be found in general, so they're said: `hk volume risk add <name> home` for the house a drive and a laptop are both in, or a person, a cloud account. Every volume also risks itself. A block's safety is how many risks would have to fail to lose every copy, the smallest set touching every copy's risks, so copies sharing a disk or a house count as one against it. `hk volume replicate --copies n` copies each block, each copy wherever adds most, until that's at least `n`, as if it had `n` copies with nothing in common, where attached volumes allow, and reports what's still short. `hk volume copy <name> [cid...]` copies to a volume regardless, the DAGs under the CIDs or everything, to carry blocks to another machine. Claims about what's copied go with it, and the tombs retracting them, so tags go where what they tag does. Dissolved claims aren't blocks, so they've no copies to count: they're tiny, and every database volume a repo replicates to keeps them all.
- *External files are provisional mounts* (planned): a file imported in place is linked under its current hash, and when it changes an anchor moves to the new version, an implicit history, closer to git's refs and commits than to Kubo's filestore. The history is of names, not contents: old versions' bytes are gone unless something copied them, and even the names last only as long as nodes retain the claims recording them. Losing an external file isn't a real loss, since it was always provisional.

**Specialized stores must manifest exact bytes.** A store which keeps blocks as rows rather than bytes has to regenerate each block byte-for-byte, or its CID breaks. So a specialized store admits only blocks whose decoded form re-encodes identically, ie canonical blocks. Anything valid but non-canonical falls through to a generic store, which keeps raw bytes. This is why the codecs report canonicity (`dagcbor::from_slice_canon` and friends) rather than just accepting or rejecting: it's the admission test.

For now admission is checked by round trip: parse, re-encode, compare. That's verification where "parse, don't verify" should hold. Within one executable, a strict parser that only accepts canonical encodings proves the bytes can be rebuilt by construction, and the round trip becomes a debug assertion. Across trust boundaries (other stores, peers) blocks are verified regardless.

Indexes are rebuildable in the sense that *an* index can always be built from the stores, not that every table is disposable as in Perkeep. The interned multihashes are primary data; which store holds each block is derived. If a block turns up missing under one hash function, it may be worth trying the others in common use, though with two or three likely hashes that's probably more caution than it's worth.

Implemented so far (`src/store/`), in the repo's SQLite file and its shards directory:

- **`Db`** owns the interned `multihashes` table every store refers to. Foreign keys stop a multihash from being deleted while anything refers to it, so an id is never reused under a reference.
- **`Catalog`** offers each block to its volumes' stores in a placement order and indexes which took it (`blocks (block, volume, form)`), along with every CID prefix the block was put under (`block_cids`). The standard placement is the database's specialized forms, then the shards for anything large, then the database's raw store. It knows of volumes which aren't attached (`volumes`, by label, with where each was last seen): their blocks are still present and linked to, but reading one fails as `Unattached`. Opening a repo attaches each volume found where it was last seen carrying its label, so an unmounted drive, or something else mounted in its place, stays detached, then catches up with what other nodes wrote to them (`Store::catch_up`). Volumes added to keep copies take any block, since they're for durability rather than placement. It verifies every block against its CID on the way out, can `reindex` placement from the attached volumes, keeping what it knows of the rest, runs an import as one transaction, and is itself a `Store`, so catalogs nest. `hk repo stat` counts blocks by volume and form.
- **`OffsetStore`** keeps blocks as (blob, offset, length) ranges, so a file's contents are stored once, as itself. A blob is a whole file named by its multihash, and that multihash is the range's identity: a block is served from any copy of its blob, whether kept in the repo's shards or found at a path imported in place with `hk add --nocopy`. It admits only raw blocks put with a `Provenance::FileRange`, which the importer attaches to each leaf it reads. A file's multihash isn't known until all of it has been read, so the sink importing it hashes the leaves as they go by, in one pass, and `settle`s the file's pending ranges once it knows. External files are the user's and may change: each is recorded with a fingerprint (size, mtime, inode), which must hold from the start of its import to the end and afterwards for its ranges to be served; when no copy of a blob is readable, reads fail as `Stale` or `Missing` rather than returning the wrong bytes.
- **`ShardStore`** is a volume of its own, in the `flatfs` form. It keeps blobs too large to be worth keeping in SQLite, over 64 KiB at its default 4 KiB pages ([Internal Versus External BLOBs](https://sqlite.org/intern-v-extern-blob.html)), as files in a sharded directory laid out as Kubo's flatfs: named by multihash in base32upper with no multibase prefix, sharded `next-to-last/2`, so a blob's name checks its bytes without the database. It serves two cases: any large block, such as those pieced together from the network, and whole files, which plain `hk add` (`Copying`) writes into a temporary file as their leaves go by, so their leaves become ranges of it and stay contiguous on disk. A file is kept whole once it has more than one leaf and more than 64 KiB; until then its leaves are held back, and a smaller file is copied block by block. `shard_files` caches what's in the directory, just blob and size, so reads needn't touch the filesystem to find a blob; reindexing rebuilds it from the directory. Kept files aren't blocks: `shard_roots` records which UnixFS roots each was imported as, and a kept file none of whose leaves landed in it is let go.
- **`UnixfsStore`** keeps UnixFS nodes as a node row and link rows, admitting only nodes it can manifest exactly: every link named and sized, no mode or mtime, Kubo's field order. A link row is the target's id plus the CID prefix it was written with, and link rows double as a `RefIndex` by multihash. A HAMT shard's link names are split into the bucket and the entry's name, so entries are named the same whether their directory is sharded or not, and the `unixfs_entries` view lists every directory's entries alike, descending through sub-shards: `SELECT directory FROM unixfs_entries WHERE name = CAST('notes.txt' AS BLOB)` finds a file in any directory. Every node `hk add` makes lands here; of the 17 dag-pb blocks in codec-fixtures, the 2 in Kubo's form do.
- **`IpldStore`** keeps dag-cbor and dag-json blocks as SQLite JSONB in dag-json form (links `{"/": "<CID>"}`, bytes `{"/": {"bytes": …}}`), so their contents can be queried in place, eg `WHERE data ->> '$.name' = …`. A block is admitted only if what SQLite hands back manifests it exactly, which excludes non-canonical encodings and the data dag-json can't express (a map whose only key is `/` with a string value). Links are also kept as rows by interned multihash, as a `RefIndex`. All 256 dag-cbor and dag-json blocks in codec-fixtures land here, and fuzzing checks that everything dag-json can express round-trips.
- **`ClaimStore`** keeps claims as rows: a tag is a row, not a blob. It admits `Group`, `Keep` and `Tomb` claims, exactly canonical (`claim::Claim::parse`): the `claim` discriminant, a non-empty `target` set sorted by CID bytes, `into` for a group, nothing else. Every claim is a row in `claims`, with its type in `kind`, and its targets are rows in one `claim_targets` table shared by every type, so "which claims are about this block" is one lookup whatever the type; a type keeps only what's particular to it in a table of its own (`group_claims` for `into`; a tomb has nothing but targets). A dissolved claim is rows with no multihash, found by what it says; a precipitated one is rows under its multihash. Claims with the same `into` combine their targets, so tagging is a union over rows, and the `tags (target, tag, name)` view names simple tags, which are raw identity CIDs of their names: the same CID `ipfs add --inline --raw-leaves` makes of a name. A tomb deletes the dissolved claims it targets at once and keeps them from being put again; a precipitated claim it targets stays a block until it's collected, but stops counting as a tag. Its rows are a `RefIndex`, so a claim is a backref of what it tags and of the tag, and a tomb of what it buries.
- **`RawStore`** takes anything else as bytes.
- **Backreferences** span every store without storing a link twice. A store which keeps its own link rows says so (`Store::refs`); for blocks in any other store, the router reads their links by codec as they're put and keeps them in `refs`, under every codec a block is put with, since that's what says where its links are. The `Catalog`'s `RefIndex` is the union, and the `links (source, target)` view is the same in SQL. Reindexing rebuilds `refs`, reading only blocks with a codec that can link, so offset blocks whose files are gone aren't needed. `hk refs <cid>` lists a block's links as `ipfs refs` does, and `hk refs --back <cid>` every block linking to it, under each CID it was put with.

Remaining representations from the original prototype:


"Small blocks" (inlining small blobs into the database instead of separate files) turned out to be placement order rather than its own kind: the shard store declines anything at or under its threshold, which falls through to the raw store.

The original database sketch, still roughly the plan, with `multihashes` now interning identities for all of them: `blocks` (multihash, storage kind, cached current attribute state), `attrs` (an EAV table for the metadata system, each entry with its own CID from its dag-cbor form, plus a timestamp for ordering), `users` (public keys to identities), `refs` (backreferences), `stores` (connected blockstores) and `locs` (which blocks live in which stores).

Ideas:

- *Routing store* (now the `Catalog`): a composite which dispatches each put to the most specialized store that admits it, falling back to a generic one, and reads through the `blocks` index to whichever store holds a block. Specialized stores then become an optimization you can add or remove, migrating blocks between representations without changing their identity.
- *Offsets are only ever known, never searched for.* The offset store doesn't scan files for blocks; it learns offsets when they're known. On import the importer knows exactly which byte range each leaf came from, which `put(&Block)` can't express, so puts carry a small closed provenance (`Unknown`, or `FileRange { path, offset }`) that other stores ignore. The provenance is trusted, since within one executable the importer has just read those bytes, and the router re-hashes everything it serves regardless. In-place import edges towards the anchor-mounted host filesystem idea in [open questions](#open-questions).
- *Migrating into the offset store* needs no scanning either: a UnixFS file node's blocksizes give every leaf's offset, so given a path claimed to hold that file, check its size, hash each range, and move the leaves that match. It needs a way to remove blocks from the store they're leaving, which no store has yet. Until then, `hk add --nocopy` of something already copied leaves its blocks where they are.
- *Edges of dissolution.* The same claim under an identity CID and a sha2-256 one is two claims, which a tomb for one doesn't retract; `Same` would join them. A tomb interns the multihash of what it targets, which for a dissolved claim is the claim's bytes again; tombs are rare enough not to mind. Dissolved claims aren't in the `links` view, which joins on multihash ids they don't have (`tags` and `RefIndex` cover them), and nothing yet carries them between repos, since no DAG reaches them: transport will need claims about a block exported alongside it.
- *Two names for one file.* A kept file's whole-file multihash and its UnixFS root name the same bytes, which `shard_roots` records. That's a `Same` claim in all but name, and is what lets a kept file's ranges be rebuilt from its roots' blocksizes if the index is lost; without it, a kept file is an anonymous byte string. Until claims exist and blocks can be read as streams, the whole-file multihash isn't a block anyone can get: a `get` returning one 4 GiB `Vec` serves nobody.
- *Kept files outlive failed imports.* A kept file is moved into place when its own file finishes, inside the import's transaction but not part of it, so a later failure can leave a kept file nothing refers to; re-adding reuses it, and collection should sweep the rest. Its ranges are pending in a connection-local table until it's settled, so a crash forgets them along with the transaction. Stdin has no path to fingerprint or settle under, so it's copied block by block, its large leaves landing in the shards one by one.
- *Shape metadata*: a cached classification of each block (UnixFS file leaf, HAMT shard, claim…) recomputable from its bytes, to find candidates for a new specialized store without parsing everything. IPLD codecs have no magic numbers; the CID's codec is the out-of-band equivalent, and already narrows what each store considers.
- *Verify on read*: blocks from untrusted stores or peers are re-hashed (`Block::verify`); trusted local stores can skip it.

### Data model and codecs

Every codec round-trips through one canonical IPLD data model (`model::Ipld`: null, bool, integer, float, string, bytes, list, map, link). The serde layer (`src/serde/`) reduces each codec to a small `Encoder`/`Decoder` trait pair, so dag-cbor and dag-json are a few hundred lines each and any `Serialize` type can be encoded directly. CIDs pass through serde as a newtype named `$__private__serde__identifier__for__cid`, the same convention as the ecosystem's `cid` crate.

Design decisions:

- **Hand-rolled codecs**, mainly for canonicity reporting (see [blockstores](#physical-blockstores)), plus control over determinism and digest types. The ecosystem implementations are used only as test oracles (dev-dependencies), so `ipld-core` and `Multihash<usize>` never reach the runtime.
- **Strict decoding with canonicity.** Invalid input (duplicate keys, NaN, indefinite lengths, malformed CIDs) is an error; valid but non-canonical input (unsorted keys, short floats, padded integers, whitespace) decodes and is reported as non-canonical.
- **Nesting is limited to 256 levels** (`serde::MAX_DEPTH`). Decoding recurses, so without a limit a kilobyte of nested lists overflows the stack. The limit applies to ignored values too.
- **Integers are i128** in the data model so dag-cbor's full range, -2^64 to 2^64 - 1, survives.
- **dag-json** follows the spec where implementations disagree: integral floats keep a `.0`, big integers stay integers, and only `{"/": string}` and `{"/": {"bytes": string}}` under a leading `/` key are reserved; `{"/": null}` is an ordinary map. Floats otherwise print like JavaScript's `Number#toString`, matching the fixtures.
- **dag-pb** has its own strict codec (`pb.rs`) for its PBNode/PBLink framing, with UnixFS layered on top (`unixfs.rs`). It's not in the data model yet: the plan is for dag-pb to convert to and from `Ipld`, with UnixFS eventually treated as an ADL the way go-unixfsnode does, rather than baking UnixFS into the codec.
- **Import layouts are pluggable**: file layouts (balanced, later trickle) and directory layouts (basic, HAMT, dynamic) are strategy traits.

### Linking: claims

Under strict IPLD semantics, blocks are related to each other by directed CID links. In Holokeep, this is augmented by backreferences within the local repository, which hoist mutability into indexes so that "what refers to this?" is a valid query. This is the core of the Nayuki-style tagging system and what I believe can take IPFS from a dead archive to a living local ecosystem.

**Claims** are sidecar blocks representing information about their targets not necessarily present in the content itself, such as metadata or derived information like headers. Unlike ordinary blocks they do not typically have a CID. The process of having a CID assigned to a claim is called **precipitation**; this is necessary for transport and whenever another block (such as another claim) needs to refer to it. The opposite, a block being indexed without its CID, is **dissolution**.

The point is to keep claims ultra-lightweight and very numerous: compact rows in a table, for thousands or millions of them. Their hashes would often be bigger than the claims themselves, so they're elided except during transport, when the claim is manifested; a tiny claim can also use the `identity` hash function. Precipitation only works if a dissolved claim always manifests to the same bytes, which is exactly what the canonical dag-cbor encoder guarantees.

```ipldsch
type iso8601 string

# Mark a block as collectable.
type Tomb struct {
  target [Link]
  when optional iso8601 # When a tombstone was added to determine collection priority
}
# Targets belong to the given group.
type Group struct {
  target [Link]
  into Link # id multicodec represents a simple tag
}
# Targets refer to the same bytes.
type Same struct {
  target [Link]
}
# Attributes associated with the targets.
type Attr struct {
  target [Link]
  attrs Map
  prev [&Attr] (implicit "[]")
}
# Additional structure derived from the targets.
type Derive struct {
  target [Link]
  into Any
}
type Claim union {
  | Tomb "tomb"
  | Group "group"
  | Same "same"
  | Attr "attr"
  | Derive "derive"
} representation inline {
  discriminantKey "claim"
}
```

For all claim types, `target` represents an unordered set. This is translated into IPLD by ordering the array lexicographically by CID bytes. Each claim type has CRDT semantics when claims coexist within a repo; `Tomb`, `Group` and `Same` combine their `target`s.

A claim is the unit of assertion, so it's retracted whole: a tomb can't take one target out of a `Group` of fifty, and a signed claim couldn't be edited anyway. So claims are made one relationship at a time, and a multi-target claim is a batch, equivalent to the single claims it unions. Retracting one relationship from a batch is a tomb for the batch and a single claim for each of the others.

Small objects can just be themselves. **A claim dissolves only if it has one target and fits in an `identity` CID** (128 bytes, per IPIP-0512): then its CID is its own bytes, it needs no hash, and anyone (a UI, a peer) can name it, since the name is the content, while a store keeps it as rows found by what they say. A single-target tag of `music` is 80 bytes, and a tomb for it, which holds the whole claim, 109. So tags dissolve with names up to about 70 bytes, and their tombs with names up to about 24; past that a tomb is precipitated, which is correct, only less compact. Anything bigger is precipitated, an ordinary sha2-256 block, and collected like any other.

What claims are for:

- **Tags** (`Group`): primarily search and discovery. A simple tag is a name (an `identity` CID), or a link to a complex tag such as a globally recognized anchor with extensible metadata.
- **Attributes** (`Attr`): When was this photo taken? What year is this album? Who is pictured? Who did I get this from? How many times have I viewed it? `prev` links form an attribute's history.
- **Anchors**: compare Perkeep's permanodes. Empty objects whose state is attached by the claims which reference them; the core of mutability, a stable identity decoupled from content.
- **Signed claims**: trustful state claims such as "this is a snapshot of this URI at this time" (an import claim) or anchor mutations.
- **Derivations** (`Derive`): "this metadata can be extracted from this file", "this file is this ZIP's member". Claims, tags and indexes may all be special cases of a derivation graph.
- **Views**: instead of magic numbers or mime xattrs, files can have view objects linking to them that hint which content types are valid. Using ADLs could make opaque blobs traversable.
- **Equivalence** (`Same`): "hash X is an alias of hash Y". This still requires trust, since checking means rehashing.
- **Administration** (`Tomb`): tombstones, and see the keep and pin claims in [open questions](#open-questions).

### Retention

Blocks are reference-counted. Because a DAG is acyclic by construction, reference-counting garbage collection is complete. The `refcount` of a block is the number of *non-claim* blocks in the local repo which refer to it. A block may have a refcount *after* it is collected, which indicates that there are still dangling references to it; this allows old or unwanted data to be collected even if references would otherwise keep it alive. Garbage collection is best conceived as purging the *cache* of a platonic, immutable object, not deleting an object from the universe. Thus a repo might have a nonzero refcount for an unknown block which a peer is able to provide.

Blocks are collectable if they are referenced by a tombstone or their refcount is 0. Claims are collectable if they are referenced by a tombstone or if all of their *targets* are collected and have a refcount of 0. Blocks are never garbage collected except under these conditions. Claim targets keep both the claim and target alive by design.

A tombstone outlives its target's local refcount: a tomb's target is usually a claim nothing else refers to, so by the rule above the tomb would be collectable the moment its target is, and the next sync with a peer still holding the target would bring it straight back. So a tomb is only collectable once anti-entropy acknowledges that no peer in the mesh still holds its target. A node that never acknowledges (one kept offline) holds tombs forever; evicting it from the mesh releases them. If it returns after its tombs are gone, the deleted blocks come back with it, so a tomb can carry a keep to make it permanent; such a keep marks the tomb itself rather than pointing at content, so it isn't counted as a reference.

Collection is a lazy trickle with a hard boundary on what is collectable, and always local. Objects with refcount 0 are collected first, then tombstones ordered by `when`, then tombstone targets with no `when`. This is done iteratively so refcounts are recalculated and newly collectable items join the work queue; as blocks are collected their links become eligible in turn, until the whole subgraph has had the opportunity to be collected. When a node runs low on space, it raises the collection rate in proportion to usage.

Collection is also too slow for some things. A *purge* removes a block now, for infohazards (leaked secrets, abuse material, anything legally or personally dangerous to hold) that shouldn't wait for the trickle. It's complicated by user profiles and tiered permissions: who may purge a block several users refer to, whether a purge propagates to replicas and peers or only cleans the local cache, and what's left behind so it isn't simply fetched back (a tombstone naming the multihash is itself a pointer to the hazard). Kept files and in-place ranges make it concrete too: a purge has to remove every representation, including whole files whose other leaves are still wanted. And a SQLite volume's generation row for a departed block refers to its multihash, so readers see it leave; a purge has to drop that once it's been seen, or the multihash stays.

Audit/repair and trickle GC are the same homeostasis with opposite signs, akin to soup convecting, weighed against the bandwidth they cost.

### Replication and transport

- **Private**: Nodes join a private DHT to stochastically replicate files. These are assumed to be owned by the same entity and are fully permissioned and trusted. Replication is aware of blockstores, which are identified by private-DHT-local UUIDs because nodes are not assumed to own their stores outright. This allows, eg, multiple nodes sharing access to cloud storage without double-counting replicas.
- **Protected**: Private DHTs can connect at the periphery to semi-trusted nodes (eg owned by friends) which are trusted to provide and maintain access control for encrypted blocks, for mutual replication. Negotiating who provides what is out of scope, but this could also serve paid nodes. The protected tier is a commons, mutual aid: sharing as infrastructure instead of sharing through a platform. Its accounting should be legible enough for trust, but not so financialized it becomes a market.
- **Public**: The Amino DHT, for public block access. Imported blocks are private by default, and bitswap participation happens only for blocks that are shared or were obtained from bitswap in the first place, to avoid leaking information.

Nodes within a mesh use anti-entropy to maintain a well-replicated set of blocks, mediated by set reconciliation. When a new node joins, all peers share lists of multihashes they believe are under-replicated; each node aggregates these and responds with a Bloom filter of every block it hosts.

**Nodes exchange what's needed, not their indexes.** Catching up (`catch_up`, generations) belongs to shared volumes, where two catalogs index the same storage and each must notice what the other wrote. Between nodes there are no unindexed blocks, only blocks elsewhere, and mirroring every node's placement into every catalog would cost every machine for nothing it needs. Each exchange has its own trigger:

- *Durability*: a node audits what it holds as a trickle (below; `hk node run --copies`, 2 by default, or every block at once with `hk node audit`), and advertises (`/holokeep/adverts/1.0.0`) the blocks it believes would take fewer failures than that to lose, by its volumes' risks and the copies it has sighted elsewhere. Every member answers with the copies it holds of those, by volume label and risks, which corrects the belief (labels keep a volume two nodes share from counting twice, and each volume's implicit risk is its label, so it means the same volume everywhere), and with an *offer*: what its own volume risks, and its free space. If a block's still short, a target is chosen by rendezvous hashing over the block and the members whose copy would raise its tolerance most, weighted by free space, and it's sent there (`/holokeep/push/1.0.0`), again until it's enough or no one can raise it. The same hashing, unweighted, over the holders picks which one does this: a holder advertises only what it's responsible for among the holders it knows of, and passes over a block once it learns of a holder ranked higher, so holders auditing at once still send each block once. Every node computes the same answer without coordinating, so there's no herd and no block left unreplicated or replicated twice; a target which doesn't keep what it's sent (full, or a friend, later) is passed over for the next. Every member answering suits a small mesh; gossip is for when it isn't fully connected.
- *Access*: a reader wants what it doesn't hold (`/holokeep/blocks/1.0.0`). A fetch walks a DAG from its root, reading what's here for its links (a raw block has none, so it's only looked for) and wanting what isn't, in batches. Each multihash is asked of one connected member at a time, starting from a different one for each block so a big DAG's load is spread, and a member without it passes it to the next; an answer carries each block under the CID it was put with, so its codec comes along, and keeps to a few megabytes, leaving the rest to be asked again. Every block is verified before it's kept, and what's fetched is kept, as a cached copy. `hk dag fetch` fetches a DAG, and `hk cat`, `get` and `dag export` fetch first whenever the node's running. Asking members in turn suits a small mesh; Kademlia provider records are for when it isn't.
- *Backrefs*: structure (UnixFS nodes, IPLD, claims, dissolved ones included) is noticed to members with the multihashes it links to (`/holokeep/notices/1.0.0`), and a member wants what it doesn't have and links to something it holds, which is pushed as copies are; that's how a node makes its best effort to know every backref to what it holds, tags included. Structure arriving in the catalog, written here or sent from elsewhere, is noticed to each member from a cursor of its own over the generations the catalog's database already stamps, moved on only once the member answers, so one that was away hears of what it missed when it's back and a new one hears of everything; and a block sent to a member, as a copy or fetched, takes the structure linking to it along. It's one hop: what links to what a member holds, not what links to that.

Beliefs about other nodes' copies, *sightings*, are kept apart from `blocks`, which stays authoritative for the node's own volumes: only for blocks the node holds, expiring by its own clock after a week, unless the peer's stayed connected since, since a member says what it lets go of (below), so while it's connected nothing it held has gone unsaid; expiry is for what disconnections hide. A sighting past half its time is due: the block's advertised even if it has copies enough, and the answers sight them again, on both sides, since a holder answering an advert sights the advertiser's copies too; one that expires anyway lowers a block's tolerance, which brings an advertisement, which brings a "have" or a new copy. Audit and repair are the same loop. A copy pushed or fetched comes with the sender's copies, so the receiver needn't ask.

**Auditing is a trickle**, a homeostat rather than a schedule. Each tick audits the blocks which have arrived since the last, so what's added finds copies within seconds, and a random sample of the rest, sized so that while calm every block comes up about every 21 hours, well before its sightings are due. The pace answers to what's found: a tick which makes copies halves the interval, down to 2 seconds, since more may be needed; a calm one stretches it by a quarter, up to a minute; a member coming or going, or something added, snaps it back to alert. What no member can raise doesn't count, or it would keep the node hurrying for nothing; each interval is jittered by a fifth so nodes don't fall into step. So the mesh carries a constant low murmur of adverts rather than bursts, rising where something needs doing and settling when it's done. `hk node status` shows the pace.

**Trimming surplus, between watermarks.** When the repo's free space falls below a low watermark (`hk node run --low-water`, 2G by default), the node lets go of copies the mesh can spare until it's back above the high one (`--high-water`, 4G), and between them it neither trims nor takes copies from others, whose offers count only the space above the high mark: hysteresis, so it doesn't flap at a threshold. This collects surplus, not garbage: nothing leaves the mesh, only copies beyond `--copies`, and only leaves in the repo's own stores (structure stays, being small and what's queried, and so do leaves which are ranges of files imported in place, which are the user's). A kept file, the whole file `hk add` keeps so its leaves are contiguous, exists for the file it was imported as, so once any of its leaves goes the file has too: the kept file goes, and what's left of it, leaves other DAGs share, becomes blocks of their own first. Leaves let go of together move nothing, so a file that's spare everywhere goes whole. A leaf is a candidate when its copies elsewhere, as sighted, would still be enough; sightings may be wrong, so before letting go the node asks every connected member what it holds of the candidates *now* (`/holokeep/trim/1.0.0`), and only what's still enough by the answers goes. Two nodes meaning to let go of the same block at once can't both: a member about to let go of a block refuses an intent for it unless the asker ranks below it by the holders' rendezvous hashing, and then gives way, so the lowest-ranked goes first. What's let go of is told to every member (`/holokeep/dropped/1.0.0`), which forget their sightings of it and audit it soon if they hold it. `hk node trim` lets go of everything spare now, short of space or not.

**Joining**, so far: every node of a repository shares a *swarm key*, a libp2p private-network key (Kubo's `swarm.key` format), which encrypts a connection before anything else is said, so a machine without it can't speak to the mesh; it works over TCP, not QUIC. Each node also keeps the members it lets in, so one can be shut out without changing the key, and members tell each other of the members they know whenever they connect, so a machine invited by one is let in by all. A machine joins with a ticket from a member: `hk node id` on it, `hk node invite <id>` on the member, `hk node join <ticket>` back on it. The keys are files beside the catalog (`node.key`, `swarm.key`), not rows in it, since its database is a volume another node may open. mDNS finds members on the LAN; identify tells each where the others listen; Kademlia, under `/holokeep/kad/1.0.0` so it's no part of Amino, will find them as they move. `hk node run` owns the mesh on one thread, the catalog's database with it; other commands open the repo as ever, and ask the daemon over a Unix socket for what needs the mesh. Until users have DIDs, holding the key and being on the list is what being yours means.

Ideas:

- *Failure-domain placement*: describe each blockstore's risk with a set of tags, eg `{living-room, home, new-mexico, us}` is very far from `{bangkok, data-center}` and very close to `{living-room, raid-3, home, new-mexico, us}`, and place replicas to maximize the distance between them. Volumes' risks, found and said, now do this for counting (see durability above); what's open is weighing distance beyond shared risks, perhaps with Ceph's CRUSH, perhaps latency-aware.
- *CAR files* are the interchange format between repos, Kubo included, before any networking exists. Export walks the DAG depth first, writing each block the first time it's reached, which is Kubo's order. Import trusts nothing: every block is verified, sections are bounded as go-car's are (8 MiB, headers 32 MiB), and a CARv2's index is ignored, since the repo indexes for itself. Blocks are placed by structure like any others; importing into the offset store would need provenance into the CAR, which isn't a whole file of anything.

## Roadmap

1. **Private DHT for replicating file archives**
2. **Limited distributed mutability and local indexing** (Perkeep parity)
3. **Social networking**: shares, encrypted puts with friends, subsuming website databases for per-user data pods, BAT/delegated distributed access control (DIDs necessary)
4. **Abstract transport**: mounts to anchors for arbitrary RPC and Plan 9-esque file access, proxying across the network

Checklist:

- [x] Kubo hash compatibility for imported files
  - [x] Small file with raw codec
  - [x] Multi-block file
  - [x] Directory
  - [x] HAMT
- [x] dag-pb, dag-cbor and dag-json codecs
- [x] Blockstore that keeps what `hk add` imports
- [x] Retrieval (`hk cat`, `hk get`)
- [x] CAR import/export
- [x] UnixFSv1 indexing in SQL
- [x] Backreference indexing
- [x] Catalog over labelled volumes (the database, the shards)
- [x] Volumes on other devices, attached where they were last seen (`hk volume add/ls`)
  - [x] Catching up with shared flatfs volumes by shard mtimes
  - [x] Replicating until it takes a number of failures to lose a block (`hk volume replicate`), counting risks found (disks, machines) and said (`hk volume risk`)
  - [x] SQLite volumes holding structure, caught up with by generation (`hk volume add --sqlite`)
  - [x] Copying to a volume regardless of disk, eg to carry blocks between machines (`hk volume copy`)
  - [x] Claims on other volumes, dissolved ones stamped by row, following what they're about
  - [ ] Repacking blocks which belong together, eg a UnixFS file's leaves, into a whole file
- [x] Tagging
  - [x] Tags as `Group` claims, kept as rows (`hk tag add/ls/find`)
  - [x] Untagging, by tombstoning the claims (`hk tag rm`)
  - [x] Keeps, `Keep` claims which say to keep their targets and what they link to: `hk add` keeps what it adds unless `--no-keep` (`hk keep add/rm/ls`)
  - [x] Dissolved claims, named by identity CIDs
- [ ] Purging blocks immediately, across stores and permission tiers
- [ ] Querying
- [ ] Perkeep-style claims
- [ ] File mutation
- [ ] FUSE
- [ ] P2P private mesh
  - [x] Joining: swarm key, members, tickets, mDNS, identify (`hk node id/invite/join/run/peers`)
  - [x] Fetching DAGs from other nodes (`hk dag fetch`, and `cat`/`get`/`dag export` through a running node)
  - [x] Advertising under-replication, sightings, recruiting by rendezvous hashing (`hk node run --copies`, `hk node audit`)
  - [x] Noticing structure to holders, for backrefs and claims
  - [x] Auditing as a trickle: what's arrived and a random sample each tick, paced by what it finds; full audits only when asked (`hk node status`)
  - [x] Trimming surplus copies between free-space watermarks, confirmed with members first, lowest-ranked first (`hk node run --low-water/--high-water`, `hk node trim`)
  - [x] Advertising what's let go of, so sightings of members connected since needn't expire
  - [x] Trimming leaves of kept files: a file goes whole, or is split into blocks of its own once any leaf goes
  - [x] Holding what's kept: a keep is only added by a node holding all of what it keeps, fetching what isn't here first (`hk keep add`), so a keep added while what it keeps is being collected keeps a copy alive, and the trickle replicates it. Slippage then needs no timeout to be safe, only to be prompt
  - [ ] Frontier claims: where a keep's reach stops, for DAGs too large to hold (`--shallow` writes what couldn't be fetched as the frontier, rather than failing)
  - [ ] Collecting garbage: what nothing kept links to, judged by backrefs. Condemned blocks are advertised and dropped after a grace period, unless a keep or link revives them; a node never takes not having heard of a keep as there being none for what it keeps itself
  - [ ] Noticing files imported in place which have gone or changed, in the trickle, so their blocks are re-replicated
  - [ ] Kademlia provider records, once broadcast wants don't scale
- [ ] Public Amino DHT
- [ ] BitTorrent bridging
- [ ] User ownership model
- [ ] Peergos BAT with friends

## Open questions

**Privacy and trust**
- Encryption vs deduplication: encrypting blocks defeats deduplicating them.
- Dedup reveals structure, which could be useful user-facing, and is a leak otherwise.
- Metadata is more sensitive than data.
- A threat model for each tier.
- Node eviction if a computer is stolen: key rotation, etc.
- Stochastic placement raises safe-harbor questions: whose drive is holding what?

**Claims**
- Keep claims: signal "this is an object you probably don't want garbage-collected", importable from another repo. Is that a claim type, or covered by refcounts?
- Pin claims: distinct from Kubo's pins, "pin to this particular node". These may work better out of band, since it doesn't make sense to transport claims about where an object should live.
- Should mutations be administrative claims too? CRDTs and live shared editing eventually, but by a long shot the priority is repo curation.
- Do claims need their hashes "just in case"? Only if something references them, which happens if the claim exists elsewhere in the DHT and someone wants to talk about it; but then they could ask for the block and match it to the object. At a few dozen bytes each, even millions of claims are only tens of megabytes.

**Mounts and mutability**
- What if something anchor-shaped signalled a mutable mount into a host filesystem? It could be referred to in CAS, but rather than traversal going through ordered claims, it defers to some handler. This would allow much better interoperability, and even navigating the filesystems of my different computers completely abstracted from where they are.
- This might also be the key for mutable files. A major problem with IPFS's MFS is that every mutation has to rehash up to the root, and delaying risks data loss and doesn't play nicely with a private DHT. What if instead you mount a single file like this, hooked into a CRDT scheme so changes propagate at the speed they need to, and eventually recommit it to immutability?
- Anchor mounts are named ports: simple transport with no assumed protocol.
- Apps as pure functions over the soup? See VLAD in [RESEARCH.md](RESEARCH.md).

**Replication**
- The write path: what happens when a new file is added at an access point, before it's replicated?
- The audit/repair loop, and diversity weighting for replica placement.

**Storage**
- Coalesce existing files as large blobs, promoting their blocks to offset blocks (kept files do this at import); and chunk large blocks automatically.

## Development

```sh
cargo build --release
hk=target/release/hk
$hk add <path> [--no-keep]          # store it, printing CIDs like `ipfs add -r`, and keep it
$hk add -n <path>                   # only print CIDs, like `ipfs add --only-hash`
$hk add --nocopy <path>             # keep contents in place, like Kubo's filestore
$hk cat <cid>                       # a file's contents
$hk get <cid> -o <path>             # a file, directory or symlink
$hk block get <cid>                 # a block's bytes
$hk refs [--back] <cid>             # a block's links, or what links to it
$hk tag add <name> <cid>...         # tag blocks, with a Group claim
$hk tag ls <cid>                    # a block's tags
$hk tag find <name>                 # the blocks with a tag
$hk keep add|rm <cid>...            # keep blocks and what they link to, or stop
$hk keep ls                         # what's kept
$hk tag rm <name> <cid>...          # untag blocks, with tombs
$hk dag export <cid> -o <file.car>  # a DAG as a CARv1, like `ipfs dag export`
$hk dag import <file.car>...        # CARv1 or v2 files, like `ipfs dag import`
$hk repo stat                       # blocks per volume and form
$hk volume add <name> <path>        # keep copies on another drive, attached whenever it's there
$hk volume add --sqlite <name> <file.db>  # ...as a database, holding structure as rows
$hk volume ls                       # volumes known, attached or not
$hk volume risk add <name> <risk>   # say what volumes fail together: a house, a person
$hk volume risk ls                  # every volume's risks, found or said
$hk volume replicate [--copies n]   # copy blocks until it takes n failures to lose each
$hk volume copy <name> [cid...]     # copy DAGs, or everything, to a volume wherever it is
$hk node id                         # this node's peer id, to be invited by
$hk node invite <peer-id>           # let a machine into the mesh; prints a secret ticket
$hk node join <ticket>              # join a mesh
$hk node run [--listen <addr>] [--copies n]  # run in the mesh (default /ip4/0.0.0.0/tcp/4011),
                                    # trickling copies to members until it takes n failures to lose each
$hk node peers                      # members, and which are connected
$hk node status                     # connected members, blocks, the trickle's pace, free space
$hk node trim                       # let go now of every copy here the mesh can spare
$hk node audit [--copies n]         # have the running node audit every block now
$hk dag fetch <cid>                 # fetch what isn't here of a DAG from the mesh
```

The repo is `~/.holokeep` unless `--repo` or `HOLOKEEP_REPO` says otherwise.

Every layer is tested against an independent implementation:

```sh
git submodule update --init         # ipld/codec-fixtures
cargo test                          # unit tests, codec fixtures, quick fuzzing
PROPTEST_CASES=1000000 cargo test --release differential   # long fuzzing
scripts/kubo-compare.sh             # every CID vs Kubo, then store and get back; needs `ipfs`
LARGE=1 scripts/kubo-compare.sh     # adds >1 GiB files
```

| Module | |
|---|---|
| `varint`, `multihash`, `cid` | Multiformats primitives |
| `block` | Blocks, which always match their CID |
| `store` | The blockstore traits, routing store and stores |
| `pb`, `unixfs` | dag-pb framing and UnixFSv1 nodes |
| `chunker`, `dag`, `hamt`, `import` | Importing files and directories |
| `export` | Reading them back out |
| `serde`, `model`, `dagcbor`, `dagjson` | The data model and its codecs |
| `canon` | Tracking whether decoded data was canonical |
| `codec_fixtures`, `differential` | Fixture and fuzz tests |
| `dagpb`, `ipld` | Earlier experiments, not compiled |
