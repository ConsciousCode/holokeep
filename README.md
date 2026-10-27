# Data Soup
## Principles
- Objects "live" in multiple possibly remote locations but can be accessed from anywhere within the mesh without the user knowing where they are.
- Objects are automatically stochastically replicated so they are never lost.
- Scales automatically with however many (or few) servers you add.
- Integrates nicely with the existing IPFS/IPLD ecosystem - the public DHT is a subset of the repository.
- Non-hierarchical/relational by default with support for hierarchy as-needed.
- Privacy needs exactly one of permissioned or cryptographic security.
- Private and user-owned by default.
- It can take any data you throw at it and sort the mess later.
- Consume the universe, import everything.

## Architecture
- Physical - "Blockstores" supervised by one or more gateways map CIDs to actual blocks. They do not have any concept of users, ownership, or authentication except as needed to provide their service.
- Access - Users authenticated by public key have logical views of the underlying unauthenticated blockstores.
- Logical - Backreferences, attributes, and joint queries which also implement mutation.
- Transport - P2P communication between gateways to coordinate replication and DHT resolution.
- Social - Contact between separate private DHTs including mutually storing encrypted blocks and sharing access.

## Database
So the tables I can think of:
- `blocks` - mapping CID to any block storage metadata
	- `type` - enumeration of `raw`, `cbor`, `json`, `anchor`
	- `current` - cache of the current state of the block's attributes to avoid recalculating them every time
- `attrs` - an EAV table for the metadata system - each entry has its own CID calculated by converting it to `dag-cbor`. There needs to be some magic for determining that an object is an attribute (relation?) to rebuild the index from exported blocks. Also need a timestamp to order them.
- `users` - mapping public keys to user identities
- `refs` - for backreference indexing
- `stores` - the blockstores to connect to
- `locs` - one to many mapping of blocks to their blockstores.

## Join blocks
This is the core of the Nayuki-style tagging system and what I believe can take IPFS from a dead archive to a living local ecosystem. The concept hoists mutability into backref indexes so "what refers to this" is a valid query. The use-cases:
- Tags
  - Primarily for search and discovery
  - Simple tags associated with a name
  - Could link to a complex tag like a globally recognized anchor with extensible metadata associated with it
- Attributes
  - When was this photo taken?
  - What year is this album?
  - Who is pictured?
  - Who did I get this from?
  - How many times have I viewed it?
- Anchors
  - Compare to Perkeep permanodes
  - Empty objects where state is attached by the presence of blocks which reference them in the repo
  - Core of mutability, define a stable identity decoupled from content
- Claims
  - Signed trustful state claims
  - "This is a snapshot of this URI at this time" - import claim?
  - Anchor mutations
  - "This metadata can be extracted from this file"
  - Could be less trustful: "hash X is an alias of hash Y" - still requires trust as rehashing could be an expensive operation
- ADL/content-typed views
  - Instead of magic or mime xattrs, files can have view objects that link to them providing a hint about what content types are valid
  - Using ADLs could make opaque blobs traversable
- Administrative
  - Keep claims
  - Pin claims
    - Distinct from Kubo, "pin to this particular node"
    - May work better out-of-band. Keep claims make sense just as a matter of signaling "this is an object you probably don't want garbage-collected" which can be imported from another repo, but it doesn't make sense to transport claims about where an object would live.
  - Arguably mutations could fall under this. I want to put more thought into CRDT and live shared editing eventually, but the priority by a longshot is repo curation.
  - Tombstones

What if I had something anchor-shaped that signalled a kind of mutable mount into a host filesystem? Then it could be referred to in CAS but rather than traversal going through ordered claims, it defers to some handler. This would allow much better interoperability and even allow me to navigate the filesystems of my different computers completely abstracted from where they are.

This might also be the key for mutable files. One major problem MFS has is every single mutation has to rehash up to the root; delaying risks data loss and doesn't play nicely with my private DHT aim. What if instead, you mount one singular file like this and it hooks into some CRDT scheme so changes propagate at the speed they need to and eventually it can be recommitted to immutability?

```ipld
type ComplexTag struct {
	name String
}
type Tag union {
	| String simple
  | ComplexTag complex
} representation kinded;

type Attrs struct {
	attrs map
}

type Holokeep union {
	| [Link] "keeps"
	| [Link] "tombs"
	| [Tag] "tags"
} representation keyed
```

Note that this kind of block tends to be content first, address second. That is, because it's defined by *what* it references the hash can be elided except during transport when it's manifested. Optionally you might want to keep the hash around "just in case" someone references it, but when would that happen? Hnnn... it might if the hash exists elsewhere in the DHT and they want to talk about it. But, it could just ask for the block then match it to the object...

The problem I'm trying to avoid here is I want these to be ultra-lightweight and very numerous. Essentially they represent compact rows in a table, for each one of thousands or millions to have its own hash "just in case" seems absurd especially since the hash is likely to be bigger than the object itself. But, if I do truly get to millions then that's just a few dozen megabytes. Also if it's bigger I can just use the `id` hashfunc.

## Phases
1. Private DHT for replicating file archives
2. Limited distributed mutability and local indexing (Perkeep parity)
3. Social networking (shares, encrypted puts with friends, subsumption of website databases for per-user data pods, BAT/delegated distributed access control including website databases on your user, DIDs necessary)
4. Abstract transport (mount to anchors (permanodes) for arbitrary RPC and plan9-esque file access, proxying across the network)

## Checklist
- [ ] Kubo hash compatibility for imported files
  - [ ] Small file with raw codec
  - [ ] Multi-block file
  - [ ] Directory
  - [ ] HAMT
- [ ] UnixFSv1 indexing in SQL
- [ ] Backreference indexing
- [ ] Tagging
- [ ] Querying
- [ ] Perkeep-style claims
- [ ] File mutation
- [ ] FUSE
- [ ] P2P private DHT
- [ ] Public Amino DHT
- [ ] Bittorrent bridging
- [ ] User ownership model
- [ ] Peergos BAT with friends

## Optimizations
- Coalesce files as large blobs and promote blocks to offset-blocks. Also, chunk large blocks automatically.

---

Attempt to re-frame this project:

## Naming and intuition
The high-level idea is "data soup" which anchors intuition to a view of data as a fluid which flows to fill the shape of its container with data (particles) being roughly fungible at a high-level view. Soup also contains larger chunks which are files and objects, the soup has no identifiable location for anything.

My particular project is "Holokeep", a particular implementation of data soup as a concept.

## Prior art
Perkeep: archival object focus, importing, abstractions, permanodes (anchors)
IPFS/IPLD: Protocols, formats, CIDs, libp2p plumbing
Nayuki RelFS: Backreference indexing, tagging as a core organizational principle, tables as a compact representation of object classes
Peergos: BAT for hierarchical access control via semi-trusted nodes

## Principles
- Objects "live" in multiple possibly remote locations but can be accessed from anywhere within the mesh without the user knowing where they are.
- Objects are automatically stochastically replicated so they are never lost.
- Scales automatically with however many (or few) servers you add.
- Integrates nicely with the existing IPFS/IPLD ecosystem - the public DHT is a subset of the repository.
- Non-hierarchical/relational by default with support for hierarchy as-needed.
- Privacy needs exactly one of permissioned or cryptographic security.
- Private and user-owned by default.
- It can take any data you throw at it and sort the mess later.
- Consume the universe, import everything.

## Layers
- Physical - Each node may have one or more blockstores. These are dumb by design and do not track user ownership. All blocks can be serialized to raw bytes, but blockstores can specialize in storing specific types of blocks. For instance, objects with common properties may instead be stored as rows in a database indexed by multihash. Like Perkeep, indexes should generally be derivable from data, but not to its level of paranoia. It should be possible *in principle* but not something done lightly, akin to fsck.
- Logical - Nodes keep track of user block ownership in their repository ("repo") and make a best effort to restrict access to the blocks users actually control. Users are coordinated by DID and their documents.
- Linking - Within a user's repo, indexes keep track of which blocks reference other blocks which forms the basis of mutable anchoring, tagging, and collections. At any given moment these indexes might be incomplete, spread across multiple nodes, but a node should try to aggregate the totality of any given block's indexes within its blockstores.
- Transport
  - Private - Nodes join a private DHT to stochastically replicate files. These are assumed to be owned by the same entity and are fully permissioned/trusted. Replication is aware of blockstores which are indexed by private-DHT-local UUID because nodes are not assumed to have total ownership of their store. This allows eg multiple nodes having access to shared cloud storage without double-counting replications.
  - Protected - Private DHTs can connect between each other at the periphery to semi-trusted nodes (eg owned by friends) which are trusted to provide and maintain access control of encrypted blocks for mutual replication. Negotiation of providing blocks is out of scope, but I could see this also being used for paid nodes rather than simply friends.
  - Public - Amino DHT for public block access. Blocks that users import are assumed private by default and participation in bitswap occurs only when blocks are shared or that block is provided by bitswap in the first place to avoid leaking information.

## Use cases
- Personal archive
- Stochastic replication
- Social data sharing
- Distributed application hosting
- General transport via anchor mounts. Basically mount arbitrary RPC servers on anchors to be serviced by nodes ala 9P. This could let you access a node's local filesystem and facilities through the DAG.

## Vision
- Short-term: I want to treat my data like a tiny data lake without having to know "where" anything is and without ever having to configure replication or redundancy. From any node in the network, all files are accessible even if they don't "live" with that node. I just add 5 computers to my network and they automatically figure out which hard drives get which blobs to maintain a default 3x replication. It needs to be robust to changing network topologies so I can keep my laptop as part of it even as it connects and disconnects. Compare this to other distributed filesystems like ceph where nodes are expected to be always-on and NFS where data lives in one server.
- Mid-term: Imports act as a local cache of external data repositories and applications to eventually support the long-term vision where those applications provide the blocks directly without needing an import step.
- Long-term: Re-imagine the internet as one enormous global filesystem that everyone is a part of. Personal files are invisible to everyone unless shared, and there's a shift in applications from storing user data in proprietary servers to storing data with the user's own data sectors with BAT-style permissions. Compare this to DNS/HTTP where the authority itself is decentralized.

---

Trust is an optimization

Lampshade:
- Encryption vs deduplication
- Pin "privacy needs exactly one of permissioned or cryptographic" to the layers: private is permissioned, protected is cryptographic, public is neither
- Need a story for node eviction in case a computer is stolen. Key rotation etc
- A partitioned node is indistinguishable from a dead one thus every mutable structure must be merge-shaped
- Read-your-writes on the local node, eventual everywhere else, convergence via anti-entropy.
- Threat model for each tier
- Non-goals: not a blockchain, not Byzantine-fault-tolerant against malicious mesh members, not a POSIX filesystem, not low-latency block storage, no availability guarantee during total partition.
- Hardware now is like a hermit crab shell; discard the old, move into the new, renovate, and grow into it. Data soup reframes the relationship to adding a machine to a mesh and it becomes yours, receives of your identity
- Derivation graphs as a generalization of claims/tags/indexes
- Homeostasis as a goal weighed against the bandwidth costs
- Dedup reveals structure, could be useful user-facing
- Metadata is more sensitive than data
- Stochastic placement presents safe-harbor questions
- AP system vis a vis CAP theorem
- Protected tier is a commons/mutual aid, sharing as infrastructure instead of sharing through a platform. Accounting should be legible enough for trust but not so financialized it becomes a market
- Apps are pure function over soup - VLAD?
- Data soup decentralizes authority over state as opposed to DNS which decentralizes authority over names
- Anchor mounts are named ports, simple transport with no assumed protocol
- Audit/repair and trickl-GC are the same homeostasis with different signs akin to soup convecting
- Primordial soup, beautiful soup

Split principles into invariants, defaults, and design stances

Identity
  Multihash identity
Claims
  Carry retention implications

Retention
  Lazy trickle GC - hard boundary on what is collectable, priority collection. Always local. Mention that merkle DAG cannot contain loops by construction and thus refcounting is sound
Replication
  Audit/repair immune loop
  Diversity weighting
Tiers

---

Conventional filesystems are incredibly useful. They provide a unified interface for coordinating impossibly heterogeneous data in the form of "files" across multiple systems. However, the cost of this utility is the tyranny of *location*. A file must always "live" somewhere under a rigid ontology communicated by hierarchical directories. Does the album name or the year it was released come first? Where do you put a "School" folder? They must have a unique name even when that name would be meaningless - "Cat.jpg", "Cat (1).jpg", "Cat (1)-backup.jpg", "Cat (1) (1).jpg". Placing a file entails a decision about which drive it exists within, tying its lifetime to the health of the drive itself. There is no formal way to tie a backup to its file, particularly when that file is edited. Given long enough, any filesystem succumbs to entropy and the only choices are to give up or continue pushing the boulder against the gravity of decay.

What if files didn't have a location? They could be pure objects identified by their content found by their intrinsic attributes. They could exist on any of your drives, computers, or even your friends' computers without worry that anything had changed. They could be in multiple locations at once so you don't have to worry about drive failure.

This is "data soup", a content-addressable storage model where location is not tied to an object's identity or meaning. Objects are identified by their content and organized through relationships, not paths or hosts. The medium is homeostatic through anti-entropy replication and stochastic garbage collection acting in tension to return to a steady state. Semantics are contextual and relational; applications interpret objects in terms of the local graph of links and descriptors that surround them.

Holokeep is a particular implementation of this storage model.

## Identity
A block is a finite sequence of bytes. Blocks are addressed by multihashes, where each multihash encodes a choice of hash function and a digest of the block's bytes. For any fixed hash function, the system treats the hash as injective over all blocks it will store so that, operationally, each multihash acts as its primary key and hash collisions are treated as impossible for all practical purposes. Two multihashes may, by design, refer to the same block (for example, when using different hash functions) and Holokeep makes the opinionated assertion that these constitute distinct logical objects, even if they share physical storage. Equivalence relations between different multihashes with the same preimage are deferred to the relational layer.

## Relational
Under strict IPLD semantics, blocks are related to each other by directed CID links. In Holokeep, this is augmented by backreferences within the local repository. **Claims** are sidecar blocks representing information about their targets not necessarily present in the content itself such as metadata or derived information such as headers. Unlike ordinary blocks they do not typically have a CID. The process of having a CID assigned to a claim is called "**precipitation**". This is necessary for transport and whenever another block (such as another claim) needs to refer to it. The opposite action, a block being indexed without its CID, is called "**dissolution**".

- Tomb - Mark a block as collectable.
- Tag - General category associated with the block.
- Same - Given multihashes refer to the same bytes.
- Attr - General attribute association. Use for names, titles, descriptions, dates, provenance, etc.

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

For all claim types, `target` represents an unordered set. This is translated into IPLD by ordering the array lexicographically by CID bytes.

`Attr` 

## Retention
Blocks are reference-counted. Because a DAG is acyclic by construction, reference-counting garbage collection is complete. The `refcount` of a block is the number of *non-claim* blocks in the local repo which refer to a block. Note that a block may have a refcount *after* it is collected which indicates that there are still dangling references to it. This is to allow old or unwanted data to be collected even if references would otherwise keep them alive. Garbage collection is best conceived as purging the *cache* of a platonic, immutable object and not the deletion of an object from the universe. Thus, a repo might have a nonzero refcount for an unknown block which a peer is able to provide.

Blocks are collectable if they are referenced by a tombstone or their refcount is 0. Claims are collectable if they are referenced by a tombstone or if all of their *targets* are collected and have a refcount of 0. Blocks are never garbage collected except under these conditions. Claim targets keep both the claim and target alive by design. During operation, objects with refcount = 0 are collected with highest priority, then tombstones ordered by `when`, then tombstone targets with no `when` field. This is done iteratively to allow the system to recalculate refcounts and add new collectable items to the work queue. As blocks are collected, their links become eligible for collection until the entire subgraph has the opportunity to be collected. When a node runs low on memory, it increases the GC rate proportional to the amount of used memory to collect more quickly.

Each claim type has CRDT semantics with its own type when they coexist within a repo.
- Tomb, Group, and Same claims combine `target`.

## Replication
Nodes within a mesh use anti-entropy protocols to maintain a well-replicated DHT of blocks. This is mediated by a set reconciliation algorithm

When a new node joins, all peers share lists of multihashes they believe are under-replicated. Each node aggregates these and responds with a bloom filter containing every block they host.

When a new file is added to an access point (AP), 

Audit, repair 

## Misc ideas
- Coordinate proximity for deduplication via distance metics wrt sets of tags representing risk categories, eg {living-room, home, new-mexico, us} is very far from {bangkok, data-center} and very close to {living-room, raid-3, home, new-mexico, us}
  - Failure-aware domain placement
  - Possibly use Ceph CRUSH?
  - Latency-aware? AI-enabled relationships between risk categories?
  - Claude's idea from early 2026