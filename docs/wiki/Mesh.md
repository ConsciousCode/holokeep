A **mesh** is the set of nodes that replicate and serve each other's
blocks: one user's devices (private), or a vault's holders (protected,
see [[Protected Meshes]]). `hk node run` is the
daemon. It owns the mesh on one thread, along with the catalog's
database, and other `hk` commands ask it over a Unix socket in the repo
for anything that needs the network.

## Transport

libp2p over TCP, stacked as:

1. **pnet**: a libp2p private-network pre-shared key (Kubo's `swarm.key`
   format), applied before anything else is said. A machine without the
   key can't speak to the mesh. (So no QUIC.)
2. **noise** for authentication, with the node's ed25519 key.
3. **yamux** for multiplexing.

Behaviours: identify, ping, mDNS (LAN discovery), Kademlia under
`/holokeep/kad/1.0.0` (kept apart from Amino), and the request-response
protocols below.

## Joining

Every node of a mesh shares the swarm key, and each keeps the list of
members it lets in, so one can be shut out without changing the key.
Members exchange rosters whenever they connect, so a machine invited by
one is let in by all.

1. `hk node id` on the new machine prints its peer ID.
2. `hk node invite <id>` on a member prints a ticket.
3. `hk node join <ticket>` on the new machine.

A **ticket** is dag-cbor, multibase base32-lower encoded:

| Key | Value |
|---|---|
| `inviter` | bytes: the inviter's peer ID |
| `key` | string: the swarm key in `swarm.key` text form |
| `members` | list of `[peer ID bytes, [multiaddr bytes…]]` |
| `user` | link: the user's root key (when the mesh has one) |
| `blocks` | list of bytes: every certificate and revocation, the joiner's included, and the sealed root with what keeps it |
| `protected` | `true` for a protected mesh (omitted otherwise) |
| `sealed` | list of bytes: a vault's sealed blocks, for recovery |
| `held` | list of links: the vault's manifests, for recovery |

The keys are files beside the catalog (`node.key`, `swarm.key`), not rows
in it, since the database is a volume another node may open. A repo in no
mesh runs alone: an ephemeral swarm key, no listening, no dialing, but
still watching files imported in place and collecting.

**Several meshes.** A node may be in several, each with its own swarm
key, members and daemon (`--mesh <name>`, files in `meshes/<name>/`),
acting for one account each. A daemon hears of, holds and serves only
its account's view.

## Protocols

All of these are libp2p request-response with the **CBOR codec** (serde):
structs are maps keyed by field name, tuples are arrays, and `bytes`
below are CBOR byte strings. A "key" is a multihash's bytes; a "CID" is a
CID's binary form. A **replica** is `{label: bytes, risks: [string]}`,
one copy of a block: the volume it's on, by its random label, and what
that volume risks (see [[Replication and Retention]]).
An **offer** is `{risks: [string], free: uint | null}`.

| Protocol | Request | Response | Purpose |
|---|---|---|---|
| `/holokeep/members/1.0.0` | `{members: [[peer, [addr]]]}` | same | Exchange rosters. |
| `/holokeep/blocks/1.0.0` | `{want: [key]}` | `{blocks: [[CID, data]], missing: [key], copies: [[replica]]}` | Fetch blocks. |
| `/holokeep/adverts/1.0.0` | `{blocks: [[key, [replica]]]}` | `{held: [[key, [replica]]], offer: offer \| null}` | "These may be under-replicated." |
| `/holokeep/push/1.0.0` | `{blocks: [[CID, data]], copies: [[replica]]}` | `{kept: [[key, [replica]]]}` | Send copies to keep. |
| `/holokeep/notices/1.0.0` | `{blocks: [[CID, [key]]]}` | `{want: [CID]}` | Notice structure and what it links to. |
| `/holokeep/trim/1.0.0` | `{keys: [key]}` | `{held: [[key, [replica]]], refused: [key]}` | "I mean to let go of these." |
| `/holokeep/dropped/1.0.0` | `{keys: [key]}` | `{}` | "I let go of these." |
| `/holokeep/condemn/1.0.0` | `{blocks: [key]}` | `{kept: [key]}` | "Does a keep of yours reach these?" |

### Access (`blocks`)

A fetch walks a DAG from its root, reading what's here for links and
wanting what isn't, in batches of 64. Each key is asked of one member at
a time, starting from a different member per block to spread load; a
member without it reports it `missing` and the next is asked. A response
keeps to about 4 MiB and leaves the rest to be asked again. Every block
is verified against its CID before it's kept, and what's fetched is
kept as a cached copy. A fetch can also be of just the named blocks, not
their DAGs, which is how `hk mount` reads only what's read.

### Backrefs (`notices`)

Structure (UnixFS nodes, IPLD, claims, dissolved claims included) is
noticed to members with the keys it links to, in batches of 256. A
member wants what it lacks that links to something it holds, or to
something else wanted from the same notice. Rules that keep this from
spreading everything everywhere:

- A `sign` is noticed by the claims it signs, not by its key or `prev`.
- An identity block counts as held only if it's a dissolved claim held
  here.

Each member has a cursor over the catalog's generations (see
[[Storage]]), moved only once it answers, so a member that was
away hears of what it missed. A block sent to a member, by push, fetch
or want, takes the structure linking to it along. It's one hop: what
links to what a member holds, not what links to that.

Durability (`adverts`, `push`), trimming (`trim`, `dropped`) and garbage
collection (`condemn`) are described in
[[Replication and Retention]].

Source: `src/net/node.rs`, `src/net/mesh.rs`, `src/net/blocks.rs`, `src/net/structure.rs`, `src/net/daemon.rs`.
