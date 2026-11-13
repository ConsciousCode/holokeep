A **mesh** is the set of nodes that replicate and serve each other's
blocks: machines serving one or more users (private), or a vault's
holders (protected, see [[Protected Meshes]]). A user's blocks go only to
the machines hosting the user (see [[#Users sharing a mesh]]). `hk node run` is the
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

A daemon running alone when its repo's first invite makes a mesh joins
that mesh in place, without a restart, and the invite then reads where
it listens, so the ticket says where to find it.

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
key, members and daemon (`--mesh <name>`, files in `meshes/<name>/`). A
daemon hears of, holds and serves only the views of the accounts its mesh
serves: its own, and for the main mesh, any others joined to it.

## Users sharing a mesh

The main mesh's daemon serves the owner's account and any other account
joined to it, each a user sharing the machine, listed in `mesh_accounts`.
Each has a device key of its own in `accounts/` and a user, whose root
certifies it.

- `hk node invite <peer> --account <uid>` on the main mesh serves that
  account too, making it a user first if it has none (asking that user's
  passphrase), and certifies the joiner as that user's device.
- `hk node join <ticket> --account <uid>` makes that account a device of
  the ticket's user, served by the main mesh.
- `<uid>` may be a host user's, or an unused number for a user this
  machine hosts who has no login here (`hk node id --account <uid>` prints
  the key it'd act for them with, for an invite's `--device`).

**Hosting.** On connecting, and whenever what it hosts changes, each
machine tells the other which users it hosts (`/holokeep/hosts/1.0.0`):
for each served account with a user, the user's key, the device key it
acts for the user with, and that key's signature over the machine's peer
ID:

```
sig = ed25519(device, "holokeep hosts\x00" || peer ID bytes)
```

A machine takes another to host a user only if it serves that user too,
the signature checks, and the device is certified by the user here and
not revoked. So a machine can't claim to host a user without one of the
user's device keys, and learns nothing from what it's told of users it
doesn't serve.

**Serving.** Every request about blocks names, as `user`, the user's key
CID whose blocks it's about. The answering machine works it out as its
account for that user, and only if the asker hosts the user; otherwise it
answers as though it had none of them. Audits, trims and fetches run for
each account served, among the members hosting its user. Nothing is asked
of a member until it's answered what this machine hosts, as it now is.

An account with no user yet, such as a vault's, acts for its device key,
and its blocks go to any member, as before there were users. A machine of
an older build, which doesn't answer `hosts`, is taken to host the user
of the answering daemon's own account, and its requests, which name no
user, are for that account.

`hk node peers` lists, for each connected member, the accounts here whose
users it hosts.

## Connections

Members are dialled on start and once a minute after, and a member is
dialled again 2 s after its connection drops. Every connection is pinged
every 10 s, and one whose ping fails is closed, so a peer that slept or
changed networks isn't left as connected over a dead link: it's
redialled instead.

A daemon never stops for another program writing to its database, such
as a big `hk add`: it waits a second, so its connections stay up, and
tries again on a later tick (see [[Storage#Transactions]]).

## Protocols

All of these are libp2p request-response with the **CBOR codec** (serde):
structs are maps keyed by field name, tuples are arrays, and `bytes`
below are CBOR byte strings. A "key" is a multihash's bytes; a "CID" is a
CID's binary form. A **replica** is `{label: bytes, risks: [string]}`,
one copy of a block: the volume it's on, by its random label, and what
that volume risks (see [[Replication and Retention]]).
An **offer** is `{risks: [string], free: uint | null}`. `user?` is
`user: CID`, the key of the user whose blocks a request is about, omitted
by older builds (see [[#Users sharing a mesh]]).

| Protocol | Request | Response | Purpose |
|---|---|---|---|
| `/holokeep/members/1.0.0` | `{members: [[peer, [addr]]]}` | same | Exchange rosters. |
| `/holokeep/hosts/1.0.0` | `{hosts: [{user: CID, device: CID, sig: bytes}]}` | same | Say which users each hosts. |
| `/holokeep/blocks/1.0.0` | `{want: [key], user?}` | `{blocks: [[CID, data]], missing: [key], copies: [[replica]]}` | Fetch blocks. |
| `/holokeep/adverts/1.0.0` | `{blocks: [[key, [replica]]], user?}` | `{held: [[key, [replica]]], offer: offer \| null}` | "These may be under-replicated." |
| `/holokeep/push/1.0.0` | `{blocks: [[CID, data]], copies: [[replica]], user?}` | `{kept: [[key, [replica]]]}` | Send copies to keep. |
| `/holokeep/notices/1.0.0` | `{blocks: [[CID, [key]]], user?}` | `{want: [CID]}` | Notice structure and what it links to. |
| `/holokeep/trim/1.0.0` | `{keys: [key], user?}` | `{held: [[key, [replica]]], refused: [key]}` | "I mean to let go of these." |
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
[[Storage]]) for each account served whose user it hosts, moved only once
it answers, so a member that was away hears of what it missed. The
daemon's own account's is named by the peer ID; another's adds `#` and
the account's uid. A block sent to a member, by push, fetch
or want, takes the structure linking to it along. It's one hop: what
links to what a member holds, not what links to that.

Durability (`adverts`, `push`), trimming (`trim`, `dropped`) and garbage
collection (`condemn`) are described in
[[Replication and Retention]].

Source: `src/net/node.rs`, `src/net/hosts.rs`, `src/net/mesh.rs`, `src/net/blocks.rs`, `src/net/structure.rs`, `src/net/daemon.rs`.

## Forgetting members

`hk node forget <peer>` is for a member that's gone for good, as a node's
old key. A member away holds up [[Replication and Retention#Garbage collection|collection]]
and [[Replication and Retention#Lost blocks|lost reports]], so this ends
that: it's no longer let in, and copies it was believed to hold aren't
counted. Others telling of it aren't heeded, in `mesh_forgotten`, so each
node has to say so itself. It's refused while the peer's connected.
Inviting it lets it back in. Its key can still sign, which `hk device
revoke` stops.
