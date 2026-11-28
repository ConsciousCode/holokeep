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

Where a member listens for [[#Clients|clients]], on a port of its own,
connections skip pnet, since clients haven't the key.

Behaviours: identify, ping, mDNS (LAN discovery), Kademlia under
`/holokeep/kad/1.0.0` (kept apart from Amino), circuit relay v2 and
DCUtR (below), and the request-response protocols below.

## Relays

Members that can't reach each other, a laptop away and a desktop at
home behind their NATs, connect through a member that both can reach and
that relays (`relay = true` in [[Configuration]]), such as a server with
a public address. Nothing is routed at the IP layer, so only the mesh's
traffic goes this way, and only between the members that need it.

- Every member holds a reservation on each relay it's connected to, and
  listens through it (`hk node status` says `reachable through`).
- A member it can't reach otherwise is dialled where it was last seen
  and through every relay at once, so whichever works first wins. One
  found on the LAN, or reached where it listens, is dialled directly as
  ever.
- A relayed connection is pnet, noise and yamux over the circuit, end to
  end, so the relay sees how much passes and when, and nothing of what.
  The relay itself is a member, with the swarm key, and lets in only
  members, so it relays only for them, and only to members that would
  let them in directly.
- Connected through a relay, two members try to punch through to each
  other (DCUtR), and keep dialling each other directly; once they're
  connected directly, the circuit's dropped. `hk node peers` says
  `connected through a relay` till then.
- A relay relays as long and as much as members like, where libp2p's
  defaults allow a few minutes and kilobytes, enough to punch through
  and no more.

Setting one up, on a server with a public address:

1. `hk node id` on it, `hk node invite <id>` on a member, `hk node
   join <ticket>` back on it.
2. `relay = true` in its `config.toml`, TCP 4011 open, and `hk node
   run`.
3. `hk node reach <id> /ip4/<its address>/tcp/4011` (or
   `/dns4/<its name>/tcp/4011`) on any member. A relay can't reach the
   members behind their NATs, so it can't say where it is; this says it
   for it, and the member dials it and tells the members it's connected
   to, which tell theirs.

A member that's away when this is said hears of it once it's connected
to one that knows, so say it while they're together, or on each.

Hole punching is over TCP, since pnet rules out QUIC, so it works with
fewer NATs than it would with QUIC; where it doesn't, the relay carries
the traffic.

## Joining

Every node of a mesh shares the swarm key, and each keeps the list of
members it lets in, so one can be shut out without changing the key.
Members exchange rosters whenever they connect, so a machine invited by
one is let in by all. Once the mesh has [[Grants|grants]], which the
main mesh's first invite makes, the members are exactly the machines
given `/mesh/machine`, and a roster is heeded only for those.

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
| `key` | string: the swarm key in `swarm.key` text form (never in a client's) |
| `client` | `true` for a [[#Clients|client]]'s (omitted otherwise) |
| `members` | list of `[peer ID bytes, [multiaddr bytes…]]`: for a client's, the inviter and the others serving the user, where each listens for clients |
| `user` | link: the user's root key (when the mesh has one) |
| `blocks` | list of bytes: every certificate and revocation, the joiner's included, and the sealed root with what keeps it (not for a client) |
| `protected` | `true` for a protected mesh (omitted otherwise) |
| `sealed` | list of bytes: a vault's sealed blocks, for recovery |
| `held` | list of links: the vault's manifests, for recovery |
| `mesh` | link: the mesh's first grant (when it has grants) |
| `grants` | list of bytes: every grant, with what makes each count (see [[Grants#Sharing grants]]) |

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

A machine takes another to host a user only if the signature checks, the
device is certified by the user here and not revoked, and, if the mesh
has grants, the user holds `/mesh/user`; it can tell for a user it
doesn't serve as for one it does, since every user's certificates and
revocations go with the grants (see [[Grants#Sharing grants]]). So a
machine can't claim to host a user without one of the user's device
keys. Of a user it doesn't serve, only what's shared with them is the
other's (see **Guests**). What a machine was told is kept, and judged
again whenever the grants change, since the grants that make a user one
of the mesh's travel on their own and may arrive after: a user told of
before them is taken to be hosted once they come.

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

**Guests.** A user hosted by a member, who shares a view of an anchor with
another user this machine serves (one may read or write the other's, by
[[Grants#Grants on anchors|grants on anchors]]), is a **guest** of this
machine's: what's shared between them goes to and from the member,
whether or not the member hosts this machine's user. That's so even
where both users are served here, as what one user has for another is
withheld from the other's account. A guest is served nothing else.

- **What's shared with a guest:** the sets that count in views of anchors
  they may read, and what those sets are and reach; the sets made for
  their own views, and what those reach; tombs of sets on anchors they
  may read; and the signs of all these.
- **Asking as a guest.** A request naming a user this machine doesn't
  serve, from a member hosting them, is answered with what's shared with
  them, and no copies (`copies` empty), so a guest's machine is never
  counted as holding a user's blocks.
- **Noticing a guest.** Each machine notices every member of the claims
  shared with each guest it hosts, those it's not yet noticed and been
  answered, with `guest: true`; noticed again only once the grants change
  or it reconnects, or if the member couldn't place it (below). The
  member wants everything noticed that it lacks,
  there being nothing there for it to link to, and takes only claims from
  a push marked `guest`. Whether they count is for the claims there to
  say, as anywhere.
- **Fetching as a guest.** A fetch for an account asks the members
  hosting its user first, then those hosting its guests. A set pushed by
  a guest's machine for the view of a user served here is what that user's
  view is, so what it's set to is fetched for them at once, from the
  guest's machine if need be, and kept as theirs.

So a reader sees a view of an anchor on a machine that doesn't host its
owner, fetching from the owner's machines as the mount reads, and what a
writer sets for it reaches every machine of the owner's.

`hk node peers` lists, for each connected member, the accounts here whose
users it hosts, and last, what each member's called (see
[[Claims#Names]]), or `-`.

## Clients

A **client** is a device of a user that isn't a machine of the mesh: a
laptop that only visits, or an agent running somewhere the mesh doesn't
trust with everyone's plaintext. It keeps a repo of its own, as a cache,
and connects to one member, which serves it as its user, and no one else.
It isn't a member: it hasn't the swarm key, holds nothing but what's its
user's, and is counted on for nothing.

1. `hk node id` in the client's repo prints its peer ID, its device key.
2. `hk node invite <id> --client [--account <uid>]` on the member certifies
   it as a device of the account's user (asking the user's passphrase),
   lets it in, in `mesh_clients`, and prints its ticket.
3. `hk node join <ticket>` in the client's repo makes it a device of the
   user, a client of the member alone, in `mesh_client_of`.
4. `hk node run --clients [<addr>]` on the member listens for clients
   (port 4012 by default); `hk node run` on the client connects.

**Several members.** In a mesh with [[Grants|grants]], the invite also
gives the client's device `/mesh/client`, and every member serving the
client's user lets it in, as the grants say, whichever member invited
it; the clients a member was told of count only in a mesh without
grants. Members tell each other where they listen for clients in their
rosters (`clients`), so the ticket lists every member serving the user
that does, and a member tells a client that connects where the others
serving its user listen, and nothing else: a client keeping a repo
connects to all of them, and a thin client to whichever answers first.
A client is cut off only once every one of them is away.

**The gate.** A member listens for clients apart, without pnet, so that
port is open to anyone who can reach it, but only clients' keys get in:
noise authenticates the client by its device key, its peer ID, and the
member lets in only the clients it was told to whose devices are still
certified and not revoked, whose user the mesh recognizes. Each is let
in only where clients connect, and members only where members do, so
neither passes for the other. A client given `/mesh/client` is shut out
by every member once that's taken away (`hk node grant rm <id>
/mesh/client`), which `hk node forget` refuses to do for it, as for a
machine; one let in without grants is forgotten (`hk node forget <id>`)
and shut out at once. One whose device is revoked is shut out as soon as
the revocation reaches each member.

**Once in**, a client is as a machine hosting its user alone: it says so
over `hosts`, signing the member's peer ID with its device key, and
everything about blocks then goes as for a member hosting that user. Its
reads are fetches from the member, and what the member lacks of the
user's, it fetches from the user's other machines, to have when the
client asks again. What the client says, the member takes in as its
user's. What it adds, its audits copy to the member, counting its own
copy for nothing, so a block is short till a member holds it whatever
risks they share (a sandbox on the member's own disk still hands its work
over), and no longer: the member's audits see to the rest. It's a guest's machine as any is, so
what other users share with its user reaches it. But it's asked nothing a
member is:

- no copies go to it to make blocks durable, and none it holds count, so
  its member's audits and trims leave it out, and its sightings aren't
  believed;
- it's told of no members, its roster isn't heeded, and it's no part of
  mDNS or Kademlia;
- collection doesn't ask it, nor wait for it.

A client looks for nothing lost, its copies being a cache. It finds its
members where its ticket and their rosters said, and again wherever each
says it listens on the port it connected to it on.

`hk node peers` on the member lists each client, whether it's connected,
`client`, the account it acts for, and what it's called; `hk node status` on a client says
whose client it is.

### Thin clients

A **thin client** has no repo of its own: a directory holding its key
and the ticket it joined with, for a sandbox without a disk to keep a
repo on. Every `hk` command run with that directory as `--repo` connects
to its member, does what it's for there, and disconnects; nothing's kept
between commands. It's let in as any client is: `hk node id` in the
directory, `hk node invite <id> --client` on the member, then `hk node join --thin <ticket>` in the directory (again with a newer ticket from
the same member, to find it where it listens now).

- **Reading** (`hk cat`, `hk get`, `hk block get`) asks the member over
  `blocks`, as any client's reads do, and each block is verified against
  its CID. What the member lacks of the user's it fetches from the user's
  other machines, and the thin client asks again a while (up to 30 s)
  rather than failing at once. It reads up to 16 blocks ahead, so a file
  comes a few at a time without a sandbox's memory filling.
- **Writing** (`hk add`) imports on the client, as anywhere, and pushes
  the blocks to the member over `push`, a few megabytes at a time, which
  holds them for the client's account; then keeps the root, unless
  `--no-keep`. What the member won't take, short of space or of the
  account's quota, fails the command.
- **Saying** (`hk keep`, `hk tag`, `hk anchor new/set/show/root`, `hk
  whoami`) asks the member over `ask`, which answers as the client's
  account, signing with the account's key there, as for the host's users
  sharing a repo (`hk node run --shared`): the same commands, in
  `src/account.rs`. A keep, or an anchor set, of a DAG that isn't all on
  the member waits while the member fetches it, then answers.

Only clients ask; a member asked by anyone else refuses. What a thin
client says is signed by its account's key on the member, not by the
client's device key, so revoking the device shuts it out but leaves what
it said standing, as for any account. A thin client can't mount the
soup, nor do anything else needing a repo: a client keeping a repo as a
cache does that.

### Visitors

A **visitor** is a key outside the mesh, no user of it, that a user
shares a view of an anchor with: a friend who doesn't run a mesh, or an
agent trusted with one folder. What it may read is the owner's grants on
their views, as for any user they share with (see [[Grants#Visitors]]),
so it's given, passed on by those holding `/anchor/grant`, and taken
away as any share is, and every machine works out the same answer.

1. `hk node id` in a directory of the visitor's prints its key.
2. `hk anchor share <anchor> <peer> read` on a machine of the owner's,
   and `write` too, if it's to set it, and `grant`, to pass it on; with
   `--for 7d`, say, for only so long (see [[Grants#Expiry]]).
3. `hk node invite <peer> --visitor [--account <uid>]` prints a ticket
   saying where the members serving the owner listen for clients;
   nothing's certified.
4. `hk node join --thin <ticket>` in the visitor's directory, which is a
   [[#Thin clients|thin client]] from then on.

A member serving the owner, and recognizing them, lets in on its client
port each key the owner's shares say may read, unless it's a member or
client. A visitor reads as a guest of what's shared with its key, and
nothing else: `blocks` answers only for blocks those views reach
(`hk cat`, `hk get`), and `ask` only `whoami`, `shared` (the views shared
with it, `hk anchor shared`, as `<view> <owner> <commands>`),
`anchor show <view>`, and what a set or grant of its own needs:
`anchor heads <view>` (each head's CID and time), `grant heads` (the
mesh's), `anchor latest <view> <key>` (a key's sets that stand, to take
its write away), and `signed` (its last sign there).

A visitor let write a view writes as itself, since no member may sign for
it. `hk add` pushes the blocks, keeping nothing, and `hk anchor set <view> <cid>` signs a set with its own key, after the view's heads and
its last sign, and pushes both. The member holds what a visitor pushes
for the owner it's pushed for, if it serves them and the visitor may
write a view of theirs; of claims, it takes only sets and their signs,
which count in the owner's view as the grants say, there and on every
machine they reach. It refuses anything pushed otherwise, and `hk anchor
set` checks the set counts before it says so.

A visitor let pass a view on (`/anchor/grant`) does as itself: `hk anchor share <view> <peer> read` (or `unshare`) signs a grant with its
own key, after the mesh's, and pushes it. The member takes grants on
anchors from a visitor that may give on a view of the user it pushes
for, works the grants out again, and tells every member, so a visitor it
let in is let in everywhere the owner's served. A visitor's ticket names
no one and certifies nothing, so `hk node invite <peer> --visitor` on a
visitor prints its own, for the friend to join with.

Anything else it sends is dropped unanswered: notices, adverts, rosters,
hosts, grants, and identify. It's told
nothing unasked: no roster, hosts or grants, no notices, and it's no
part of audits, trims or collection. Unshared, it's shut out as soon as
the grant reaches each member. Kademlia and identify still answer it as
they would any connection, so it may learn where members listen, which
the swarm key keeps closed to it.

A share that ends shuts a visitor out within 10 s of its time, on each
member by its own clock, unless something else still lets it in.

`hk node peers` lists visitors as `<peer> <state> visitor -`, and `hk
node status` says how many are connected.

## Connections

Members are dialled on start. One that isn't reached is dialled again
2 s later, then after twice as long each time, to at most a minute, so
a member that was restarting, as an inviter does on joining a mesh, is
reached within seconds, and one that's offline is tried once a minute.
Connecting, or a connection dropping, starts it from 2 s again. Every connection is pinged
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
by older builds (see [[#Users sharing a mesh]]). `guest?` is `guest:
true`, from a machine that doesn't host the user, of what's shared with
them; omitted otherwise.

| Protocol | Request | Response | Purpose |
|---|---|---|---|
| `/holokeep/members/1.0.0` | `{members: [[peer, [addr]]], clients?: [[peer, [addr]]]}` | same | Exchange rosters, and where members listen for clients. |
| `/holokeep/hosts/1.0.0` | `{hosts: [{user: CID, device: CID, sig: bytes}]}` | same | Say which users each hosts. |
| `/holokeep/grants/1.0.0` | `{mesh: CID, have: [CID]}` | `{blocks: [[CID, data]]}` | Share grants (see [[Grants#Sharing grants]]). |
| `/holokeep/blocks/1.0.0` | `{want: [key], user?}` | `{blocks: [[CID, data]], missing: [key], copies: [[replica]]}` | Fetch blocks. |
| `/holokeep/adverts/1.0.0` | `{blocks: [[key, [replica]]], user?}` | `{held: [[key, [replica]]], offer: offer \| null}` | "These may be under-replicated." |
| `/holokeep/push/1.0.0` | `{blocks: [[CID, data]], copies: [[replica]], user?, guest?}` | `{kept: [[key, [replica]]]}` | Send copies to keep, or claims shared with a guest. |
| `/holokeep/notices/1.0.0` | `{blocks: [[CID, [key]]], user?, guest?}` | `{want: [CID], unplaced?}` | Notice structure and what it links to, or claims shared with a guest. |
| `/holokeep/trim/1.0.0` | `{keys: [key], user?}` | `{held: [[key, [replica]]], refused: [key]}` | "I mean to let go of these." |
| `/holokeep/dropped/1.0.0` | `{keys: [key]}` | `{}` | "I let go of these." |
| `/holokeep/condemn/1.0.0` | `{blocks: [key]}` | `{kept: [key]}` | "Does a keep of yours reach these?" |
| `/holokeep/ask/1.0.0` | `{words: [string]}` | `{lines: [string]}` | A [[#Thin clients\|thin client]]'s command, answered as its account. |
| `/holokeep/clock/1.0.0` | `{}` | `{got: uint, sent: uint}` | "What's the time?" (see [[#Clocks]]). |
| `/holokeep/serve/1.0.0` | `{user?, session, anchor, service, message}` | `{message}` | A 9P2000.L message for an anchor the peer serves, in a session; empty ends it (see [[Servers#Across the mesh]]). |

A request or response may be up to 64 MiB. libp2p's CBOR codec allows a
megabyte a request and ten a response by default, too little for a push
of whole 1 MiB chunks, which no member could copy to another until it was
raised.

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
noticed to members with the keys it links to, in batches of 256: every
10 s, and within 2 s of anything being written to the catalog, by the
daemon or another process such as the mount, as its latest generation
changing says (see [[Storage]]). A
member wants what it lacks that links to something it holds, or to
something else wanted from the same notice. Rules that keep this from
spreading everything everywhere:

- A `sign` is noticed by the claims it signs, not by its key or `prev`.
- An identity block counts as held only if it's a dissolved claim held
  here.

A member that can't place a notice, not knowing yet whose it is, says
so (`unplaced: true`) rather than wanting nothing: as when a notice for
a guest comes before the grants that make them one, since grants travel
on their own. The notice isn't taken as answered, and it's noticed
again at the next announce. Older builds don't say so, and are read as
placing everything.

Each member has a cursor over the catalog's generations (see
[[Storage]]) for each account served whose user it hosts, moved only once
it answers, and not for an unplaced answer, so a member that was away hears of what it missed. The
daemon's own account's is named by the peer ID; another's adds `#` and
the account's uid. A block sent to a member, by push, fetch
or want, takes the structure linking to it along. It's one hop: what
links to what a member holds, not what links to that.

Durability (`adverts`, `push`), trimming (`trim`, `dropped`) and garbage
collection (`condemn`) are described in
[[Replication and Retention]].

### Clocks

Every announce, 10 s, a member asks each other member connected, not
clients or visitors, for the time, unless it's still to answer the
last. As NTP does, it notes when it asked (`t1`) and heard back (`t4`)
by its own clock, and the member says when the ask arrived (`got`,
`t2`) and its answer left (`sent`, `t3`), by its, all in microseconds
since the Unix epoch:

```
ahead = ((t2 - t1) + (t3 - t4)) / 2      how far ahead the member's clock is
trip  = (t4 - t1) - (t3 - t2)            the round trip, less the member's time answering
```

Of each member's last 8, the one with the shortest `trip` counts, as
the least delayed. The **mesh's clock** is the median of the members'
`ahead`, with this machine's own as 0. When this machine's clock goes
more than 2 s from it, or comes back, the node says so where it logs.
`hk node clocks` lists each member's `ahead` and `trip`, and `hk node
status` the mesh's as `clock`.

It's advisory: nothing is judged by it. A grant's expiry is still each
machine's own clock's (see [[Grants#Expiry]]).

Source: `src/net/node.rs`, `src/net/clock.rs`, `src/net/clients.rs`, `src/net/thin.rs`, `src/net/node/asks.rs`, `src/net/hosts.rs`, `src/net/grants.rs`, `src/net/mesh.rs`, `src/net/blocks.rs`, `src/net/structure.rs`, `src/net/daemon.rs`.

## Forgetting members

In a mesh with grants, a machine is taken out by taking away its
`/mesh/machine` (`hk node grant rm <peer> /mesh/machine`), which every
machine heeds as the grant reaches it, and `hk node forget` refuses a
machine the grants say is in. In one without:

`hk node forget <peer>` is for a member that's gone for good, as a node's
old key. A member away holds up [[Replication and Retention#Garbage collection|collection]]
and [[Replication and Retention#Lost blocks|lost reports]], so this ends
that: it's no longer let in, and copies it was believed to hold aren't
counted. Others telling of it aren't heeded, in `mesh_forgotten`, so each
node has to say so itself. It's refused while the peer's connected.
Inviting it lets it back in. Its key can still sign, which `hk device
revoke` stops.

A client is forgotten by the member it connects to, at once, connected or
not, and is no longer let in.
