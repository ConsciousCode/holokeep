How several users share machines and data. **Most of this page is a
design, not yet implemented**: what exists is said under its own heading,
and everything else is planned. When a part is built, its description
moves to the page it belongs on and this page links to it.

## The trust boundary

A [[Mesh|mesh]]'s machines hold plaintext, and whoever has root on any of
them can read all of it. So the trust boundary surrounds a mesh's
machines. Users inside it needn't trust each other: the machines enforce
what each may do. Meshes overlap only where no trust is needed, as a
[[Protected Meshes|protected mesh]] holds only ciphertext.

| Layer | What it is | Who trusts it | What decides access |
|---|---|---|---|
| machine | A mesh member, named by `node.key` (its peer ID), holding plaintext | Every user of the mesh | The swarm key and the roster |
| user | A root key: a partition of the mesh with permissions of its own | No one need: machines enforce its limits | Roles and grants |
| device | A key acting for one user, on a machine or a client of one | Its user | The user's `device` certificate |

Inside the boundary, access is policy that trusted machines enforce.
Across it, access is capabilities and encryption, since nothing on the
other side enforces anything.

## What exists

- **Accounts.** One repo serves several users, each an account by uid
  with a device key in `accounts/` (see [[Keys and Users#Accounts]]):
  a host user's, or one with no login there. What an account sees is
  what counts for its user, and blocks it has; another account's are as
  good as absent.
- **A mesh serves several users.** The main mesh's one daemon serves the
  owner's account and any other joined to it, and machines tell each
  other which users they host, each proved by a device key's signature
  over the machine's peer ID, checked against the user's certificates. A
  user's blocks are served, noticed and pushed only to machines hosting
  the user, and audits, trims and fetches run per user among those
  machines (see [[Mesh#Users sharing a mesh]]).
- **A daemon's peer ID is its machine's.** Every daemon of a repo uses
  `node.key` for libp2p, whichever account it acts for.
- **The owner's device is the machine.** The owner's device key *is*
  `node.key`, so the owner's devices and the machines are the same keys,
  and an invite certifies the joining machine as a device as well as
  giving it `/mesh/machine`.
- **Other meshes act for one account each** (`--mesh <name>`), with their
  own swarm key, roster, port and daemon: protected meshes, and any made
  that way before the main mesh served several.
- **Grants.** The main mesh's machines and users are those its grants
  say, a history of claims from a first grant giving the founder `/`
  (see [[Grants]]): `/mesh/machine` makes a machine, `/mesh/user` a
  user, `/mesh/grant` lets one give what one holds, and an operator holds
  `/mesh`. Taking away undoes what was concurrent with it, the senior
  operator winning, and what's given goes with the giver's power to give
  it. Machines share grants as they connect.
- **Local clients.** With `hk node run --shared`, the host's other users
  ask the daemon over its socket, as their own accounts.
- **Block access tokens** are computed and checked (see
  [[Protected Meshes#Block access tokens]]), but nothing asks for them.

## Machines, users and devices

Not yet implemented, beyond what's above.

- **Devices apart from machines.** The owner gets a device key of their
  own, like any other account's, and `node.key` names only the machine.
  This waits for machines to be admitted by grants of their own, since
  until then an invite certifies the joining machine as a device, and
  one ID is all it needs.
- **Remote clients.** A device needn't be a machine. A client connects to
  a member machine and acts as its user, seeing only what that user may.
  An agent running on a machine outside the mesh (a hosted assistant) is
  a client, never a member, or it would hold everyone's plaintext.

## Roles and grants

Grants on the mesh are implemented (see [[Grants]]); roles, grants on
anchors, and `stands` are not yet. Modelled on SQL's, since a SQL
server, like a member machine, is trusted to enforce them.

| SQL | Here |
|---|---|
| role | A user, or a named role granted to users and other roles. |
| superuser, `CREATEROLE` | Mesh commands: `/mesh/machine`, `/mesh/user`, `/mesh/grant`. The **operator** holds `/mesh`. |
| database owner | The user whose first grant made the mesh: the first operator. |
| table owner | The user who made an anchor, with `/anchor` on it. |
| `SELECT` | `/anchor/read`: see what an anchor's value reaches. |
| `INSERT`, `UPDATE` | `/anchor/write`: sets on an anchor count for its owner too. |
| `WITH GRANT OPTION` | `/anchor/grant`, `/mesh/grant`: pass on what one has. |
| `GRANT role TO user` | `/role/member` on the role. |
| row-level security | Grants on a path within an anchor, if ever needed. |

- **Users are keys.** A user is its root key, a `libp2p-key` CID, much as
  a `did:key` is. Every key exists; a mesh **recognizes** one as a user
  once it's given `/mesh/user`. An unrecognized key can't act in the
  mesh, as a shell account can't be logged into before it's given a
  role. (Implemented.)
- **Roles are names** within the mesh, not keys: the machines enforce
  them, so nothing needs to prove it holds one. A role is the raw
  identity CID of its name, as a tag is (see [[Claims]]).
- **The roster is grants too**: admitting a machine is giving it
  `/mesh/machine`, which only someone holding it and `/mesh/grant` can
  do, so one user's stolen device can't admit a machine that would then
  hold everyone's data. (Implemented; a mesh without grants still merges
  any member's roster into every other's.)
- **Writers share an anchor** as devices of one user do now: each name is
  a multi-value register, and concurrent writes show as conflicts (see
  [[Anchors and Names#Conflicts]]).

### Commands

Privileges are named as [UCAN](https://github.com/ucan-wg/spec) names
commands: lower case paths starting with `/`, and a shorter path covers
the longer ones under it (`/anchor` covers `/anchor/write`, but `/mesh`
doesn't cover `/meshes`). `/` covers everything. A command names what
its holder may do itself: being a user is holding `/mesh/user`, and
recognizing others is holding that and `/mesh/grant`. The mesh's
commands are implemented, as [[Grants#Commands]] describes; the rest
aren't yet.

| Command | On | Allows |
|---|---|---|
| `/mesh/machine` | the mesh | Being a machine of the mesh. |
| `/mesh/user` | the mesh | Being a user of the mesh. |
| `/mesh/grant` | the mesh | Giving and taking away mesh commands one holds. |
| `/anchor/read` | an anchor | Seeing what its value reaches. |
| `/anchor/write` | an anchor | Sets on it, which count for its owner. |
| `/anchor/grant` | an anchor | Granting commands one holds on it. |
| `/role/member` | a role | Holding whatever the role holds. |

### The `grant` claim

Implemented for the mesh, as [[Grants#The grant claim]] describes; what
follows is the whole design. A `grant` is a [[Claims|claim]] type of its
own, signed by a device of the user making it (the first, by the
founder's root key):

| Key | Type | Meaning |
|---|---|---|
| `claim` | `"grant"` | |
| `target` | `[Link]` | Who it's for: users' root keys, machines' keys, roles. A set, as every claim's is. |
| `on` | `Link` | The anchor or role it's about; omitted for the mesh. |
| `add` | `[string]` | Commands given, sorted and distinct; omitted when empty. |
| `del` | `[string]` | Commands taken away, sorted and distinct; omitted when empty. |
| `stands` | `[Link]` | Only with `/anchor/write` (or what covers it) in `del`: the last of the targets' sets on `on` that still count. |
| `prev` | `[Link]` | The latest grants its signer had seen; empty for the first. |

```json
{"claim": "grant", "add": ["/anchor/write"], "on": {"/": "bafyqag…"}, "prev": [{"/": "bafyrei…"}], "target": [{"/": "bafzaa…"}]}
```

- **Grants have a history**: a mesh's grants are one history, by `prev`,
  as an anchor's sets are, apart from its anchors'.
- **The mesh is named by its first grant**, which gives the founder `/`,
  making them its first operator.
- **Taking away is a grant**, never a [[Claims|tomb]]: a tomb has no
  place in a history, so it can't say what came before or after it.
- **A grant counts if its signer could make it** in the state its `prev`
  names. Whether someone was an operator when they signed is then one
  answer, which every machine works out alike from the same grants,
  whatever order they arrived in.
- **Taking away undoes what was concurrent with it.** A grant by someone
  whose command is taken away doesn't count unless the taking away came
  after it (named it, or something after it, in its `prev`). So a stale
  or stolen device can't act in the window before it hears it's lost a
  command. When two operators take each other's away concurrently, the
  one made operator earlier in the history keeps it; the founder always
  does.
- **Writes after access is taken away.** Sets on a shared anchor don't
  name the grants they saw, or a writer whose access was taken away could
  claim to have seen an old state forever. Instead, taking
  `/anchor/write` away names, in `stands`, the last of the grantee's sets
  that count, as revoking a device does (see
  [[Keys and Users#Revocation]]); a set of theirs not before one of those
  doesn't count, though it stays in history.
- Taking away a `grant` command takes away what was granted with it,
  unless it was granted again by someone else.

Prior art: Matrix authorizes each event against the state at the events
before it; Ink & Switch's Keyhive and `@localfirst/auth` keep signed
membership histories, and `@localfirst/auth` undoes concurrent acts of
a removed member as above.

### Devices and certificates

A user's `device` certificate says a key acts for the user. Whether the
mesh must also recognize the key depends on what it can reach:

- **Devices that only sign**, clients and accounts on another's machine:
  the certificate is enough. The machine they act through checks it, and
  that the user is recognized.
- **A machine hosting only its own user** receives only what counts for
  that user, so its certificate could be enough, if the mesh lets users
  add such machines themselves: a setting of the mesh.
- **A machine hosting other users** holds their plaintext, inside the
  boundary, so it needs `/mesh/machine` from an operator. (Today every
  machine does.)

### Meshes don't merge

A mesh's users come into another by being recognized there and importing
a dump of what they had (`hk dag export`). Kept with their own root key,
their certificates and signatures come along, so what they said counts
for them as it did, with nothing signed again; under a new key it
wouldn't. Merging meshes without sending everything over again may be
worth looking into for efficiency.

## Across the boundary

Not yet implemented, beyond protected meshes.

- **Friends** hold ciphertext in a protected mesh, as now. A paid storage
  node is the same: a member of its company's mesh, where its customers
  are users, and a friend to each customer's mesh.
- **Capabilities.** Sharing with someone outside the mesh means giving
  them keys, not permissions. A block access token only lets a holder
  that can't read a block decide whether to hand it over; read access is
  holding the decryption key. Scoped sharing (a folder, not everything)
  needs keys derived down the tree, as Peergos's cryptree does, whereas a
  vault's keys are derived per block from one secret, so all or nothing.
- Revoking a capability means encrypting again, which is one reason
  grants, not capabilities, are used inside the boundary.
- **UCAN at the edge.** [UCAN](https://github.com/ucan-wg/spec) tokens,
  signed chains of delegation from a resource's owner, suit a remote
  client or someone outside the mesh: a member machine checks the chain
  when it's used. Inside, they don't fit: revoking is a growing set of
  revoked tokens with no place in a history, tokens expire by the clock,
  a required nonce keeps equal grants from being equal blocks, and their
  checking assumes one executor where every machine checks every claim.

## Phases

1. One daemon per machine serving every user of the mesh; hosting,
   serving and placement per user. Done.
2. The `grant` claim and its history: recognizing users, the operator,
   and a roster of grants. Done, but for devices apart from machines and
   named roles.
3. Grants on anchors, `/anchor/read` and `/anchor/write`, and taking
   them away.
4. Remote clients.
5. Capabilities for sharing outside the mesh.

## Open questions

- How a grant's `del` of `/anchor/write` names `stands` when the grantee
  wrote on several branches, and what happens to a set made after one of
  `stands` concurrently with another.
- The format of a mesh's setting for machines users add themselves.
- How grants are fetched and checked by a machine joining late: the whole
  history, as now, or a snapshot of the state with its heads, once there
  are too many to send each time or to work out quadratically.
- Whether a device that's revoked takes its grants with it: today a
  grant counts only while a key that signed it is certified, so revoking
  needs to sign again what it trusts, as it does for other claims.

Source: `src/account.rs`, `src/grants.rs`, `src/keys.rs`, `src/net/daemon.rs`, `src/net/grants.rs`, `src/net/hosts.rs`, `src/net/mesh.rs`, `src/net/node.rs`, `src/vault.rs`.
