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

- **Accounts.** One repo serves several of the host's users, each an
  account by uid with a device key in `accounts/` (see
  [[Keys and Users#Accounts]]). What an account sees is what counts for
  its user, and blocks it has; another account's are as good as absent.
- **A daemon's peer ID is its machine's.** Every daemon of a repo uses
  `node.key` for libp2p, whichever account it acts for.
- **The owner's device is the machine.** The owner's device key *is*
  `node.key`, so the owner's devices and the mesh's machines are the same
  keys.
- **A mesh acts for one account**, with its own swarm key, roster, port
  and daemon (`--mesh <name>`). Users sharing machines today means a mesh
  each, over the same machines, which can't share anything between them.
- **Local clients.** With `hk node run --shared`, the host's other users
  ask the daemon over its socket, as their own accounts.
- **Block access tokens** are computed and checked (see
  [[Protected Meshes#Block access tokens]]), but nothing asks for them.

## Machines, users and devices

Not yet implemented.

- **A mesh is its machines.** One daemon per machine serves every user
  the mesh has; a user is a partition of it, not a mesh of its own.
  Today's mesh is the case of one user.
- **Devices apart from machines.** The owner gets a device key of their
  own, like any other account's, and `node.key` names only the machine.
- **Hosting.** On connecting, a machine says which of the mesh's users it
  hosts, each by its device key's signature over the machine's peer ID
  and a time, with the user's certificate of that device. A block is
  served, noticed or pushed to a machine only if it counts for a user
  that machine hosts: a laptop of one user never hears of another's
  blocks, and a server hosting everyone holds everything.
- **Placement.** [[Replication and Retention#Durability|Rendezvous hashing]]
  chooses among the machines hosting a block's users, with every
  machine's risks and free space in one picture. Blocks are stored once
  however many accounts have them, as now.
- **Remote clients.** A device needn't be a machine. A client connects to
  a member machine and acts as its user, seeing only what that user may.
  An agent running on a machine outside the mesh (a hosted assistant) is
  a client, never a member, or it would hold everyone's plaintext.

## Roles and grants

Not yet implemented. Modelled on SQL's, since a SQL server, like a
member machine, is trusted to enforce them.

| SQL | Here |
|---|---|
| role | A user, or a named role granted to users and other roles. |
| superuser, `CREATEROLE` | Mesh privileges: admitting machines, admitting users, setting quotas. The **operator** is a role holding them. |
| database owner | The user whose first invite made the mesh: the first operator. |
| table owner | The user who made an anchor, with every privilege on it. |
| `SELECT` | `read`: see what an anchor's value reaches. |
| `INSERT`, `UPDATE` | `write`: sets on an anchor count for its owner too. |
| `WITH GRANT OPTION` | `grant`: pass on what one has. |
| row-level security | Grants on a path within an anchor, if ever needed. |

- **Roles are names** within the mesh, not keys: the machines enforce
  them, so nothing needs to prove it holds one.
- **Users are keys.** A user is its root key, a `libp2p-key` CID, much as
  a `did:key` is. Every key exists; a mesh **recognizes** one as a user
  once a grant says so. An unrecognized key can't act in the mesh, as a
  shell account can't be logged into before it's given a role.
- **The roster is grants too**: admitting a machine is a grant an
  operator signs, so one user's stolen device can't admit a machine that
  would then hold everyone's data. Today any member's roster merges into
  every other's.
- **Writers share an anchor** as devices of one user do now: each name is
  a multi-value register, and concurrent writes show as conflicts (see
  [[Anchors and Names#Conflicts]]).

### Grants

- **A `grant` is a claim type of its own**, signed by a device of the
  user making it, so it replicates like any [[Claims|claim]]. It gives
  or takes away privileges, of users, roles or machines, on the mesh or
  an anchor. Its fields beyond these aren't settled.
- **Grants have a history**: each names, as `prev`, the latest grants
  its signer had seen, as a `set` does for an anchor. A mesh's grants are
  one history, apart from its anchors'.
- **The mesh is named by its first grant**, signed by the founder's root
  key, which makes the founder its first operator.
- **Taking away is a grant**, never a [[Claims|tomb]]: a tomb has no
  place in a history, so it can't say what came before or after it.
- **A grant counts if its signer could make it** in the state its `prev`
  names. Whether someone was an operator when they signed is then one
  answer, which every machine works out alike from the same grants,
  whatever order they arrived in.
- **Taking away undoes what was concurrent with it.** A grant by someone
  whose privilege is taken away doesn't count unless the taking away came
  after it (named it, or something after it, in its `prev`). So a stale
  or stolen device can't act in the window before it hears it's lost a
  privilege. When two operators take each other's away concurrently, the
  one made operator earlier in the history keeps it; the founder always
  does.
- **Writes after access is taken away.** Sets on a shared anchor don't
  name the grants they saw, or a writer whose access was taken away could
  claim to have seen an old state forever. Instead, taking `write` away
  names the last of the grantee's sets that stand, as revoking a device
  does (see [[Keys and Users#Revocation]]); a later set of theirs doesn't
  count, though it stays in history.
- Taking away a `grant` privilege takes away what was granted with it,
  unless it was granted again by someone else.

Prior art: Matrix authorizes each event against the state at the events
before it; Ink & Switch's Keyhive and `@localfirst/auth` keep signed
membership histories, and `@localfirst/auth` undoes concurrent acts of
a removed member as above.

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

## Phases

1. Devices apart from machines; one daemon per machine serving every user
   of the mesh; hosting, serving and placement per user.
2. Roles, the operator role, and a roster operators sign.
3. Grants on anchors, `read` and `write`, and revoking them.
4. Remote clients.
5. Capabilities for sharing outside the mesh.

## Open questions

- The fields of a `grant`, and the privileges' names.
- Whether `device` certificates, signed by a user's root, stay as they
  are, or a mesh also has to recognize a user's devices.
- Joining a mesh that already has data of its own (a user who ran a
  one-user mesh) is likely simple: its machines are admitted, its user is
  recognized, and its claims already count for that user, so its data
  comes along with nothing granted. A new user in an existing mesh simply
  has nothing granted to it.

Source: `src/account.rs`, `src/keys.rs`, `src/net/daemon.rs`, `src/net/mesh.rs`, `src/vault.rs`.
