What users and machines may do in a [[Mesh|mesh]]: grants, a history of
claims giving and taking away commands. Once a mesh has grants, its
machines are those given `/mesh/machine`, and its users those given
`/mesh/user`; and a user may let others read or write their view of an
anchor (see [[#Grants on anchors]]). Why, and what's planned beyond
this, is on [[Sharing]].

## Commands

A command is a lower case path from `/`: names of letters, digits and
`-`, each after a `/`, as [UCAN](https://github.com/ucan-wg/spec) names
them. A command **covers** itself and the longer ones under it:
`/mesh` covers `/mesh/user`, not `/meshes`, and `/` covers everything.

| Command | Allows its holder |
|---|---|
| `/mesh/user` | To be a user of the mesh: its accounts are served, and grants need it. |
| `/mesh/machine` | To be a machine of the mesh: let in, listed, and given plaintext. |
| `/mesh/client` | To be a [[Mesh#Clients\|client]] of the mesh: a user's device that's no machine, let in by every member serving its user where they listen for clients, and counted on for nothing. `hk node invite --client` gives it. |
| `/mesh/grant` | To give and take away the mesh commands it holds. |
| `/mesh` | All of these: an **operator**. |
| `/` | Everything: the founder. |
| `/anchor/read` | On a user's view of an anchor: to see it, and what it reaches. |
| `/anchor/write` | On a user's view of an anchor: sets on it for them count there. |
| `/anchor/grant` | On a user's view of an anchor: to give and take away the commands on it one holds. |
| `/anchor` | All of these: a user holds it on their own view of every anchor. |

A machine is one given `/mesh/machine` itself, and a client one given
`/mesh/client` itself; an operator holding either by `/mesh` isn't taken
for one.

## The `grant` claim

A [[Claims|claim]] of type `grant`, never dissolved, signed by a key of
the user making it: its root key, or a device it certified (see
[[Keys and Users]]).

| Key | Type | Meaning |
|---|---|---|
| `claim` | `"grant"` | |
| `target` | `[Link]` | Who it's for: users' root keys, machines' keys. |
| `on` | `Link` | An anchor it's about (see [[#Grants on anchors]]), or a role (planned, kept but not worked out); omitted for the mesh. |
| `add` | `[string]` | Commands given, sorted and distinct; omitted when empty. |
| `del` | `[string]` | Commands taken away, sorted and distinct; omitted when empty. |
| `stands` | `[Link]` | Only with a `del` covering `/anchor/write`: the targets' latest sets on `on` that still count (see [[#Taking write away]]). |
| `prev` | `[Link]` | The grants its signer had seen last, sorted by CID bytes; empty for the first. |
| `until` | integer | Only with no `del`: when what it gives goes, in seconds since the epoch (see [[#Expiry]]); omitted for good. |

At least one of `add` and `del`, and nothing in one overlapping
(covering, or covered by) anything in the other: `add: ["/mesh"], del:
["/mesh/machine"]` isn't a grant. Each grant means one thing.

### Expiry

A grant that gives, and takes nothing away, may say `until`: what it
gives is held only before then, by the clock of the machine working it
out. It's still in the history, and counts, so what was made after it
stands as it did; but at its time it gives nothing, so what its targets
passed on of it goes too, as when a giver's power goes, unless someone
else gave it as well, and what they set till then still counts. Taking
away has no `until`: it lasts, since an end to it would give back what
it took, which is a grant's to do.

Every machine works the grants out as of now, so machines whose clocks
differ disagree for as long as they differ, about grants ending between
them. A daemon works them out again within 10 s of a grant's time
passing, and with them who may read and write each view and who's let
in, so a visitor whose share's gone is shut out. A repo with no daemon
running works them out as of whenever a grant's next made there.

```json
{"add": ["/"], "claim": "grant", "prev": [], "target": [{"/": "bafzaa…"}]}
{"add": ["/mesh/machine"], "claim": "grant", "prev": [{"/": "bafyrei…"}], "target": [{"/": "bafzaa…"}, {"/": "bafzaa…"}]}
```

A mesh's grants are one history by `prev`. The mesh is named by its
**first grant**, which gives its one target, the founder, `/`, and is
signed by them. Grants not reaching it by `prev` aren't the mesh's, and
one naming a grant that isn't here waits for it.

## Working out who holds what

Every machine works out the same from the same grants, whatever order
they arrived in. A grant's **signers** are the users whose root key
signed it, or who certified a key that did and haven't revoked it.

1. **Valid.** A grant is valid for those of its signers who held, in
   the state its `prev` names (its ancestors, worked out alone),
   `/mesh/user`, `/mesh/grant`, and every command in its `add` and
   `del`. The founder needs nothing.
2. **Concurrent.** Two grants are concurrent if neither is among the
   other's ancestors.
3. **Taking away undoes what was concurrent with it.** A valid grant
   doesn't count for a signer who no longer holds what it needed in its
   state at its `prev` with the grants taking away that count and are
   concurrent with it heeded too: whether a command was taken from
   them, or went with what they were given by someone taken away (5).
   Only what its ancestors gave is held there; what's given
   concurrently makes nothing valid. So naming an old `prev` gains
   nothing, however late a grant's made. Grants with a `del` are decided
   first, in order of their most senior signer: the founder, then
   whoever was given a command covering `/mesh/grant` earliest, by
   position in the order below. So of two operators taking each other's
   commands away concurrently, the senior keeps theirs. Then the rest
   are decided against those that count.
4. **Taking away wins.** Someone holds a command if a grant that counts
   gives it to them (an `add` covering it) and no grant that counts,
   after it or concurrent with it, takes it away (a `del` overlapping
   it).
5. **What's given goes with the power to give it.** A grant's `add`
   holds only while one of its signers holds `/mesh/user`,
   `/mesh/grant`, and each command it gives, worked out from the founder
   outwards, so a chain of gifts with no founder at its root holds
   nothing.
6. The founder holds everything, always.

Grants are ordered by depth (the longest `prev` path back to the first)
and then CID bytes. Every grant's state at its `prev` is worked out
afresh, and again with what's taken away concurrently with it, if
anything is: polynomial of low degree in grants, fine for the dozens a
mesh has.

A device's revocation is the boundary for what it signed, not a time:
grants it signed up to the sign trusted are signed again and count,
those after don't (see [[Keys and Users#Revocation]]).

## Grants on anchors

Every user holds `/anchor` on **their own view** of every anchor: what
the sets that count for them say it is. A grant `on` an anchor is about
the view of whoever it's judged from, not anything of the anchor's
everywhere: "I'll take your sets on this as mine". So grants on anchors
are worked out separately for each user who signed one on that anchor,
as the **owner** of a view, by the rules above, with the owner in the
founder's place, `/anchor/grant` in `/mesh/grant`'s, and being a user
still a matter for the mesh: the signer must hold `/mesh/user` in the
mesh's state at the grant's `prev` (and with what's taken away
concurrently heeded), and a giver must hold it still for what they gave
to be held. A mesh's operators and founder hold nothing on a user's
view, and no one does once the owner isn't a user.

**Visitors.** A key that's no user of the mesh, and that the mesh's own
grants have never named (as founder, user, machine or client, given or
taken anything), may still be given commands on a user's view: it's a
**visitor**, and holds there what the grants say, as a user would.
Being no user, it has no devices: it signs with its own key, which is
itself. Its sets count where it may write, and taking write away names
which of them stand, as for a user. Its grants on a view are judged as
a user's are, where it signs as itself, so it passes on what it may
give, to users or other visitors, and what it gave goes with its power
to give it. Its own views are no one's, since it's no user. A user
taken from the mesh was named by its grants, so keeps nothing as a
visitor, and signs nothing on a view. See [[Mesh#Visitors]] for how a
visitor reads, writes and passes on.

If B holds `/anchor/grant` on U's view of A and passes `/anchor/read` to
C, that grant is judged in U's view (where B may give it), and in B's
own (where B holds everything). Taking B's `/anchor/grant` away in U's
view takes C's read there too, not in B's.

### Views

A user's view of an anchor is named by a CID of its own, an anchor
too (see [[Anchors and Names#Views]]): the identity CID of
`{"anchor": <its nonce>, "of": <user>}`. What a catalog shows of a view
is what counts in that user's view of the anchor, if the acting user
may read it (it's theirs, or they hold `/anchor/read`), and nothing
otherwise.

A set counts in owner O's view of anchor A if:

- it's for its signer's own view (no `for`), and O signed it; or
- it's for O's view (`for: O`; see [[Claims]]), and O, a user O has
  given `/anchor/write` on A, or one whose set stands (below) signed it;
- and no tomb O signed retracts it.

So the owner and every writer who may read see the same history, and
concurrent writes merge and conflict as one user's devices' do (see
[[Anchors and Names#Forks and merges]]). A writer's own view of the
anchor is apart: a set for O's view doesn't count in theirs.

A reader sees the blocks the view reaches, whatever it is and was, and
what that mounts, as though they were their own (see [[Keys and
Users#Accounts]]), without a keep of their own.

### Taking write away

Sets don't name the grants their signer had seen, or a writer whose
write was taken away could claim to have seen an old state forever.
Instead, a grant taking `/anchor/write` away names, in `stands`, the
writer's latest sets in the view that still count: `hk anchor unshare`
names those that none of theirs came after, one for each branch they
wrote on. A set of theirs that's one of those, or before one by `prev`,
still counts; any other doesn't, though it stays in history. Giving
write back makes all of theirs count again, the ones in between too,
since sets don't say when they were made.

## Using them

- The first invite of the main mesh's owner (see [[Mesh#Joining]]) makes
  its first grant, signed with the user's root key, then gives
  `/mesh/machine` to every member and `/mesh/user` to the user of every
  other account it serves. `hk node grant init` does the same for a
  mesh made before there were grants.
- After that, each invite gives the joining machine `/mesh/machine`,
  and an invite `--account` for another user gives that user
  `/mesh/user`, signed by the inviting device. A ticket brings the
  mesh's first grant and every grant (see [[Mesh#Joining]]).
- `hk node grant add <who> <command>…` and `hk node grant rm <who>
  <command>…` give and take away, by peer ID; `hk node grant ls` lists
  who holds what.
- A daemon works its grants out afresh as they arrive, lists as members
  exactly the machines they say are in, lets in and dials only those,
  and closes connections to any other. A machine taken away is no
  longer counted as holding copies. Rosters from other members are
  heeded only for machines the grants say are in.
- `hk node forget` refuses a machine the grants say is in.
- `hk anchor share <anchor> <who> read|write|grant|all… [--for <d>]`
  gives a user commands on the acting user's view of an anchor, or on
  another's they may pass on, if `<anchor>` is a view of one, for good or
  for a while (`90s`, `30m`, `12h`, `7d`, `2w`); `hk anchor unshare` takes
  them away, naming what `stands` of theirs taking write; `hk anchor
  shared [<anchor>]` lists who holds what on views of anchors the acting
  user owns or holds something on, and till when, if all of it ends; `hk anchor view <anchor> <owner>`
  prints a view's CID, to show, mount or set.
- Who may read and write each view is worked out from the grants into
  `anchor_access`, and the sets that stand into `anchor_stood`, when a
  grant's made here and whenever the daemon's grants change, for the
  SQL that counts sets.
- An account's user who doesn't hold `/mesh/user` is served to no one:
  no machine is taken to host them.

## Sharing grants

`/holokeep/grants/1.0.0`, request-response with the CBOR codec. On
connecting, and whenever its grants change, a machine sends each member
`{mesh: CID, have: [CID]}`: the mesh's first grant, and every grant it
has with what makes each count: the signs of it, and the certificates
and revocations of the keys that signed them, and of every key each of
the mesh's users has certified, so any machine can tell a user's devices,
whether or not it hosts them. The member answers
`{blocks: [[CID, bytes]]}`: those of these it has that the asker
doesn't. If the asker has some it doesn't, it asks back. So a
revocation, or a signing again, travels as a new grant does. Only claims arriving under their own CIDs are
kept. A machine of another mesh, or without grants, answers with
nothing; one that knows the first grant but hasn't any grants yet asks
for them.

Source: `src/claim.rs`, `src/grants.rs`, `src/store.rs`, `src/store/claims.rs`, `src/net/grants.rs`, `src/net/node.rs`, `src/net/mesh.rs`, `src/main.rs`, `src/mount.rs`.
