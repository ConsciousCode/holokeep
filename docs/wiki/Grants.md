What users and machines may do in a [[Mesh|mesh]]: grants, a history of
claims giving and taking away commands. Once a mesh has grants, its
machines are those given `/mesh/machine`, and its users those given
`/mesh/user`. Why, and what's planned beyond this, is on [[Sharing]].

## Commands

A command is a lower case path from `/`: names of letters, digits and
`-`, each after a `/`, as [UCAN](https://github.com/ucan-wg/spec) names
them. A command **covers** itself and the longer ones under it:
`/mesh` covers `/mesh/user`, not `/meshes`, and `/` covers everything.

| Command | Allows its holder |
|---|---|
| `/mesh/user` | To be a user of the mesh: its accounts are served, and grants need it. |
| `/mesh/machine` | To be a machine of the mesh: let in, listed, and given plaintext. |
| `/mesh/grant` | To give and take away the mesh commands it holds. |
| `/mesh` | All of these: an **operator**. |
| `/` | Everything: the founder. |

A machine is one given `/mesh/machine` itself; an operator holding it
by `/mesh` isn't taken for a machine.

## The `grant` claim

A [[Claims|claim]] of type `grant`, never dissolved, signed by a key of
the user making it: its root key, or a device it certified (see
[[Keys and Users]]).

| Key | Type | Meaning |
|---|---|---|
| `claim` | `"grant"` | |
| `target` | `[Link]` | Who it's for: users' root keys, machines' keys. |
| `on` | `Link` | An anchor or role it's about; omitted for the mesh. Grants with `on` are kept, but not yet worked out. |
| `add` | `[string]` | Commands given, sorted and distinct; omitted when empty. |
| `del` | `[string]` | Commands taken away, sorted and distinct; omitted when empty. |
| `stands` | `[Link]` | Only with a `del` covering `/anchor/write`: the targets' last sets on `on` that count. Not yet worked out. |
| `prev` | `[Link]` | The grants its signer had seen last, sorted by CID bytes; empty for the first. |

At least one of `add` and `del`, and no command in both.

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
   doesn't count for a signer if a grant that counts, concurrent with
   it, targets that signer with a `del` overlapping (covering, or
   covered by) a command it needed. Grants with a `del` are decided
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
and then CID bytes. Working out is quadratic in grants for each grant,
fine for the dozens a mesh has.

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
- An account's user who doesn't hold `/mesh/user` is served to no one:
  no machine is taken to host them.

## Sharing grants

`/holokeep/grants/1.0.0`, request-response with the CBOR codec. On
connecting, and whenever its grants change, a machine sends each member
`{mesh: CID, have: [CID]}`: the mesh's first grant, and every grant it
has. The member answers `{blocks: [[CID, bytes]]}`: the grants it has
that the asker doesn't, with the signs of each, and the certificates and
revocations of the keys that signed them. If the asker has grants it
doesn't, it asks back. Only claims arriving under their own CIDs are
kept. A machine of another mesh, or without grants, answers with
nothing; one that knows the first grant but hasn't any grants yet asks
for them.

Source: `src/claim.rs`, `src/grants.rs`, `src/store.rs`, `src/store/claims.rs`, `src/net/grants.rs`, `src/net/node.rs`, `src/net/mesh.rs`, `src/main.rs`.
