## Keys

All keys are **ed25519**. A key is named by a CID: the identity multihash
of its protobuf-encoded public key (`08 01 12 20` then 32 bytes) under
the `libp2p-key` codec (`0x72`). So a node's key *is* its libp2p peer
ID. A node's secret is kept as libp2p keeps it, a protobuf keypair, in
`node.key` in the repo, mode 0600.

## Devices and users

- A **device** is a node's key.
- A **user** is a root key. It signs nothing but certificates: a `device`
  claim naming device keys, signed by the root, says they act for the
  user; a `tomb` of that claim, signed by the root, revokes it.
- Devices sign everything else.

A repo has no user until it makes a mesh: its first `hk node invite`
generates the root, which certifies this device and the joiner. Until
then claims are taken at their word, though the node signs them all the
same, so they count once the user certifies the device. Joining or
merging meshes is certifying devices; nothing is signed again.

## Signatures

A signature is itself a [[Claims|claim]], about the claims it signs:

```
{"claim": "sign", "target": [claims…], "by": <key>, "at": <secs>, "prev": <previous sign>, "sig": <64 bytes>}
```

- `sig` is ed25519 over the canonical dag-cbor encoding of the same map
  **without** `sig`.
- Keeping signatures outside claims means equal claims stay equal blocks
  whoever makes them (a keep from two devices is one keep with two
  signs), and small claims can still dissolve.
- What a batch says is signed once, when the batch commits.
- **Chains.** Each sign names the device's previous sign as `prev`
  (omitted for its first), taken under the database's write lock, so an
  honest key has exactly one chain. A fork (two signs with one `prev`)
  means a copy of the key is at work; `hk device list` says `forked`.

## Revocation

Revoking a device stops everything it signed from counting, then the
revoking node re-signs, with its own key, what the revoked device alone
had signed up to a sign the user names (`hk device log` lists them).
Nothing made later can be among those, so a thief can't backdate: what
the device said before it was lost stands, nothing after does.

`hk device log <peer> --claims` lists what each sign says, and whether the
device is all that makes each claim count. `hk device revoke` lists what'd
stop counting, trusting what it's told, and asks before going ahead (`--yes`
when there's no terminal, `--dry-run` to only see). `--until` takes a sign for
each chain, if the key's forked, as a time can't say which it means. What keeps
the user's sealed root and root anchor is signed again regardless, as neither
is any good to lose.

## The sealed root

The root key is kept on no machine. It's **sealed** with the user's
passphrase as a dag-cbor block the mesh keeps like any other, and opened
only on the node that invites or revokes, then forgotten:

```
{
  "cipher": "xchacha20poly1305",
  "kdf": "argon2id",
  "key": <key CID>,
  "memory": <KiB>, "passes": <n>, "lanes": <n>,
  "salt": <16 bytes>,
  "nonce": <24 bytes>,
  "sealed": <ciphertext>,
  "what": "vault"            (only when more than a key is sealed)
}
```

- The passphrase goes through argon2id v0x13 with the block's cost and
  salt to make a 32-byte key. The default cost is RFC 9106's second
  recommendation: 64 MiB, 3 passes, 4 lanes.
- The plaintext is the protobuf keypair, followed by anything else sealed
  with it (a vault's secret).
- The associated data is the key's CID bytes, then `0x00` and `what` if
  present, so a sealed block opens only as the key it says.

Whoever holds the passphrase is the user. A stolen device holds no more
of the root than anyone.

## Accounts

One [[Storage|repo]] can serve several users, each an **account** by
uid, with a device key in `accounts/` (the owner's is `node.key`) and,
once in a mesh, a user. An account is a host user's, or an unused uid
for a user the machine hosts who has no login on it. A catalog acts for
one account at a time: what it says is signed with that account's key,
and what it sees (tags, keeps, anchors, devices) is what counts for that
account's user. A daemon serving several accounts looks as each in turn
(see [[Mesh#Users sharing a mesh]]).

Blocks belong to whoever has them: each account's view is the blocks it
put here within the grace period, plus whatever a counting keep of its
reaches. Anything else is as good as absent to it: it can't read it,
its mesh can't fetch it, and members asking hear nothing of it. Knowing
a CID isn't being able to read it. The bits are stored once and kept
while any account has them.

`hk node run --shared` lets other host users use the daemon's socket,
identified by `SO_PEERCRED`. The owner and root may ask anything;
others may fetch, keep and tag as their own account, and what a host user
fetches is fetched for their account if the mesh serves it.

Source: `src/keys.rs`, `src/claim.rs` (`Sign`), `src/account.rs`, `src/store/claims.rs`.

## Restoring a user

`hk device restore` makes a repo a device of a user with no other device
to invite it, from a root key sealed in the repo, as brought by
`hk dag export --sealed-root`. It tries each user's sealed root here with
the passphrase, signs a certificate for this device, and joins the user. A
repo that already has another user refuses. Their other devices stay
certified, since a lost one can't say it's lost: `hk device revoke` them.

## Recomputing what's authorized

The `authorized` table holds what certificates and their tombs say, and is
worked out again when a claim that might change it arrives: a certificate,
a tomb of one, or a signature by a user's root key. A device's signature
can't change it, so doesn't cost anything.
