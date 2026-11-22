A **protected mesh** is friends holding your data encrypted, for mutual
replication. It's separate from your private mesh: no private claim
goes there, and the holders learn how much you keep, not what.

## Vaults

Each account has a **vault**, an internal account with its own ed25519
key and a 32-byte secret (`accounts/<uid>.secret`, mode 0600).
`hk protect add <cid>` encrypts a DAG into it.

Keys are derived per block with HMAC-SHA256 keyed by the secret:

```
derive(label, data) = HMAC-SHA256(secret, label || 0x00 || data)
```

For a block whose plaintext CID is `p` (binary form):

| Label | Use |
|---|---|
| `"key"`, `p` | the XChaCha20-Poly1305 key |
| `"nonce"`, `p` | the first 24 bytes are the nonce |
| `"bat"`, `p` | the block access token |
| `"manifest"`, empty | the key for manifests' sealed parts |

The same block encrypts the same way every time within one vault (so
pushing again is idempotent and duplicates are stored once), but nobody
without the secret can predict it, so no one can confirm a vault holds a
file they know, as convergent encryption would allow.

## Encrypted block format

An encrypted block is a **raw** sha2-256 block, laid out as Peergos does:

```
offset 0   8 bytes   magic "hkbats\x00\x01"
offset 8   3 bytes   0x81 0x58 0x20   (dag-cbor: a list of one 32-byte string)
offset 11  32 bytes  the BAT
offset 43  …         XChaCha20-Poly1305 ciphertext, with the 43-byte header as associated data
```

## Manifests

A vault keeps a **manifest** of what it encrypted, as a dag-cbor map:

| Key        | Value                                                                                                                                                                      |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `manifest` | the string `"holokeep-vault-1"`                                                                                                                                            |
| `blocks`   | plain links to the ciphertext blocks, at most 1024, so a holder keeps all of it from one keep                                                                              |
| `next`     | plain links to further manifests (omitted if none)                                                                                                                         |
| `sealed`   | a random 24-byte nonce, then XChaCha20-Poly1305 of dag-cbor `{plain: [CID bytes…], root: CID bytes}` under the `"manifest"` key, with associated data `"holokeep-vault-1"` |
| `bats`     | a list of one token: `derive("bat", sealed)`                                                                                                                               |

`plain` says which plaintext CID each entry of `blocks` is, in order,
and the first manifest's `root` says the DAG's root.

A holder learns how many blocks there are and their sizes, nothing of
their content or how they link. `hk protect restore <manifest>` fetches
what's missing through the vault's meshes, decrypts, checks every block
against its CID, and keeps the root.

## Holding for a friend

`hk node invite <peer> --mesh <name> --protected --device <vault> --quota <size>`
makes the friend's vault an internal account here (its user is the
vault's key, from `hk protect id` on their side). Its daemon hears of,
holds and serves only that vault's ciphertext, manifests and keeps, and
takes no more than the quota. Holding for each other is inviting each
other: each direction is its own mesh. `hk node status` tallies use.

## Recovery from the passphrase

The first `hk protect add` has the vault keep itself sealed with the
user's passphrase (`what: "vault"`, sealing its key and secret, see
[[Keys and Users]]), and the user's sealed root key. A
machine that has lost everything asks a friend for a new protected
invite, which carries those sealed blocks and the manifests. Joining
with it and the passphrase restores the vault and the user, whose root
certifies the new machine; `hk protect restore` brings the data back.

## Protecting the soup

`hk protect add` copies one DAG into the vault as it is then. `hk protect soup` protects the soup as it goes on: it publishes the root
anchor, and every anchor mounted in it, as sealed anchors (see
[[Capabilities]]), with no capability handed out, so no one but the
account reads them. The vault keeps what's published, so friends
holding the vault hold it, and the node publishes it again as the
anchors change, sealing only what's changed. It seals the vault with
the passphrase too, if `hk protect add` hasn't yet.

Unlike a protected DAG, what's published this way keeps its history as
heads, follows mount points, and is read through its keys down the
tree; what a holder learns is the same: how many blocks and how big,
padded, not how they link or what's in them.

`hk protect recover`, after the vault's recovered with the passphrase
(see [[#Recovery from the passphrase]]), fetches whatever the vault
keeps through its protected meshes, then reads back every anchor the
vault publishes, as its owner, with the read keys derived from the
vault secret: each one's heads merged and its tree put in the repo. An
anchor that's nothing here is set to it; one that's something else is
left be, and said so. It prints each anchor, its value, and `set`,
`already` or `otherwise here: left be`. So the passphrase and a friend
bring back the soup itself, not only DAGs protected one by one.

## Block access tokens

A proof of knowing a block's BAT, to ask for it:

```
proof = HMAC-SHA256(bat, CID bytes || 0x00 || asker peer ID || 0x00 || u64_be(at))
```

It's good for that block, that asker, and 300 seconds either side of
`at`, and checked in constant time. Nothing asks for proofs yet: only
members can reach a mesh, so sharing beyond it waits on a way in for
non-members.

Source: `src/vault.rs`, `src/cap.rs` (`recover`), `src/main.rs`.
