A **claim** is a small dag-cbor block that says something about other
blocks, its *targets*: that they're tagged, kept, what an anchor is now,
who vouches for them. Claims are how anything mutable or relational is
expressed while every block stays immutable.

## Encoding

A claim is a canonical dag-cbor map with its type inline under the key
`claim`. `target` is a **set**, written as an array sorted by CID bytes
with no duplicates, so equal claims are equal blocks whoever makes them.
A claim with any other key, unsorted targets, or non-canonical encoding
is not a claim; it's stored as ordinary data.

| Type     | Fields (besides `claim`, `target`)                                                                        | Meaning                                                                                                                                                                                                                                                                                                                                                                                 |
| -------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `group`  | `into: Link`                                                                                              | The targets belong to `into`. With a raw identity CID for `into`, a simple tag named by its bytes.                                                                                                                                                                                                                                                                                      |
| `keep`   | `beyond: [Link]` (omitted if empty), `n: int` (omitted if 0), `copies: int` (omitted for the mesh's own)  | Keep the targets and what they link to, stopping at `beyond`. `n` is which time they're kept, since a tomb is forever. `copies`, at least 1, is how many failures it should take to lose what this is the nearest keep of (see [[Replication and Retention#Durability]]).                                                                                                               |
| `set`    | `value: Link`, `at: int`, `prev: [Link]` (omitted by older builds), `wrote: [bytes]` (omitted when empty), `for: Link` (omitted for the signer's own view) | The targets (anchors) are `value` as of `at`, seconds since the epoch, in place of the sets `prev` (an empty list for none). `wrote` lists paths under `value` (names joined by `/`, sorted and distinct) it wrote though they hold what they did, as when a conflict's resolved to its latest version. `for` is the user whose view of the anchors it's for, where it counts if they've let its signer write it (see [[Grants#Grants on anchors]]). See [[Anchors and Names#Forks and merges]] and [[Anchors and Names#Conflicts]]. |
| `tomb`   | none                                                                                                      | Retract the target claims.                                                                                                                                                                                                                                                                                                                                                              |
| `sign`   | `by: Link`, `at: int`, `prev: Link` (omitted for the first), `sig: bytes`                                 | `by` vouches for the target claims. See [[Keys and Users]].                                                                                                                                                                                                                                                                                                                             |
| `device` | none                                                                                                      | The target keys act for whoever signs this: a certificate when a user's root key signs it.                                                                                                                                                                                                                                                                                              |
| `lost`   | `at: int`                                                                                                 | The targets couldn't be found as of `at`, seconds since the epoch. See [[Replication and Retention#Lost blocks]].                                                                                                                                                                                                                                                                       |
| `grant`  | `on: Link` (omitted for the mesh), `add: [string]`, `del: [string]` (each omitted if empty), `stands: [Link]` (omitted if empty), `prev: [Link]`, `until: int` (omitted for good) | The targets hold the commands `add`, till `until` if it says, and no longer `del`, after the grants `prev`. Never dissolved. See [[Grants]]. |
| `same`   | `as: string` (omitted for each codec's data model)                                                        | The targets, two or more, are the same, read through the lens `as`. Never dissolved. See [[#Same]]. |
| `public` | `mode: string`, `n: int` (omitted if 0)                                                                   | The targets and what they link to are anyone's to have, in `mode`: `serve` or `announce`. `n` is which time, since a tomb is forever. See [[#Public]]. |
| `name`   | `name: string`, `n: int` (omitted if 0)                                                                   | The device whose key is among the targets goes by `name`. The targets are the key and its certificates. `n` is which time, since a tomb is forever. See [[#Names]]. |

Examples, in dag-json for readability:

```json
{"claim": "group", "into": {"/": "bafkqablnovzwsyy"}, "target": [{"/": "bafkrei…"}]}   (tagged "music")
{"claim": "set", "at": 1793750400, "target": [{"/": "bafyqag…"}], "value": {"/": "bafybei…"}}
{"claim": "keep", "target": [{"/": "bafybei…"}]}
{"claim": "keep", "copies": 1, "target": [{"/": "bafyqag…"}]}   (made again easily: one copy)
{"at": 1793750400, "claim": "lost", "target": [{"/": "bafkrei…"}]}
{"as": "unixfs", "claim": "same", "target": [{"/": "bafkrei…"}, {"/": "bafybei…"}]}   (a file and its whole multihash)
{"claim": "public", "mode": "serve", "target": [{"/": "bafybei…"}]}   (anyone's who asks, unannounced)
{"claim": "name", "name": "theseus", "target": [{"/": "bafzaaj…"}, {"/": "bafyqah…"}]}   (a device's key and its certificate)
```

A node of an older build doesn't know `copies`, so it takes such a keep
for ordinary data, not a keep; likewise `lost`, `grant`, and a set with
`for`, and `same`, `public` and `name`.

Not yet implemented, but planned: `attr` (attributes, with `prev`
history), `derive` (structure derived from the targets).

## Dissolved and precipitated

Claims are meant to be numerous and tiny, often smaller than a hash.
So:

- A claim **dissolves** if it has exactly one target and encodes to at
  most 128 bytes. Its CID is then a dag-cbor *identity* CID: the CID is
  the claim. Anyone can name it without hashing, and a store keeps it as
  rows with no multihash, found by what it says.
- Anything else is **precipitated**: an ordinary sha2-256 dag-cbor block.
- A `sign` never dissolves, and nor does a `keep` with a `beyond`.

A single-target tag named `music` is 80 bytes, and its tomb, which
contains the whole claim, is 109. Tags dissolve with names up to about
70 bytes; their tombs up to about 24.

## Semantics

- **Retraction is whole.** A tomb can't remove one target of a claim of
  fifty. So claims are made one relationship at a time, and a
  multi-target claim is a batch, equivalent to the single claims it
  unions. Retracting one relationship from a batch is a tomb for the
  batch plus single claims for the rest.
- **Tags union.** Claims with the same `into` combine their targets.
- **Sets replace what they name.** An anchor is what its heads say, the
  counting sets no other replaces, merged if there's more than one (see
  [[Anchors and Names#Forks and merges]]). Every set stays, so the
  history is free.
- **A tomb deletes the dissolved claims it targets at once** and keeps
  them from being put again. A precipitated claim it targets stays a
  block until collected, but stops counting.
- **What counts.** Once a repo has a user, a claim only counts when a key
  the user authorized signs it, and a tomb only retracts when it counts.
  Unsigned claims, or those signed by strangers, are kept as data but say
  nothing.
- **Claims travel with their claims.** A claim is sent along with its
  signatures and tombs, and theirs, however deep.

## Same

A CID's codec says how to decode a block, not what it means: a UnixFS
file's root decodes as a dag-pb node, and the file is what the UnixFS ADL
reads from it and the blocks under it. So a `same` claim names how its
targets are read, its **lens**, and says they read the same through it:

| Lens | Reads | So these are the same |
|---|---|---|
| none (`data` to `hk same`) | Each codec's data model: a raw block as its bytes | One value in dag-cbor and dag-json; a raw block and a dag-cbor byte string of its bytes; one block by two hash functions |
| `unixfs` | What the UnixFS ADL does: a file's contents, a raw block as a file of its bytes, a directory's entries (each name's CID), a symlink's target | A file however it's chunked or laid out, and its whole multihash, by any hash function; a directory basic or a HAMT |

- **Checkable.** `hk same add` checks before it says so, reading each
  target through the lens; what isn't here is fetched. A raw target
  beside others is checked by its multihash against what they read as,
  so it needn't be here: a kept file's whole multihash is no block anyone
  can get. Past 64 MiB that's only by sha2-256.
- **An equivalence.** It's symmetric and transitive, so claims of one
  lens join: `hk same ls` lists whatever's the same as a block, or as
  what is, and so on. Lenses don't mix: the same file isn't the same
  dag-pb node. Membership is by CID, not multihash, as one multihash is
  different things to different codecs.
- **A set, and nothing else.** Which member to prefer depends on what
  for (matching Kubo, streaming, what's near), so it's said elsewhere, by
  the node's policy or facts about members, and claims still merge by
  union alone.
- **What isn't `same`.** Similarity isn't transitive: a lossy copy of a
  lossy copy drifts. Renditions of one work (a JPEG of a PNG, a scaled
  copy, a translation) are a `group` of the work, said explicitly.
- **Kept files say so.** A file [[Storage#Placement|kept whole]] is
  said to be the same, through `unixfs`, as the root it was imported
  as, by its whole CID (raw, sha2-256): how DASL and ATproto name a
  blob, and a common denominator any layout can be checked against. A
  repo opening with files kept before says so of each, once, in one
  sign. The repo's own record of which roots a kept file is
  (`shard_roots`) stands apart, so its ranges never hang on a claim.
- **A whole CID reads through a layout.** A raw CID that isn't a block
  here, as a kept file's whole one isn't, is read through a layout a
  `unixfs` claim that counts says it's the same as, one whose root is
  here if any is, else fetched from members as blocks, each checked
  against its own CID: by `hk cat`, `hk get`, and the mount's
  `cid/<cid>`. `hk cat` and `hk get` hash what they write and fail if
  it isn't the whole CID, `get` taking the file away; a read of part of
  it, as the mount's, can't be checked against a whole hash, so takes
  the claim at its signer's word. What's fetched, and must be this
  account's to read, is the layout: knowing a whole CID isn't reading
  it. Members answer for one: asked for a whole CID as a block, a member
  without it sends the `same` claims saying what it's the same as, with
  their signatures, beside its not having it, and the asker keeps them
  and, if they count there, fetches the layout instead. A thin client,
  keeping no claims, can't yet. A lens is a name for now; one not
  known is kept, and says nothing this can check. A lens could later be
  an ADL's code by CID, as WASM.

```
hk same add --as unixfs <cid> <cid>…   # check, then say so
hk same ls <cid>                       # lens and CID of what's the same
hk same rm --as unixfs <a> <b>         # tomb the claims saying both
```

## Public

Everything is private by default: another account's blocks are as good as
not here, and nothing is given to anyone outside the mesh. A `public`
claim makes its targets, and whatever they link to however deep,
anyone's to have, in a mode:

| Mode       | Given to whoever asks by CID | Announced                       |
| ---------- | ---------------------------- | ------------------------------- |
| `serve`    | yes                          | no                              |
| `announce` | yes                          | the targets, as Kubo's `roots` |

- **Roots are what's announced.** Announcing every block of a big DAG
  is millions of records reprovided daily; a fetcher finds the rest
  from whoever provides the root.
- **An anchor is public as it is now**, every head of it if it's forked,
  by whichever account's sets count here, and so is what it mounts:
  what it was isn't, once it's changed. A public folder is an anchor,
  as Kubo's `mfs` strategy announces its MFS root. **A group**, such as
  a tag, is public as its members are now: tagged later, it's public;
  untagged, it isn't.
- **What's public is kept by unit, not walked to.** Each public target,
  anchor and group is a *unit*, whose reach is what it links to, by the
  stores' link indexes, here or not, short of other units, which are
  its edges (`public_units`, `public_reach`, `public_edges`). A unit's
  filled in as it's made and as blocks arrive, and walked again alone
  when its anchor or group changes, so publishing a soup of mounted
  anchors and editing one walks that one's tree. Whether a block's
  public is a lookup and a walk up the few units to a public claim,
  however widely the block's shared. Walking up through every link on
  each request, as for guests, would let anyone make a node visit
  every parent of a block thousands of files share, only to say no.
- **A tomb of a public claim needs nothing taken away.** Units count
  only through claims that count, as signed by a key that counts for
  any account here, and not retracted; making it public again takes a
  new claim, `n`. Who's authorized changing, every unit's built again.
- **A whole CID is public if its layout is**, as a `unixfs` same claim
  says (see [[#Same]]).
- A mode not known is kept, and makes nothing public. [[#Amino]] serves
  what's public over Bitswap and announces what's in `announce` mode,
  and the [[#Gateway]] serves it over HTTP.
- **Every member hears what's public**, holding it or not: a notice
  marks public claims as wanted by all, so any member can serve what's
  public, fetching it if need be. What's under a public root is known to
  be once what links to it is here, so it's known block by block as a
  reader walks it, or all at once with a CAR.

```
hk public add [--serve] <cid>…   # anyone's to have; announced unless --serve
hk public add --tag <name>        # what a tag tags, as it does
hk public ls                      # mode and root of each
hk public check <cid>             # public or private, by whatever reaches it
hk public rm <cid>                # private again
```

## Amino

`hk node run --amino [addr]` (or `amino = true`) takes part in Amino,
the public IPFS network: a swarm of its own, apart from the mesh, with a
key of its own (`amino.key`), so nothing there links to the mesh, and no
private network, so its peers reach its Kademlia DHT
(`/ipfs/kad/1.0.0`) and Bitswap 1.2.0, and nothing else.

- **What's served** to a peer who wants it is what's public, and what was
  fetched from Amino to be shared (all that's fetched, unless fetched to
  be kept to oneself). Bitswap holds nothing for anyone: a node gets only
  what it asks for. Whoever wanted something once may again, so what's
  fetched is served back; it's never announced, since provider records
  are kept by indexers long after they lapse. Kubo wants things only of
  peers it's had blocks from, on its LAN or peered (`Peering.Peers`),
  and a few at random, so what's only served reaches a Kubo node that
  peers this one, or has had blocks of it before.
- **What isn't served**, private or missing, is said not to be had alike,
  where the asker wants to be told, and only after 50 ms and up to 50 ms
  more at random: how long it takes says nothing of which.
- **Fetching** from Amino is for what the mesh hasn't got: `hk dag fetch`
  and `hk cat`, `get` and `dag export` ask it, through the running
  node, once members haven't the DAG, but only of a CID nothing here
  links to, or a public one. What's private here may be linked to by
  what's lost, and asking for it would say it's wanted; `hk dag fetch
  --amino` asks regardless. Providers of each root are looked for in the
  DHT, and whoever's connected is asked whether they have some of what's
  wanted; providers, and whoever says they have it or sends any of it,
  are its sources. Blocks are wanted only of sources, at most 256 at a
  time, each of one source in turn, as Kubo's sessions do: wanting every
  block of everyone connected floods them, and Kubo keeps only a peer's
  first 1024 wants. What's sent is kept, each block checked against its
  CID, and what it links to wanted too. A block a source says it hasn't,
  or hasn't sent in 3 s, is wanted of the next, since an answer lost
  isn't sent again. A fetch goes on as long as blocks keep arriving, and
  gives up after 20 s of nothing.
- **Seeking**: a fetch that's had nothing for 2 s, from no source or
  none with much of it, seeks who has a block it's waiting on, one not
  sought before, and again every 5 s while nothing comes: in the DHT,
  and of a router (`amino-routers`, the Routing V1 HTTP API), which
  knows many providers the DHT doesn't, from IPNI's indexers. A DAG's
  roots may be provided by many who hold little under them, as whoever
  visited a site's front page, so it's what's under them that's sought.
  Those a router finds are dialled and become sources, and, as servers
  of the DHT, join the routing table, so the DHT finds more next time.
  A router learns what's sought of it, as a DNS resolver learns what's
  visited, so it's asked only of a fetch that's stalled: the more of
  Amino that's known, the less it's asked. It's `delegated-ipfs.dev`,
  Kubo's, unless `amino-bootstrap` says peers of an Amino of its own;
  empty for none. Fetching waits on a router's answer, and on the
  roots' providers being looked for, but a router finding no one new
  doesn't keep it from giving up.
- **Gateways**: some providers a router finds are trustless gateways,
  reached over HTTP rather than Bitswap (`/dns/…/tcp/443/https`, or
  `…/tls/http`), as storage providers often are. Each block's had of
  them as `/ipfs/<cid>?format=raw`, 8 at a time from each
  (`amino-gateway-requests`), and checked
  against its CID as a block from Bitswap is, what it links to wanted
  too; one that sends something else, or 404s, is taken not to have
  that block, and one that's had none of 16 running is asked no more.
  A gateway sees what's wanted of it as a Bitswap peer does.
  `--private` keeps what's fetched to oneself, answered as missing.
- **Announcing**: what each `announce` claim names is provided on the
  DHT, an anchor as what it is now and a group, such as a tag, as its
  members, as Kubo's `roots` strategy does; looked at again within 5 s
  of the catalog changing, and every minute regardless, what's no longer
  to be is no longer provided, and the DHT republishes the rest. Nothing fetched is ever announced. A provider record says
  where the node's reached, which takes a public address, or
  `amino-server`.
- **Joining**: Amino's bootstrap peers, unless `amino-bootstrap` says
  others (empty for none). Where it's reached is found by AutoNAT: peers
  asked dial back where they see it, and only an address one reaches is
  taken, so the DHT takes it for a server. Being seen at a port it
  listens on isn't enough, since it dials out from that port, and a
  firewall or NAT lets the answers back in but no one else.
  `amino-server = true` makes it a server regardless, reached where it
  listens, as on a LAN. A peer that serves the DHT joins the routing
  table where it says it listens, wherever it's connected from, so
  those who dial in, and those a router finds, add to it; only public
  addresses are taken, from it and from routers alike.

`hk node amino` says how the running node is in Amino: its peer id,
where it listens and where it's taken to be reached, whether it's a
server of the DHT and how many peers its routing table has, how many
roots it provides, how many peers it's connected to, how many times a
router's been asked who has a block, and the last dial that failed, which says why if it can't join; `--peers` lists each
connected peer, where, and its agent (`kubo/0.42.0`).

## Gateway

`hk node run --gateway [addr]` (or `gateway = true` in
[[Configuration]]) serves what's public over HTTP as a trustless
gateway, as the IPFS spec has it, for whatever can't reach the mesh: a
browser, `curl`, any IPFS client, which checks each block against its
CID, so nothing needs trusting.

- `GET` or `HEAD /ipfs/<cid>?format=raw` (or `Accept:
  application/vnd.ipld.raw`) is the block; a whole file's CID, which is
  no block, is the file, read through its layout.
- `?format=car` (or `Accept: application/vnd.ipld.car`) is a `CARv1` of
  the DAG under it, depth first, each block once; `dag-scope=block`, of
  it alone.
- Only what's public is served, and what isn't here is fetched through
  the node, only if it's public. What's private is answered exactly as
  what's missing is, `404`.
- Paths under a CID, and other formats, aren't served (`400`, `406`).
- It's plain HTTP, on `127.0.0.1:4014` by default, for a reverse proxy
  in front to give it HTTPS. A connection has a thread of its own, at
  most 32 at once, idle ones closed after 15 s.

## Names

A device is known by its key, its peer ID, which is what grants, allow
lists and certificates name. A `name` claim gives it a label for
people, shown by `hk node peers` and `hk node status`, and never what
anything's let in by.

- A device names itself by its hostname when its node first runs, if
  it's never been named. Once it's named, renamed or unnamed, that
  stands.
- Any device of the user may name another, as two machines of one
  hostname need. Naming a device again tombs what it was called.
- The targets are the device's key and its certificates. Every member
  holds the certificates, so a name reaches every member, the way any
  claim reaches holders of what it targets. Guests are sent only what's
  shared with them, so they never hear of names.
- Of the names that count, the one with the greatest `n` wins, and of
  those, the least CID, so names given at once on two devices come out
  the same everywhere. Two devices may share a name, so `peers` shows
  the name beside the peer ID, not instead of it.
- A name is up to 64 characters, with no tabs, newlines or spaces at
  either end. Claims are kept, so a device's old names stay in its
  history even once they're tombed.

```
hk node name                       # what this device is called
hk node name <name>                # call it this
hk node name --peer <id> <name>    # call another of the user's devices this
hk node name --rm [--peer <id>]    # call it nothing
```

## Backreferences

Every claim is a backreference of what it targets: "which claims are
about this block?" is one lookup. Claims are stored as rows (`claims`,
with targets in one shared `claim_targets` table), and a tag is a row,
not a file. The `tags (target, tag, name)` SQL view names simple tags.

Source: `src/claim.rs`, `src/store/claims.rs`.
