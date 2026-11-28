# Notes for agents

Continuity between sessions working on holokeep: how the user likes to
work, what's been decided and why, and what's been learned the hard way.
The README says what holokeep is and where it's going; the wiki
(`docs/wiki`, a snapshot of the one in the soup) says how each piece
works. This is what neither says.

## Working agreements

- **Commit when green, and push.** Any time the checks below pass, commit
  with a descriptive message and push to `origin master`
  (`git push origin master`: the branch has no upstream set). No need to
  ask. Never commit a red tree, never force-push.
- **Never commit `IDEAS.md`.** It holds the user's own uncommitted notes.
- **Gate on exit codes, not on grepping output.** A `grep -E
  "FAIL|all passed" && git commit` chain once committed over a failing
  run, since the grep matched `FAIL`.
- **The checks:**
  - clippy in three configurations, all must be clean:
    `for f in "" --all-features --no-default-features; do cargo clippy --all-targets $f; done`
  - `cargo test --all-features`
  - `tests/mesh/run.sh [scenario...]`: rootless Podman containers; the
    whole suite takes about 10 minutes, so name the scenarios a change
    touches (`amino` for Amino work).
    **A flaky scenario is a bug until shown otherwise**: every one so
    far has been a real race with effects outside the test. Reproduce
    with `KEEP=1` in a loop till it fails, then look at the kept
    containers.
  - `tests/mesh/kubo.sh`: hk against real Kubo (needs `ipfs` on the
    PATH); for anything touching Amino.
  - `scripts/kubo-compare.sh`: for anything touching the importer.
  - `cargo install --path .` after each commit.
- **Never run `cargo fmt`.** The repo isn't rustfmt-formatted: lines are
  long on purpose, and fmt rewrites every file. It was run once by
  mistake and undone.
- **Lints are strict**: clippy pedantic and nursery are denied, as are
  `unwrap`, `expect`, indexing, unchecked arithmetic, `as` conversions
  and panics. Use `get`, `saturating_*`, `checked_*`, `?`. Functions over
  100 lines and structs with more than three bools are refused too.
- **Prose style**, in comments, docs, the wiki and commit messages:
  plain English that says what something is and does ("what's had of a
  gateway", "a fetch that's had nothing for 2 s"), no jargon where a
  plain word does, no marketing. Commit subjects read like
  `Amino: fetching as sessions, and where it's reached by AutoNAT`.
- **Keep the wiki current** when a protocol, format or command changes.
  It lives in the soup at `~/soup/wiki` (the user reads it in Obsidian:
  page names with spaces, `[[wiki links]]`, no H1, a `Source:` line; its
  "Style Guide" page has the rest). Edit it there, then
  `scripts/snapshot-wiki.sh` copies it into `docs/wiki`. **The soup takes
  some seconds to take in an edit**, so a snapshot taken straight after
  can be stale: wait, then check `docs/wiki` has the new text before
  committing.
- **README roadmap**: tick off what's done, one line each, saying how
  it's checked.
- **Schema changes** must keep old repos opening: add a fixture with
  `scripts/make-repo-fixture.sh <date>` and raise `SCHEMA` in
  `src/store.rs`.

## Running things

- The user's real repo is `~/.holokeep`, mounted at `~/soup`. Don't run a
  new build against it while their older daemon and mount run: views
  call functions the old build lacks, and edits stall. After
  `cargo install`, **tell the user to restart their daemon and mount.**
- The installed `hk` is in `~/.cargo/bin`, which isn't on the agent
  shell's PATH; use `./target/release/hk`.
- Throwaway nodes: a fresh repo under the scratchpad, with
  `HOLOKEEP_REPO=<dir>/repo HK_PASSPHRASE=throwaway`, listening on ports
  that don't clash with the user's (e.g. `--listen
  /ip4/127.0.0.1/tcp/4111 --amino /ip4/0.0.0.0/tcp/4115 --no-collect
  --no-lost-scan`). Start with `nohup setsid … & disown` (a plain `&`
  dies with the shell). Stop with an anchored pattern,
  `pkill -f "^(\./target/release/)?hk node run --listen /ip4/127.0.0.1/tcp/4111"`:
  a loose `pkill -f` matches the shell running it.
- The user's machines: **ender**, their desktop, behind a home NAT,
  where development happens; **miny**, a VPS (`relay = true`,
  `gateway = true`, `amino = true`) behind ufw; **theseus**. To update one,
  copy `target/release/hk` over and restart the daemon: no need to pull
  and build there.
- Ports: 4011 the mesh, 4015 Amino (TCP and UDP, for QUIC), 4014 the
  gateway (local by default). 4001 is Kubo's, nothing of hk's.

## Shell safety

- No `rm` on a variable path (`rm -rf "$E/repo"`): the safety filter
  blocks it, and the variable could be empty. Use fresh `mktemp -d`
  directories that need no removing, or spell out literal paths.
- Never put a delete in the same command as the selection that picks its
  targets. A `find … -exec test … -exec rm` once ran the user's own
  `~/bin/test` (always true) and deleted 39 directories instead of 13.
  List and count first, delete literal paths separately, and use
  absolute paths for utilities in `find -exec`.
- No privilege escalation without the user's explicit say: no docker
  group (rootless Podman instead), no scripted sudo doing real work.
  `sudo -n true` as a probe is fine.

## Design decisions, and why

- **Homeostasis over hyperparameters** (the user's founding principle,
  2026-11-27): lean into homeostatic, organic, cybernetic dynamics
  wherever possible, so the system settles by itself with as few knobs
  to tune as can be. Config is different: it's an explicit statement of
  the user's intent that can't be derived from what's actually wanted.
  So prefer forces that balance (memory pressure against replication
  pressure, say) over thresholds to set, and when adding a setting, ask
  whether it states intent or merely tunes a process that could find
  its own level.
- **Copies are a balance, not a count** (built 2026-11-28; the wiki's
  "Replication as a Balance"). Space costs a node `p/(1−p)`, `p` its
  stored over its `target`, or over stored + free with no target (the
  user chose this so a disk's other files don't cut default
  durability). A block's `k`-th copy is worth `q^(k−n)`, `n` its
  `copies`, `q` the chance of losing a copy (`copy-loss`, 0.1). Add
  where worth ≥ the member's cost with the block, drop where worth <
  cost here; both count the block as stored, which is what stops
  flapping. `k` is how many members hold a copy (a shared volume label
  once), not tolerance: with tolerance, a risk all members share (in
  the Podman tests every copy has `overlay:overlay`) made every copy
  past the first worth 0, so members dropped them and an offline member
  couldn't edit. Which volume a copy goes on is a later, local
  placement policy, and risk classes are out of the balance on
  purpose. A node whose fill isn't known (no free space
  reported, as in the in-memory node tests) costs 1, so `copies` acts
  as a count there. Not built: estimating `q` from losses (Beta prior
  `(lost+1)/(seen+10)` over the `TTL` window, `copy-loss` then fixing it
  till removed, a reset), and local value `ℓ(node, store, block)`.
  Pinned for their own debates: placement units (rendezvous on what a
  block was placed as part of), a configurable `TTL`. The watermarks
  (`low-water`, `high-water`) are gone; the keys still parse, with a
  warning, since the config denies unknown keys.

- **IPLD**: one canonical data model that codecs round-trip through;
  codecs hand-rolled on the serde harness in `src/serde/`, checked against
  `ipld/codec-fixtures`. `src/ipld.rs` is an abandoned experiment: don't
  build on it. The ecosystem's `ipld-core`/`serde_ipld_*` are dev-only
  oracles (they bring a different `Multihash`).
- **Stores**: multihashes interned per database, ids never crossing
  databases; the multihash is the interchange. It's enough that *an*
  index can be rebuilt. Equivalence across hash functions goes through
  `Same` claims. Parse, don't verify. The offset store never scans for
  offsets.
- **Whole-file CIDs** (kept files, `Same` claims) bridge DASL/ATproto
  blobs to UnixFS, so a whole-file CID can be fetched as blocks verified
  one at a time rather than from a central blob server.
- **Transactions** need only be as big as keeps states valid; batch for
  performance, not by reflex.
- **History is a reference**: letting go of an anchor's past is always
  explicit (`hk anchor forget --before`). No automatic retention or age
  expiry unless asked.
- **The mesh**: libp2p with a private network key and a daemon owning
  the network; the CLI opens SQLite directly and asks the daemon over a
  Unix socket. Need-driven exchange (adverts of under-replicated blocks,
  wants), sightings apart from blocks, rendezvous hashing to pick who
  holds what. Collection: a keep is only added by a node holding all it
  keeps; condemned, every member asked, collected after a grace period.
- **Users and devices**: a root key certifies device keys; no "root
  machine" (the root is sealed with a passphrase, carried in the mesh
  and in invites). No user until a mesh. Private (one user's trusted
  nodes), protected (friends, separate meshes) and public (Amino) are
  separate regimes. Blocks aren't readable across accounts by CID.
- **Mesh relays**: circuit relay v2 and DCUtR over TCP (the private
  network rules out QUIC); a member with `relay = true` relays, others
  reserve on it. The relay is a full member for now, so it holds blocks
  like any other: with `copies = 2` over three machines, miny holds
  everything. A relay-only node holding nothing is a later option.
- **What's public** (the user's rules):
  - Everything's private by default. A `public` claim makes its roots,
    and everything they link to, public: in `serve` mode given to anyone
    who asks by CID, in `announce` mode also provided on the DHT. Only
    roots are announced, as Kubo's `roots` strategy.
  - What's fetched from Amino is served back by default but **never
    announced**: indexers keep provider records long after they lapse.
    `--private` keeps a fetch to oneself.
  - A private block gets exactly the answer a missing one does, with the
    same timing.
  - Whether a block's public is looked up in stored tables, never by
    walking up through parents per request.
  - Bitswap holds nothing for anyone; its ledger is only for fairness.
  - Phase two, experimental, to be designed in the wiki first: relaying
    others' wants (which hides one's own among them), gated by the
    ledger, a cache quota and a denylist (badbits, IPIP-383), announcing
    relayed fetches only after 24 h ± jitter. The long-term aim is users
    of content indirectly funding its hosting.

## Races to watch for in the mesh

Grants travel on their own protocol, so anything a machine receives may
come before the grants that make sense of it. Judging it against the
grants as they are, once, and never again, loses it: a member told of a
user it hosted before the grants recognized them took it to host no one,
and a guest noticed of shared claims before its grants arrived wanted
nothing and was never noticed again (both fixed 2026-11-27, found as the
`shared` scenario's flakiness). When something's judged by grants, keep
what was said and judge it again when they change, or have the other
side say "can't tell yet" (`unplaced`) rather than "nothing".

## Amino, as learned against Kubo and the real network

- **Kubo sends each Bitswap reply on a stream of its own** and never
  resends one lost. libp2p-stream hands inbound streams over a channel
  with no room and resets the overflow, so Amino takes Bitswap streams
  with its own behaviour (`src/net/amino/inbound.rs`).
- **Kubo wants only of peers it's had blocks from**, LAN peers, peered
  peers and a few at random (`Internal.Bitswap.BroadcastControl`). So
  what hk only serves reaches a Kubo that peers hk.
- **Kubo keeps about 1024 wants per peer**, so fetching is windowed: 256
  wanted at once, each of one source, moved to the next after 3 s or a
  DONT_HAVE. Connected peers are only asked whether they have some.
- **Kubo's WAN DHT ignores peers with only private addresses**, and its
  LAN DHT is another protocol (`/ipfs/lan/kad/1.0.0`): tests use
  11–13.0.0.0/24, not private ranges.
- **The bootstrap peers have RSA keys** (the `rsa` feature).
- **Being seen at the port you listen on proves nothing**: hk dials out
  from it, and a firewall or NAT lets the answers back in. Reachability
  is AutoNAT's dial-back.
- **A DAG's roots are provided by many who hold little under them**:
  whoever visited a site's front page. So a stalled fetch seeks
  providers of a block it's waiting on, in the DHT and of a delegated
  router (`delegated-ipfs.dev`, Routing V1), which knows far more
  providers than the DHT. The router learns what's sought, so it's asked
  only when a fetch stalls.
- **Many providers are HTTP-only trustless gateways**, or reachable only
  through relays or over QUIC. A site that wouldn't fetch at all came at
  400 KB/s once gateways were used.
- **Relays carry almost nothing**: a Kubo relay cuts a circuit after
  2 min or 128 KiB, and Kubo serves no Bitswap over a relayed
  connection. Data flows once DCUtR has punched through, which mostly
  takes QUIC; TCP simultaneous open between rust-libp2p and Kubo fails.
- **rust-libp2p's Kademlia drops a provide whose query times out**, with
  no record put anywhere; Amino provides it again at the next look.
  Queries stall on closest peers that can't be dialled.
- **Podman quirks** for tests: its networks route to each other through
  the host, so a "NAT" network can still be dialled into from another
  podman network (kubo.sh keeps the fetcher out with
  `Swarm.AddrFilters`); `--internal` cuts a network off entirely. The
  test image has no `ip`; use `hostname -I`.

## Where things stand (2026-11-27)

Amino phase one is done: serving and announcing public claims, fetching
as sessions, AutoNAT, delegated routing, HTTP gateways, QUIC, the relay
client with DCUtR, and relay reservations behind a NAT. Not done:
phase two (relaying wants); a fetch outliving the command that started
it, which the user may want cancelled with the command; `hk block get`
falling back to Amino as `cat` and `get` do; a "hold no copies" setting
for a relay like miny; `strip = true` for a smaller binary.
