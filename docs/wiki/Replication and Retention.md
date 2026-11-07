Replication and collection pull in opposite directions: one makes copies
until every block is safe, the other lets go of what's surplus or
unwanted. Both run as slow trickles rather than schedules.

## Risks

Each volume has a set of **risks**, things whose failure would take every
volume sharing them:

- `disk:` each physical disk under the filesystem, found through sysfs
  past partitions, LVM, RAID and encryption, by WWID or serial number.
  A mirror's disks are one risk.
- `host:` the machine (by machine id), for internal disks.
- a mount source (`nfs4:server:/data`) for filesystems on no disk.
- `volume:<label hex>`, the volume itself, always.
- anything said by hand: `hk volume risk add <volume> home`.

A block's **tolerance** is how many risks would have to fail to lose
every copy: the smallest set of risks touching every copy. Copies on
one disk, or in one house, count as one.

## Durability

Each node audits what it holds and advertises (see [[Mesh#Protocols|protocols]]) the blocks whose tolerance
is below their target, with the replicas it knows of.

A block's **target** is what its keeps say. Walking up from it, by links
and from anchors' values to the anchors, each path stops at the first
block or anchor a [[Claims|keep]] targets; that keep's `copies`, or else the
mesh's (`hk node run --copies`, default 2), is the path's target, and
the block's is the most of any path. So a nearer keep says over a
farther one for what's under it (`hk keep add --copies 1` on what's
made again easily), and a block shared with something more precious is
as safe as that. What no keep reaches has the mesh's. Every member answers with what it holds of those
(correcting the advertiser's belief, both ways) and an offer: its
volume's risks and free space.

If a block is still short, a target is chosen by **weighted rendezvous
hashing** over the members whose copy would raise tolerance most:

```
draw(key, peer)  = (u32_be(sha256(key || peer_id_bytes)[0..4]) + 1) / (2^32 + 1)
score(key, peer) = -weight / ln(draw)
weight           = max(1, free space in MiB)
```

The highest score wins, and the block is pushed there. The same hashing,
unweighted, over the block's holders picks which holder is responsible
for it, so holders auditing at once send each block once. Every node
computes the same answer without coordinating. A target that doesn't
keep what it's sent is passed over for the next.

**Sightings** (beliefs about others' copies) are kept apart from the
node's own placement, expire after a week by the node's own clock
unless the peer has stayed connected, and are refreshed by advertising a
block once its sightings pass half their life.

**The audit trickle.** Each tick audits what arrived since the last plus
a random sample, sized so every block comes up about every 21 hours. A
tick that makes copies halves the interval (down to 2 s); a calm one
stretches it by a quarter (up to a minute); membership changes snap it
back. Intervals are jittered by a fifth.

## Trimming surplus

When free space falls below `--low-water` (2G), a node lets go of copies
the mesh can spare, by each block's target until it's above `--high-water` (4G). Only leaves in
its own stores go, never structure, never ranges of files imported in
place. Before letting go it asks every member what it holds *now*
(`trim`). A member about to let go of the same block refuses unless the
asker ranks below it by the holders' rendezvous order, so the
lowest-ranked goes first. What's let go is announced (`dropped`), and
members forget their sightings and audit it soon.

## Lost blocks

A `lost` [[Claims|claim]] reports a block couldn't be found as of a time.
It's a report, not a verdict: only a block that isn't here is lost, so
one that turns up, by any means, including the same bytes being added
again, ends it with nothing to retract. Only claims that count, as any,
are heeded, so a stranger can't stop anything being looked for.

- **Reading.** A mount asks members for a lost block once an hour per
  thread at most, rather than on every read; `hk cat`, `hk get` and
  `hk dag fetch` ask whenever they're run. Failing, the error says it's
  been reported lost.
- **Keeping.** `hk keep add` keeps a DAG short of its lost blocks, as
  `--shallow` would, saying so, if those are all it's missing. A root
  that's lost itself can't be kept.
- **Making good.** A claim reaches members as any does: those holding
  what it's about want it, and others don't hear of it, so a member away
  hears when it's back. A member's audit takes up lost claims it's newly
  seen, once each time the node starts, if it holds what they're about,
  so what's short of copies is copied on. A `keep --copies 1` it holds is
  at its target, so isn't pushed. A member getting the block only after
  it's heard nothing tells no one, but asking for it fetches it.

`hk lost scan` finds what to report. A candidate is a block with a
`holdings` row and no copy recorded here, that a block or claim here
refers to. Collection deletes the holding as it lets go, so what's left
went some other way: a file imported in place changed, say. Candidates
are fetched through the running node. What no member has is reported, one
claim each, unless any known member is away, when it only lists them. A
repo with members needs its node running; one with none needs nothing. A
reference counts even if it's only a version in an anchor's history.

A running node scans likewise 10 minutes after it starts and then daily,
unless `--no-lost-scan` (`hk node scan-lost` says now), and `hk node
status` says how many are lost. `hk lost add` reports by hand, whatever's
known, and `hk lost rm` tombs reports. `hk lost ls` lists what's reported
and isn't here.

## Garbage collection

A block is **condemned** when nothing here references it: no structure
links to it and no counting [[Claims|keep]] reaches it. Tags don't keep things; a
tomb's link is the opposite of a reference; claims are never collected.

An anchor's current value is referenced while a keep targets the anchor,
or while a block here links to the anchor: an IPLD link
(`{"/": "bafyqag…"}` in dag-cbor, a PBLink) or a **mount point** (see
[[Anchors and Names#Mount points]]), which is indexed as a link from its
block to the anchor. Claims don't count, as a `set` links to its own
anchor. What an anchor was before isn't referenced. A keep reaches
through any of these links, and when the block linking goes, what the
anchor is now is condemned in the same cascade. Each account's root anchor is kept by a keep of its
own (see [[Anchors and Names#The root anchor]]), so everything the root
names, however deep, is kept, and an anchor nothing names any more is
collected after the grace period, as a deleted file would be.

The node asks every member whether a keep of theirs reaches what's
condemned (`condemn`). A member that keeps it pardons it, as does a
reference arriving here. A condemned block goes only once:

1. it has been condemned for the grace period (a week),
2. every member has answered since, keeping none of it, and
3. nothing here references it still.

What it linked to is then condemned as of when it was, so a DAG goes a
level per round of answers, a week after its root was condemned,
however deep. Blocks condemned together are answered for as a batch.
Condemned blocks aren't audited, and don't count as held when another
member trims. Keeping again what was tombed takes a new keep (`n` + 1).

`hk node collect` condemns everything unreferenced now and lets go of
what's due; `--no-collect` turns collection off.

Source: `src/net/durability.rs`, `src/net/trim.rs`, `src/net/collect.rs`.
