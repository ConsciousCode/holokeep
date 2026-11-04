# Replication and retention

Back to [Data Soup](Data_Soup.md).

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

Each node audits what it holds and advertises the blocks whose tolerance
is below the target (`hk node run --copies`, default 2), with the
replicas it knows of. Every member answers with what it holds of those
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
the mesh can spare until it's above `--high-water` (4G). Only leaves in
its own stores go, never structure, never ranges of files imported in
place. Before letting go it asks every member what it holds *now*
(`trim`). A member about to let go of the same block refuses unless the
asker ranks below it by the holders' rendezvous order, so the
lowest-ranked goes first. What's let go is announced (`dropped`), and
members forget their sightings and audit it soon.

## Garbage collection

A block is **condemned** when nothing here references it: no structure
links to it and no counting keep reaches it. Tags don't keep things; a
tomb's link is the opposite of a reference; claims are never collected.

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
