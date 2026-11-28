How replication weighs a copy: a block's copies settle where the value
of one more copy meets the cost of the space it takes, rather than at a
count set in advance. Space spare is filled with copies, and given back
as it's needed. How copies are found, sent and let go of is in
[[Replication and Retention]]. Estimating `q` and local value aren't
built yet: `q` is what `copy-loss` says, 0.1 by default, and a copy's
worth only its durability.

## Cost

A node's **cost** of space is the odds of its being full:

```
c(p) = p / (1 − p)
```

where `p` is how full it is: what's stored over its `target` (see
[[Configuration]]), or, with none, over what's stored and free space
together, so the disk's other uses count only as they take free space.
`c` is 1 at half full, 9 at 90% and 99 at 99%,
and has no bound as the node fills. It takes the place of the
watermarks: there's no line at which a node starts or stops trimming,
only space growing dearer.

Cost and value are both taken per byte, so a block's size cancels.

## The value of a copy

A copy's **value** is how much it lowers the chance of losing its block,
in the same units as cost. Every copy is lost within a window with the
same probability `q` (see **Failure rates**), independently of the
others, so a block with `k` copies is lost with probability `q^k`, and
its `k`-th copy takes `q^(k − 1) × (1 − q)` off that. Weighted by how
much the block matters:

```
v(k) = I × q^(k − 1) × (1 − q)
I = 1 / (q^(n − 1) × (1 − q))
```

so that

```
v(k) = q^(k − n)
```

`n` is the block's **copies**: a [[Claims|keep]]'s `copies`, or else the
node's own (`--copies`). `I` is set so that a block's `n`-th copy is
worth exactly 1: as much as space costs a node at half full. So `n`
isn't a count to keep, but the copies a block settles at while nodes are
half full, on average; it's more where space is spare, fewer where it's
short.

A node drops the `k`-th copy once `c > v`, as `p > v / (1 + v)`. With
`q` = 0.1:

| copy, of n = 2 | value | worth keeping till the node's past |
|---|---|---|
| 2nd | 1 | 50% |
| 3rd | 0.1 | 9.1% |
| 4th | 0.01 | 0.99% |

and a block with `n` = 3 keeps its 2nd copy till 90.9%.

Which of a node's volumes a copy goes on, and whether a node holds more
than one, is its own placement, to be worked out later: the risks a
volume shares with others (see [[Replication and Retention#Risks]]) are
for that, not for this. Here `k` is how many members hold a copy: one
for each, however many of its volumes it's on, and a volume two
members share, as a NAS both mount, once. Counting tolerance instead
would bring risks back in: a risk every member shares, such as a mount
source, would leave every copy past the first worth nothing, though
each still guards against its own volume failing.

## Failure rates

**Not yet implemented**: for now `q` is `copy-loss`, or 0.1.

`q` is to be estimated from what's seen, with a prior:

```
q = (lost + 1) / (seen + 10)
```

A prior mean of 0.1, with the weight of 10 observations, so what's seen
outweighs it once there's more of it than that. An observation is one
copy over one window, and it's lost if the copy is gone from where it
was without having been let go of: trims, collection and forgetting are
said (`dropped`), and don't count. Only observations within the window
count, the sighting lifetime (`TTL`, 7 days; see [[Replication and
Retention]]), so the rate follows what's happening now.

`copy-loss` in [[Configuration]] fixes it. While it's set, `q` is what
it says. Removed, the last value becomes the prior's mean, and
estimating goes on from there; so setting it and taking it away again is
a reset.

## Adding and dropping

What the audit and the trim each ask of a block today, whether it's
short of copies and whether a copy here is spare, becomes one
comparison:

- **Adding.** A holder advertises a block while some member's copy would
  be worth more than space costs that member: `v(new copy) > c(member)`.
  Of the members for whom it would, the one chosen is the highest
  weighted rendezvous score (see [[Replication and Retention]]), with
  weight `1 / c`, so emptier members win in proportion.
- **Dropping.** A node lets go of its copy once it's worth less than its
  space costs here: `v(this copy) < c(here)`. Confirming with members
  first, and the lowest-ranked letting go first, are as now. The last
  copy never goes.

Both are judged with the block counted as stored: adding, by what space
would cost the member once it's taken the block; dropping, by what it
costs here, block included. So a copy that's just been taken isn't
worth dropping where it went, and one just dropped isn't worth taking
back, and nothing flaps at the margin with nothing to set. A block with
`k` copies stays at `k` while `c` lies between `v(k + 1)` and `v(k)`,
a band a factor of `1 / q` wide: the hysteresis the watermarks gave.
What's chosen within an audit counts what's already been sent to each
member, as the offers it answered with are of before.

What a block settles at is

```
k* ≈ n − ln c / ln (1 / q)
```

one copy fewer for each factor of `1 / q` in the odds of being full. A
copy on a node filling past what it's worth is dropped while an emptier
node's copy is still worth adding, so blocks move from fuller nodes to
emptier ones by these two rules, and a last copy, which never drops, is
handed to the emptier node first, as a trim hands off now.

## Local value

**Not yet implemented.**

A copy is worth something to the node holding it besides durability:
what it saves that node fetching it, `ℓ`. Its value here is

```
v_here(copy) = v(copy) + ℓ(node, store, block)
```

`ℓ` doesn't fall as copies are added elsewhere, so a node keeps what it
uses however well it's replicated, as a cache, and its copy still
counts towards durability. How a block counts is for the store it's in
(see [[Storage]]) to say:

- **Structure** (UnixFS nodes, IPLD, claims) is kept wherever it's
  linked to anything held, as now, for backrefs and queries to be
  answered here: it's always worth keeping, whatever the block.
- **Leaves** (raw blocks, the sharded store) are worth what they're
  used: `ℓ` is the uses of the block here within the window, so a block
  used once a week is worth a copy at half full.

## Cases worth knowing

- **A mesh filling up.** As every node fills, `c` grows without bound
  and copies fall back towards one, those with the highest `n` last; a
  write fails only once nothing has room.
- **Plenty of space.** Copies past `n` fill it, and are the first to go
  when it's needed.

## Not decided

- **Placement within a node**: which volume a copy goes on, and when a
  node's worth a second one, by the risks its volumes share. A machine
  with several disks is then a RAID 1 of sorts, guarding against disks
  failing but not the machine.
- **Where a block's placed.** Rendezvous could hash what a block was
  placed as part of, the file an `hk add` made, a fetched DAG, rather
  than the block itself, so a file's leaves land together. A block may
  be part of several, so it would be carried with the work as context
  (a table of placements and blocks, or with an advert), not worked out
  from links. To be argued on its own.
- **`ℓ`'s rate of exchange**: what a use is worth against space. A use a
  window for a copy at half full is a start; the cost of fetching, as
  measured, may say better.
- **The window.** `TTL` serves as both how long a sighting's believed
  and how long evidence counts; it may want to be configurable.
- **Many nodes.** Weighted rendezvous takes a hash per candidate, and
  adverts go to every member, each answering. For thousands of nodes,
  a block's candidates would be the few nearest it by hash, found
  through a DHT, with offers gossiped in coarse buckets; the rules here
  are the same among those.

Source: `src/balance.rs`, with its use in `src/net/durability.rs` and
`src/net/trim.rs`.
