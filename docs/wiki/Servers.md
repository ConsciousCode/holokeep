**Partly implemented.** The first slice exists: serve claims, `[[serve]]`
services, and the mount reaching a service of its own node's, live (see
[[#Slices]] for what's yet to come, which this page describes as the
plan, saying so where it does).

A **served anchor** is an [[Anchors and Names|anchor]] whose tree a
process answers live, over 9P, instead of being read from blocks. It
appears wherever the anchor is linked, as any anchor does at its
[[Anchors and Names#Mount points|mount points]]: a mount point names an
anchor, not a value, so it doesn't matter to a directory whether the
anchor's state comes from sets or from a server. A server is one more
source of an anchor's changes, beside the people writing through the
[[Mount]]; with persistence on, it's a writer whose states become sets
like anyone's.

What this is for: sockets, which are meeting places rather than data and
mean nothing stored; a machine's shell; `/proc`-like status; and
gateways to other systems (feeds, APIs, other filesystems), whose fetched
state is worth keeping.

## Bindings

A binding has two halves, kept apart on purpose.

- **The routing fact is a claim.** A `serve` [[Claims|claim]] says an
  anchor is served by a node as a named service. It's public, replicates
  like any claim, and tells every machine's mount where to send what it's
  asked of the anchor. It's withdrawn with a tomb, as a keep is.
- **The implementation is local configuration.** Which socket implements
  a service, and as whom, is said only in the serving node's own
  [[Configuration]], never in a claim.

So a claim can never make a node run, open or connect to anything: a
node serves only the services its own configuration lists, and a claim
naming a service it doesn't have does nothing.

### The `serve` claim

dag-cbor, as claims are:

| Key       | Type        | Meaning                                                                    |
| --------- | ----------- | -------------------------------------------------------------------------- |
| `claim`   | `"serve"`   | The claim's type.                                                          |
| `target`  | [anchor]    | The anchor served, alone.                                                  |
| `node`    | bytes       | The serving node's peer ID.                                                |
| `service` | string      | The service's name in that node's configuration.                           |
| `persist` | bool        | Whether the server's states are kept as sets (see [[#Persistence]]).       |
| `at`      | integer     | When, in milliseconds since the epoch, so binding again is a new claim.    |

It counts only signed by a key that may set the anchor, as
[[Grants]] judge sets. Of the bindings that count for an anchor, the
latest wins; a tomb of it leaves the one before, or none.

### Services

In the serving node's `config.toml`:

```toml
[[serve]]
name = "notes"                        # what serve claims name
socket = "/run/user/1000/notes.9p"    # a Unix socket speaking 9P2000.L
```

A service runs as the owner of the configuration that defines it: a
user's services are in their repo's `config.toml`, and run as them; a
service as root must be in configuration only root can write, and a node
refuses one that isn't, as sshd refuses loose key files.

## The protocol

9P2000.L, as Linux's v9fs, QEMU's virtio-9p and diod speak it. 9P2000.u
isn't spoken: it's the older Unix extension .L replaced, and little
speaks only it. Plain 9P2000, as Plan 9, plan9port and Inferno servers
speak it, may come later; it's a different message set (`Topen`,
`Tstat`, `Twstat` rather than `Tlopen`, `Tgetattr`, `Tsetattr`).

`Tattach` carries who's asking, filled in by Holokeep and never taken
from the caller:

| Field     | Value                                                                 |
| --------- | --------------------------------------------------------------------- |
| `uname`   | The asking user's root key CID, as text.                              |
| `n_uname` | The asking user's uid on the serving machine, if local; else `~0`.    |
| `aname`   | The anchor's CID, as text, so one service may serve several anchors.  |

A service trusts these because only Holokeep can connect to its socket:
the node refuses a socket that isn't owned by the service's user, or that
lies in a directory anyone else may write.

## Through the mount

- A served anchor's mount point is a directory whose entries are the
  server's: lookups walk, listings `Treaddir`, and reads, writes,
  creation, removal, renames, symlinks and attributes are the .L
  messages of the same names.
- Nothing served is cached: entries and attributes have no TTL, and
  files open with direct I/O, so a size that changes, or isn't known, is
  read as it is.
- Requests to a server time out (10 s), failing `ETIMEDOUT`, and are
  answered on threads of their own (16), apart from the mount's (8), so
  a slow server holds up only what's asked of it. A served anchor itself
  is a directory without asking, since what a server's attached to is,
  so looking it up never waits on its server either.
- A server that can't be reached, its socket gone or its connection
  hung up, fails with `ENOTCONN`, and is connected to again on the next
  request. Not yet: a persisted anchor showing its last set meanwhile.
- Renaming between a served anchor and anything else fails `EXDEV`, as
  across filesystems, so `mv` copies.
- Only an anchor served by this node is reached so far; one served by
  another node is shown as an ordinary anchor, from its sets.

## Persistence

**Not yet implemented**: `persist` is said, and kept, but nothing reads it
yet.

With `persist` on, the serving node keeps the server's tree as sets, as
if someone had written it through the mount: its files become blocks, by
the same [[Rules]], and a set is signed when it's changed, at most once a
minute. Changes are found by `qid.version`, walking only directories
whose version moved. A file or directory whose qid has `QTTMP` (`0x04`),
which Plan 9 used for what's left out of its archive, is never kept: a
server marks what mustn't be, such as handshakes, and the rest is kept.

Persisted sets are ordinary history: `hk fs log`, replication, trimming
and everything else take them as they are.

## Privilege

The node forwards; it never acts for a caller with privileges of its
own. Running as root, it must give no user a way to act as root, or as
anyone else, without authenticating as them, as sshd doesn't.

1. **Who's asking comes from the kernel or a key**: the uid of a FUSE
   request, the peer credentials of a Unix socket, or a mesh peer's
   authenticated device key, mapped to its user. Nothing a message says
   about who sent it is believed.
2. **Grants are checked at attach**, for that identity.
3. **A service is defined by whoever it runs as** (see [[#Services]]).
4. **No confused deputy.** A user's service sockets are connected to with
   that user's credentials, by the user's own mount or by a helper that's
   dropped to them, never by a root daemon on their behalf, which would
   bypass the socket's permissions.
5. **Nothing is on by default**: no services, no persistence, no shell.

## Slices

1. **On one machine** (implemented). The `serve` claim (`hk serve add`,
   `rm`, `show`), `[[serve]]` configuration, and a 9P2000.L client in the
   mount for a socket of the mount's own user. Live only, with the rules
   of [[#Privilege]] and their tests.
2. **Across the mesh.** A node protocol carrying 9P to the serving node,
   which connects to the service as its user, for whoever grants let in.
3. **Persistence**, as above.
4. **A shell**, as a service: sessions in the manner of Plan 9's `/net`
   clone files, as the authenticated user only, if their device is
   granted a shell on that machine; root only as root's own
   configuration allows, as `/root/.ssh/authorized_keys` does.

Source: `src/claim.rs`, `src/store/claims.rs`, `src/served.rs`,
`src/ninep.rs`, `src/ninep/client.rs`, `src/mount/served.rs`.
