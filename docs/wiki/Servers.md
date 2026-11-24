**Partly implemented.** The first three slices exist: serve claims,
`[[serve]]` services, the mount reaching an anchor served by its own node
or, through it, by another machine, the user's own or, as grants let
them, another user's, and persistence (see [[#Slices]] for what's yet to
come, which this page describes as the plan, saying so where it does).

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
  request. Not yet: a persisted anchor showing its last set meanwhile
  (see [[#Persistence]]).
- Renaming between a served anchor and anything else fails `EXDEV`, as
  across filesystems, so `mv` copies.
- An anchor another node serves is reached through this node's (see
  [[#Across the mesh]]); while this node isn't running, it's
  `ENOTCONN`.

## Across the mesh

A mount reaches an anchor another node serves through its own node, on
the repo's `serve.sock` (or, where that path's too long for a socket,
`$XDG_RUNTIME_DIR/hk-<hash>-serve.sock`; never anywhere others may
write). Only the node's own user may connect, by the socket's peer
credentials, and the mount connects only to a socket that's its user's.
Its first line names what it's for, then it speaks 9P2000.L:

```
<anchor> <service> <node's peer ID>\n
```

The node answers `Tversion` itself, and sends every other message to the
serving node over `/holokeep/serve/1.0.0`, a request each, in a
*session* of the connection's own, the answer coming back as the
response. Sessions are numbered from the time the node started, in
nanoseconds, so one from before a restart isn't taken for a new one.

| Request field | Type        | Meaning                                                  |
| ------------- | ----------- | -------------------------------------------------------- |
| `user`        | bytes, opt. | The asking node's user's root key CID, as others say it. |
| `session`     | integer     | The session.                                             |
| `anchor`      | bytes       | The anchor's CID.                                        |
| `service`     | string      | The service, as the serve claim names it.                |
| `message`     | bytes       | A whole 9P2000.L message; empty ends the session.        |

The response is `{message}`, the answer. Requests time out after 30 s, a
mount's own wait being 10 s.

The serving node answers `EACCES` unless the anchor is its own
account's, and its serve claim names this node and the service, which its
config has; and the asker is either:

- a machine hosting the anchor's owner, as for anything of theirs (see
  [[Sharing]]), which may do anything; or
- a machine hosting another user, a **guest** of this node's (see
  [[Mesh#Users sharing a mesh]]), asking of the owner's view of the
  anchor, whom [[Grants#Grants on anchors|grants on it]] let read it or
  write it. A reader may only read: whatever would change anything
  (opening to write or truncate, creating, writing, removing, renaming,
  setting attributes) is answered `EROFS`.

Grants are judged at each message, so taking them away shuts a session
out at once. Only messages it decodes as 9P2000.L's filesystem requests
go on, else `EOPNOTSUPP`; and an attach is as it says: `uname` the asking
user's root key, `n_uname` none, as they're no user of this machine,
`aname` the anchor itself, whoever's view it was asked of. A session is
for the user and the anchor it was first asked for, as its attach was,
and anything asked in it for another is `EACCES`. Each session has a
connection of its own to the service, made as the node's own user, so
several users share a server, told apart by `uname`; a session ends when
its asker says so, its asker disconnects, or its service hangs up,
whatever's waiting answered `ENOTCONN`.

A serve claim is shared with guests as the sets of an anchor are: one
that counts in a view they may read reaches their machines, so their
mounts show the anchor served there too.

Not yet: a node serving accounts other than its own, and visitors.

## Persistence

With `persist` on (`hk serve add --persist`), the serving node's daemon
keeps the server's tree as sets of the anchor, as if someone had written
it through the mount, signed by the node's own account: its files become
blocks as `hk add` makes them, and the anchor's set when what's served
has changed. It looks every minute, so that's the most often it's set.

- A file or directory whose qid has `QTTMP` (`0x04`), which Plan 9 used
  for what's left out of its archive, is never kept: a server marks what
  mustn't be, such as handshakes or a clock, and the rest is kept.
- Each directory is listed every time, a message or so each. A file is
  read again only if it seems changed: its qid's version moved, or, for a
  server that keeps no versions (zero), its size or mtime did. A server
  with neither has every file read every time.
- It attaches as the anchor's owner: `uname` the user's root key, and
  `n_uname` the node's own uid.
- A server that can't be reached is skipped, and said so once; it's kept
  again once it's back.

Persisted sets are ordinary history: `hk fs log`, replication, trimming
and everything else take them as they are. The mount still shows the
server live, never the last set; not yet: showing the last set while the
server can't be reached.

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
2. **Across the mesh** (implemented). A node protocol carrying 9P to the
   serving node, which connects to the service as its user (see
   [[#Across the mesh]]), for the user's own machines and for other
   users, as grants on the anchor let them read or write it.
3. **Persistence** (implemented), as above.
4. **A shell**, as a service: sessions in the manner of Plan 9's `/net`
   clone files, as the authenticated user only, if their device is
   granted a shell on that machine; root only as root's own
   configuration allows, as `/root/.ssh/authorized_keys` does.

Source: `src/claim.rs`, `src/store/claims.rs`, `src/served.rs`,
`src/served/persist.rs`,
`src/ninep.rs`, `src/ninep/client.rs`, `src/mount/served.rs`,
`src/net/serve.rs`, `src/net/node/serving.rs`, `src/net/daemon.rs`.
