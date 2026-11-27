A repo's configuration is `config.toml` in its directory
(`~/.holokeep/config.toml`; `hk config path` prints it): what its nodes
are tuned to and what they mount, so a service runs `hk node run` with
no flags. A repo with no file has the defaults.

Each key mirrors a flag of `hk node run`. A flag says over the file,
and the file over the default. A key not understood, or a value that
doesn't parse, is an error when anything reads the file, so a typo
stops a service at start rather than being ignored. `hk config show`
prints the file as it's understood, or why it isn't.

```toml
[node]              # the main mesh's node, and every other's defaults
copies = 3
low-water = "10G"
ping = "30s"
door = true

[mesh.work]         # the node of `hk node run --mesh work`, over [node]
listen = "/ip4/0.0.0.0/tcp/4111"

[[mount]]           # kept mounted by the main mesh's node
dir = "~/soup"
```

## Nodes

`[node]` tunes the main mesh's node, and is the default for every other
mesh's. `[mesh.<name>]` tunes the node of `--mesh <name>`, key by key
over `[node]`; there's no `[mesh.main]`. `listen`, `clients`, `door`,
`gateway` and `amino` in `[node]` are the main mesh's alone, since two nodes can't share a
port.

| Key          | Type                    | Default                         | Meaning                                                                                                    |
| ------------ | ----------------------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `listen`     | multiaddr               | port 4011 (main), any (others)  | Where to listen for members (`--listen`).                                                                  |
| `copies`     | integer                 | 2                               | Failures it should take to lose a block (`--copies`); see [[Replication and Retention]].                   |
| `low-water`  | size                    | `"2G"`                          | Free space below which spare copies are let go of (`--low-water`).                                         |
| `high-water` | size                    | `"4G"`                          | ...until it's back above this (`--high-water`).                                                            |
| `target`     | size                    | none                            | The most to keep here: past it, copies are let go of or handed off till it's a tenth under (`--target`).   |
| `collect`    | boolean                 | true                            | Whether to collect garbage (`--no-collect` if false).                                                      |
| `lost-scan`  | boolean                 | true                            | Whether to look daily for what's lost (`--no-lost-scan` if false).                                         |
| `shared`     | boolean                 | false                           | Whether the host's other users may connect (`--shared`); see [[Sharing]].                                  |
| `clients`    | boolean or multiaddr    | off                             | Listen for clients: `true` on port 4012, or where it says (`--clients`). The main mesh's only.             |
| `door`       | boolean or multiaddr    | off                             | Open a door: `true` on port 4013, or where it says (`--door`); see [[Capabilities]].                       |
| `ping`       | duration                | `"10s"`                         | How often a connection's pinged, and how long an answer's waited for, before it's closed and redialled.     |
| `idle`       | duration                | `"1h"`                          | How long a connection with nothing going on is kept open.                                                  |
| `amino`      | boolean or multiaddr    | off                             | Take part in Amino, the public IPFS network: `true` on port 4015, or where it says (`--amino`); see [[Claims#Amino]]. The main mesh's only. |
| `amino-bootstrap` | list of multiaddrs | Amino's own                     | The peers Amino's joined by; empty for none, as for a test of its own. |
| `amino-server` | boolean              | false                           | Be a server of Amino's DHT, reached where it listens, whatever it's seen as: for a LAN or a test. A public address makes it one anyway. |
| `gateway`    | boolean or address      | off                             | Serve what's public over HTTP: `true` on `127.0.0.1:4014`, or where it says, as `host:port` (`--gateway`); see [[Claims#Gateway]]. The main mesh's only. |
| `relay`      | boolean                 | false                           | Relay between members which can't reach each other, for a member they all can; see [[Mesh#Relays]].         |

A size is a number of bytes, or a string with `K`, `M`, `G` or `T`
(binary). A duration is a string with `ms`, `s`, `m`, `h` or `d`:
`"250ms"`, `"30s"`, `"7d"`. `ping` and `idle` have no flags; any node
the repo opens takes them, `hk node join`'s included.

## Mounts

Each `[[mount]]` is a directory the main mesh's node keeps the soup
mounted on while it runs (see [[Mount]]):

| Key         | Type    | Default | Meaning                                       |
| ----------- | ------- | ------- | --------------------------------------------- |
| `dir`       | path    |         | Where; a leading `~/` is the home directory.  |
| `read-only` | boolean | false   | Anchors too are read-only (`--read-only`).    |

Each is an `hk mount` process of its own, in its own process group, so
one that fails takes nothing else with it, and an interrupt at the
terminal reaches only the node:

- It's started again when it ends, after a second, doubling to a
  minute while it keeps ending within 30 seconds of starting.
- Where it goes, a mount that died (`Transport endpoint is not
  connected`) is cleared first with `fusermount3 -u -z`; a directory
  that's missing is made; a live holokeep mount that isn't the node's,
  such as one started by hand, is left be, and looked at again every
  30 seconds.
- When the node stops, each is interrupted to unmount, and killed if
  it hasn't ended within 10 seconds.

`hk mount` with no directory mounts on the one `[[mount]]` there is.

## As a service

`hk node run` stops cleanly on `SIGINT` or `SIGTERM`. `hk node
service` prints a systemd user unit for it, run as the repo's owner
since FUSE mounts are per user:

```sh
hk node service > ~/.config/systemd/user/holokeep.service
systemctl --user enable --now holokeep
```

The unit runs `hk node run --repo <repo>` (with `--mesh` for another
mesh), restarts it on failure, and stops it with `KillMode=mixed`:
`SIGTERM` to the node alone, which unmounts its mounts before it ends.
To run while logged out, `loginctl enable-linger`.

Source: `src/config.rs`, `src/mounts.rs`, `src/main.rs`
(`node_run`, `node_service`), `src/net/daemon.rs` (`open_node`).
