#!/usr/bin/env bash
# hk's Amino against real Kubo: its DHT and Bitswap, both ways. Two Kubo
# nodes, a hub of the DHT and a provider, and an hk node joined by the hub
# alone, so whatever it finds of the provider's it finds through the DHT.
#
# Usage: tests/mesh/kubo.sh   (KEEP=1 leaves the containers)
#
# Needs what tests/mesh/run.sh does, and Kubo's `ipfs` on the PATH, which
# is bind-mounted in. The network's on 11.0.0.0/24, an address range that
# isn't private, since Kubo's DHT ignores peers only reached at private
# ones, and its LAN DHT is a protocol of its own (/ipfs/lan/kad/1.0.0).
set -euo pipefail
cd "$(dirname "$0")/../.."

image=localhost/holokeep-mesh-test
run=hkkubo-$$
net=$run
timeout=${TIMEOUT:-60}
nodes=()
ipfs_bin=$(command -v ipfs) || { echo "needs Kubo's ipfs on the PATH" >&2; exit 1; }

cleanup() {
    if [ "${KEEP:-}" = 1 ]; then
        echo "kept: ${nodes[*]:-} on $net" >&2
        return
    fi
    for node in "${nodes[@]}"; do
        podman rm -f -t 0 "$node" >/dev/null 2>&1 || true
    done
    podman network rm -f "$net" "$net-behind" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say() { printf '\033[1m%s\033[0m (%ds)\n' "$*" "$SECONDS" >&2; }
on() { local node=$1; shift; podman exec "$run-$node" "$@"; }
sh_on() { local node=$1; shift; podman exec "$run-$node" sh -c "$*"; }

fail() {
    echo "FAIL: $*" >&2
    for node in "${nodes[@]}"; do
        for log in node ipfs; do
            echo "--- ${node#"$run-"} $log" >&2
            podman exec "$node" sh -c "tail -n 30 /tmp/$log.log 2>/dev/null" >&2 || true
        done
    done
    exit 1
}

wait_for() {
    local what=$1; shift
    local end=$((SECONDS + timeout))
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$end" ] || fail "waited ${timeout}s for $what"
        timeout 1 tail -f /dev/null || true
    done
}

machine() {
    local name=$1
    podman run -d --name "$run-$name" --hostname "$name" --network "$net" \
        -v "$PWD/target/release/hk:/usr/local/bin/hk:ro" \
        -v "$ipfs_bin:/usr/local/bin/ipfs:ro" \
        -e HK_PASSPHRASE=kubo-test -e IPFS_PATH=/root/.ipfs -e IPFS_TELEMETRY=off \
        "$image" sleep infinity >/dev/null
    nodes+=("$run-$name")
}
ip_of() { sh_on "$1" "hostname -I | awk '{ print \$1 }'"; }

# A Kubo node, a server of the DHT, with a key of this algorithm, joined
# by these peers, and a router (/routing/v1) on its gateway; listening
# where $SWARM says, over TCP if unsaid, and configured as $CONFIG says
kubo_up() {
    local name=$1 algorithm=$2; shift 2
    local bootstrap= swarm=${SWARM:-'["/ip4/0.0.0.0/tcp/4001"]'} config=${CONFIG:-true}
    [ $# -eq 0 ] || bootstrap=$(printf '"%s",' "$@")
    on "$name" ipfs init --empty-repo --algorithm "$algorithm" >/dev/null
    sh_on "$name" "ipfs config --json Bootstrap '[${bootstrap%,}]' \
        && ipfs config --json AutoConf.Enabled false \
        && ipfs config --json DNS.Resolvers '{}' \
        && ipfs config --json Routing.DelegatedRouters '[]' \
        && ipfs config --json Ipns.DelegatedPublishers '[]' \
        && ipfs config --json Discovery.MDNS.Enabled false \
        && ipfs config Routing.Type dhtserver \
        && ipfs config --json Addresses.Swarm '$swarm' \
        && ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001 \
        && ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080 \
        && ipfs config --json Gateway.ExposeRoutingAPI true \
        && $config"
    podman exec -d "$run-$name" sh -c "GOLOG_LOG_LEVEL=error,bitswap/server=debug exec ipfs daemon >>/tmp/ipfs.log 2>&1"
    wait_for "$name's Kubo to be ready" sh_on "$name" "grep -q 'Daemon is ready' /tmp/ipfs.log"
}
kubo_addr() { echo "/ip4/$(ip_of "$1")/tcp/4001/p2p/$(on "$1" ipfs id -f '<id>')"; }

say "building hk and the machine image"
cargo build --release --quiet
podman build -q -t "$image" -f tests/mesh/Containerfile tests/mesh >/dev/null
podman network create --subnet 11.0.0.0/24 "$net" >/dev/null
# A network hk isn't on, with no way out, reached only through the hub,
# which is on both
podman network create --internal --subnet 12.0.0.0/24 "$net-behind" >/dev/null
say "$(ipfs version) against hk"

# The hub's key is RSA, as Amino's bootstrap peers' are, and many of
# its older peers'
# The provider listens over QUIC alone, so what hk has of it, through
# the DHT or a router, it has over QUIC
say "a Kubo hub with an RSA key, and a Kubo provider joined by it, over QUIC alone"
machine hub
podman network connect "$net-behind" "$run-hub"
# A relay too, for a node behind it
SWARM='["/ip4/0.0.0.0/tcp/4001","/ip4/0.0.0.0/udp/4001/quic-v1"]' CONFIG='ipfs config --json Swarm.RelayService.Enabled true' kubo_up hub rsa
hub=$(kubo_addr hub)
machine provider
SWARM='["/ip4/0.0.0.0/udp/4001/quic-v1"]' kubo_up provider ed25519 "$hub"
provider_id=$(on provider ipfs id -f '<id>')

say "an hk node in Amino, joined by the hub alone"
machine hk
on hk hk node id >/dev/null
sh_on hk "printf '[node]\namino-bootstrap = [\"$hub\"]\n' > ~/.holokeep/config.toml"
podman exec -d "$run-hk" sh -c "exec hk node run --amino >>/tmp/node.log 2>&1"
wait_for "hk to join its Amino" sh_on hk "grep -q 'in Amino as' /tmp/node.log"
hk_id=$(sh_on hk "grep 'in Amino as' /tmp/node.log | tail -1 | awk '{ print \$NF }'")
wait_for "the hub to have hk in its DHT" sh_on hub "ipfs stats dht wan | grep -q $hk_id"
wait_for "hk to have the hub in its routing table" sh_on hk "hk node amino | grep -q 'with [1-9][0-9]* peers in its routing table'"
on hk hk node amino --peers | grep -q "kubo/" || fail "hk node amino --peers didn't show Kubo"

say "hk fetches a file of many blocks the Kubo provider announced, through the DHT"
sh_on provider "head -c 3000017 /dev/urandom > /tmp/big"
big=$(on provider ipfs add -Q /tmp/big)
wait_for "the provider's record to be on the hub" sh_on hub "timeout 5 ipfs routing findprovs -n 1 $big | grep -q $provider_id"
on hk hk dag fetch "$big" >/dev/null || fail "hk couldn't fetch $big from Kubo"
[ "$(on hk hk cat "$big" | sha256sum)" = "$(on provider ipfs cat "$big" | sha256sum)" ] || fail "hk fetched something else"
on hk hk node amino --peers | grep "^$provider_id" | grep -q "/quic-v1" || fail "hk isn't connected to the provider over QUIC"

say "and a directory, whole"
sh_on provider "mkdir -p /tmp/dir/sub && echo one > /tmp/dir/one && echo two > /tmp/dir/sub/two && head -c 300000 /dev/urandom > /tmp/dir/sub/three"
dir=$(on provider ipfs add -Q -r /tmp/dir)
wait_for "the directory's record to be on the hub" sh_on hub "timeout 5 ipfs routing findprovs -n 1 $dir | grep -q $provider_id"
on hk hk dag fetch "$dir" >/dev/null || fail "hk couldn't fetch the directory $dir from Kubo"
on hk hk get -o /tmp/got "$dir" >/dev/null
[ "$(sh_on hk 'cd /tmp/got && find . -type f | sort | xargs sha256sum')" = "$(sh_on provider 'cd /tmp/dir && find . -type f | sort | xargs sha256sum')" ] || fail "the directory hk fetched isn't the one Kubo added"

say "an hk node joined by no one finds the provider by asking the hub as a router"
machine loner
on loner hk node id >/dev/null
sh_on loner "printf '[node]\namino-bootstrap = []\namino-routers = [\"http://$(ip_of hub):8080\"]\n' > ~/.holokeep/config.toml"
podman exec -d "$run-loner" sh -c "exec hk node run --amino >>/tmp/node.log 2>&1"
wait_for "the loner to join its Amino" sh_on loner "grep -q 'in Amino as' /tmp/node.log"
on loner hk dag fetch "$big" >/dev/null || fail "the loner couldn't fetch $big through the router"
[ "$(on loner hk cat "$big" | sha256sum)" = "$(on provider ipfs cat "$big" | sha256sum)" ] || fail "the loner fetched something else"
on loner hk node amino | grep -q "asked a router who has a block [1-9]" || fail "the loner didn't say it asked the router"
# And the provider it found, a server of the DHT, is in its routing table
wait_for "the loner to have the provider in its routing table" sh_on loner "hk node amino | grep -q 'with [1-9][0-9]* peers in its routing table'"

say "Kubo finds what hk announced through the DHT, and fetches it"
sh_on hk "head -c 2500000 /dev/urandom > /tmp/announced"
announced=$(on hk hk add -q /tmp/announced)
on hk hk public add "$announced" >/dev/null
seeker() { sh_on provider "timeout 10 ipfs routing findprovs -n 5 $1" | grep -q "$hk_id"; }
wait_for "Kubo to find hk providing what it announced" seeker "$announced"
sh_on provider "timeout 60 ipfs cat $announced > /tmp/got" || fail "Kubo couldn't fetch $announced from hk"
[ "$(sh_on provider 'sha256sum < /tmp/got')" = "$(sh_on hk 'sha256sum < /tmp/announced')" ] || fail "Kubo fetched something else"

say "what hk only serves, a Kubo peering it gets, and finds no record of"
served=$(sh_on hk 'echo "served, not announced" | hk add -q -')
private=$(sh_on hk 'echo "for no one on Amino" | hk add -q -')
on hk hk public add --serve "$served" >/dev/null
# Kubo wants only of peers it has had blocks from, on its LAN or peered,
# and a few at random (Internal.Bitswap.BroadcastControl), so as one who
# wants what an hk node serves would, peering it
on hub ipfs swarm peering add "/ip4/$(ip_of hk)/tcp/4015/p2p/$hk_id" >/dev/null
wait_for "the hub to connect to hk" sh_on hub "ipfs swarm peers | grep -q $hk_id"
[ "$(sh_on hub "timeout 30 ipfs cat $served")" = "served, not announced" ] || fail "Kubo couldn't fetch what hk serves"
! sh_on hub "timeout 10 ipfs cat $private" >/dev/null 2>&1 || fail "Kubo fetched what's private"
! sh_on provider "timeout 10 ipfs routing findprovs -n 1 $served" | grep -q "$hk_id" || fail "what hk only serves was announced"

# Kubo serves nothing over a relayed connection, which a relay cuts off
# soon anyway: what's had of a node behind one is had once DCUtR has
# punched through to it, which takes a NAT that lets it out, as this
# network doesn't
say "a Kubo node behind the hub, reached by hk only through it as a relay"
podman run -d --name "$run-hidden" --hostname hidden --network "$net-behind" \
    -v "$ipfs_bin:/usr/local/bin/ipfs:ro" -e IPFS_PATH=/root/.ipfs -e IPFS_TELEMETRY=off \
    "$image" sleep infinity >/dev/null
nodes+=("$run-hidden")
hub_behind="/ip4/$(sh_on hub "hostname -I | tr ' ' '\\n' | grep '^12\\.0\\.0\\.'")/tcp/4001/p2p/$(on hub ipfs id -f '<id>')"
CONFIG="ipfs config --json Swarm.RelayClient.Enabled true && ipfs config --json Swarm.RelayClient.StaticRelays '[\"$hub_behind\"]' && ipfs config Internal.Libp2pForceReachability private" kubo_up hidden ed25519 "$hub_behind"
hidden_id=$(on hidden ipfs id -f '<id>')
wait_for "the hidden node to be reached through the hub" sh_on hidden "ipfs id -f '<addrs>' | grep -q p2p-circuit"
sh_on hidden "head -c 60000 /dev/urandom > /tmp/small"
small=$(on hidden ipfs add -Q /tmp/small)
wait_for "the hidden node's record to be on the hub" sh_on hub "timeout 5 ipfs routing findprovs -n 1 $small | grep -q $hidden_id"
on hk hk dag fetch "$small" >/dev/null 2>&1 || true
on hk hk node amino --peers | grep "^$hidden_id" | grep -q "/p2p-circuit" || fail "hk isn't connected to the hidden node through the relay"
on hk hk node amino | grep -q "reached [1-9][0-9]* through a relay" || fail "hk didn't say it reached anyone through a relay"

# hk takes every stream Kubo sends on: none reset, losing what's on it
for kubo in hub provider; do
    ! sh_on "$kubo" "grep -q 'stream reset' /tmp/ipfs.log" || fail "$kubo's Kubo had a Bitswap stream reset by hk"
done

say "all passed"
