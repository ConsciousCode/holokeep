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
    podman network rm -f "$net" >/dev/null 2>&1 || true
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

# A Kubo node, a server of the DHT, joined by these peers
kubo_up() {
    local name=$1; shift
    local bootstrap=
    [ $# -eq 0 ] || bootstrap=$(printf '"%s",' "$@")
    on "$name" ipfs init --empty-repo >/dev/null
    sh_on "$name" "ipfs config --json Bootstrap '[${bootstrap%,}]' \
        && ipfs config --json AutoConf.Enabled false \
        && ipfs config --json DNS.Resolvers '{}' \
        && ipfs config --json Routing.DelegatedRouters '[]' \
        && ipfs config --json Ipns.DelegatedPublishers '[]' \
        && ipfs config --json Discovery.MDNS.Enabled false \
        && ipfs config Routing.Type dhtserver \
        && ipfs config --json Addresses.Swarm '[\"/ip4/0.0.0.0/tcp/4001\"]' \
        && ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001 \
        && ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080"
    podman exec -d "$run-$name" sh -c "GOLOG_LOG_LEVEL=error,bitswap/server=debug exec ipfs daemon >>/tmp/ipfs.log 2>&1"
    wait_for "$name's Kubo to be ready" sh_on "$name" "grep -q 'Daemon is ready' /tmp/ipfs.log"
}
kubo_addr() { echo "/ip4/$(ip_of "$1")/tcp/4001/p2p/$(on "$1" ipfs id -f '<id>')"; }

say "building hk and the machine image"
cargo build --release --quiet
podman build -q -t "$image" -f tests/mesh/Containerfile tests/mesh >/dev/null
podman network create --subnet 11.0.0.0/24 "$net" >/dev/null
say "$(ipfs version) against hk"

say "a Kubo hub, and a Kubo provider joined by it"
machine hub
kubo_up hub
hub=$(kubo_addr hub)
machine provider
kubo_up provider "$hub"
provider_id=$(on provider ipfs id -f '<id>')

say "an hk node in Amino, joined by the hub alone"
machine hk
on hk hk node id >/dev/null
sh_on hk "printf '[node]\namino-bootstrap = [\"$hub\"]\n' > ~/.holokeep/config.toml"
podman exec -d "$run-hk" sh -c "exec hk node run --amino >>/tmp/node.log 2>&1"
wait_for "hk to join its Amino" sh_on hk "grep -q 'in Amino as' /tmp/node.log"
hk_id=$(sh_on hk "grep 'in Amino as' /tmp/node.log | tail -1 | awk '{ print \$NF }'")
wait_for "the hub to have hk in its DHT" sh_on hub "ipfs stats dht wan | grep -q $hk_id"

say "hk fetches a file of many blocks the Kubo provider announced, through the DHT"
sh_on provider "head -c 3000017 /dev/urandom > /tmp/big"
big=$(on provider ipfs add -Q /tmp/big)
wait_for "the provider's record to be on the hub" sh_on hub "timeout 5 ipfs routing findprovs -n 1 $big | grep -q $provider_id"
on hk hk dag fetch "$big" >/dev/null || fail "hk couldn't fetch $big from Kubo"
[ "$(on hk hk cat "$big" | sha256sum)" = "$(on provider ipfs cat "$big" | sha256sum)" ] || fail "hk fetched something else"

say "and a directory, whole"
sh_on provider "mkdir -p /tmp/dir/sub && echo one > /tmp/dir/one && echo two > /tmp/dir/sub/two && head -c 300000 /dev/urandom > /tmp/dir/sub/three"
dir=$(on provider ipfs add -Q -r /tmp/dir)
wait_for "the directory's record to be on the hub" sh_on hub "timeout 5 ipfs routing findprovs -n 1 $dir | grep -q $provider_id"
on hk hk dag fetch "$dir" >/dev/null || fail "hk couldn't fetch the directory $dir from Kubo"
on hk hk get -o /tmp/got "$dir" >/dev/null
[ "$(sh_on hk 'cd /tmp/got && find . -type f | sort | xargs sha256sum')" = "$(sh_on provider 'cd /tmp/dir && find . -type f | sort | xargs sha256sum')" ] || fail "the directory hk fetched isn't the one Kubo added"

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

# hk takes every stream Kubo sends on: none reset, losing what's on it
for kubo in hub provider; do
    ! sh_on "$kubo" "grep -q 'stream reset' /tmp/ipfs.log" || fail "$kubo's Kubo had a Bitswap stream reset by hk"
done

say "all passed"
