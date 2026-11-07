#!/usr/bin/env bash
# End-to-end tests of a mesh of hk nodes: real binaries, daemons, TCP and
# FUSE mounts, each node in a rootless Podman container on a network of
# its own, which a node can be cut off from and put back on.
#
# Usage: tests/mesh/run.sh [scenario...]   (all of them by default, in
# order: each builds on the mesh the ones before it left)
#
# Needs rootless Podman, with subordinate IDs for your account (see
# README). Nothing runs as root on the host; everything is removed after,
# unless KEEP=1, which leaves the containers to look at.
set -euo pipefail
cd "$(dirname "$0")/../.."

image=localhost/holokeep-mesh-test
run=hkmesh-$$
net=$run
timeout=${TIMEOUT:-60}
nodes=()

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

say() { printf '\033[1m%s\033[0m\n' "$*" >&2; }

# Run a command on a node, or a shell line
on() { local node=$1; shift; podman exec "$run-$node" "$@"; }
sh_on() { local node=$1; shift; podman exec "$run-$node" sh -c "$*"; }

# What every node logged, for when something fails
logs() {
    for node in "${nodes[@]}"; do
        for log in node mount; do
            echo "--- ${node#"$run-"} $log" >&2
            podman exec "$node" sh -c "tail -n 30 /tmp/$log.log 2>/dev/null" >&2 || true
        done
    done
}

fail() {
    echo "FAIL: $*" >&2
    logs
    exit 1
}

# Wait till a command succeeds, or fail saying what was waited for
wait_for() {
    local what=$1; shift
    local deadline=$((SECONDS + timeout))
    until "$@" >/dev/null 2>&1; do
        [ $SECONDS -lt $deadline ] || fail "waited ${timeout}s for $what"
        sleep 0.5
    done
}

# A machine, on the network, with hk and FUSE
machine() {
    local name=$1
    podman run -d --name "$run-$name" --hostname "$name" --network "$net" \
        --device /dev/fuse --cap-add SYS_ADMIN \
        -v "$PWD/target/release/hk:/usr/local/bin/hk:ro" \
        -e HK_PASSPHRASE=mesh-test \
        "$image" sleep infinity >/dev/null
    nodes+=("$run-$name")
    on "$name" mkdir -p /soup
}

# Start a node's daemon, and wait till it answers
node_up() {
    podman exec -d "$run-$1" sh -c 'exec hk node run >>/tmp/node.log 2>&1'
    wait_for "$1's node to run" on "$1" hk node status
}

# Mount a node's soup at /soup, and wait till it's there
mount_up() {
    podman exec -d "$run-$1" sh -c 'exec hk mount /soup >>/tmp/mount.log 2>&1'
    wait_for "$1's mount" sh_on "$1" 'grep -q " /soup fuse" /proc/mounts'
}

# Let a machine into the mesh `from` is in
invite() {
    local from=$1 to=$2 peer ticket
    peer=$(on "$to" hk node id)
    ticket=$(on "$from" hk node invite "$peer" 2>/dev/null)
    on "$to" hk node join "$ticket" >/dev/null
}

cut_off() { podman network disconnect "$net" "$run-$1"; }
put_back() { podman network connect "$net" "$run-$1"; }

# What a path through a node's mount holds, sorted
listing() { sh_on "$1" "ls -1 '$2' | sort"; }

same_listing() { [ "$(listing "$1" "$3")" = "$(listing "$2" "$3")" ]; }

holds() { [ "$(sh_on "$1" "cat '$2'")" = "$3" ]; }

# --- Scenarios -----------------------------------------------------------

# Two nodes: what's written on one is read on the other
scenario_write_read() {
    sh_on one 'mkdir /soup/wiki && echo "hello from one" > /soup/wiki/page.md'
    wait_for "two to read one's page" holds two /soup/wiki/page.md "hello from one"
    sh_on two 'echo "two was here" > /soup/wiki/two.md'
    wait_for "one to read two's page" holds one /soup/wiki/two.md "two was here"
}

# A node joining later sees what the root names, and reads it
scenario_late_joiner() {
    machine three
    invite one three
    node_up three
    mount_up three
    wait_for "three to see the wiki" holds three /soup/wiki/page.md "hello from one"
}

# A file imported in place changes, with no copy anywhere: it's found, and only
# reported once every member's been asked. The same bytes made again end it.
scenario_lost() {
    sh_on one 'echo "only here" > /tmp/only'
    local cid
    cid=$(sh_on one 'hk add -q --nocopy --no-keep /tmp/only | tail -1')
    on one hk keep add --copies 1 "$cid" >/dev/null
    [ -z "$(on one hk lost scan --dry-run)" ] || fail "reported what's here"
    sleep 1
    sh_on one 'echo "changed since" > /tmp/only'
    wait_for "one to notice it changed" sh_on one "! hk block get $cid"

    cut_off two
    wait_for "one to see two's gone" sh_on one 'hk node peers | grep -q -- "	-	"'
    [ "$(on one hk lost scan 2>/dev/null)" = "$cid" ] || fail "the scan didn't find $cid"
    [ -z "$(on one hk lost ls)" ] || fail "reported it with a member away"
    put_back two
    wait_for "one and two to reconnect" sh_on one '! hk node peers | grep -q -- "	-	"'

    [ "$(on one hk lost scan)" = "$cid" ] || fail "the scan didn't report $cid"
    [ "$(on one hk lost ls | cut -f1)" = "$cid" ] || fail "it isn't listed"
    # The daemon's own scan reports what it finds, signed so it counts
    sh_on one 'echo "only here too" > /tmp/too'
    local too
    too=$(sh_on one 'hk add -q --nocopy --no-keep /tmp/too | tail -1')
    on one hk keep add --copies 1 "$too" >/dev/null
    sleep 1
    sh_on one 'echo "changed too" > /tmp/too'
    wait_for "one to notice it changed too" sh_on one "! hk block get $too"
    # Asked as the node may yet be noticing, as a day's wait would never be
    wait_for "one's node to report it" sh_on one "hk node scan-lost; hk lost ls | grep -q $too"

    # Two hasn't got it, so wasn't told. The same bytes made there end it
    [ -z "$(on two hk lost ls)" ] || fail "two heard of what it hasn't got"
    sh_on two 'echo "only here" > /tmp/again && hk add -q /tmp/again >/dev/null'
    on one hk dag fetch "$cid" >/dev/null
    ! on one hk lost ls | grep "$cid" >/dev/null || fail "one still says it's lost, having it"
    [ "$(on one hk cat "$cid")" = "only here" ] || fail "it isn't what it was"
}

# A device's claims can be seen, and revoking it says what it'd cost first,
# trusting what's asked to and taking nothing else unasked
scenario_revoke() {
    local peer block keep sign
    machine leaving
    invite one leaving
    node_up leaving
    peer=$(on leaving hk node id)
    block=$(sh_on one 'echo "only kept by leaving" | hk add -q --no-keep -')
    wait_for "leaving to be connected" sh_on one "hk node peers | grep '$peer' | grep -q connected"
    on leaving hk dag fetch "$block" >/dev/null
    keep=$(on leaving hk keep add "$block")
    on leaving hk dag export "$block" --claims -o /tmp/kept.car 2>/dev/null
    podman cp "$run-leaving:/tmp/kept.car" "$run-one:/tmp/kept.car"
    on one hk dag import /tmp/kept.car >/dev/null 2>&1

    on one hk device log "$peer" --claims | grep "$keep" | grep "keep" | grep "alone" >/dev/null || fail "the log doesn't say what it signed"
    sign=$(on one hk device log "$peer" | awk -v keep="$keep" 'END { print $1 }')
    [ "$(on one hk device revoke "$peer" --until 1 --dry-run 2>/dev/null | cut -f1)" = "$keep" ] || fail "the dry run doesn't name it"
    on one hk node peers | grep "$peer" >/dev/null || fail "a dry run shouldn't have done anything"
    ! on one hk device revoke "$peer" --until 1 </dev/null >/dev/null 2>&1 || fail "revoked without being told to lose it"
    on one hk keep ls | grep "$block" >/dev/null || fail "refusing lost it"
    [ -z "$(on one hk device revoke "$peer" --until "$sign" --dry-run 2>/dev/null)" ] || fail "trusting its sign still costs"
    on one hk device revoke "$peer" --until "$sign" </dev/null >/dev/null
    on one hk device list | grep "$peer" | grep "revoked" >/dev/null || fail "it isn't revoked"
    on one hk keep ls | grep "$block" >/dev/null || fail "what was trusted isn't kept"
}

# Every device gone, a new machine with a backup and the passphrase is the user
# again, and has the soup; without the passphrase it's only got ciphertext
scenario_restore() {
    local root user
    root=$(on one hk anchor root | sed -n 1p)
    user=$(on one hk device list | sed -n 1p | cut -f2)
    on one hk dag export "$root" --claims --history --sealed-root -o /tmp/backup.car
    machine phoenix
    podman cp "$run-one:/tmp/backup.car" "$run-phoenix:/tmp/backup.car"
    on phoenix hk dag import /tmp/backup.car >/dev/null
    ! sh_on phoenix 'HK_PASSPHRASE=wrong hk device restore' >/dev/null 2>&1 || fail "restored with the wrong passphrase"
    [ "$(on phoenix hk device restore | cut -f2)" = "$user" ] || fail "not the same user"
    [ "$(on phoenix hk anchor root | sed -n 1p)" = "$root" ] || fail "not the same root"
    on phoenix hk device list | grep "certified	this node" >/dev/null || fail "this node isn't certified"
    mount_up phoenix
    # What the merged anchor says: one's own mount shows its own edit over that
    local page
    page=$(sh_on two 'cat /soup/wiki/page.md')
    wait_for "phoenix to read the wiki" holds phoenix /soup/wiki/page.md "$page"
    same_listing one phoenix /soup/wiki || fail "phoenix doesn't have all the wiki"
}

# A CAR carries what's said of a DAG to another device of the user, where it
# counts, and to a stranger, where it's only data
scenario_car() {
    sh_on one 'mkdir -p /tmp/album && echo "a song" > /tmp/album/song'
    local root
    root=$(sh_on one 'hk add -q --no-keep /tmp/album | tail -1')
    on one hk tag add album "$root" >/dev/null
    on one hk keep add --copies 1 "$root" >/dev/null
    on one hk dag export "$root" --claims -o /tmp/album.car 2>/dev/null
    podman cp "$run-one:/tmp/album.car" "$run-two:/tmp/album.car"
    on two hk dag import /tmp/album.car >/dev/null 2>&1
    on two hk tag find album | grep "$root" >/dev/null || fail "two doesn't see the tag"
    on two hk keep ls | grep "$root" >/dev/null || fail "two doesn't see the keep"
    [ "$(sh_on two "hk get $root -o /tmp/got >/dev/null 2>&1; cat /tmp/got/song")" = "a song" ] || fail "two can't read it"

    # What a tag retracted stays so, wherever it's imported
    on one hk tag rm album "$root" >/dev/null
    on one hk dag export "$root" --claims -o /tmp/album.car 2>/dev/null
    podman cp "$run-one:/tmp/album.car" "$run-two:/tmp/album.car"
    on two hk dag import /tmp/album.car >/dev/null 2>&1
    ! on two hk tag find album | grep "$root" >/dev/null || fail "two still sees the tag"

    machine stranger
    podman cp "$run-one:/tmp/album.car" "$run-stranger:/tmp/album.car"
    on stranger hk dag import /tmp/album.car >/dev/null 2>&1
    on stranger hk keep add "$root" >/dev/null 2>&1 || fail "the stranger has the blocks"
}

# A member that's gone for good stays gone from here, though others say it's
# there, and history's kept till it's forgotten, leaving what the anchor is
scenario_forget() {
    machine ghost
    invite one ghost
    local ghost
    ghost=$(on one hk node peers | grep -- "	-	" | cut -f1 | head -1)
    [ -n "$ghost" ] || fail "no member away"
    # Members tell each other of members as they connect
    reconnect_two() {
        cut_off two
        wait_for "two to be gone" sh_on one "hk node peers | grep -v $ghost | grep -q -- '	-	'"
        put_back two
        wait_for "two to be back" sh_on one "! hk node peers | grep -v $ghost | grep -q -- '	-	'"
    }
    reconnect_two
    wait_for "two to hear of the ghost" sh_on two "hk node peers | grep -q $ghost"
    on one hk node forget "$ghost"
    ! on one hk node peers | grep "$ghost" >/dev/null || fail "still a member"
    reconnect_two
    sleep 2
    ! on one hk node peers | grep "$ghost" >/dev/null || fail "two brought it back"

    local anchor first second now
    anchor=$(on one hk anchor new)
    first=$(sh_on one 'echo first | hk add -q -')
    second=$(sh_on one 'echo second | hk add -q -')
    on one hk anchor set "$anchor" "$first" >/dev/null
    sleep 2
    now=$(sh_on one 'date +%s')
    sleep 2
    on one hk anchor set "$anchor" "$second" >/dev/null
    [ "$(on one hk anchor forget "$anchor" --before "$now" --dry-run | cut -f2)" = "$first" ] || fail "it'd forget something else"
    [ "$(on one hk anchor show "$anchor" | tail -n +2 | wc -l)" = 2 ] || fail "a dry run forgot"
    on one hk anchor forget "$anchor" --before "$now" >/dev/null
    [ "$(on one hk anchor show "$anchor" | head -1)" = "$second" ] || fail "forgetting changed what it is"
    [ "$(on one hk anchor show "$anchor" | tail -n +2 | wc -l)" = 1 ] || fail "it still has its history"
}

# Cut off, both sides change the same anchor; put back, both merge it the
# same, conflicts side by side
scenario_fork_merge() {
    cut_off two
    sh_on one 'echo "one, offline" > /soup/wiki/page.md; echo a > /soup/wiki/only-one.md'
    sh_on two 'echo "two, offline" > /soup/wiki/page.md; echo b > /soup/wiki/only-two.md'
    # Each commits on its own
    sleep 3
    put_back two
    wait_for "one to see two's change" sh_on one 'test -e /soup/wiki/only-two.md'
    wait_for "two to see one's change" sh_on two 'test -e /soup/wiki/only-one.md'
    wait_for "one and two to agree" same_listing one two /soup/wiki
    listing one /soup/wiki | grep -q '^page (conflict ......)\.md$' \
        || fail "no conflict beside page.md: $(listing one /soup/wiki | tr '\n' ' ')"
}

# --- Main ----------------------------------------------------------------

say "building hk and the machine image"
cargo build --release --quiet
podman build -q -t "$image" -f tests/mesh/Containerfile tests/mesh >/dev/null
podman network create "$net" >/dev/null

say "a mesh of two"
machine one
machine two
node_up one
invite one two
node_up two
mount_up one
mount_up two

scenarios=("$@")
[ ${#scenarios[@]} -gt 0 ] || scenarios=(write_read late_joiner fork_merge lost forget car restore revoke)
for scenario in "${scenarios[@]}"; do
    say "scenario: $scenario"
    "scenario_$scenario"
done
say "all passed"
