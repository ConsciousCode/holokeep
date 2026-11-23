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

say() { printf '\033[1m%s\033[0m (%ds)\n' "$*" "$SECONDS" >&2; }

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

# Start a node's daemon, with any more arguments, and wait till it answers
node_up() {
    local name=$1; shift
    podman exec -d "$run-$name" sh -c "exec hk node run $* >>/tmp/node.log 2>&1"
    wait_for "$name's node to run" on "$name" hk node status
}

# Stop a node's daemon, and wait till it's stopped
node_down() {
    sh_on "$1" 'for p in /proc/[0-9]*; do tr "\0" " " < "$p/cmdline" 2>/dev/null | grep -q "^hk node run" && kill -INT "${p#/proc/}"; done; true'
    wait_for "$1's node to stop" sh_on "$1" '! hk node status'
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
    local two_peer
    sh_on one 'mkdir /soup/wiki && echo "hello from one" > /soup/wiki/page.md'
    wait_for "two to read one's page" holds two /soup/wiki/page.md "hello from one"
    sh_on two 'echo "two was here" > /soup/wiki/two.md'
    wait_for "one to read two's page" holds one /soup/wiki/two.md "two was here"
    # Connected, they measure each other's clocks
    two_peer=$(on two hk node id)
    wait_for "one to measure two's clock" sh_on one "hk node clocks | grep -q '^$two_peer'"
    sh_on one 'hk node status' | grep -q '^clock	' || fail "one's status doesn't say how far its clock is"
}

# Taking turns at one file, each sees the other's edit, and writing something
# else after doesn't undo it, nor bring back what the other removed
scenario_edits() {
    sh_on one 'echo first > /soup/wiki/turns.md'
    wait_for "two to read one's edit" holds two /soup/wiki/turns.md first
    sh_on two 'echo second > /soup/wiki/turns.md'
    wait_for "one to read two's edit" holds one /soup/wiki/turns.md second
    sh_on one 'echo other > /soup/wiki/other.md'
    wait_for "two to read one's other file" holds two /soup/wiki/other.md other
    holds one /soup/wiki/turns.md second || fail "one undid two's edit"
    holds two /soup/wiki/turns.md second || fail "two lost its own edit"
    ! listing one /soup/wiki | grep conflict >/dev/null || fail "a conflict, taking turns"
    sh_on two 'rm /soup/wiki/turns.md'
    wait_for "one to see it gone" sh_on one '! test -e /soup/wiki/turns.md'
    sh_on one 'echo more > /soup/wiki/other.md'
    wait_for "two to read more" holds two /soup/wiki/other.md more
    sh_on two '! test -e /soup/wiki/turns.md' || fail "one brought it back"
    sh_on one '! test -e /soup/wiki/turns.md' || fail "one still shows it"
}

# Where a block's copies are: here and on the other member, asked or as
# sighted. Containers share the host's disks, so audits make no copies to
# raise it; two fetches it, a copy one hears of only by asking
scenario_copies() {
    local cid two_peer health
    two_peer=$(on two hk node id)
    sh_on one 'echo "kept twice" > /tmp/twice'
    cid=$(sh_on one 'hk add -q /tmp/twice | tail -1')
    on two hk dag fetch "$cid" >/dev/null
    health=$(on one hk dag health --ask-all "$cid") || fail "dag health failed"
    grep -q "^blocks	1 block" <<<"$health" || fail "it's not one block: $health"
    grep -q "^asked	.*$two_peer" <<<"$health" || fail "two wasn't asked: $health"
    sh_on one "hk block where $cid" | grep -q "^$two_peer	" || fail "one doesn't say two holds it"
    # Sighted freshly, two needn't be asked again
    ! sh_on one "hk dag health --ask $cid" | grep -q "^asked" || fail "asked again what was sighted"
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
    local page
    page=$(sh_on one 'cat /soup/wiki/page.md')
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
    # The mesh has grants, from its first invite: so it's forgotten by
    # taking away what makes it a machine of the mesh
    ! on one hk node forget "$ghost" 2>/dev/null || fail "forgot a machine the grants say is in"
    on one hk node grant rm "$ghost" /mesh/machine >/dev/null
    ! on one hk node peers | grep "$ghost" >/dev/null || fail "still a member"
    wait_for "two to hear it's gone" sh_on two "! hk node peers | grep -q $ghost"
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
    wait_for "one and two to agree what it says" sh_on one "test \"\$(cat /soup/wiki/page.md)\" = \"$(sh_on two 'cat /soup/wiki/page.md')\""
    listing one /soup/wiki | grep -q '^page (conflict ......)\.md$' \
        || fail "no conflict beside page.md: $(listing one /soup/wiki | tr '\n' ' ')"
}

# Another user sharing the mesh's machines: one serves an account for them,
# made as it invites their machine, which hosts only them; their copies go
# to one, and neither user's blocks reach the other's machines
scenario_shared() {
    local peer ticket theirs ours
    machine ezra
    peer=$(on ezra hk node id)
    ticket=$(on one hk node invite "$peer" --account 4000000001 2>/dev/null)
    on ezra hk node join "$ticket" >/dev/null
    node_up ezra
    wait_for "ezra to connect" sh_on one "hk node peers | grep '$peer' | grep -q connected"
    on one hk node status | grep -q "^serving	4000000001$" || fail "one doesn't serve ezra's account"
    # The invite made ezra's user one of the mesh's, and its machine one
    [ "$(on one hk node grant ls | grep -c '	/mesh/user$')" = 1 ] || fail "ezra's user isn't given /mesh/user"
    on one hk node grant ls | grep -q "^$peer	/mesh/machine$" || fail "ezra's machine isn't given /mesh/machine"
    wait_for "two to have the grants" sh_on two "hk node grant ls | grep -q '^$peer	'"
    # Each says which accounts the other's users are, and two's only one's own
    local one_peer two_peer
    one_peer=$(on one hk node id)
    two_peer=$(on two hk node id)
    wait_for "one to see ezra hosts its account" sh_on one "hk node peers | grep '^$peer	connected	' | grep -q '	4000000001$'"
    wait_for "ezra to see one hosts its user" sh_on ezra "hk node peers | grep '^$one_peer	connected	' | grep -q '	0$'"
    on one hk node peers | grep "^$two_peer" | grep -q '	0$' || fail "one doesn't see two hosts only its own"
    theirs=$(sh_on ezra 'echo "a note of ezra'"'"'s" | hk add -q -')
    ours=$(sh_on one 'echo "a note of one'"'"'s" | hk add -q -')
    ! on two hk dag fetch "$theirs" >/dev/null 2>&1 || fail "two fetched ezra's note"
    ! on two hk block get "$theirs" >/dev/null 2>&1 || fail "two has ezra's note"
    ! on ezra hk dag fetch "$ours" >/dev/null 2>&1 || fail "ezra fetched one's note"
    ! on one hk block get "$theirs" >/dev/null 2>&1 || fail "one's owner reads ezra's note"
    on two hk dag fetch "$ours" >/dev/null || fail "two can't fetch one's note"
    # One's owner lets ezra's user read their view of an anchor: the grant
    # reaches ezra's machine, which lists it
    local anchor ezra_user
    anchor=$(on one hk anchor new)
    on one hk anchor set "$anchor" "$ours" >/dev/null
    ezra_user=$(on one hk node grant ls | awk -F'\t' '$2 == "/mesh/user" { print $1 }')
    on one hk anchor share "$anchor" "$ezra_user" read >/dev/null || fail "one can't share an anchor with ezra's user"
    on one hk anchor shared | grep -q "	$anchor	$ezra_user	/anchor/read$" || fail "one doesn't list the share"
    wait_for "ezra to have the share" sh_on ezra "hk anchor shared | grep -q '$anchor'"
    # Ezra's machine reads one's owner's view of it
    local owner view later
    owner=$(on one hk anchor shared | awk -F'\t' -v a="$anchor" '$2 == a { print $1; exit }')
    view=$(on ezra hk anchor view "$anchor" "$owner")
    wait_for "ezra to see one's view" sh_on ezra "hk anchor show '$view' | head -1 | grep -q '$ours'"
    on ezra hk dag fetch "$ours" >/dev/null || fail "ezra can't fetch what's shared"
    # With one cut off, two alone hosts the owner: what's set next reaches
    # ezra from two, which doesn't host ezra's user, as a guest's
    later=$(sh_on one 'echo "a later note of one'"'"'s" | hk add -q -')
    on one hk anchor set "$anchor" "$later" >/dev/null
    wait_for "two to fetch the later note" on two hk dag fetch "$later"
    wait_for "two to have the later set" sh_on two "hk anchor show '$anchor' | head -1 | grep -q '$later'"
    cut_off one
    wait_for "ezra to see the later set" sh_on ezra "hk anchor show '$view' | head -1 | grep -q '$later'"
    wait_for "ezra to fetch the later note from two" on ezra hk dag fetch "$later"
    # Let write, by the owner's other machine: what ezra sets for the
    # owner's view reaches two, which fetches what it is from ezra
    on two hk anchor share "$anchor" "$ezra_user" write >/dev/null || fail "two can't let ezra's user write"
    wait_for "ezra to have write" sh_on ezra "hk anchor shared | grep '	$anchor	$ezra_user	' | grep -q /anchor/write"
    on ezra hk anchor set "$view" "$theirs" >/dev/null || fail "ezra can't set one's owner's view"
    ! on ezra hk anchor show "$anchor" 2>/dev/null | head -1 | grep -q "$theirs" || fail "ezra's own view of the anchor was set"
    wait_for "two to see ezra's set" sh_on two "hk anchor show '$anchor' | head -1 | grep -q '$theirs'"
    wait_for "two to fetch what ezra set" on two hk block get "$theirs"
    put_back one
    wait_for "one to see ezra's set" sh_on one "hk anchor show '$anchor' | head -1 | grep -q '$theirs'"
}

# A client of one: a device of ezra's user which is no member, connecting
# to one alone, where it listens for clients, and seeing what ezra's user
# may, and only that
scenario_client() {
    local peer one_peer ticket theirs ours mine
    machine laptop
    peer=$(on laptop hk node id)
    one_peer=$(on one hk node id)
    ticket=$(on one hk node invite "$peer" --client --account 4000000001 2>/dev/null)
    on laptop hk node join "$ticket" >/dev/null
    node_up laptop
    wait_for "the client to connect" sh_on one "hk node peers | grep -q '^$peer	connected	client	4000000001$'"
    on laptop hk node status | grep -q "^client of	$one_peer$" || fail "the laptop doesn't say it's one's client"
    [ "$(on one hk node grant ls | grep "^$peer	")" = "$peer	/mesh/client" ] || fail "the client wasn't given /mesh/client, and that alone"
    [ "$(on laptop hk node peers | cut -f1)" = "$one_peer" ] || fail "the client was told of members"
    ! on two hk node peers | grep -q "$peer" || fail "two was told of the client"
    # It reads what ezra's user has, through one, and nothing else
    theirs=$(sh_on ezra 'echo "a note for the laptop" | hk add -q -')
    ours=$(sh_on one 'echo "a note of one'"'"'s alone" | hk add -q -')
    wait_for "the laptop to fetch ezra's note" on laptop hk dag fetch "$theirs"
    ! on laptop hk dag fetch "$ours" >/dev/null 2>&1 || fail "the laptop fetched one's owner's note"
    # What it adds goes to one, and on to ezra's machine, not to two
    mine=$(sh_on laptop 'echo "a note from the laptop" | hk add -q -')
    wait_for "ezra to fetch the laptop's note" on ezra hk dag fetch "$mine"
    ! on two hk dag fetch "$mine" >/dev/null 2>&1 || fail "two fetched the laptop's note"
    # Its mount is ezra's user's soup, read and written both ways
    mount_up laptop
    mount_up ezra
    sh_on laptop 'mkdir /soup/notes && echo "written on the laptop" > /soup/notes/laptop.md'
    wait_for "ezra to read the laptop's page" holds ezra /soup/notes/laptop.md "written on the laptop"
    sh_on ezra 'echo "and ezra replies" > /soup/notes/ezra.md'
    wait_for "the laptop to read ezra's page" holds laptop /soup/notes/ezra.md "and ezra replies"
    # Forgotten, it's shut out at once
    ! on one hk node forget "$peer" 2>/dev/null || fail "forgot a client the grants say is one"
    on one hk node grant rm "$peer" /mesh/client >/dev/null
    wait_for "one to stop listing the client" sh_on one "! hk node peers | grep -q '$peer'"
    wait_for "the laptop to be cut off" sh_on laptop "hk node status | grep -q '^connected	0$'"
}

# A thin client of one, in a sandbox: no repo, just a key and a ticket,
# every command asking one, as ezra's user
scenario_thin() {
    local peer one_peer ticket theirs ours mine anchor
    machine sandbox
    peer=$(on sandbox hk node id)
    one_peer=$(on one hk node id)
    ticket=$(on one hk node invite "$peer" --client --account 4000000001 2>/dev/null)
    on sandbox hk node join --thin "$ticket" 2>/dev/null
    ! sh_on sandbox 'test -e ~/.holokeep/blocks.db' || fail "the thin client made a repo"
    [ "$(on sandbox hk whoami | head -1)" = "member	$one_peer" ] || fail "the thin client doesn't say whose it is"
    # It reads what ezra's user has, which one fetches from ezra's machine
    theirs=$(sh_on ezra 'echo "a note for the sandbox" | hk add -q -')
    [ "$(on sandbox hk cat "$theirs")" = "a note for the sandbox" ] || fail "the sandbox couldn't read ezra's note"
    ours=$(sh_on one 'echo "a note of one'"'"'s owner alone" | hk add -q -')
    ! on sandbox hk cat "$ours" >/dev/null 2>&1 || fail "the sandbox read one's owner's note"
    # What it adds, whole chunks among it, one keeps for ezra's user, and
    # ezra's machine has
    sh_on sandbox 'head -c 3000000 /dev/urandom > /tmp/big'
    mine=$(on sandbox hk add -q /tmp/big)
    [ "$(sh_on sandbox "hk cat $mine | sha256sum")" = "$(sh_on sandbox 'sha256sum < /tmp/big')" ] || fail "the sandbox's file came back changed"
    on sandbox hk keep ls | grep -q "^$mine$" || fail "the sandbox's file isn't kept"
    wait_for "ezra to fetch the sandbox's file" on ezra hk dag fetch "$mine"
    # It sets anchors, as ezra's user
    anchor=$(on sandbox hk anchor new)
    on sandbox hk anchor set "$anchor" "$mine" >/dev/null
    [ "$(on sandbox hk anchor show "$anchor" | head -1)" = "$mine" ] || fail "the sandbox's anchor isn't set"
    wait_for "ezra to see the sandbox's anchor" sh_on ezra "hk anchor show $anchor 2>/dev/null | head -1 | grep -q $mine"
    # Its grant taken away, it's shut out
    on one hk node grant rm "$peer" /mesh/client >/dev/null
    wait_for "one to shut the sandbox out" sh_on one "! hk node peers | grep -q '$peer'"
    ! on sandbox hk whoami >/dev/null 2>&1 || fail "the sandbox still got in"
}

# A visitor: a key outside the mesh, no user of it, which one's owner
# shares an anchor with, reading that and nothing else
scenario_visitor() {
    local peer ticket shared private anchor view written friend
    machine guest
    peer=$(on guest hk node id)
    shared=$(sh_on one 'echo "shared with a visitor" | hk add -q -')
    private=$(sh_on one 'echo "not for visitors" | hk add -q -')
    anchor=$(on one hk anchor new)
    on one hk anchor set "$anchor" "$shared" >/dev/null
    on one hk anchor share "$anchor" "$peer" read >/dev/null
    ticket=$(on one hk node invite "$peer" --visitor 2>/dev/null)
    on guest hk node join --thin "$ticket" 2>/dev/null
    view=$(on guest hk anchor shared | cut -f1)
    [ -n "$view" ] || fail "nothing's shared with the visitor"
    [ "$(on guest hk anchor show "$view")" = "$shared" ] || fail "the visitor can't see the anchor"
    [ "$(on guest hk cat "$shared")" = "shared with a visitor" ] || fail "the visitor can't read what's shared"
    ! on guest hk cat "$private" >/dev/null 2>&1 || fail "the visitor read what isn't shared"
    ! on guest hk keep ls >/dev/null 2>&1 || fail "the visitor asked what only a client may"
    ! sh_on guest 'echo "from a visitor" | hk add -q -' >/dev/null 2>&1 || fail "the visitor wrote, let only read"
    on one hk node peers | grep -q "^$peer	.*visitor" || fail "one doesn't list the visitor"
    # two serves the owner too, so lets it in, but listens for no clients
    wait_for "two to let the visitor in" sh_on two "hk node peers | grep -q '^$peer	-	visitor'"
    # Let write, it sets the view as itself, and both members count it
    on one hk anchor share "$anchor" "$peer" write >/dev/null
    wait_for "the visitor to be let write" sh_on guest "hk anchor shared | grep -q /anchor/write"
    written=$(sh_on guest 'echo "from a visitor" | hk add -q -') || fail "the visitor couldn't add, let write"
    on guest hk anchor set "$view" "$written" >/dev/null || fail "the visitor couldn't set what it may write"
    [ "$(on guest hk anchor show "$view")" = "$written" ] || fail "the visitor doesn't see its set"
    [ "$(on one hk anchor show "$anchor" | head -1)" = "$written" ] || fail "one doesn't count the visitor's set"
    wait_for "two to count the visitor's set" sh_on two "hk anchor show '$anchor' | head -1 | grep -q '$written'"
    wait_for "two to have what the visitor wrote" sh_on two "[ \"\$(hk cat $written)\" = 'from a visitor' ]"
    # Let pass it on, it shares with a friend of its own, who reads it
    # through either member, till it takes that back
    machine friend
    friend=$(on friend hk node id)
    on one hk anchor share "$anchor" "$peer" grant >/dev/null
    wait_for "the visitor to be let pass it on" sh_on guest "hk anchor shared | grep -q /anchor/grant"
    on guest hk anchor share "$view" "$friend" read >/dev/null || fail "the visitor couldn't pass it on"
    on friend hk node join --thin "$(on guest hk node invite "$friend" --visitor 2>/dev/null)" 2>/dev/null
    [ "$(on friend hk anchor show "$view")" = "$written" ] || fail "the friend can't see the anchor"
    [ "$(on friend hk cat "$written")" = "from a visitor" ] || fail "the friend can't read what's shared"
    wait_for "two to let the friend in" sh_on two "hk node peers | grep -q '^$friend	-	visitor'"
    on guest hk anchor unshare "$view" "$friend" read >/dev/null || fail "the visitor couldn't take it back"
    wait_for "one to shut the friend out" sh_on one "! hk node peers | grep -q '^$friend	'"
    ! on friend hk anchor shared >/dev/null 2>&1 || fail "the friend still got in, unshared"
    # Unshared, it's shut out
    on one hk anchor unshare "$anchor" "$peer" read write grant >/dev/null
    wait_for "one to shut the visitor out" sh_on one "! hk node peers | grep -q '^$peer	'"
    wait_for "two to shut the visitor out" sh_on two "! hk node peers | grep -q '^$peer	'"
    ! on guest hk anchor shared >/dev/null 2>&1 || fail "the visitor still got in, unshared"
}

# A share for a while: a visitor reads it, then it's gone by every
# member's clock, and the visitor with it
# An anchor published sealed, read at a member's door by a machine in no
# mesh, by its capability alone; and read again as one's node publishes
# what it's become
scenario_door() {
    local anchor note again one_peer one_ip cap
    anchor=$(on one hk anchor new)
    note=$(sh_on one 'echo "read at the door" | hk add -q -')
    on one hk anchor set "$anchor" "$note" >/dev/null
    one_peer=$(on one hk node id)
    one_ip=$(podman inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$run-one")
    cap=$(on one hk cap publish "$anchor" --at "/ip4/$one_ip/tcp/4013/p2p/$one_peer" 2>/dev/null)
    grep -q "^$anchor	" <<<"$(on one hk cap ls)" || fail "one doesn't list what it published"
    machine outsider
    [ "$(on outsider hk cap import "$cap" 2>/dev/null)" = "root $note" ] || fail "the outsider couldn't read it at the door"
    [ "$(on outsider hk cat "$note")" = "read at the door" ] || fail "what the outsider read isn't what was published"
    # Another character in the middle, where every one says something
    local wrong=${cap:0:30}
    if [ "${cap:30:1}" = a ]; then wrong+=b; else wrong+=a; fi
    wrong+=${cap:31}
    ! on outsider hk cap import "$wrong" >/dev/null 2>&1 || fail "a capability that isn't one read it"
    # What's published now, kept aside, for a holder left behind to offer
    on one hk cap publish "$anchor" -o /tmp/first.car >/dev/null || fail "one couldn't write what's published to a CAR"
    on one cat /tmp/first.car | podman exec -i "$run-outsider" sh -c 'cat > /tmp/first.car' || fail "couldn't give the outsider the CAR"
    again=$(sh_on one 'echo "and again" | hk add -q -')
    on one hk anchor set "$anchor" "$again" >/dev/null
    wait_for "the outsider to read what one's node published again" sh_on outsider "test \"\$(hk cap import '$cap' 2>/dev/null)\" = 'root $again'"
    # Having read the newer, the outsider won't take the older as the latest
    local older
    older=$(on outsider hk cap import "$cap" /tmp/first.car 2>&1) && fail "the outsider took an older head as the latest: $older"
    grep -q "older than one read before" <<<"$older" || fail "the outsider couldn't read the older head, but not for being older: $older"
    # A writer outside: reads at the door, writes to a CAR, which one takes in
    local wcap written
    wcap=$(on one hk cap grant "$anchor" --at "/ip4/$one_ip/tcp/4013/p2p/$one_peer" 2>/dev/null) || fail "one couldn't let a writer write"
    written=$(sh_on outsider 'echo "written at the door" | hk add -q -')
    on outsider hk cap write "$wcap" "$written" >/dev/null 2>&1 || fail "the outsider couldn't write at the door"
    wait_for "one's node to take in what the outsider wrote at the door" sh_on one "hk anchor show $anchor | tail -1 | grep -q '	$written\$'"
    wait_for "the outsider to read what it wrote at the door" sh_on outsider "test \"\$(hk cap import '$cap' 2>/dev/null)\" = 'root $written'"
    # And again by CAR, which one takes in itself
    written=$(sh_on outsider 'echo "written from outside" | hk add -q -')
    on outsider hk cap write "$wcap" "$written" -o /tmp/written.car >/dev/null 2>&1 || fail "the outsider couldn't write"
    on outsider cat /tmp/written.car | podman exec -i "$run-one" sh -c 'cat > /tmp/written.car' || fail "couldn't give one the CAR"
    on one hk cap take /tmp/written.car >/dev/null 2>&1 || fail "one didn't take in what the outsider wrote"
    [ "$(on one hk anchor show "$anchor" | tail -1 | cut -f2)" = "$written" ] || fail "one's anchor isn't what the outsider wrote"
    wait_for "the outsider to read what it wrote, as one publishes it" sh_on outsider "test \"\$(hk cap import '$cap' 2>/dev/null)\" = 'root $written'"
    # Its write taken away, the door turns the outsider away
    local writer late
    writer=$(on one hk cap writers "$anchor" | grep -v "this machine" | cut -f1)
    [ -n "$writer" ] || fail "one doesn't list the outsider's writer"
    on one hk cap revoke "$anchor" "$writer" 2>/dev/null || fail "one couldn't take the outsider's write away"
    on one hk cap writers "$anchor" | grep -q "^$writer	taken away" || fail "one doesn't list the writer's write as taken away"
    late=$(sh_on outsider 'echo "too late" | hk add -q -')
    ! on outsider hk cap write "$wcap" "$late" >/dev/null 2>&1 || fail "the door took a write from a writer whose write's taken away"
    # A new read key: the old capability reads nothing new, the new one reads
    local rekeyed
    rekeyed=$(on one hk cap rekey "$anchor" --at "/ip4/$one_ip/tcp/4013/p2p/$one_peer" 2>/dev/null) || fail "one couldn't change the read key"
    [ "$rekeyed" != "$cap" ] || fail "the new capability is the old"
    ! on outsider hk cap import "$cap" >/dev/null 2>&1 || fail "the old capability read what's sealed with the new key"
    on outsider hk cap import "$rekeyed" 2>/dev/null | grep -q "^root " || fail "the new capability didn't read it"
    # Readers by keyring: one stays, one's read is taken away, and the one
    # that stays reads on through the new key
    local stays goes gone
    stays=$(on one hk cap reader "$anchor" --at "/ip4/$one_ip/tcp/4013/p2p/$one_peer" 2>/dev/null) || fail "one couldn't let a reader read"
    goes=$(on one hk cap reader "$anchor" --at "/ip4/$one_ip/tcp/4013/p2p/$one_peer" 2>/dev/null)
    on outsider hk cap import "$goes" 2>/dev/null | grep -q "^root " || fail "a reader couldn't read through its keyring"
    gone=$(on one hk cap readers "$anchor" | tail -1)
    on one hk cap unread "$anchor" "$gone" 2>/dev/null || fail "one couldn't take a reader's read away"
    ! on outsider hk cap import "$goes" >/dev/null 2>&1 || fail "a reader read with its read taken away"
    on outsider hk cap import "$stays" 2>/dev/null | grep -q "^root " || fail "the reader that stays didn't read on through the new key"
    # Sealed again whole, its past let go of: the reader still reads
    on one hk cap reseal "$anchor" --forget 2>/dev/null || fail "one couldn't seal it again and forget"
    on outsider hk cap import "$stays" 2>/dev/null | grep -q "^root " || fail "the reader didn't read what was sealed again"
    on one hk cap unpublish "$anchor" 2>/dev/null
    ! grep -q "^$anchor	" <<<"$(on one hk cap ls)" || fail "one still lists it, unpublished"

    # A folder published is made an anchor, and read through what mounts it
    local tree folder_cap whole_cap read inside
    sh_on one 'mkdir -p /tmp/tree/shared && echo "in the folder" > /tmp/tree/shared/inside.txt && echo "on top" > /tmp/tree/top.txt'
    tree=$(sh_on one 'hk add -q --no-keep /tmp/tree | tail -1')
    inside=$(sh_on one 'hk add -q --no-keep /tmp/tree/shared | tail -1')
    anchor=$(on one hk anchor new)
    on one hk anchor set "$anchor" "$tree" >/dev/null
    folder_cap=$(on one hk cap publish "anchors/$anchor/shared" --at "/ip4/$one_ip/tcp/4013/p2p/$one_peer" 2>/dev/null) || fail "one couldn't publish a folder"
    [ "$(on one hk cap ls | wc -l)" = 1 ] || fail "publishing the folder published other than it"
    [ "$(on outsider hk cap import "$folder_cap" 2>/dev/null)" = "root $inside" ] || fail "the outsider couldn't read the folder published"
    whole_cap=$(on one hk cap publish "$anchor" --at "/ip4/$one_ip/tcp/4013/p2p/$one_peer" 2>/dev/null)
    read=$(on outsider hk cap import "$whole_cap" 2>/dev/null)
    grep -q "^mount shared	$inside$" <<<"$read" || fail "the outsider didn't read the folder through what mounts it: $read"
    [ "$(on outsider hk cat "$(sh_on one 'hk add -q --no-keep /tmp/tree/shared/inside.txt')")" = "in the folder" ] || fail "what the outsider read through the mount point isn't the folder"
    # The soup protected: the root anchor published for no one else, and
    # read back as what it is
    local root
    root=$(on one hk anchor root | sed -n 1p)
    # Alone, as when this scenario's run by itself, it's something to protect
    if ! on one hk anchor show "$root" | grep -q "	"; then
        local kept
        kept=$(sh_on one 'mkdir -p /tmp/kept && echo "kept safe" > /tmp/kept/note && hk add -q --no-keep /tmp/kept | tail -1')
        on one hk anchor set "$root" "$kept" >/dev/null
    fi
    local protected
    protected=$(on one hk protect soup 2>&1) || fail "one couldn't protect the soup: $protected"
    grep -q "^$root	" <<<"$(on one hk cap ls)" || fail "the root anchor isn't published: $protected"
    grep -q "^$root	.*	already$" <<<"$(on one hk protect recover 2>/dev/null)" || fail "the root anchor doesn't read back as it is"
}

scenario_expiry() {
    local peer anchor shared view
    machine passer
    peer=$(on passer hk node id)
    shared=$(sh_on one 'echo "for a while" | hk add -q -')
    anchor=$(on one hk anchor new)
    on one hk anchor set "$anchor" "$shared" >/dev/null
    on one hk anchor share "$anchor" "$peer" read --for 15s >/dev/null
    on one hk anchor shared "$anchor" | grep -q "^.*	$peer	/anchor/read	until " || fail "the share doesn't say it ends"
    on passer hk node join --thin "$(on one hk node invite "$peer" --visitor 2>/dev/null)" 2>/dev/null
    view=$(on passer hk anchor shared | cut -f1)
    [ "$(on passer hk cat "$shared")" = "for a while" ] || fail "the visitor can't read it while it lasts"
    wait_for "two to let the passer in" sh_on two "hk node peers | grep -q '^$peer	-	visitor'"
    wait_for "one to shut the passer out" sh_on one "! hk node peers | grep -q '^$peer	'"
    wait_for "two to shut the passer out" sh_on two "! hk node peers | grep -q '^$peer	'"
    ! on passer hk anchor show "$view" >/dev/null 2>&1 || fail "the passer still got in, its share gone"
    ! on one hk anchor shared "$anchor" | grep -q "	$peer	/anchor/read" || fail "one still lists the share"
}

# A client of the mesh, not just of one member: ezra's machine listens for
# clients too, and a thin client invited by one reads through it while
# one's away
scenario_several() {
    local peer ticket theirs
    node_down ezra
    node_up ezra --clients
    wait_for "one to hear where ezra listens for clients" sh_on one "hk node status | grep -q '^members listening for clients	1$'"
    machine roamer
    peer=$(on roamer hk node id)
    ticket=$(on one hk node invite "$peer" --client --account 4000000001 2>/dev/null)
    on roamer hk node join --thin "$ticket" 2>/dev/null
    wait_for "ezra to let the roamer in" sh_on ezra "hk node peers | grep -q '^$peer	.*client'"
    theirs=$(sh_on ezra 'echo "read through ezra" | hk add -q -')
    cut_off one
    if [ "$(on roamer hk cat "$theirs" 2>&1)" != "read through ezra" ]; then
        put_back one
        fail "the roamer couldn't read through ezra with one away"
    fi
    put_back one
    # Its grant taken away on one, ezra shuts it out too
    on one hk node grant rm "$peer" /mesh/client >/dev/null
    wait_for "ezra to shut the roamer out" sh_on ezra "! hk node peers | grep -q '^$peer	'"
}

# --- Main ----------------------------------------------------------------

say "building hk and the machine image"
cargo build --release --quiet
podman build -q -t "$image" -f tests/mesh/Containerfile tests/mesh >/dev/null
podman network create "$net" >/dev/null

say "a mesh of two"
machine one
machine two
node_up one --clients --door
invite one two
node_up two
mount_up one
mount_up two

scenarios=("$@")
[ ${#scenarios[@]} -gt 0 ] || scenarios=(write_read edits copies late_joiner fork_merge lost forget car restore revoke shared client thin visitor expiry door several)
for scenario in "${scenarios[@]}"; do
    say "scenario: $scenario"
    "scenario_$scenario"
done
say "all passed"
