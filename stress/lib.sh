#!/bin/bash
# Common helpers for dns2ipset stress scenarios.
# Source from any scenario script with: . "$(dirname "$0")/../lib.sh"
set -euo pipefail

METRICS_URL=${METRICS_URL:-http://127.0.0.1:9301/metrics}
RULES_FILE=${RULES_FILE:-/etc/dns2ipset/rules.yaml}
RESOLVER_BIND=${RESOLVER_BIND:-127.0.0.1}
RESOLVER_PORT=${RESOLVER_PORT:-53}
SERVICE=${SERVICE:-dns2ipset}
FAKE_RESOLVER_BIN=${FAKE_RESOLVER_BIN:-$(dirname "${BASH_SOURCE[0]}")/fake-resolver/fake-resolver}
QUERIES_DIR=${QUERIES_DIR:-$(dirname "${BASH_SOURCE[0]}")/queries}

# need_cmd cmd [cmd...] — exits if any required tool is missing.
need_cmd() {
    local missing=()
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo >&2 "missing required commands: ${missing[*]}"
        echo >&2 "install with: sudo apt-get install -y dnsperf  (provides dnsperf and resperf)"
        exit 1
    fi
}

# need_port_free port — fails if port (UDP) is bound.
need_port_free() {
    local port=$1
    if sudo ss -tulpn 2>/dev/null | awk -v p=":$port " '$5 ~ p {found=1} END {exit !found}'; then
        echo >&2 "UDP port $port is in use:"
        sudo ss -tulpn | awk -v p=":$port " '$5 ~ p'
        echo >&2 "stop the holder before running stress (e.g. systemd-resolved, dnsmasq)."
        exit 1
    fi
}

# need_service [name] — fails if dns2ipset isn't installed (unit file missing).
need_service() {
    local svc=${1:-$SERVICE}
    if ! systemctl cat "$svc" >/dev/null 2>&1; then
        echo >&2 "service '$svc' not installed (no systemd unit)."
        echo >&2 "install the .deb first: sudo apt install ./dns2ipset_*_amd64.deb"
        exit 1
    fi
}

# fake_resolver_start [pool] [ttl]
# Starts the fake resolver in the background bound to $RESOLVER_BIND:$RESOLVER_PORT.
# Stores pid in $FAKE_PID. Caller must arrange teardown via fake_resolver_stop.
fake_resolver_start() {
    local pool=${1:-256}
    local ttl=${2:-60}
    if [ ! -x "$FAKE_RESOLVER_BIN" ]; then
        echo >&2 "fake-resolver binary not found at $FAKE_RESOLVER_BIN"
        echo >&2 "build with: (cd stress/fake-resolver && go build -o fake-resolver .)"
        exit 1
    fi
    sudo "$FAKE_RESOLVER_BIN" --addr "$RESOLVER_BIND:$RESOLVER_PORT" --pool "$pool" --ttl "$ttl" \
        > /tmp/dns2ipset-stress-resolver.log 2>&1 &
    FAKE_PID=$!
    sleep 0.3
    if ! kill -0 "$FAKE_PID" 2>/dev/null; then
        echo >&2 "fake-resolver failed to start; log:"
        sed 's/^/  /' /tmp/dns2ipset-stress-resolver.log >&2
        exit 1
    fi
    echo "fake-resolver up (pid=$FAKE_PID, pool=$pool, ttl=$ttl)"
}

fake_resolver_stop() {
    if [ -n "${FAKE_PID:-}" ]; then
        sudo kill "$FAKE_PID" 2>/dev/null || true
        wait "$FAKE_PID" 2>/dev/null || true
        FAKE_PID=
    fi
}

# rules_write <rules-yaml-content-on-stdin>
# Atomically replaces $RULES_FILE so dns2ipset's inotify watcher fires once.
rules_write() {
    local tmp
    tmp=$(sudo mktemp /etc/dns2ipset/rules.yaml.XXXXXX)
    sudo tee "$tmp" >/dev/null
    sudo chmod 644 "$tmp"
    sudo mv "$tmp" "$RULES_FILE"
}

# ipset_create_v4 <name>
ipset_create_v4() {
    sudo ipset create "$1" hash:ip family inet timeout 86400 -exist
}

# ipset_destroy <name>
ipset_destroy() {
    sudo ipset destroy "$1" 2>/dev/null || true
}

# generate_rules <count> <rule-prefix> <set-prefix>
# Writes a rules.yaml with N rules of the form
#   <rule-prefix>-<i>.test -> <set-prefix>-<i>-v4
# and creates the matching v4 ipsets.
generate_rules() {
    local count=$1 rprefix=${2:-bench} sprefix=${3:-snoop_bench}
    local body="version: 1\nrules:\n"
    for i in $(seq 1 "$count"); do
        body+="  - {domain: ${rprefix}-${i}.test, ipset_v4: ${sprefix}_${i}_v4}\n"
        ipset_create_v4 "${sprefix}_${i}_v4"
    done
    printf "%b" "$body" | rules_write
}

# generate_queries_file <count> <rule-prefix> <output-path>
# Writes dnsperf-format queries to <output-path>.
generate_queries_file() {
    local count=$1 rprefix=${2:-bench} out=$3
    : > "$out"
    for i in $(seq 1 "$count"); do
        printf "%s-%d.test A\n" "$rprefix" "$i" >> "$out"
    done
}

# clear_rules — minimal "no rules" config. dns2ipset stays running but
# matches nothing. Useful for the with/without comparison.
clear_rules() {
    printf "version: 1\nrules: []\n" | rules_write
}

# wipe_bench_ipsets — destroy all snoop_bench_*_v4 sets.
wipe_bench_ipsets() {
    sudo ipset list -terse 2>/dev/null | awk '/^Name: snoop_bench_/ {print $2}' | while read -r s; do
        ipset_destroy "$s"
    done
}

# metrics_get <name> [labels-substr] — read a single counter/gauge value.
# Example: metrics_get dns2ipset_events_total 'direction="recv"'
metrics_get() {
    local name=$1 label_substr=${2:-}
    if [ -n "$label_substr" ]; then
        curl -fsS "$METRICS_URL" | awk -v n="$name" -v l="$label_substr" '
            $0 ~ "^" n "{" && index($0, l) { print $NF; exit }
        '
    else
        curl -fsS "$METRICS_URL" | awk -v n="$name" '
            $0 ~ "^" n "[ {]" { print $NF; exit }
        '
    fi
}

# metrics_snapshot <output-path> — dumps every dns2ipset_* line for delta.
metrics_snapshot() {
    curl -fsS "$METRICS_URL" | grep '^dns2ipset_' > "$1" || true
}

# metrics_diff <before-path> <after-path> — prints lines whose VALUE changed.
metrics_diff() {
    diff -u "$1" "$2" | awk '
        /^---|^\+\+\+/ {next}
        /^[+-]/ { print }
    '
}

# pidstat_dns2ipset <duration-sec> <output-path>
# Captures CPU/RSS for the dns2ipset process in 1-sec bins.
pidstat_dns2ipset() {
    local dur=$1 out=$2
    local pid
    pid=$(pgrep -f '/usr/local/bin/dns2ipset' | head -1)
    if [ -z "$pid" ]; then
        echo "pidstat: dns2ipset not running" > "$out"
        return
    fi
    sudo pidstat -h -p "$pid" -u -r 1 "$dur" > "$out" 2>&1 || true
}

# announce header — pretty banner for scenario output.
announce() {
    echo
    echo "===================================================================="
    echo "  $*"
    echo "===================================================================="
}
