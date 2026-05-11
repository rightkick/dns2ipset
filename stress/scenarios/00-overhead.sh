#!/bin/bash
# 00-overhead — measure the overhead dns2ipset's BPF hooks add to plain DNS resolution.
#
# Procedure:
#   1. Stop dns2ipset.
#   2. Run dnsperf at $QPS for $DURATION → baseline (resolver throughput, latency, CPU).
#   3. Start dns2ipset (with one matching rule so the full hot path runs).
#   4. Run dnsperf at the same $QPS → with-snooping result.
#   5. Print deltas.
#
# Tunables (env): QPS, DURATION, POOL, RULE_DOMAIN.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"

QPS=${QPS:-20000}
DURATION=${DURATION:-30}
POOL=${POOL:-256}
RULE_DOMAIN=${RULE_DOMAIN:-bench-1.test}

need_cmd dnsperf curl awk pidstat
need_service
need_port_free "$RESOLVER_PORT"

WORKDIR=$(mktemp -d)
trap 'cd /; fake_resolver_stop; sudo systemctl start "$SERVICE" >/dev/null 2>&1 || true; rm -rf "$WORKDIR"' EXIT

# Single query, repeated, so dnsperf hits the fake resolver in a tight loop.
echo "$RULE_DOMAIN A" > "$WORKDIR/queries.txt"

run_load() {
    local label=$1 outdir=$2
    mkdir -p "$outdir"
    pidstat_dns2ipset "$DURATION" "$outdir/pidstat.dns2ipset" &
    local pidstat_pid=$!
    # Resolver pidstat — measures the cost on the resolver process itself.
    local rpid; rpid=$(pgrep -f fake-resolver | head -1)
    if [ -n "$rpid" ]; then
        sudo pidstat -h -p "$rpid" -u 1 "$DURATION" > "$outdir/pidstat.resolver" 2>&1 &
    fi
    metrics_snapshot "$outdir/metrics.before"
    dnsperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
        -Q "$QPS" -l "$DURATION" -S 5 -c 4 \
        > "$outdir/dnsperf.txt" 2>&1
    metrics_snapshot "$outdir/metrics.after"
    wait "$pidstat_pid" 2>/dev/null || true
    announce "$label — dnsperf summary"
    awk '
        /Statistics:/ {seen=1}
        seen && (/Queries sent:/ || /Queries completed:/ || /Queries lost:/ || /Response codes/ || /Average packet size/ || /Run time/ || /Queries per second/ || /Average Latency/ || /Latency StdDev/)
    ' "$outdir/dnsperf.txt"
}

announce "00-overhead — comparing dns2ipset OFF vs ON ($QPS QPS, ${DURATION}s)"

# 1) baseline (dns2ipset stopped)
sudo systemctl stop "$SERVICE"
fake_resolver_start "$POOL" 60
run_load "BASELINE (dns2ipset stopped)" "$WORKDIR/baseline"
fake_resolver_stop

# 2) configure & start dns2ipset
generate_rules 1 bench snoop_bench
sudo systemctl start "$SERVICE"
sleep 1   # let the daemon attach BPF + watch rules
fake_resolver_start "$POOL" 60
run_load "WITH dns2ipset" "$WORKDIR/with"
fake_resolver_stop

announce "deltas"
echo "Resolver throughput:"
echo "  baseline: $(awk '/Queries per second/ {print $4}' "$WORKDIR/baseline/dnsperf.txt") qps"
echo "  with:     $(awk '/Queries per second/ {print $4}' "$WORKDIR/with/dnsperf.txt") qps"
echo
echo "Average latency:"
echo "  baseline: $(awk '/Average Latency/ {print $4}' "$WORKDIR/baseline/dnsperf.txt") s"
echo "  with:     $(awk '/Average Latency/ {print $4}' "$WORKDIR/with/dnsperf.txt") s"
echo
echo "Detailed reports under: $WORKDIR"
echo "  $WORKDIR/baseline/dnsperf.txt   — full dnsperf output (no dns2ipset)"
echo "  $WORKDIR/with/dnsperf.txt       — full dnsperf output (with dns2ipset)"
echo "  $WORKDIR/*/pidstat.{dns2ipset,resolver}  — CPU/RSS samples"
echo "  $WORKDIR/with/metrics.{before,after}     — dns2ipset metric counters"
echo
echo "(WORKDIR preserved; rm -rf when done. cleanup of bench ipsets:)"
echo "  bash stress/teardown.sh"
trap - EXIT
