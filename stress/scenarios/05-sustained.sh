#!/bin/bash
# 05-sustained — long-duration run at moderate load. Use this to catch
# slow leaks (FDs, goroutines, RSS growth, GC pauses).
#
# Defaults: 30k QPS for 1 hour. Override DURATION_HOURS for longer.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"

QPS=${QPS:-30000}
DURATION_HOURS=${DURATION_HOURS:-1}
POOL=${POOL:-1024}
RULE_DOMAIN=${RULE_DOMAIN:-bench-1.test}
SAMPLE_INTERVAL=${SAMPLE_INTERVAL:-60}  # seconds between metric snapshots

need_cmd dnsperf curl awk
need_service
need_port_free "$RESOLVER_PORT"

WORKDIR=$(mktemp -d)
trap 'cd /; fake_resolver_stop; rm -rf "$WORKDIR"' EXIT

duration_sec=$((DURATION_HOURS * 3600))
echo "$RULE_DOMAIN A" > "$WORKDIR/queries.txt"

generate_rules 1 bench snoop_bench
sudo systemctl restart "$SERVICE"
sleep 1
fake_resolver_start "$POOL" 60

announce "05-sustained — $QPS QPS for ${DURATION_HOURS}h"
echo "Metric snapshots every ${SAMPLE_INTERVAL}s in $WORKDIR/samples/"
mkdir -p "$WORKDIR/samples"

# Background sampler — captures /metrics + RSS so leak trends are visible.
(
    n=0
    end=$(( $(date +%s) + duration_sec ))
    while [ "$(date +%s)" -lt "$end" ]; do
        ts=$(date +%s)
        metrics_snapshot "$WORKDIR/samples/metrics.${ts}"
        local_pid=$(pgrep -f '/usr/local/bin/dns2ipset' | head -1)
        if [ -n "$local_pid" ]; then
            ps -o rss=,vsz=,nlwp= -p "$local_pid" > "$WORKDIR/samples/proc.${ts}" 2>/dev/null || true
        fi
        n=$((n+1))
        sleep "$SAMPLE_INTERVAL"
    done
) &
SAMPLER_PID=$!

dnsperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
    -Q "$QPS" -l "$duration_sec" -c 4 \
    > "$WORKDIR/dnsperf.txt" 2>&1

kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true

awk '/Statistics:/,/^$/' "$WORKDIR/dnsperf.txt"

announce "RSS / threads over time (rss_kb vsz_kb threads)"
ls "$WORKDIR/samples"/proc.* 2>/dev/null | sort | while read -r f; do
    ts=${f##*/proc.}
    printf '%s  %s\n' "$(date -d @"$ts" +%H:%M:%S)" "$(cat "$f" | tr -s ' ')"
done | head -200

echo
echo "Full samples in $WORKDIR/samples/  (use awk on metrics.<ts> for trends)"
trap - EXIT
