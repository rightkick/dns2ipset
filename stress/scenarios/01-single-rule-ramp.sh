#!/bin/bash
# 01-single-rule-ramp — find the saturation point.
#
# Uses resperf to ramp QPS from 0 to MAX over RAMP seconds against a single
# rule. resperf reports the highest sustained QPS before response failures
# climb above its threshold. dns2ipset metrics are dumped before/after so you
# can see writes/sec and any error counters.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"

MAX_QPS=${MAX_QPS:-200000}
RAMP=${RAMP:-60}     # seconds to ramp from 0 to MAX_QPS
PLATEAU=${PLATEAU:-30}  # seconds at MAX_QPS after ramp completes
POOL=${POOL:-256}
RULE_DOMAIN=${RULE_DOMAIN:-bench-1.test}

need_cmd resperf curl awk
need_service
need_port_free "$RESOLVER_PORT"

WORKDIR=$(mktemp -d)
trap 'cd /; fake_resolver_stop; rm -rf "$WORKDIR"' EXIT

echo "$RULE_DOMAIN A" > "$WORKDIR/queries.txt"

generate_rules 1 bench snoop_bench
sudo systemctl restart "$SERVICE"
sleep 1
fake_resolver_start "$POOL" 60

announce "01-single-rule-ramp — ramping 0 → ${MAX_QPS} QPS over ${RAMP}s"

metrics_snapshot "$WORKDIR/metrics.before"
pidstat_dns2ipset "$((RAMP+PLATEAU))" "$WORKDIR/pidstat.dns2ipset" &
PIDSTAT_PID=$!

resperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
    -m "$MAX_QPS" -r "$RAMP" -t "$PLATEAU" -c 4 \
    > "$WORKDIR/resperf.txt" 2>&1 || true

wait "$PIDSTAT_PID" 2>/dev/null || true
metrics_snapshot "$WORKDIR/metrics.after"

announce "resperf summary"
awk '/^[A-Z].*:/ || /maximum/ || /lost/ || /response/' "$WORKDIR/resperf.txt" | tail -30

announce "metric deltas"
metrics_diff "$WORKDIR/metrics.before" "$WORKDIR/metrics.after" | head -40

echo
echo "Detailed reports under: $WORKDIR"
echo "  resperf.txt          — full resperf output (look at 'maximum throughput')"
echo "  metrics.before/after — counters; diff shows what dns2ipset processed"
echo "  pidstat.dns2ipset    — daemon CPU/RSS during the run"
trap - EXIT
