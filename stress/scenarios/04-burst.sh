#!/bin/bash
# 04-burst — alternating idle / hammer / idle phases. Stresses the events
# channel buffer (1024) and dedup window. Watch dns2ipset_pipeline_inflight
# in Grafana during the run; if it spikes near 1024 you're seeing the source
# stall workers.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"

LOW_QPS=${LOW_QPS:-100}
HIGH_QPS=${HIGH_QPS:-100000}
PHASE=${PHASE:-15}      # seconds per phase
CYCLES=${CYCLES:-3}
POOL=${POOL:-256}
RULE_DOMAIN=${RULE_DOMAIN:-bench-1.test}

need_cmd dnsperf curl awk
need_service
need_port_free "$RESOLVER_PORT"

WORKDIR=$(mktemp -d)
trap 'cd /; fake_resolver_stop; rm -rf "$WORKDIR"' EXIT

echo "$RULE_DOMAIN A" > "$WORKDIR/queries.txt"

generate_rules 1 bench ipset_bench
sudo systemctl restart "$SERVICE"
sleep 1
fake_resolver_start "$POOL" 60

announce "04-burst — ${CYCLES}× (low ${LOW_QPS} QPS / high ${HIGH_QPS} QPS), ${PHASE}s each"

metrics_snapshot "$WORKDIR/metrics.before"
for c in $(seq 1 "$CYCLES"); do
    echo "[$(date +%T)] cycle $c low ${LOW_QPS} QPS"
    dnsperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
        -Q "$LOW_QPS" -l "$PHASE" -c 1 > /dev/null 2>&1
    echo "[$(date +%T)] cycle $c high ${HIGH_QPS} QPS"
    dnsperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
        -Q "$HIGH_QPS" -l "$PHASE" -c 4 \
        > "$WORKDIR/dnsperf.cycle-$c.txt" 2>&1
    awk '/Queries per second/ || /Queries lost/' "$WORKDIR/dnsperf.cycle-$c.txt"
done
metrics_snapshot "$WORKDIR/metrics.after"

announce "metric deltas"
metrics_diff "$WORKDIR/metrics.before" "$WORKDIR/metrics.after" | head -25
trap - EXIT
