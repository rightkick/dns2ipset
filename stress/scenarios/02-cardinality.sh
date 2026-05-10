#!/bin/bash
# 02-cardinality — single rule, large IP pool. Stresses ipset growth and
# kernel hash:ip insert behaviour as the set fills toward maxelem.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"

QPS=${QPS:-30000}
DURATION=${DURATION:-120}
POOL=${POOL:-65000}     # close to default ipset hash:ip maxelem (65536)
RULE_DOMAIN=${RULE_DOMAIN:-bench-1.test}

need_cmd dnsperf curl awk
need_service
need_port_free "$RESOLVER_PORT"

WORKDIR=$(mktemp -d)
trap 'cd /; fake_resolver_stop; rm -rf "$WORKDIR"' EXIT

echo "$RULE_DOMAIN A" > "$WORKDIR/queries.txt"

generate_rules 1 bench snoop_bench
sudo systemctl restart "$SERVICE"
sleep 1
fake_resolver_start "$POOL" 60

announce "02-cardinality — $QPS QPS for ${DURATION}s, IP pool of $POOL"

metrics_snapshot "$WORKDIR/metrics.before"
dnsperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
    -Q "$QPS" -l "$DURATION" -c 4 \
    > "$WORKDIR/dnsperf.txt" 2>&1
metrics_snapshot "$WORKDIR/metrics.after"

awk '/Statistics:/,/^$/' "$WORKDIR/dnsperf.txt"

announce "ipset state"
sudo ipset list snoop_bench_1_v4 -terse

announce "metric deltas"
metrics_diff "$WORKDIR/metrics.before" "$WORKDIR/metrics.after" | head -40

echo
echo "Watch: 'Number of entries' in ipset list approaches POOL ($POOL)."
echo "If entries plateau below POOL, ipset hit maxelem; recreate with maxelem=N."
trap - EXIT
