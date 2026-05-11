#!/bin/bash
# 03-many-rules — N rules, queries cycle through all of them. Stresses trie
# lookup and ipset.Add dispatch across distinct sets.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"

RULES=${RULES:-1000}
QPS=${QPS:-30000}
DURATION=${DURATION:-60}
POOL=${POOL:-1024}

need_cmd dnsperf curl awk
need_service
need_port_free "$RESOLVER_PORT"

WORKDIR=$(mktemp -d)
trap 'cd /; fake_resolver_stop; rm -rf "$WORKDIR"' EXIT

generate_queries_file "$RULES" bench "$WORKDIR/queries.txt"

generate_rules "$RULES" bench snoop_bench
sudo systemctl restart "$SERVICE"
sleep 2  # rules.yaml is bigger; give the loader time
fake_resolver_start "$POOL" 60

announce "03-many-rules — $RULES rules, $QPS QPS for ${DURATION}s"

metrics_snapshot "$WORKDIR/metrics.before"
dnsperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
    -Q "$QPS" -l "$DURATION" -c 4 \
    > "$WORKDIR/dnsperf.txt" 2>&1
metrics_snapshot "$WORKDIR/metrics.after"

awk '/Statistics:/,/^$/' "$WORKDIR/dnsperf.txt"

announce "metric deltas (top 15)"
metrics_diff "$WORKDIR/metrics.before" "$WORKDIR/metrics.after" | head -15

announce "rules_active gauge"
metrics_get dns2ipset_rules_active

echo
echo "Heads-up: with $RULES rules and the dashboard's 'matches by rule' panel,"
echo "Grafana legend cardinality will explode. Cap with topk(20, ...) for queries."
trap - EXIT
