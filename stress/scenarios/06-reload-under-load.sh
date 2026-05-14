#!/bin/bash
# 06-reload-under-load — atomic-rename rules.yaml repeatedly while load is
# running. Verifies the snapshot swap survives saturation and that
# rules_reload_total{result="error"} stays 0.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"

QPS=${QPS:-30000}
DURATION=${DURATION:-60}
RELOAD_INTERVAL=${RELOAD_INTERVAL:-3}   # seconds between atomic rename
RULES_VARIANTS=${RULES_VARIANTS:-5}

need_cmd dnsperf curl awk
need_service
need_port_free "$RESOLVER_PORT"

WORKDIR=$(mktemp -d)
trap 'cd /; fake_resolver_stop; rm -rf "$WORKDIR"' EXIT

# Single rule, but its definition will get rewritten with different
# alternative ipset names each cycle. Domain stays "bench-1.test" so the
# loadgen continues to match.
echo "bench-1.test A" > "$WORKDIR/queries.txt"
for i in $(seq 1 "$RULES_VARIANTS"); do
    sname="ipset_bench_${i}_v4"
    ipset_create_v4 "$sname"
    cat > "$WORKDIR/rules-v$i.yaml" <<EOF
version: 1
rules:
  - {domain: bench-1.test, ipset_v4: $sname}
EOF
done

# Initial install
sudo install -m 0644 "$WORKDIR/rules-v1.yaml" "$RULES_FILE"
sudo systemctl restart "$SERVICE"
sleep 1
fake_resolver_start 256 60

announce "06-reload-under-load — $QPS QPS, atomic-rename rules every ${RELOAD_INTERVAL}s"

metrics_snapshot "$WORKDIR/metrics.before"

# Reload loop in background.
(
    end=$(( $(date +%s) + DURATION ))
    i=2
    while [ "$(date +%s)" -lt "$end" ]; do
        v=$(( ((i-1) % RULES_VARIANTS) + 1 ))
        sudo cp "$WORKDIR/rules-v$v.yaml" "$WORKDIR/rules.next"
        sudo mv "$WORKDIR/rules.next" "$RULES_FILE"   # atomic rename → inotify
        i=$((i+1))
        sleep "$RELOAD_INTERVAL"
    done
) &
RELOADER_PID=$!

dnsperf -s "$RESOLVER_BIND" -p "$RESOLVER_PORT" -d "$WORKDIR/queries.txt" \
    -Q "$QPS" -l "$DURATION" -c 4 \
    > "$WORKDIR/dnsperf.txt" 2>&1

kill "$RELOADER_PID" 2>/dev/null || true
wait "$RELOADER_PID" 2>/dev/null || true
metrics_snapshot "$WORKDIR/metrics.after"

awk '/Statistics:/,/^$/' "$WORKDIR/dnsperf.txt"

announce "reload counter delta (must show ok>0, error=0)"
metrics_diff "$WORKDIR/metrics.before" "$WORKDIR/metrics.after" \
  | grep -E 'rules_reload_total|rules_active' || echo "(no diff — reload didn't fire?)"

announce "ipsets touched (each variant should have entries)"
for i in $(seq 1 "$RULES_VARIANTS"); do
    sudo ipset list "ipset_bench_${i}_v4" -terse
done
trap - EXIT
