#!/bin/bash
# 07-perf-baseline — run dnsperf at a target resolver and print stats.
#
# This scenario is client-side only. It does NOT modify the target server
# (no systemctl, no cache flush, no SSH). The caller controls server-side
# state (dns2ipset on/off, resolver cache cold/warm) manually and labels
# each run with the LABEL env var.
#
# Typical 4-run sequence (defaults aimed at gw.lab.local):
#
#   # On gw.lab.local: stop dns2ipset, flush dnsmasq cache.
#   #   sudo systemctl stop dns2ipset
#   #   sudo kill -HUP $(pidof dnsmasq)
#   LABEL=cold-off  bash stress/scenarios/07-perf-baseline.sh
#
#   # No state change — cache is hot from the previous pass.
#   LABEL=warm-off  bash stress/scenarios/07-perf-baseline.sh
#
#   # On gw.lab.local: start dns2ipset, flush dnsmasq cache again.
#   #   sudo systemctl start dns2ipset
#   #   sudo kill -HUP $(pidof dnsmasq)
#   LABEL=cold-on   bash stress/scenarios/07-perf-baseline.sh
#
#   LABEL=warm-on   bash stress/scenarios/07-perf-baseline.sh
#
# The four reports each show a dnsperf Statistics block; eyeball them
# side-by-side for the comparison.
#
# Tunables (env):
#   TARGET         default gw.lab.local         target resolver
#   DOMAIN_LIST    default stress/domain-list.csv   CSV in `rank,domain` format
#   QUERIES_COUNT  default 10000                top-N domains used as queries
#   CONCURRENCY    default 100                  dnsperf -c
#   LABEL          default run-<epoch>          tag for the report filename
#
# Prereqs on the client VM:
#   sudo apt-get install -y dnsperf
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TARGET=${TARGET:-gw.lab.local}
DOMAIN_LIST=${DOMAIN_LIST:-$SCRIPT_DIR/../domain-list.csv}
QUERIES_COUNT=${QUERIES_COUNT:-10000}
CONCURRENCY=${CONCURRENCY:-100}
LABEL=${LABEL:-run-$(date +%s)}

command -v dnsperf >/dev/null 2>&1 || {
    echo >&2 "dnsperf not on PATH — install with: sudo apt-get install -y dnsperf"
    exit 1
}
[ -f "$DOMAIN_LIST" ] || {
    echo >&2 "domain list not found: $DOMAIN_LIST"
    echo >&2 "place a Tranco-format CSV (rank,domain) there, or override DOMAIN_LIST=…"
    exit 1
}

WORKDIR=$(mktemp -d -p /tmp dns2ipset-perf-$LABEL.XXXXXX)
QUERIES=$WORKDIR/queries.txt
REPORT=$WORKDIR/dnsperf.txt

head -n "$QUERIES_COUNT" "$DOMAIN_LIST" | awk -F, '{ printf "%s A\n", $2 }' > "$QUERIES"
actual=$(wc -l < "$QUERIES")
if [ "$actual" -lt "$QUERIES_COUNT" ]; then
    echo "WARN: only $actual entries in $DOMAIN_LIST (asked for $QUERIES_COUNT)"
fi

echo
echo "======================================================================"
echo "  dnsperf  label=$LABEL"
echo "  target:    $TARGET"
echo "  queries:   $actual (top-N of $DOMAIN_LIST)"
echo "  -c:        $CONCURRENCY"
echo "  workdir:   $WORKDIR"
echo "======================================================================"
echo

# Run. dnsperf exits non-zero on EOF-of-input which is normal; tolerate it.
dnsperf -s "$TARGET" -d "$QUERIES" -c "$CONCURRENCY" > "$REPORT" 2>&1 || true

# Echo the Statistics block.
awk '/^Statistics:/,0' "$REPORT" | sed 's/^/  /'

echo
echo "full report: $REPORT"
