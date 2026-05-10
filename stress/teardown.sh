#!/bin/bash
# Cleanup after stress runs: destroy bench ipsets, stop any orphan
# fake-resolver, restore minimal rules.yaml.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

echo "stopping any fake-resolver…"
sudo pkill -f fake-resolver 2>/dev/null || true

echo "restoring minimal rules.yaml…"
clear_rules

echo "destroying snoop_bench_* ipsets…"
wipe_bench_ipsets

echo "restarting $SERVICE…"
sudo systemctl restart "$SERVICE" 2>/dev/null || true

echo "done."
