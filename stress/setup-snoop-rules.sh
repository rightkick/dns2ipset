#!/bin/bash
# setup-snoop-rules — run on the dns2ipset gateway to install a rules.yaml
# and matching ipsets generated from the top N of a Tranco-format CSV.
#
# Pairs with stress/scenarios/07-perf-baseline.sh, which runs from a client
# VM and points dnsperf at this gateway. The point of this script is to
# avoid hand-writing a 100-rule rules.yaml.
#
# Tunables (env):
#   DOMAIN_LIST    default ../stress/domain-list.csv (relative to this script)
#   SNOOP_COUNT    default 100      top-N domains used as rules
#   RULES_FILE     default /etc/dns2ipset/rules.yaml
#   SET_PREFIX     default snoop_top_   ipset name prefix
#   TIMEOUT        default 86400    seconds; ipset entry TTL ceiling
#
# Idempotent: re-running with the same SNOOP_COUNT regenerates the same
# rules.yaml and re-creates the ipsets (no-op if they already exist).
#
# Cleanup later with:
#   . stress/lib.sh && wipe_ipsets_with_prefix snoop_top_
#   sudo bash stress/teardown.sh   # also restores rules.yaml to rules: []
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$SCRIPT_DIR/lib.sh"

DOMAIN_LIST=${DOMAIN_LIST:-$SCRIPT_DIR/domain-list.csv}
SNOOP_COUNT=${SNOOP_COUNT:-100}
SET_PREFIX=${SET_PREFIX:-snoop_top_}
TIMEOUT=${TIMEOUT:-86400}

need_cmd awk ipset
[ -f "$DOMAIN_LIST" ] || {
    echo >&2 "domain list not found: $DOMAIN_LIST"
    echo >&2 "place a Tranco-format CSV (rank,domain) there, or override DOMAIN_LIST=…"
    exit 1
}

[ -d /etc/dns2ipset ] || {
    echo >&2 "/etc/dns2ipset does not exist — is dns2ipset installed?"
    exit 1
}

echo "Reading top $SNOOP_COUNT domains from $DOMAIN_LIST"
mapfile -t domains < <(head -n "$SNOOP_COUNT" "$DOMAIN_LIST" | awk -F, '{ print $2 }')
got=${#domains[@]}
if [ "$got" -lt "$SNOOP_COUNT" ]; then
    echo "WARN: only $got entries in $DOMAIN_LIST (asked for $SNOOP_COUNT)"
fi

# Compose rules.yaml in memory, atomically rename into place so the
# dns2ipset inotify watcher fires exactly once.
body="version: 1\nrules:\n"
for i in "${!domains[@]}"; do
    domain=${domains[$i]}
    sname=${SET_PREFIX}$((i + 1))_v4
    # Create the v4 ipset for this rule with the configured timeout.
    sudo ipset create "$sname" hash:ip family inet timeout "$TIMEOUT" -exist
    body+="  - {domain: ${domain}, ipset_v4: ${sname}}\n"
done

printf "%b" "$body" | rules_write
echo "Wrote $RULES_FILE with $got rules; created/refreshed $got ${SET_PREFIX}*_v4 ipsets"
echo
echo "Verify dns2ipset picked up the reload:"
echo "  journalctl -u dns2ipset -n 10 --no-pager | grep -E 'rules reloaded|rules_active'"
