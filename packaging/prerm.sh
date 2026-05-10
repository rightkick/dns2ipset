#!/bin/sh
# Pre-remove hook for the dns2ipset .deb.
# Runs before files are removed. Idempotent.
set -e

if command -v systemctl >/dev/null 2>&1; then
    # Stop the unit if running. Ignore errors: unit may already be stopped,
    # or systemd may not be the active init.
    systemctl stop dns2ipset.service >/dev/null 2>&1 || true
    # Disable on full purge (`remove --purge`) is conventionally handled
    # by postrm, but a plain `remove` should also leave systemd in a
    # consistent state, so disable here too.
    systemctl disable dns2ipset.service >/dev/null 2>&1 || true
fi

exit 0
