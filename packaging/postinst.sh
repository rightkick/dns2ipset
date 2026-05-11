#!/bin/sh
# Post-install hook for the dns2ipset .deb.
# Runs as root after files are placed.
set -e

# Reload systemd so it picks up the new unit. Don't auto-enable: the
# operator still needs to pre-create ipsets and write /etc/dns2ipset/rules.yaml.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# CO-RE-relocated BPF objects need kernel BTF at load time. Warn if it's
# missing — install still succeeds, but the daemon will fail to start
# on this host until BTF is available.
if [ ! -e /sys/kernel/btf/vmlinux ]; then
    cat >&2 <<'EOF'
dns2ipset: WARNING — /sys/kernel/btf/vmlinux is missing on this host.
The eBPF program is built with CO-RE and resolves struct field offsets
against kernel BTF at load time. Without BTF, dns2ipset will not start.
This is typical of distroless or minimal kernels. Either install a
kernel built with CONFIG_DEBUG_INFO_BTF=y, or do not start the service
on this host.
EOF
fi

cat <<'EOF'
dns2ipset installed. Next steps:
  1. Pre-create the ipsets referenced by your rules (the daemon does
     not create sets — only adds entries):
       sudo ipset create snoop_example_v4 hash:ip family inet  timeout 86400
       sudo ipset create snoop_example_v6 hash:ip family inet6 timeout 86400
  2. Write your rules into /etc/dns2ipset/rules.yaml
     (a sample is at /etc/dns2ipset/rules.example.yaml).
  3. Start the service:
       sudo systemctl enable --now dns2ipset
EOF

exit 0
