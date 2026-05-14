# dns2ipset on Debian 12 — install & smoke test

End-to-end walkthrough for installing dns2ipset on a fresh Debian 12 (Bookworm)
VM, wiring it up to a local resolver, and confirming the data path with `dig`,
`ipset list`, and `iptables`. Everything is `sudo` — assumes you have root or
sudoer access on the VM.

Debian 12 ships with kernel 6.1, which has BTF and `fentry` support — the two
hard requirements. If you're on an older kernel, stop here.

---

## 0. Sanity checks

```bash
uname -r                            # expect 6.1.x or newer
ls /sys/kernel/btf/vmlinux          # must exist; CO-RE depends on it
test -d /sys/fs/bpf && echo bpf-fs  # bpf filesystem must be mountable
```

If `/sys/kernel/btf/vmlinux` is missing the kernel was built without BTF and
this won't work — re-image the VM with the stock Debian kernel.

---

## 1. Install build prerequisites

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    linux-headers-$(uname -r) \
    ipset \
    iptables \
    git \
    ca-certificates
```

Verify each:

```bash
clang --version | head -1           # expect clang 14.x or newer
bpftool version | head -1           # expect any non-zero
ipset --version | head -1
iptables -V
```

Install Go 1.24 (Debian 12's repo Go is 1.19, too old):

```bash
GO_VER=1.24.0
curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" | sudo tar -C /usr/local -xz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
export PATH=$PATH:/usr/local/go/bin
go version                          # go version go1.24.0 linux/amd64
```

---

## 2. Build the binary on the VM

```bash
cd ~
git clone https://github.com/rightkick/dns2ipset.git   # or rsync your local checkout
cd dns2ipset
git checkout feat/initial-implementation               # until merged to main
make generate                                          # bpf2go: clang -> .o + bindings
go vet ./...
go test ./...                                          # all tests should pass
make build                                             # produces ./dns2ipset (static)
file dns2ipset                                         # statically linked, stripped
```

If `make generate` fails on `vmlinux.h`, regenerate it manually:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c \
    > internal/bpf/c/headers/vmlinux.h
make generate
```

---

## 3. Install a local resolver (if the VM doesn't have one yet)

dns2ipset snoops the resolver's UDP-53 traffic on `127.0.0.1`. Either bind9 or
dnsmasq works. Pick **one**:

### Option A — `dnsmasq` (lighter)

```bash
sudo apt-get install -y dnsmasq
sudo systemctl disable --now systemd-resolved      # frees port 53
sudo rm -f /etc/resolv.conf
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
sudo systemctl enable --now dnsmasq
dig @127.0.0.1 example.com +short                  # should resolve
```

### Option B — `bind9`

```bash
sudo apt-get install -y bind9
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
sudo systemctl enable --now named
dig @127.0.0.1 example.com +short
```

If either resolver fails to start with "address already in use", another
DNS service is bound to `:53` — `sudo ss -tulpn | grep ':53 '` will tell
you what.

---

## 4. Pre-create the ipsets

dns2ipset only adds entries; it never creates sets. Create at least one v4
set and one v6 set, with `timeout` so per-entry expiry from the daemon
takes effect:

```bash
sudo ipset create ipset_example_v4 hash:ip family inet  timeout 86400
sudo ipset create ipset_example_v6 hash:ip family inet6 timeout 86400
sudo ipset list -terse
```

Output should show both sets with `Number of entries: 0`.

---

## 5. Install the binary, rules, and systemd unit

```bash
sudo install -m 0755 dns2ipset /usr/local/bin/

sudo install -d /etc/dns2ipset
sudo tee /etc/dns2ipset/rules.yaml > /dev/null <<'EOF'
version: 1
rules:
  - domain: example.com
    ipset_v4: ipset_example_v4
    ipset_v6: ipset_example_v6
EOF

sudo install -m 0644 deploy/dns2ipset.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dns2ipset
sudo systemctl status dns2ipset --no-pager
```

`status` should show `active (running)` and (in the journal) lines like
`dns2ipset starting rules=/etc/dns2ipset/rules.yaml rule-count=1`.

If it failed:

```bash
sudo journalctl -u dns2ipset -n 50 --no-pager
```

Common failures:
- `failed to load BPF object`: BTF/kernel mismatch — confirm `vmlinux.h`
  was generated from THIS VM's kernel BTF.
- `attach udp_sendmsg: …`: kernel doesn't support `fentry` on the
  function (very old kernel, or hardened config). Confirm
  `cat /boot/config-$(uname -r) | grep BPF_LSM` etc.
- `ipset … missing`: you didn't pre-create the set. Re-run section 4.

---

## 6. End-to-end smoke test

```bash
# Trigger a fresh resolution. Use +trace +recurse to make sure it isn't cached.
dig @127.0.0.1 example.com +short
dig @127.0.0.1 www.example.com +short

# Within ~100 ms the IPs should appear in the set.
sudo ipset list ipset_example_v4
sudo ipset list ipset_example_v6
```

Expected: each `ipset list` shows the resolved addresses with TTLs near the
DNS answer's TTL (typically 30–600 seconds for example.com).

Negative test (a domain NOT in the rules):

```bash
dig @127.0.0.1 example.org +short
sudo ipset list ipset_example_v4         # unchanged
```

Reload test (atomic-rename swap):

```bash
sudo tee /tmp/rules.new > /dev/null <<'EOF'
version: 1
rules:
  - domain: github.com
    ipset_v4: ipset_example_v4
EOF
sudo mv /tmp/rules.new /etc/dns2ipset/rules.yaml      # inotify fires
dig @127.0.0.1 github.com +short
sudo ipset list ipset_example_v4                           # github.com IPs now appear
```

The journal should show `rules reloaded rules=1` from the inotify watcher.

---

## 7. iptables integration (optional)

To prove the loop closes — DNS-resolved IPs really do block traffic:

```bash
# Add a DROP rule against the v4 set
sudo iptables -I OUTPUT -m set --match-set ipset_example_v4 dst -j DROP

# Re-resolve so a fresh IP lands in the set, then try to reach it
sudo ipset flush ipset_example_v4
dig @127.0.0.1 www.example.com +short
curl -m 5 -I https://www.example.com               # should time out / fail

# Cleanup
sudo iptables -D OUTPUT -m set --match-set ipset_example_v4 dst -j DROP
sudo ipset flush ipset_example_v4
```

---

## 8. Metrics (optional)

The systemd unit binds Prometheus on `127.0.0.1:9301`:

```bash
curl -s http://127.0.0.1:9301/metrics | grep -E '^dns2ipset_'
```

Useful counters under load:
- `dns2ipset_events_total{direction="send"|"recv"}` — should both increase
  during traffic.
- `dns2ipset_matches_total{rule="example.com"}` — incremented per matched response.
- `dns2ipset_ipset_writes_total{set="ipset_example_v4",family="v4"}` — successful adds.
- `dns2ipset_ipset_errors_total{reason="missing"}` — should stay 0 if you
  pre-created the sets.
- `dns2ipset_dedup_hits_total` — usually equal to or close to `recv` events,
  since the same DNS response usually fires both `udp_sendmsg` and
  `udp_recvmsg` paths.
- `dns2ipset_ringbuf_drops_total` — currently always reads 0; the
  cilium/ebpf v0.21 ringbuf API doesn't expose per-record loss. Don't
  alert on this until that's wired (see `internal/bpf/loader.go` notes).

---

## 9. Tear-down

```bash
sudo systemctl disable --now dns2ipset
sudo rm /etc/systemd/system/dns2ipset.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/dns2ipset
sudo rm -rf /etc/dns2ipset
sudo ipset destroy ipset_example_v4
sudo ipset destroy ipset_example_v6
```

---

## Troubleshooting cheatsheet

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed to load BPF object: program: …: invalid argument` | `vmlinux.h` was generated against a different kernel | Re-run `sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/bpf/c/headers/vmlinux.h && make generate` on this VM |
| `attach udp_sendmsg: not supported` | Kernel doesn't expose fentry attach | Need ≥ 5.5 with BTF; on Debian use the stock kernel (≥ 6.1) |
| `ipset "ipset_example_v4" missing` in logs | Set was never created, or got destroyed | `sudo ipset create ipset_example_v4 hash:ip family inet timeout 86400` |
| `ipset list ipset_example_v4` empty after `dig` | DNS query was answered from local cache, no new wire response | `sudo systemctl restart <resolver>` to flush cache, then `dig +trace` |
| Curl still reaches example.com with iptables DROP rule | DNS gave a CDN pool of IPs and curl picked one not yet in the set | `sudo ipset list` to see what's there; fresh `dig` populates more |
| `rules.yaml` change doesn't take effect | Watcher isn't seeing the inotify event (e.g. file edited via `cp` overwriting in place outside the watched dir) | Use `mv` (atomic rename) into the dir, or send `SIGHUP` to force reload: `sudo systemctl kill -s HUP dns2ipset` |
