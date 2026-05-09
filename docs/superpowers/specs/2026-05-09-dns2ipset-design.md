# dns2ipset — Design

**Status:** Approved (2026-05-09)
**Project name:** `dns2ipset` (the repo currently lives at `ebpf-snoop/` and will be renamed to `dns2ipset/` before the first commit).

---

## Context

A multi-homed Linux box runs a local DNS resolver (bind9 or dnsmasq) that serves clients on the LAN. We want a way to drop or allow traffic by **domain** using standard `iptables`, but `iptables` only matches IPs. The bridge: snoop DNS replies, and as A/AAAA records are seen for "interesting" domains, push the resolved IPs into named `ipset`s. Existing `iptables` rules then match the sets (`-m set --match-set …`).

A separate already-built tool generates the rules — it produces unique ipset names and emits a (domain → ipset name) mapping. This project consumes that mapping and does the snooping + ipset population. Out of scope: creating ipsets, writing iptables rules, or generating the rule mappings.

The intended outcome: `dns2ipset` runs as a single Go binary on the gateway, observes every DNS response served by the local resolver (regardless of which network interface is involved), and keeps the configured ipsets populated with the freshest resolution data, expiring entries via the DNS TTL.

---

## Architecture

```
upstream rule generator
        │  writes /etc/dns2ipset/rules.yaml (atomic rename)
        ▼
┌────────────────────────────────────────────┐
│ dns2ipset (single Go binary)               │
│  capabilities: CAP_BPF, CAP_PERFMON,       │
│                CAP_NET_ADMIN               │
│                                            │
│  rules loader (inotify) ── trie swap ──┐   │
│                                        ▼   │
│  ringbuf reader → workers (parse,         │
│  match, dedup, ipset write)               │
│                                        ▲   │
│  eBPF (fentry on udp_sendmsg /            │
│   udp_recvmsg, port-53 filter) ─────────┘  │
└────────────────────────────────────────────┘
                 │ NFNL_SUBSYS_IPSET (netlink)
                 ▼
            kernel ipsets (pre-created by generator,
                            with `timeout` flag)
                 │
                 ▼
            iptables -m set --match-set …
```

Userspace owns DNS parsing and rule matching. The kernel side is intentionally thin: filter to port 53, ship the UDP payload up. This keeps the eBPF code small and lets the rule trie hot-reload without touching BPF maps.

---

## Components

### 1. eBPF program (`internal/bpf/dns2ipset.bpf.c`)

- **Type:** two `fentry` programs.
- **Attach:** `fentry/udp_sendmsg` and `fentry/udp_recvmsg`. We hook both because cached resolver answers never trigger an upstream query (only `udp_sendmsg` sees those), while uncached upstream replies appear on `udp_recvmsg`. Userspace dedupes the overlap.
- **Filter:** read `inet_sport` / `inet_dport` from the socket; if neither equals 53, return.
- **Payload extraction:** read up to 4096 bytes of UDP payload from the `msghdr`'s iov; copy into a ringbuf record together with timestamp, family (4/6), direction (send/recv), and ports.
- **Maps:** one `BPF_MAP_TYPE_RINGBUF` (~1 MB).
- **Portability:** CO-RE via `vmlinux.h`; built with `clang -target bpf -O2 -g`. BTF is required at runtime — no kprobe fallback. Modern kernels only (≥5.4 with BTF, recommended ≥5.8).

### 2. Loader & ringbuf reader (`internal/bpf/loader.go`)

- Uses `github.com/cilium/ebpf` and `bpf2go` to embed the compiled object. Single deployable artifact, `CGO_ENABLED=0`.
- One goroutine reads ringbuf records and pushes them onto a buffered channel for the worker pool.

### 3. Rule loader & watcher (`internal/rules/`)

- **Format:** YAML at `/etc/dns2ipset/rules.yaml`:
  ```yaml
  version: 1
  rules:
    - domain: facebook.com         # matches facebook.com AND *.facebook.com
      ipset_v4: snoop_fb_v4        # pre-created with `timeout` flag
      ipset_v6: snoop_fb_v6        # optional; omit to skip AAAA records
    - domain: ads.example.org
      ipset_v4: snoop_ads_v4
  ```
- **Matching:** suffix-based, case-insensitive, label-aligned. `facebook.com` matches `facebook.com`, `www.facebook.com`, `a.b.facebook.com`, but NOT `notfacebook.com`.
- **Reload:** inotify on the *parent directory* of the rules file (so we catch atomic-rename writes — `IN_MOVED_TO` for the target name and `IN_CLOSE_WRITE` for in-place edits). Trie is rebuilt off-thread and swapped via `atomic.Value`. In-flight events finish on the prior trie.
- **Validation:** initial load failure exits non-zero. Reload failures keep the prior trie and increment an error metric.
- **Duplicates:** last domain wins, warning logged.

### 4. Suffix trie (`internal/rules/trie.go`)

- Labels stored reversed (root → `com` → `facebook` → terminal). Lookup walks the candidate name's labels right-to-left; first terminal match wins. O(label-count) per lookup.

### 5. DNS parser (`internal/dnsparse/`)

- Thin wrapper over `github.com/miekg/dns` `dns.Msg.Unpack`.
- Extracts: txid, qname, qtype, response code, and the full chain of owner-names plus their A/AAAA records from the answer section.
- Drops anything that isn't a response (`QR=0`), has `RCODE != NOERROR`, or has zero answers.

### 6. Dedup LRU (`internal/dedup/`)

- Key: `fnv64(qname || qtype || txid || fnv64(payload))`.
- 4096 entries, 200ms TTL. Collapses the send/recv duplicate of the same response.

### 7. ipset client (`internal/ipset/`)

- Netlink directly via `NFNL_SUBSYS_IPSET` (using `vishvananda/netlink` if its ipset support is sufficient, else hand-rolled atop `mdlayher/netlink` — chosen at implementation time based on API ergonomics).
- One method: `Add(setName string, ip net.IP, ttl time.Duration) error`. Sets `IPSET_ATTR_TIMEOUT` to the DNS TTL, clamped to `[60s, 7d]` (configurable via flags `--ttl-min`, `--ttl-max`).
- Missing set → log once per (set, minute) at WARN; drop. Do not auto-create.

### 8. Pipeline (`internal/pipeline/`)

- Worker count defaults to `GOMAXPROCS`. Each worker: parse DNS → for each name in `{qname} ∪ owner-names`, look up in trie → for each match, dispatch every A record to `rule.ipset_v4` and every AAAA to `rule.ipset_v6`.
- Failures (parse, ipset write) are counted, never propagated; the pipeline keeps draining.

### 9. Entrypoint (`cmd/dns2ipset/main.go`)

Flags:
- `--rules` (default `/etc/dns2ipset/rules.yaml`)
- `--ttl-min` / `--ttl-max` (defaults `60s` / `168h`)
- `--metrics-addr` (off by default; e.g. `127.0.0.1:9301`)
- `--log-level` (`info` default)
- `--dedup-window` (default `200ms`)

Signals: `SIGTERM` → graceful drain; `SIGHUP` → force reload.

---

## Repository layout

```
dns2ipset/
├── cmd/dns2ipset/main.go
├── internal/
│   ├── bpf/        ← eBPF C, bpf2go output, loader
│   ├── rules/      ← YAML loader, trie, inotify watcher
│   ├── dnsparse/   ← miekg/dns wrapper
│   ├── ipset/      ← netlink client
│   ├── dedup/      ← LRU
│   └── pipeline/   ← orchestration
├── deploy/
│   ├── dns2ipset.service
│   └── rules.example.yaml
├── docs/superpowers/specs/2026-05-09-dns2ipset-design.md   ← this file
├── go.mod
├── Makefile
└── README.md
```

---

## Operational details

- **Privileges:** `CAP_BPF` + `CAP_PERFMON` for BPF load; `CAP_NET_ADMIN` for ipset writes. Systemd unit grants these via `AmbientCapabilities=` rather than running as root.
- **Resource limits:** `MemoryHigh=128M`, `LimitNOFILE=4096`. Ringbuf 1 MB.
- **Service ordering:** `After=` and `Wants=` (not `Requires=`) the resolver unit, so a snoop failure cannot break DNS.
- **Failure modes:**
  - Ringbuf full → kernel drops; userspace records the counter from the ringbuf API; metric `dns2ipset_ringbuf_drops_total`.
  - Malformed DNS → counted as `parse_errors_total`, debug-logged with payload hex.
  - Missing ipset → rate-limited WARN, increment `ipset_errors_total{reason="missing"}`.
  - Reload error → metric `rules_reload_errors_total`; previous trie remains in effect.

## Metrics (Prometheus, optional)

- `dns2ipset_events_total{direction}`
- `dns2ipset_parse_errors_total`
- `dns2ipset_dedup_hits_total`
- `dns2ipset_matches_total{rule}`
- `dns2ipset_ipset_writes_total{set,family}`
- `dns2ipset_ipset_errors_total{reason}`
- `dns2ipset_ringbuf_drops_total`
- `dns2ipset_rules_reload_total{result}`
- `dns2ipset_rules_active`

## Testing

- **Unit tests:** trie matching (incl. edge cases like `notfacebook.com`), YAML loader, dedup LRU, DNS parser wrapper.
- **Integration tests:** synthetic DNS responses crafted with `gopacket`, fed through a fake ringbuf source — verifies pipeline end-to-end without root.
- **E2E (gated `-tags e2e`, requires root):** start `dns2ipset`, run `dig` against `127.0.0.1`, assert IPs land in the test ipset.
- **CI:** GitHub Actions matrix on Ubuntu 22.04 / Debian 12.

---

## Explicitly out of scope (v1)

- TCP DNS (rare; truncation falls back to UDP retry the resolver handles).
- DNS over HTTPS / DNS over TLS upstream paths.
- IPv6-only AAAA matching shortcut (we always handle both families).
- Auto-creating ipsets (the generator owns lifecycle).
- iptables rule generation.
- Per-rule TTL overrides (use `--ttl-min` / `--ttl-max` for now; revisit if needed).
- Older kernels without BTF.

---

## Project rename

The repo was scaffolded under `~/GIT/personal/ebpf-snoop/` (no commits). It is renamed to `~/GIT/personal/dns2ipset/` as part of this initial design step. All paths above assume the new directory name.

---

## Verification plan

1. **Build:** `make` produces `./dns2ipset` (static, `CGO_ENABLED=0`) and the embedded eBPF object.
2. **Lint/test:** `go vet ./...`, `go test ./...`, `make test-integration`.
3. **Smoke test:**
   - `sudo ipset create snoop_fb_v4 hash:ip family inet timeout 86400`
   - Write a `rules.yaml` mapping `facebook.com → snoop_fb_v4`.
   - `sudo ./dns2ipset --rules rules.yaml --log-level=debug`
   - From another shell: `dig @127.0.0.1 facebook.com` and `dig @127.0.0.1 www.facebook.com`.
   - `sudo ipset list snoop_fb_v4` should show the resolved IPs with TTLs near the answer's TTL.
4. **Reload test:** atomically replace `rules.yaml` with a different mapping; observe the `rules_reload_total{result="ok"}` metric tick and the next `dig` populating the new set.
5. **Negative test:** `dig @127.0.0.1 example.com` (not in rules) — set unchanged.
6. **iptables integration:** add `iptables -I OUTPUT -m set --match-set snoop_fb_v4 dst -j DROP`, verify `curl https://www.facebook.com` fails after a fresh resolution.
