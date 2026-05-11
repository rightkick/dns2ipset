# dns2ipset stress harness

End-to-end load tests for measuring overhead, throughput ceiling, stability,
and reload behavior of dns2ipset on a real Linux host.

> **Run on a dedicated test VM.** The harness needs to bind UDP port 53
> for the fake resolver, so there must be no other DNS service running on
> the test host (stop `systemd-resolved`, `dnsmasq`, etc. — see Prereqs).
> Don't run this on your production gateway.

---

## What's here

```
stress/
├── lib.sh                  common helpers (metrics snapshots, ipset ops, fake resolver lifecycle)
├── teardown.sh             cleanup (destroy bench ipsets, restore rules.yaml)
├── fake-resolver/main.go   deterministic miekg/dns server with rotating IP pool
└── scenarios/
    ├── 00-overhead.sh         dns2ipset OFF vs ON — headline overhead number
    ├── 01-single-rule-ramp.sh resperf ramp 0 → MAX_QPS to find saturation
    ├── 02-cardinality.sh      single rule, large IP pool — stresses ipset growth
    ├── 03-many-rules.sh       N rules, queries cycle — stresses trie + dispatch
    ├── 04-burst.sh            low/high/low cycles — stresses channel buffer + dedup
    ├── 05-sustained.sh        long-duration steady-state — leak/RSS/GC trend
    └── 06-reload-under-load.sh  atomic-rename rules.yaml mid-flight
```

There's also a Go micro-benchmark at `internal/pipeline/pipeline_bench_test.go`
that measures the userspace hot-path ceiling (no kernel, no syscalls):

```bash
go test -bench=BenchmarkPipeline -benchmem ./internal/pipeline/
```

That tells you the Go ceiling (typically ~1M events/s/core for unique events;
~8M/s/core for dedup hits). Use it to detect Go-side regressions in CI.

---

## Prereqs

On the test VM:

```bash
sudo apt-get update
sudo apt-get install -y dnsperf curl jq sysstat ipset

# free port 53 for the fake resolver
sudo systemctl disable --now systemd-resolved   # or dnsmasq, or bind9
sudo rm -f /etc/resolv.conf
echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf  # for the test box's own DNS
```

Install the dns2ipset .deb (built per [docs/build-and-package.md](../docs/build-and-package.md)):

```bash
sudo apt install ./dns2ipset_<ver>_amd64.deb
```

Build the fake resolver. From the repo root:

```bash
( cd stress/fake-resolver && go build -o fake-resolver . )
```

---

## Running a scenario

```bash
cd stress

# Headline number: overhead with dns2ipset OFF vs ON
QPS=20000 DURATION=30 sudo bash scenarios/00-overhead.sh

# Find the saturation point
MAX_QPS=200000 RAMP=60 PLATEAU=30 sudo bash scenarios/01-single-rule-ramp.sh

# After any run, clean up
sudo bash teardown.sh
```

Every scenario:
- Auto-installs rules.yaml + ipsets it needs.
- Starts/stops the fake resolver.
- Snapshots `/metrics` before & after, prints the diff.
- Captures `pidstat` for the daemon (where useful).
- Leaves a `WORKDIR` under `/tmp` with the raw outputs (`dnsperf.txt`,
  `resperf.txt`, `metrics.before`, `metrics.after`, etc.).

All scripts respect environment variables for the main tunables — see the
top of each script for the list and defaults.

---

## What to watch

The Grafana dashboard you imported (`deploy/grafana/dns2ipset-dashboard.json`)
covers most of what matters. During a run, watch:

| Panel / metric | What it tells you |
|---|---|
| Events/s by direction | BPF is seeing wire traffic; should track ~2× offered QPS (send + recv views) |
| Matches/s by rule | Trie is firing; should equal QPS for single-rule scenarios |
| ipset writes/s | Successful netlink Adds; the real "snooping is working" signal |
| ipset errors/s | Should stay flat. Spikes = misconfigured set or netlink error |
| Parse errors/s | Climbs with offered QPS — every query (QR=0) counts as a parse error here |
| Dedup hits/s | ~half of recv events under steady state (collapses send/recv views) |
| `dns2ipset_pipeline_inflight` | Channel depth (cap 1024). Spikes near 1024 = workers can't keep up |

For Go-side profiling during a stress run, pprof is wired into the metrics
listener (when `--metrics-addr` is set). On the test box:

```bash
go tool pprof -http=:8080 http://gw:9301/debug/pprof/profile?seconds=30
go tool pprof -http=:8080 http://gw:9301/debug/pprof/heap
go tool pprof -http=:8080 http://gw:9301/debug/pprof/goroutine
```

---

## Known limitations

- **`dns2ipset_ringbuf_drops_total` is always 0** under any load. cilium/ebpf
  v0.21's `ringbuf.Record` doesn't expose per-record loss. Cross-check the
  daemon's `events_total` rate against the offered QPS — if `events ≪ 2 × QPS`,
  events are being dropped in the ringbuf and the daemon can't see them.
  Long-term fix: add a kernel-side counter map, read from userspace.

- **BPF filter is hardcoded to UDP port 53.** The fake resolver must bind
  port 53 (no `--port 1053` shortcut). This is why teardown leaves
  systemd-resolved disabled.

- **Single-host load gen vs daemon.** Running dnsperf and the daemon on the
  same VM means they compete for CPU above ~30-50k QPS. For ceiling
  measurements use a second VM as the load generator and point dnsperf at
  the gateway's LAN IP. The fake resolver can run on the gateway side, or
  you can split it onto a third VM.

- **Production rules.yaml is overwritten by setup.** `teardown.sh` restores
  a `rules: []` placeholder. Save your real rules elsewhere before running.
