# dns2ipset

Snoop DNS replies via eBPF and populate Linux kernel `ipset`s so `iptables`
can match traffic by domain.

See [docs/superpowers/specs/2026-05-09-dns2ipset-design.md](docs/superpowers/specs/2026-05-09-dns2ipset-design.md)
for the design.

## Build

```
make build
```

## Run

```
sudo ./dns2ipset --rules /etc/dns2ipset/rules.yaml
```

(Requires `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`. See `deploy/dns2ipset.service`.)
