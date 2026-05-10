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

## Install

```
sudo install -m 0755 dns2ipset /usr/local/bin/
sudo install -d /etc/dns2ipset
sudo install -m 0644 deploy/rules.example.yaml /etc/dns2ipset/rules.yaml
sudo install -m 0644 deploy/dns2ipset.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dns2ipset
```

## Smoke test

```
sudo ipset create snoop_fb_v4 hash:ip family inet timeout 86400
echo 'version: 1
rules:
  - domain: facebook.com
    ipset_v4: snoop_fb_v4' | sudo tee /etc/dns2ipset/rules.yaml >/dev/null
sudo systemctl restart dns2ipset
dig @127.0.0.1 www.facebook.com
sudo ipset list snoop_fb_v4
```

## Build prerequisites

- Linux ≥ 5.4 with BTF (`/sys/kernel/btf/vmlinux` must exist)
- `clang` ≥ 10
- `bpftool` (for `vmlinux.h` generation)
- `libbpf-dev`
- Go ≥ 1.23
