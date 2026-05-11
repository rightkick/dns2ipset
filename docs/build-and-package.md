# Build and package dns2ipset

End-to-end workflow for building a `.deb` once on a build host and installing
it on many gateway VMs without giving them a Go/clang toolchain.

The original [Debian VM quickstart](debian-vm-quickstart.md) is now the
**build-host** setup reference — gateway VMs only need this doc plus the
resulting `.deb`.

---

## Why this works (across kernels)

The `.deb` is portable across kernel versions for two reasons:

1. **Static binary.** `make build` produces a `CGO_ENABLED=0` Go binary.
   No glibc link, no per-distro symbol versioning.
2. **CO-RE BPF.** bpf2go embeds the compiled `.o` into the binary. Struct
   field offsets in the BPF program (`sock`, `msghdr`, `iov_iter`, …) are
   resolved at *load* time against the target kernel's BTF, not at compile
   time. The CO-RE field-existence guard on `iov_iter.__iov` ↔ `iov_iter.iov`
   in [`internal/bpf/c/dns2ipset.bpf.c`](../internal/bpf/c/dns2ipset.bpf.c)
   already handles the 5.x → 6.x kernel rename.

Targets that meet **both** of these will work:

- Linux kernel ≥ 5.4
- `/sys/kernel/btf/vmlinux` exists (`CONFIG_DEBUG_INFO_BTF=y`)

Stock Debian 11+, Ubuntu 20.04+, Fedora 32+, and recent RHEL/Rocky/Alma all
ship BTF-equipped kernels by default. Distroless / minimal kernels are the
exception — see the troubleshooting table at the end.

---

## On the build host

One-time setup is identical to [Debian VM quickstart §1–§2](debian-vm-quickstart.md):
install `clang`, `llvm`, `libbpf-dev`, `bpftool`, `linux-headers-$(uname -r)`,
and Go ≥ 1.24. Then in the repo:

```
make generate            # regenerate vmlinux.h + run bpf2go
make build               # produce ./dns2ipset (static)
make package             # produce dns2ipset_<version>_amd64.deb
```

`make package` runs nfpm via `go run github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`,
so no separate install of nfpm is required on the build host. Version is
sourced from `git describe --tags --always --dirty` (override with
`VERSION=1.2.3 make package`).

The resulting filename looks like `dns2ipset_v0.1.0-rc1-3-gabcdef0_amd64.deb`
(or `dns2ipset_0.0.0_amd64.deb` if you're not on a tagged commit).

---

## On each target host

```
sudo apt install ./dns2ipset_<version>_amd64.deb
```

That installs:
- `/usr/local/bin/dns2ipset`
- `/etc/systemd/system/dns2ipset.service`
- `/etc/dns2ipset/rules.example.yaml`

The postinst script reloads systemd and warns (but does not fail) if BTF is
missing on the target. **It does not enable the service** — you still need
to pre-create ipsets and write your rules file.

```
# 1. Create each ipset referenced in your rules. The daemon does not
#    create sets; the `timeout` flag is mandatory.
sudo ipset create snoop_fb_v4 hash:ip family inet  timeout 86400
sudo ipset create snoop_fb_v6 hash:ip family inet6 timeout 86400

# 2. Write your rules.
sudo cp /etc/dns2ipset/rules.example.yaml /etc/dns2ipset/rules.yaml
sudo $EDITOR /etc/dns2ipset/rules.yaml

# 3. Start the service.
sudo systemctl enable --now dns2ipset
sudo systemctl status dns2ipset --no-pager
```

Verify with [Debian VM quickstart §6 onward](debian-vm-quickstart.md) — the
`dig`/`ipset list`/iptables flow is the same regardless of whether the binary
was built locally or installed from a `.deb`.

To uninstall:

```
sudo apt remove dns2ipset           # stop + disable + remove files
sudo apt purge dns2ipset            # also remove /etc/dns2ipset/
```

---

## Cross-kernel verification matrix

If you're rolling this out to a fleet, verify on at least the kernel
extremes you actually deploy to. A useful matrix:

| Build host | Target host | Why test it |
|---|---|---|
| Ubuntu 22.04, kernel 6.5 (HWE) | Debian 12, kernel 6.1 | Same major kernel line, different minor |
| Ubuntu 22.04, kernel 6.5 (HWE) | Debian 11, kernel 5.10 | Cross-major kernel: exercises CO-RE `iov_iter` rename |
| Debian 12, kernel 6.1 | Debian 12, kernel 6.1 | Baseline same-kernel sanity |

For each target, after `apt install` and the start sequence above:

1. `journalctl -u dns2ipset -n 50` — no "load BPF object" or "attach" errors.
2. `dig @127.0.0.1 facebook.com +short` followed by `sudo ipset list snoop_fb_v4` — set populates within ~100 ms.
3. `curl -s http://127.0.0.1:9301/metrics | grep dns2ipset_events_total` — increments under traffic.
4. Atomic-rename of `/etc/dns2ipset/rules.yaml` ticks `dns2ipset_rules_reload_total{result="ok"}`.

If the older-kernel target fails to attach `udp_sendmsg`/`udp_recvmsg`,
the issue is not packaging — it's the BPF program's `bpf_probe_read`
ordering, noted as a known limitation in the project's
[CLAUDE.md](../CLAUDE.md#known-limitations--todos). Fix that in the BPF C
and rebuild.

---

## Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| Postinst prints `WARNING — /sys/kernel/btf/vmlinux is missing` | Target kernel lacks BTF | Install a kernel with `CONFIG_DEBUG_INFO_BTF=y`, or don't deploy here |
| `dpkg: dependency problems` on `ipset` | `ipset` package missing on target | `sudo apt install ipset` then re-install the .deb |
| `journalctl` shows `failed to load BPF object: program: …: invalid argument` on a target newer than the build host | Very rare CO-RE relocation miss | File against the BPF C; do not work around in packaging |
| `ipset list snoop_fb_v4` empty after `dig` | DNS answer came from local cache, no wire traffic | `sudo systemctl restart <resolver>` to flush cache, then `dig +trace` |
| `make package` fails with "nfpm: command not found" | Stale Go module cache or no internet | `go clean -modcache` and retry; or pre-fetch with `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest` |

For a full troubleshooting reference (including BPF/iptables-side issues),
see the bottom of [debian-vm-quickstart.md](debian-vm-quickstart.md).
