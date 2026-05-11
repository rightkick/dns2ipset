# dns2ipset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go binary that snoops DNS replies via eBPF and populates kernel ipsets so iptables can match traffic by domain.

**Architecture:** Two `fentry` BPF programs (on `udp_sendmsg`/`udp_recvmsg`) ship UDP-port-53 payloads up a ringbuf. A Go pipeline parses the DNS, looks each owner-name up in a hot-reloadable suffix trie of rules, and writes A/AAAA records into pre-existing ipsets via netlink. Userspace owns parsing and rule matching; the BPF side stays thin.

**Tech Stack:** Go 1.23, `github.com/cilium/ebpf` + `bpf2go`, `github.com/miekg/dns`, `gopkg.in/yaml.v3`, `github.com/fsnotify/fsnotify`, `github.com/vishvananda/netlink` (with `mdlayher/netlink` fallback), `github.com/hashicorp/golang-lru/v2`, `github.com/prometheus/client_golang`. eBPF C compiled with clang ≥ 10 against `vmlinux.h` (CO-RE).

---

## Environmental notes

- Development host is **WSL2 (kernel 6.1)**. The full BPF + ipset path cannot be exercised there; root-required E2E (Tasks 11, 12 verifications, smoke test) needs a real Linux gateway. Unit and pipeline tests run anywhere.
- Build prerequisites for the eBPF object: `clang` ≥ 10, `bpftool` (for `vmlinux.h` generation), `libbpf-dev` headers, kernel with BTF (`/sys/kernel/btf/vmlinux` exists).
- Module path used throughout: `github.com/rightkick/dns2ipset`. Adjust in Task 1 if a different path is needed before any imports are written.

## File structure

```
dns2ipset/
├── cmd/dns2ipset/main.go             # entrypoint, flags, signals
├── internal/
│   ├── rules/
│   │   ├── trie.go                   # suffix trie
│   │   ├── trie_test.go
│   │   ├── loader.go                 # YAML parse + validate
│   │   ├── loader_test.go
│   │   ├── store.go                  # atomic.Value swap
│   │   ├── watcher.go                # inotify reload
│   │   └── watcher_test.go
│   ├── dnsparse/
│   │   ├── parser.go                 # miekg/dns wrapper
│   │   └── parser_test.go
│   ├── dedup/
│   │   ├── dedup.go                  # LRU + TTL
│   │   └── dedup_test.go
│   ├── ipset/
│   │   ├── client.go                 # netlink impl + interface
│   │   └── client_test.go
│   ├── source/
│   │   ├── source.go                 # Event + Source interface
│   │   └── fake/fake.go              # test source
│   ├── bpf/
│   │   ├── dns2ipset.bpf.c           # eBPF C
│   │   ├── headers/vmlinux.h         # generated, .gitignored
│   │   ├── gen.go                    # //go:generate bpf2go
│   │   ├── loader.go                 # attach + ringbuf reader
│   │   └── (bpf2go-generated _bpfel.go / .o)
│   ├── pipeline/
│   │   ├── pipeline.go               # orchestration
│   │   └── pipeline_test.go
│   └── metrics/
│       └── metrics.go                # Prometheus registry
├── deploy/
│   ├── dns2ipset.service
│   └── rules.example.yaml
├── .github/workflows/ci.yml
├── docs/superpowers/                 # specs, plans (existing)
├── go.mod / go.sum
├── Makefile
├── README.md
└── .gitignore
```

---

## Task 1: Repo scaffold

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `.gitignore`
- Create: `README.md`
- Create: `cmd/dns2ipset/main.go` (stub so `go build` succeeds)

- [ ] **Step 1: Initialize Go module**

```bash
cd /home/alex/GIT/personal/dns2ipset
go mod init github.com/rightkick/dns2ipset
```

- [ ] **Step 2: Create stub entrypoint so the tree compiles**

`cmd/dns2ipset/main.go`:

```go
package main

func main() {}
```

- [ ] **Step 3: Add Makefile**

`Makefile`:

```make
GO       ?= go
BIN      := dns2ipset
PKG      := ./cmd/dns2ipset
LDFLAGS  := -s -w
BPF_DIR  := internal/bpf

.PHONY: build vet test test-integration generate bpf clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration ./...

# Regenerate vmlinux.h and run bpf2go.
generate: $(BPF_DIR)/headers/vmlinux.h
	$(GO) generate ./...

$(BPF_DIR)/headers/vmlinux.h:
	mkdir -p $(BPF_DIR)/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(BIN)
	rm -f $(BPF_DIR)/*_bpfel.go $(BPF_DIR)/*_bpfel.o
```

- [ ] **Step 4: Add .gitignore**

`.gitignore`:

```
/dns2ipset
internal/bpf/headers/vmlinux.h
internal/bpf/*_bpfel.go
internal/bpf/*_bpfel.o
*.test
*.out
```

- [ ] **Step 5: Add README skeleton**

`README.md`:

```markdown
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
```

- [ ] **Step 6: Verify it builds**

```bash
make build
```

Expected: `./dns2ipset` produced, no errors.

- [ ] **Step 7: Commit**

```bash
git add go.mod Makefile .gitignore README.md cmd/dns2ipset/main.go
git commit -m "chore: scaffold go module, Makefile, README"
```

---

## Task 2: Suffix trie

**Files:**
- Create: `internal/rules/trie.go`
- Create: `internal/rules/trie_test.go`

**Design notes:**
- Labels stored reversed: root → `com` → `facebook` → terminal.
- Lookup walks the candidate's labels right-to-left, returning the **first terminal** encountered. Per the design spec this means **shortest-suffix wins** if multiple rules nest. Tests below assert that behavior; if longest-match is intended, only `Lookup` and one test need to change.
- Match value is a `*Rule`; that type is defined in Task 3 — for this task we use a placeholder `Value any` so the trie stays decoupled.

- [ ] **Step 1: Write failing tests**

`internal/rules/trie_test.go`:

```go
package rules

import "testing"

func TestTrie_ExactAndSubdomainMatch(t *testing.T) {
	tr := NewTrie()
	tr.Insert("facebook.com", "fb")

	cases := []struct {
		name string
		want any
	}{
		{"facebook.com", "fb"},
		{"www.facebook.com", "fb"},
		{"a.b.facebook.com", "fb"},
		{"FACEBOOK.com", "fb"}, // case-insensitive
	}
	for _, c := range cases {
		got, ok := tr.Lookup(c.name)
		if !ok || got != c.want {
			t.Errorf("Lookup(%q) = (%v,%v); want (%v,true)", c.name, got, ok, c.want)
		}
	}
}

func TestTrie_LabelAlignedNoSubstringMatch(t *testing.T) {
	tr := NewTrie()
	tr.Insert("facebook.com", "fb")

	for _, name := range []string{"notfacebook.com", "facebook.com.evil.org", "com"} {
		if _, ok := tr.Lookup(name); ok {
			t.Errorf("Lookup(%q) matched but should not have", name)
		}
	}
}

func TestTrie_ShortestSuffixWins(t *testing.T) {
	// Per design: "first terminal match wins" walking right-to-left.
	tr := NewTrie()
	tr.Insert("example.org", "outer")
	tr.Insert("ads.example.org", "inner")

	got, ok := tr.Lookup("foo.ads.example.org")
	if !ok || got != "outer" {
		t.Errorf("got (%v,%v); want (outer,true) — first terminal walking right-to-left", got, ok)
	}
}

func TestTrie_TrailingDotIgnored(t *testing.T) {
	tr := NewTrie()
	tr.Insert("facebook.com", "fb")
	if got, ok := tr.Lookup("www.facebook.com."); !ok || got != "fb" {
		t.Errorf("trailing dot not handled: got (%v,%v)", got, ok)
	}
}

func TestTrie_EmptyAndRoot(t *testing.T) {
	tr := NewTrie()
	if _, ok := tr.Lookup(""); ok {
		t.Error("empty name should not match")
	}
	if _, ok := tr.Lookup("."); ok {
		t.Error("root . should not match")
	}
}
```

- [ ] **Step 2: Run, expect fail**

```bash
go test ./internal/rules/...
```

Expected: build error / FAIL (no Trie type yet).

- [ ] **Step 3: Implement trie**

`internal/rules/trie.go`:

```go
package rules

import "strings"

// Trie is a domain suffix trie. Inserted domains match themselves and any
// subdomain (label-aligned). Lookup is case-insensitive and ignores a single
// trailing dot. When multiple inserted domains are suffixes of a candidate,
// the one closest to the root (shortest suffix) wins.
type Trie struct {
	root *node
}

type node struct {
	children map[string]*node
	terminal bool
	value    any
}

func NewTrie() *Trie {
	return &Trie{root: newNode()}
}

func newNode() *node {
	return &node{children: make(map[string]*node)}
}

func (t *Trie) Insert(domain string, value any) {
	labels := splitDomain(domain)
	if len(labels) == 0 {
		return
	}
	cur := t.root
	for i := len(labels) - 1; i >= 0; i-- {
		l := labels[i]
		next, ok := cur.children[l]
		if !ok {
			next = newNode()
			cur.children[l] = next
		}
		cur = next
	}
	cur.terminal = true
	cur.value = value
}

func (t *Trie) Lookup(name string) (any, bool) {
	labels := splitDomain(name)
	if len(labels) == 0 {
		return nil, false
	}
	cur := t.root
	for i := len(labels) - 1; i >= 0; i-- {
		next, ok := cur.children[labels[i]]
		if !ok {
			return nil, false
		}
		if next.terminal {
			return next.value, true
		}
		cur = next
	}
	return nil, false
}

func splitDomain(name string) []string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}
```

- [ ] **Step 4: Run tests, expect pass**

```bash
go test ./internal/rules/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/rules/trie.go internal/rules/trie_test.go
git commit -m "feat(rules): suffix trie with case- and label-aligned matching"
```

---

## Task 3: Rules YAML loader

**Files:**
- Create: `internal/rules/loader.go`
- Create: `internal/rules/loader_test.go`
- Modify: `go.mod`, `go.sum` (via `go mod tidy`)

- [ ] **Step 1: Write failing tests**

`internal/rules/loader_test.go`:

```go
package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_ValidProducesTrie(t *testing.T) {
	p := writeTemp(t, `
version: 1
rules:
  - domain: facebook.com
    ipset_v4: snoop_fb_v4
    ipset_v6: snoop_fb_v6
  - domain: ads.example.org
    ipset_v4: snoop_ads_v4
`)
	rs, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs.Rules))
	}
	tr := rs.BuildTrie()
	v, ok := tr.Lookup("www.facebook.com")
	if !ok {
		t.Fatal("expected facebook.com match")
	}
	r := v.(*Rule)
	if r.IPSetV4 != "snoop_fb_v4" || r.IPSetV6 != "snoop_fb_v6" {
		t.Errorf("rule mismatch: %+v", r)
	}
}

func TestLoad_RejectsBadVersion(t *testing.T) {
	p := writeTemp(t, "version: 2\nrules: []\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error on version: 2")
	}
}

func TestLoad_RejectsRuleWithoutIPSet(t *testing.T) {
	p := writeTemp(t, `
version: 1
rules:
  - domain: example.com
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: rule must specify at least one of ipset_v4/ipset_v6")
	}
}

func TestLoad_RejectsRuleWithoutDomain(t *testing.T) {
	p := writeTemp(t, `
version: 1
rules:
  - ipset_v4: x
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: rule must have a domain")
	}
}

func TestLoad_DuplicateDomainLastWins(t *testing.T) {
	p := writeTemp(t, `
version: 1
rules:
  - domain: example.com
    ipset_v4: first
  - domain: example.com
    ipset_v4: second
`)
	rs, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rs.Warnings) == 0 {
		t.Error("expected duplicate-domain warning")
	}
	tr := rs.BuildTrie()
	v, _ := tr.Lookup("example.com")
	if v.(*Rule).IPSetV4 != "second" {
		t.Errorf("last-wins violated: %+v", v)
	}
}
```

- [ ] **Step 2: Run, expect fail**

```bash
go test ./internal/rules/...
```

Expected: build error (missing types).

- [ ] **Step 3: Add the YAML library**

```bash
go get gopkg.in/yaml.v3
```

- [ ] **Step 4: Implement loader**

`internal/rules/loader.go`:

```go
package rules

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Domain  string `yaml:"domain"`
	IPSetV4 string `yaml:"ipset_v4"`
	IPSetV6 string `yaml:"ipset_v6"`
}

type RuleSet struct {
	Version  int     `yaml:"version"`
	Rules    []*Rule `yaml:"rules"`
	Warnings []string `yaml:"-"`
}

func Load(path string) (*RuleSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var rs RuleSet
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if rs.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version %d (want 1)", rs.Version)
	}
	seen := make(map[string]int) // domain -> index of last occurrence
	for i, r := range rs.Rules {
		if r == nil {
			return nil, errors.New("nil rule entry")
		}
		r.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Domain)), ".")
		if r.Domain == "" {
			return nil, fmt.Errorf("rule %d: domain is required", i)
		}
		if r.IPSetV4 == "" && r.IPSetV6 == "" {
			return nil, fmt.Errorf("rule %d (%s): must specify ipset_v4 and/or ipset_v6", i, r.Domain)
		}
		if prev, ok := seen[r.Domain]; ok {
			rs.Warnings = append(rs.Warnings,
				fmt.Sprintf("duplicate domain %q at rules[%d] overrides rules[%d] (last wins)", r.Domain, i, prev))
		}
		seen[r.Domain] = i
	}
	return &rs, nil
}

// BuildTrie builds a Trie populated with rule pointers, applying last-wins
// semantics for duplicate domains.
func (rs *RuleSet) BuildTrie() *Trie {
	t := NewTrie()
	// Iterate in order; later inserts overwrite earlier ones at the same node.
	for _, r := range rs.Rules {
		t.Insert(r.Domain, r)
	}
	return t
}
```

Note: `Trie.Insert` already overwrites the `value` of the existing terminal node when the same domain is re-inserted, so last-wins falls out naturally.

- [ ] **Step 5: Tidy and run tests**

```bash
go mod tidy
go test ./internal/rules/... -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/rules/loader.go internal/rules/loader_test.go go.mod go.sum
git commit -m "feat(rules): YAML loader with version, validation, last-wins dedup"
```

---

## Task 4: Atomic store + inotify watcher

**Files:**
- Create: `internal/rules/store.go`
- Create: `internal/rules/watcher.go`
- Create: `internal/rules/watcher_test.go`
- Modify: `go.mod`

- [ ] **Step 1: Add fsnotify**

```bash
go get github.com/fsnotify/fsnotify
```

- [ ] **Step 2: Write failing tests**

`internal/rules/watcher_test.go`:

```go
package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", d)
}

func TestWatcher_AtomicRenameTriggersReload(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rules.yaml")

	first := `
version: 1
rules:
  - domain: a.com
    ipset_v4: a4
`
	if err := os.WriteFile(target, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore()
	rs, err := Load(target)
	if err != nil {
		t.Fatal(err)
	}
	store.Replace(rs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := NewWatcher(target, func(path string) {
		rs, err := Load(path)
		if err != nil {
			return
		}
		store.Replace(rs)
	})
	if err != nil {
		t.Fatal(err)
	}
	go w.Run(ctx)
	defer w.Close()

	// Atomic rename: write tmp + os.Rename.
	second := `
version: 1
rules:
  - domain: b.com
    ipset_v4: b4
`
	tmp := filepath.Join(dir, "rules.yaml.tmp")
	if err := os.WriteFile(tmp, []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool {
		cur := store.Get()
		return cur != nil && len(cur.Rules) == 1 && cur.Rules[0].Domain == "b.com"
	})
}

func TestWatcher_InPlaceWriteTriggersReload(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rules.yaml")

	if err := os.WriteFile(target, []byte("version: 1\nrules:\n  - {domain: a.com, ipset_v4: a}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore()
	rs, _ := Load(target)
	store.Replace(rs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := NewWatcher(target, func(path string) {
		if rs, err := Load(path); err == nil {
			store.Replace(rs)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	go w.Run(ctx)
	defer w.Close()

	// In-place rewrite (no rename).
	if err := os.WriteFile(target, []byte("version: 1\nrules:\n  - {domain: c.com, ipset_v4: c}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool {
		cur := store.Get()
		return cur != nil && cur.Rules[0].Domain == "c.com"
	})
}
```

- [ ] **Step 3: Run, expect fail**

```bash
go test ./internal/rules/...
```

Expected: build error.

- [ ] **Step 4: Implement Store**

`internal/rules/store.go`:

```go
package rules

import "sync/atomic"

// Store holds the active RuleSet. Get/Replace are lock-free via atomic.Value.
type Store struct {
	v atomic.Value // *RuleSet
}

func NewStore() *Store { return &Store{} }

func (s *Store) Get() *RuleSet {
	v := s.v.Load()
	if v == nil {
		return nil
	}
	return v.(*RuleSet)
}

func (s *Store) Replace(rs *RuleSet) { s.v.Store(rs) }
```

- [ ] **Step 5: Implement Watcher**

`internal/rules/watcher.go`:

```go
package rules

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// Watcher watches the parent directory of `path` and invokes onChange when
// the target file is replaced (atomic rename) or rewritten in place.
type Watcher struct {
	path     string
	dir      string
	target   string
	w        *fsnotify.Watcher
	onChange func(path string)
}

func NewWatcher(path string, onChange func(path string)) (*Watcher, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, target := filepath.Split(abs)
	dir = filepath.Clean(dir)

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fsnotify: %w", err)
	}
	if err := fw.Add(dir); err != nil {
		fw.Close()
		return nil, fmt.Errorf("watch %s: %w", dir, err)
	}
	return &Watcher{path: abs, dir: dir, target: target, w: fw, onChange: onChange}, nil
}

func (w *Watcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.w.Events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) != w.target {
				continue
			}
			// We care about: in-place writes (Write/Create) and atomic-rename arrivals (Rename target / Create).
			// fsnotify reports IN_MOVED_TO as Create, and IN_CLOSE_WRITE as Write on Linux.
			if ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) {
				w.onChange(w.path)
			}
		case _, ok := <-w.w.Errors:
			if !ok {
				return
			}
			// Errors are non-fatal; loop continues.
		}
	}
}

func (w *Watcher) Close() error { return w.w.Close() }
```

- [ ] **Step 6: Tidy and test**

```bash
go mod tidy
go test ./internal/rules/... -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/rules/store.go internal/rules/watcher.go internal/rules/watcher_test.go go.mod go.sum
git commit -m "feat(rules): atomic store + inotify watcher with rename-and-rewrite reload"
```

---

## Task 5: DNS parser wrapper

**Files:**
- Create: `internal/dnsparse/parser.go`
- Create: `internal/dnsparse/parser_test.go`

- [ ] **Step 1: Add miekg/dns**

```bash
go get github.com/miekg/dns
```

- [ ] **Step 2: Write failing tests**

`internal/dnsparse/parser_test.go`:

```go
package dnsparse

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func buildResp(t *testing.T, qname string, qtype uint16, answers []dns.RR, rcode int) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.Response = true
	m.Rcode = rcode
	m.Answer = answers
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse_ARecord(t *testing.T) {
	a := &dns.A{Hdr: dns.RR_Header{Name: "facebook.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	b := buildResp(t, "facebook.com", dns.TypeA, []dns.RR{a}, dns.RcodeSuccess)

	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.QName != "facebook.com" {
		t.Errorf("qname = %q", r.QName)
	}
	if len(r.Records) != 1 {
		t.Fatalf("len(records) = %d", len(r.Records))
	}
	rec := r.Records[0]
	if rec.Name != "facebook.com" || !rec.IP.Equal(net.ParseIP("1.2.3.4")) || rec.TTL != 300 || rec.Family != 4 {
		t.Errorf("record = %+v", rec)
	}
}

func TestParse_CNAMEChainProducesAllOwners(t *testing.T) {
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "www.facebook.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "star-mini.c10r.facebook.com."}
	a := &dns.A{Hdr: dns.RR_Header{Name: "star-mini.c10r.facebook.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("31.13.65.36")}
	b := buildResp(t, "www.facebook.com", dns.TypeA, []dns.RR{cname, a}, dns.RcodeSuccess)

	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, rec := range r.Records {
		got[rec.Name] = true
	}
	// QName + every owner-name in the answer chain must be available to caller.
	for _, want := range []string{"www.facebook.com", "star-mini.c10r.facebook.com"} {
		if !got[want] {
			t.Errorf("missing owner %q in records (got %v)", want, got)
		}
	}
}

func TestParse_AAAA(t *testing.T) {
	aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 90}, AAAA: net.ParseIP("2001:db8::1")}
	b := buildResp(t, "x.example", dns.TypeAAAA, []dns.RR{aaaa}, dns.RcodeSuccess)
	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Records) != 1 || r.Records[0].Family != 6 {
		t.Fatalf("got %+v", r.Records)
	}
}

func TestParse_DropsQueries(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("foo.example.", dns.TypeA)
	b, _ := m.Pack()
	if _, err := Parse(b); err == nil {
		t.Error("expected error for query (QR=0)")
	}
}

func TestParse_DropsNXDOMAIN(t *testing.T) {
	b := buildResp(t, "nope.example", dns.TypeA, nil, dns.RcodeNameError)
	if _, err := Parse(b); err == nil {
		t.Error("expected error for NXDOMAIN")
	}
}

func TestParse_DropsNoAnswers(t *testing.T) {
	b := buildResp(t, "x.example", dns.TypeA, nil, dns.RcodeSuccess)
	if _, err := Parse(b); err == nil {
		t.Error("expected error for empty answers")
	}
}

func TestParse_IgnoresNonAddrRRs(t *testing.T) {
	mx := &dns.MX{Hdr: dns.RR_Header{Name: "mail.example.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "x."}
	b := buildResp(t, "mail.example", dns.TypeMX, []dns.RR{mx}, dns.RcodeSuccess)
	if _, err := Parse(b); err == nil {
		t.Error("expected error: only MX records, none usable")
	}
}
```

- [ ] **Step 3: Run, expect fail**

```bash
go test ./internal/dnsparse/...
```

- [ ] **Step 4: Implement parser**

`internal/dnsparse/parser.go`:

```go
package dnsparse

import (
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type Record struct {
	Name   string // lowercase, no trailing dot
	Family int    // 4 or 6
	IP     net.IP
	TTL    uint32
}

type Response struct {
	TxID    uint16
	QName   string
	QType   uint16
	Records []Record
}

var (
	ErrNotResponse = errors.New("not a DNS response")
	ErrBadRcode    = errors.New("non-NOERROR rcode")
	ErrNoUsable    = errors.New("no usable A/AAAA records")
)

func Parse(b []byte) (*Response, error) {
	var m dns.Msg
	if err := m.Unpack(b); err != nil {
		return nil, err
	}
	if !m.Response {
		return nil, ErrNotResponse
	}
	if m.Rcode != dns.RcodeSuccess {
		return nil, ErrBadRcode
	}
	if len(m.Answer) == 0 {
		return nil, ErrNoUsable
	}
	r := &Response{TxID: m.Id}
	if len(m.Question) > 0 {
		r.QName = normalize(m.Question[0].Name)
		r.QType = m.Question[0].Qtype
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			r.Records = append(r.Records, Record{
				Name: normalize(rr.Header().Name), Family: 4, IP: v.A.To4(), TTL: rr.Header().Ttl,
			})
		case *dns.AAAA:
			r.Records = append(r.Records, Record{
				Name: normalize(rr.Header().Name), Family: 6, IP: v.AAAA.To16(), TTL: rr.Header().Ttl,
			})
		}
	}
	if len(r.Records) == 0 {
		return nil, ErrNoUsable
	}
	return r, nil
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}
```

- [ ] **Step 5: Tidy and test**

```bash
go mod tidy
go test ./internal/dnsparse/... -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/dnsparse go.mod go.sum
git commit -m "feat(dnsparse): miekg/dns wrapper extracting A/AAAA owner-name records"
```

---

## Task 6: Dedup LRU

**Files:**
- Create: `internal/dedup/dedup.go`
- Create: `internal/dedup/dedup_test.go`
- Modify: `go.mod`

- [ ] **Step 1: Add LRU**

```bash
go get github.com/hashicorp/golang-lru/v2
```

- [ ] **Step 2: Write failing tests**

`internal/dedup/dedup_test.go`:

```go
package dedup

import (
	"testing"
	"time"
)

func TestDedup_RepeatWithinWindowIsDup(t *testing.T) {
	d, _ := New(128, 200*time.Millisecond)
	payload := []byte{1, 2, 3, 4}
	if d.Seen(payload) {
		t.Fatal("first call must report not-seen")
	}
	if !d.Seen(payload) {
		t.Fatal("second call within TTL must report seen")
	}
}

func TestDedup_DifferentPayloadsIndependent(t *testing.T) {
	d, _ := New(128, time.Second)
	if d.Seen([]byte("a")) {
		t.Fatal("a first")
	}
	if d.Seen([]byte("b")) {
		t.Fatal("b first")
	}
	if !d.Seen([]byte("a")) || !d.Seen([]byte("b")) {
		t.Fatal("repeats should match")
	}
}

func TestDedup_TTLExpires(t *testing.T) {
	d, _ := New(128, 30*time.Millisecond)
	d.Seen([]byte("x"))
	time.Sleep(60 * time.Millisecond)
	if d.Seen([]byte("x")) {
		t.Fatal("entry should have expired")
	}
}
```

- [ ] **Step 3: Run, expect fail**

```bash
go test ./internal/dedup/...
```

- [ ] **Step 4: Implement**

`internal/dedup/dedup.go`:

```go
package dedup

import (
	"hash/fnv"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type Dedup struct {
	c   *lru.Cache[uint64, time.Time]
	ttl time.Duration
	now func() time.Time
}

func New(size int, ttl time.Duration) (*Dedup, error) {
	c, err := lru.New[uint64, time.Time](size)
	if err != nil {
		return nil, err
	}
	return &Dedup{c: c, ttl: ttl, now: time.Now}, nil
}

// Seen returns true if the payload was inserted within the TTL window.
// Either way it records a fresh entry for `key`.
func (d *Dedup) Seen(payload []byte) bool {
	h := fnv.New64a()
	h.Write(payload)
	k := h.Sum64()
	now := d.now()
	if t, ok := d.c.Get(k); ok && now.Sub(t) < d.ttl {
		d.c.Add(k, now) // refresh
		return true
	}
	d.c.Add(k, now)
	return false
}
```

- [ ] **Step 5: Test**

```bash
go mod tidy
go test ./internal/dedup/... -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/dedup go.mod go.sum
git commit -m "feat(dedup): FNV+LRU dedup with time-window suppression"
```

---

## Task 7: Source interface + fake implementation

**Files:**
- Create: `internal/source/source.go`
- Create: `internal/source/fake/fake.go`

- [ ] **Step 1: Define types and interface**

`internal/source/source.go`:

```go
package source

import "context"

type Direction uint8

const (
	DirSend Direction = iota // udp_sendmsg (resolver -> client OR resolver -> upstream)
	DirRecv                  // udp_recvmsg (resolver receiving upstream answers)
)

// Event is one DNS UDP payload observed by the kernel side.
type Event struct {
	NanoTS    uint64
	Direction Direction
	Family    uint8 // 4 or 6 (IP family of the socket)
	SrcPort   uint16
	DstPort   uint16
	Payload   []byte
}

// Source produces Events. Run blocks until ctx is canceled or a fatal error occurs.
type Source interface {
	Run(ctx context.Context, out chan<- Event) error
	Close() error
}
```

- [ ] **Step 2: Implement fake source for tests**

`internal/source/fake/fake.go`:

```go
package fake

import (
	"context"

	"github.com/rightkick/dns2ipset/internal/source"
)

// Source replays a fixed list of events then blocks until the context is done.
type Source struct {
	Events []source.Event
}

func (f *Source) Run(ctx context.Context, out chan<- source.Event) error {
	for _, e := range f.Events {
		select {
		case <-ctx.Done():
			return nil
		case out <- e:
		}
	}
	<-ctx.Done()
	return nil
}

func (f *Source) Close() error { return nil }
```

- [ ] **Step 3: Build**

```bash
go build ./...
```

Expected: success.

- [ ] **Step 4: Commit**

```bash
git add internal/source
git commit -m "feat(source): event type, Source interface, fake implementation for tests"
```

---

## Task 8: ipset client (interface + netlink + recording fake)

**Files:**
- Create: `internal/ipset/client.go`
- Create: `internal/ipset/client_test.go`
- Modify: `go.mod`

**Notes:**
- Try `github.com/vishvananda/netlink` first; its `IpsetAdd` accepts an `IPSetEntry` with `Timeout *uint32`. If its API is missing required fields (e.g., `IPSET_ATTR_TIMEOUT` propagation), fall back to handcrafted attributes via `github.com/mdlayher/netlink`. Choose at this task; do not stub.
- Unit tests only cover the interface and TTL clamping. Real netlink integration is gated by build tag `integration` and run only on hosts with ipset.

- [ ] **Step 1: Add netlink dependency**

```bash
go get github.com/vishvananda/netlink
```

- [ ] **Step 2: Write failing tests**

`internal/ipset/client_test.go`:

```go
package ipset

import (
	"net"
	"testing"
	"time"
)

type recCall struct {
	set  string
	ip   net.IP
	ttl  time.Duration
}

type recClient struct{ calls []recCall }

func (r *recClient) Add(set string, ip net.IP, ttl time.Duration) error {
	r.calls = append(r.calls, recCall{set, ip, ttl})
	return nil
}
func (r *recClient) Close() error { return nil }

func TestClampTTL(t *testing.T) {
	cases := []struct {
		in, min, max, want time.Duration
	}{
		{1 * time.Second, 60 * time.Second, 7 * 24 * time.Hour, 60 * time.Second},
		{30 * time.Minute, 60 * time.Second, 7 * 24 * time.Hour, 30 * time.Minute},
		{30 * 24 * time.Hour, 60 * time.Second, 7 * 24 * time.Hour, 7 * 24 * time.Hour},
	}
	for _, c := range cases {
		got := ClampTTL(c.in, c.min, c.max)
		if got != c.want {
			t.Errorf("ClampTTL(%v,%v,%v)=%v want %v", c.in, c.min, c.max, got, c.want)
		}
	}
}

func TestClampTTL_NegativeOrZeroBecomesMin(t *testing.T) {
	if got := ClampTTL(0, time.Minute, time.Hour); got != time.Minute {
		t.Errorf("zero TTL should clamp to min, got %v", got)
	}
}
```

- [ ] **Step 3: Run, expect fail (missing ClampTTL)**

```bash
go test ./internal/ipset/...
```

- [ ] **Step 4: Implement client + clamping**

`internal/ipset/client.go`:

```go
package ipset

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// Client adds entries to an existing ipset.
type Client interface {
	Add(set string, ip net.IP, ttl time.Duration) error
	Close() error
}

// ClampTTL clamps `ttl` into [min, max]. A non-positive `ttl` becomes `min`.
func ClampTTL(ttl, min, max time.Duration) time.Duration {
	if ttl <= 0 {
		return min
	}
	if ttl < min {
		return min
	}
	if ttl > max {
		return max
	}
	return ttl
}

// Netlink implements Client by talking to NFNL_SUBSYS_IPSET via vishvananda/netlink.
// Missing-set errors are rate-limited (one log per (set, minute)).
type Netlink struct {
	mu        sync.Mutex
	missLog   map[string]time.Time
	logMissFn func(set string)
}

func NewNetlink(logMissing func(set string)) *Netlink {
	return &Netlink{
		missLog:   make(map[string]time.Time),
		logMissFn: logMissing,
	}
}

func (n *Netlink) Add(set string, ip net.IP, ttl time.Duration) error {
	if set == "" || ip == nil {
		return errors.New("empty set or nil ip")
	}
	timeout := uint32(ttl.Seconds())
	entry := &netlink.IPSetEntry{IP: ip, Timeout: &timeout}
	if err := netlink.IpsetAdd(set, entry); err != nil {
		// Detect "set not found" — netlink wraps an errno; fall back to substring.
		if isMissingSet(err) {
			n.rateLimitedMissLog(set)
			return fmt.Errorf("ipset %q missing: %w", set, err)
		}
		return fmt.Errorf("ipset add %s %s: %w", set, ip, err)
	}
	return nil
}

func (n *Netlink) Close() error { return nil }

func (n *Netlink) rateLimitedMissLog(set string) {
	if n.logMissFn == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	if last, ok := n.missLog[set]; ok && now.Sub(last) < time.Minute {
		return
	}
	n.missLog[set] = now
	n.logMissFn(set)
}

func isMissingSet(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// vishvananda/netlink surfaces "no such file or directory" / "set with the given name does not exist"
	return contains(s, "does not exist") || contains(s, "no such")
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && stringIndex(s, sub) >= 0
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 5: Test**

```bash
go mod tidy
go test ./internal/ipset/... -v
```

Expected: clamp tests PASS. Netlink path is unexercised here; real test arrives in the smoke run.

- [ ] **Step 6: API check — confirm `netlink.IpsetAdd` signature**

```bash
go doc github.com/vishvananda/netlink IpsetAdd
go doc github.com/vishvananda/netlink IPSetEntry
```

If either is absent or shaped differently than assumed, switch the implementation to handcraft attributes via `mdlayher/netlink` (NFNL_SUBSYS_IPSET=6, command IPSET_CMD_ADD=9). Don't paper over a missing `Timeout` field — clamping must hit the wire.

- [ ] **Step 7: Commit**

```bash
git add internal/ipset go.mod go.sum
git commit -m "feat(ipset): netlink-backed Add with TTL clamp and rate-limited miss logs"
```

---

## Task 9: Pipeline orchestration

**Files:**
- Create: `internal/pipeline/pipeline.go`
- Create: `internal/pipeline/pipeline_test.go`

- [ ] **Step 1: Write failing tests**

`internal/pipeline/pipeline_test.go`:

```go
package pipeline

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/rightkick/dns2ipset/internal/dedup"
	"github.com/rightkick/dns2ipset/internal/rules"
	"github.com/rightkick/dns2ipset/internal/source"
	"github.com/rightkick/dns2ipset/internal/source/fake"
)

type recordedAdd struct {
	set string
	ip  net.IP
	ttl time.Duration
}

type recIPSet struct {
	mu    sync.Mutex
	calls []recordedAdd
}

func (r *recIPSet) Add(set string, ip net.IP, ttl time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedAdd{set, ip, ttl})
	return nil
}
func (r *recIPSet) Close() error { return nil }

func packResp(t *testing.T, qname string, ips []net.IP, ttl uint32) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	m.Response = true
	for _, ip := range ips {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip,
		})
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPipeline_MatchedDomainPushesIPs(t *testing.T) {
	store := rules.NewStore()
	rs, err := rules.LoadFromBytes([]byte(`
version: 1
rules:
  - domain: facebook.com
    ipset_v4: snoop_fb_v4
`))
	if err != nil {
		t.Fatal(err)
	}
	store.Replace(rs)

	payload := packResp(t, "www.facebook.com", []net.IP{net.ParseIP("1.2.3.4")}, 300)
	src := &fake.Source{Events: []source.Event{{Payload: payload}}}

	rec := &recIPSet{}
	d, _ := dedup.New(64, 100*time.Millisecond)
	p := New(Config{
		Workers:  1,
		Store:    store,
		Source:   src,
		IPSet:    rec,
		Dedup:    d,
		TTLMin:   60 * time.Second,
		TTLMax:   24 * time.Hour,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 1 {
		t.Fatalf("got %d calls, want 1: %+v", len(rec.calls), rec.calls)
	}
	c := rec.calls[0]
	if c.set != "snoop_fb_v4" || !c.ip.Equal(net.ParseIP("1.2.3.4")) || c.ttl != 300*time.Second {
		t.Errorf("call mismatch: %+v", c)
	}
}

func TestPipeline_UnmatchedDomainNoOp(t *testing.T) {
	store := rules.NewStore()
	rs, _ := rules.LoadFromBytes([]byte("version: 1\nrules:\n  - {domain: facebook.com, ipset_v4: x}\n"))
	store.Replace(rs)

	payload := packResp(t, "example.com", []net.IP{net.ParseIP("9.9.9.9")}, 30)
	src := &fake.Source{Events: []source.Event{{Payload: payload}}}
	rec := &recIPSet{}
	d, _ := dedup.New(64, 100*time.Millisecond)
	p := New(Config{Workers: 1, Store: store, Source: src, IPSet: rec, Dedup: d, TTLMin: time.Second, TTLMax: time.Hour})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if len(rec.calls) != 0 {
		t.Errorf("expected no calls, got %+v", rec.calls)
	}
}

func TestPipeline_DedupSuppressesDuplicate(t *testing.T) {
	store := rules.NewStore()
	rs, _ := rules.LoadFromBytes([]byte("version: 1\nrules:\n  - {domain: facebook.com, ipset_v4: x}\n"))
	store.Replace(rs)

	payload := packResp(t, "facebook.com", []net.IP{net.ParseIP("1.1.1.1")}, 60)
	src := &fake.Source{Events: []source.Event{{Payload: payload}, {Payload: payload}}}
	rec := &recIPSet{}
	d, _ := dedup.New(64, time.Second)
	p := New(Config{Workers: 1, Store: store, Source: src, IPSet: rec, Dedup: d, TTLMin: time.Second, TTLMax: time.Hour})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if len(rec.calls) != 1 {
		t.Errorf("expected dedup to suppress duplicate; got calls=%d", len(rec.calls))
	}
}
```

This test file references `rules.LoadFromBytes` — add it now (small refactor of `Load`).

- [ ] **Step 2: Add `LoadFromBytes` helper to rules loader**

Edit `internal/rules/loader.go`:

```go
// Append to the file:

func LoadFromBytes(b []byte) (*RuleSet, error) {
	return loadFromBytes(b)
}

func loadFromBytes(b []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if rs.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version %d (want 1)", rs.Version)
	}
	seen := make(map[string]int)
	for i, r := range rs.Rules {
		if r == nil {
			return nil, errors.New("nil rule entry")
		}
		r.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Domain)), ".")
		if r.Domain == "" {
			return nil, fmt.Errorf("rule %d: domain is required", i)
		}
		if r.IPSetV4 == "" && r.IPSetV6 == "" {
			return nil, fmt.Errorf("rule %d (%s): must specify ipset_v4 and/or ipset_v6", i, r.Domain)
		}
		if prev, ok := seen[r.Domain]; ok {
			rs.Warnings = append(rs.Warnings,
				fmt.Sprintf("duplicate domain %q at rules[%d] overrides rules[%d] (last wins)", r.Domain, i, prev))
		}
		seen[r.Domain] = i
	}
	return &rs, nil
}
```

Also refactor `Load` to use it:

```go
func Load(path string) (*RuleSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	return loadFromBytes(b)
}
```

- [ ] **Step 3: Run rules tests, ensure refactor still green**

```bash
go test ./internal/rules/... -v
```

- [ ] **Step 4: Implement pipeline**

`internal/pipeline/pipeline.go`:

```go
package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rightkick/dns2ipset/internal/dedup"
	"github.com/rightkick/dns2ipset/internal/dnsparse"
	"github.com/rightkick/dns2ipset/internal/ipset"
	"github.com/rightkick/dns2ipset/internal/rules"
	"github.com/rightkick/dns2ipset/internal/source"
)

type Config struct {
	Workers int
	Store   *rules.Store
	Source  source.Source
	IPSet   ipset.Client
	Dedup   *dedup.Dedup
	TTLMin  time.Duration
	TTLMax  time.Duration
	Log     *slog.Logger // nil-safe
}

type Pipeline struct{ cfg Config }

func New(cfg Config) *Pipeline {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Pipeline{cfg: cfg}
}

func (p *Pipeline) Run(ctx context.Context) error {
	if p.cfg.Source == nil || p.cfg.IPSet == nil || p.cfg.Store == nil || p.cfg.Dedup == nil {
		return errors.New("pipeline: missing dependency")
	}
	events := make(chan source.Event, 1024)

	srcDone := make(chan error, 1)
	go func() { srcDone <- p.cfg.Source.Run(ctx, events) }()

	workerDone := make(chan struct{}, p.cfg.Workers)
	for i := 0; i < p.cfg.Workers; i++ {
		go p.worker(ctx, events, workerDone)
	}

	// Wait for source to finish (ctx done), then drain workers.
	err := <-srcDone
	close(events)
	for i := 0; i < p.cfg.Workers; i++ {
		<-workerDone
	}
	return err
}

func (p *Pipeline) worker(ctx context.Context, events <-chan source.Event, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			p.handle(ev)
		}
	}
}

func (p *Pipeline) handle(ev source.Event) {
	if p.cfg.Dedup.Seen(ev.Payload) {
		return
	}
	resp, err := dnsparse.Parse(ev.Payload)
	if err != nil {
		return
	}
	rs := p.cfg.Store.Get()
	if rs == nil {
		return
	}
	tr := rs.BuildTrie() // cheap-enough rebuild — alternatively cache; left simple for clarity.
	candidates := uniqueNames(resp)
	for _, name := range candidates {
		v, ok := tr.Lookup(name)
		if !ok {
			continue
		}
		rule := v.(*rules.Rule)
		for _, rec := range resp.Records {
			set := ""
			if rec.Family == 4 {
				set = rule.IPSetV4
			} else if rec.Family == 6 {
				set = rule.IPSetV6
			}
			if set == "" {
				continue
			}
			ttl := ipset.ClampTTL(time.Duration(rec.TTL)*time.Second, p.cfg.TTLMin, p.cfg.TTLMax)
			if err := p.cfg.IPSet.Add(set, rec.IP, ttl); err != nil {
				p.cfg.Log.Debug("ipset add failed", "set", set, "ip", rec.IP, "err", err)
			}
		}
	}
}

func uniqueNames(r *dnsparse.Response) []string {
	seen := map[string]bool{r.QName: true}
	out := []string{r.QName}
	for _, rec := range r.Records {
		if !seen[rec.Name] {
			seen[rec.Name] = true
			out = append(out, rec.Name)
		}
	}
	return out
}

```

- [ ] **Step 5: Performance note — trie caching**

The naive `BuildTrie` on every event is fine at low rates but wasteful at thousands of QPS. Cache a `*rules.Trie` alongside the `*RuleSet` in `rules.Store`:

Edit `internal/rules/store.go`:

```go
package rules

import "sync/atomic"

type snapshot struct {
	rs   *RuleSet
	trie *Trie
}

type Store struct{ v atomic.Value /* *snapshot */ }

func NewStore() *Store { return &Store{} }

func (s *Store) Get() *RuleSet {
	v := s.v.Load()
	if v == nil {
		return nil
	}
	return v.(*snapshot).rs
}

func (s *Store) Trie() *Trie {
	v := s.v.Load()
	if v == nil {
		return nil
	}
	return v.(*snapshot).trie
}

func (s *Store) Replace(rs *RuleSet) {
	if rs == nil {
		s.v.Store((*snapshot)(nil))
		return
	}
	s.v.Store(&snapshot{rs: rs, trie: rs.BuildTrie()})
}
```

Update pipeline `handle` to use `tr := p.cfg.Store.Trie()` instead of rebuilding:

```go
	tr := p.cfg.Store.Trie()
	if tr == nil {
		return
	}
```

(Keep the existing `Get()` test in watcher tests valid by leaving `Get()` returning the RuleSet.)

- [ ] **Step 6: Run all tests**

```bash
go mod tidy
go test ./... -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/pipeline internal/rules/loader.go internal/rules/store.go
git commit -m "feat(pipeline): wire source->parse->dedup->trie->ipset with cached trie"
```

---

## Task 10: Metrics

**Files:**
- Create: `internal/metrics/metrics.go`
- Modify: `internal/pipeline/pipeline.go` (instrument)
- Modify: `internal/ipset/client.go` (instrument)

- [ ] **Step 1: Add Prometheus client**

```bash
go get github.com/prometheus/client_golang/prometheus
go get github.com/prometheus/client_golang/prometheus/promhttp
```

- [ ] **Step 2: Define registry and instruments**

`internal/metrics/metrics.go`:

```go
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Registry *prometheus.Registry

	EventsTotal       *prometheus.CounterVec   // labels: direction
	ParseErrors       prometheus.Counter
	DedupHits         prometheus.Counter
	Matches           *prometheus.CounterVec   // labels: rule
	IPSetWrites       *prometheus.CounterVec   // labels: set, family
	IPSetErrors       *prometheus.CounterVec   // labels: reason
	RingbufDrops      prometheus.Counter
	RulesReloadTotal  *prometheus.CounterVec   // labels: result
	RulesActive       prometheus.Gauge
}

func New() *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{
		Registry:    r,
		EventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_events_total"}, []string{"direction"}),
		ParseErrors: prometheus.NewCounter(prometheus.CounterOpts{Name: "dns2ipset_parse_errors_total"}),
		DedupHits:   prometheus.NewCounter(prometheus.CounterOpts{Name: "dns2ipset_dedup_hits_total"}),
		Matches:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_matches_total"}, []string{"rule"}),
		IPSetWrites: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_ipset_writes_total"}, []string{"set", "family"}),
		IPSetErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_ipset_errors_total"}, []string{"reason"}),
		RingbufDrops: prometheus.NewCounter(prometheus.CounterOpts{Name: "dns2ipset_ringbuf_drops_total"}),
		RulesReloadTotal: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_rules_reload_total"}, []string{"result"}),
		RulesActive: prometheus.NewGauge(prometheus.GaugeOpts{Name: "dns2ipset_rules_active"}),
	}
	r.MustRegister(m.EventsTotal, m.ParseErrors, m.DedupHits, m.Matches,
		m.IPSetWrites, m.IPSetErrors, m.RingbufDrops, m.RulesReloadTotal, m.RulesActive)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
```

- [ ] **Step 3: Plumb `*Metrics` through `pipeline.Config`**

In `internal/pipeline/pipeline.go`:

```go
import (
	// ...existing imports...
	"github.com/rightkick/dns2ipset/internal/metrics"
)

type Config struct {
	// ... existing fields ...
	Metrics *metrics.Metrics // nil-safe: when nil, no instrumentation
}
```

Add a small helper:

```go
func (p *Pipeline) m() *metrics.Metrics { return p.cfg.Metrics }
```

Instrument `handle`:

```go
func (p *Pipeline) handle(ev source.Event) {
	if m := p.m(); m != nil {
		switch ev.Direction {
		case source.DirSend:
			m.EventsTotal.WithLabelValues("send").Inc()
		case source.DirRecv:
			m.EventsTotal.WithLabelValues("recv").Inc()
		}
	}
	if p.cfg.Dedup.Seen(ev.Payload) {
		if m := p.m(); m != nil {
			m.DedupHits.Inc()
		}
		return
	}
	resp, err := dnsparse.Parse(ev.Payload)
	if err != nil {
		if m := p.m(); m != nil {
			m.ParseErrors.Inc()
		}
		return
	}
	tr := p.cfg.Store.Trie()
	if tr == nil {
		return
	}
	for _, name := range uniqueNames(resp) {
		v, ok := tr.Lookup(name)
		if !ok {
			continue
		}
		rule := v.(*rules.Rule)
		if m := p.m(); m != nil {
			m.Matches.WithLabelValues(rule.Domain).Inc()
		}
		for _, rec := range resp.Records {
			set := ""
			fam := ""
			switch rec.Family {
			case 4:
				set, fam = rule.IPSetV4, "v4"
			case 6:
				set, fam = rule.IPSetV6, "v6"
			}
			if set == "" {
				continue
			}
			ttl := ipset.ClampTTL(time.Duration(rec.TTL)*time.Second, p.cfg.TTLMin, p.cfg.TTLMax)
			if err := p.cfg.IPSet.Add(set, rec.IP, ttl); err != nil {
				if m := p.m(); m != nil {
					reason := "other"
					if isMissingErr(err) {
						reason = "missing"
					}
					m.IPSetErrors.WithLabelValues(reason).Inc()
				}
				p.cfg.Log.Debug("ipset add failed", "set", set, "ip", rec.IP, "err", err)
				continue
			}
			if m := p.m(); m != nil {
				m.IPSetWrites.WithLabelValues(set, fam).Inc()
			}
		}
	}
}

func isMissingErr(err error) bool {
	return err != nil && (contains(err.Error(), "missing") || contains(err.Error(), "does not exist"))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests**

```bash
go mod tidy
go test ./... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/metrics internal/pipeline go.mod go.sum
git commit -m "feat(metrics): Prometheus instruments wired into pipeline"
```

---

## Task 11: eBPF C program

**Files:**
- Create: `internal/bpf/dns2ipset.bpf.c`
- Create: `internal/bpf/headers/.gitkeep` (so the dir exists)
- Modify: `Makefile` (already has `generate` target)

- [ ] **Step 1: Generate `vmlinux.h` (developer host)**

```bash
make internal/bpf/headers/vmlinux.h
```

Expected: `vmlinux.h` written under `internal/bpf/headers/` (this file is gitignored).

If `bpftool` is unavailable on the dev host, document in README that BPF builds require running `make generate` on a Linux box with BTF.

- [ ] **Step 2: Write the BPF program**

`internal/bpf/dns2ipset.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define MAX_PAYLOAD 4096

char LICENSE[] SEC("license") = "GPL";

enum dir { DIR_SEND = 0, DIR_RECV = 1 };

struct event {
    __u64 ts_ns;
    __u8  direction;
    __u8  family;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_len;
    __u8  payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// Per-CPU scratch so we don't blow the 512-byte stack with `struct event`.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct event);
    __uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline int handle(struct sock *sk, struct msghdr *msg, __u8 direction)
{
    if (!sk || !msg) return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    __u16 sport = BPF_CORE_READ(inet, inet_sport);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 sport_h = bpf_ntohs(sport);
    __u16 dport_h = bpf_ntohs(dport);

    if (sport_h != 53 && dport_h != 53) return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u8 fam_short = (family == AF_INET) ? 4 : (family == AF_INET6) ? 6 : 0;
    if (fam_short == 0) return 0;

    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->direction = direction;
    e->family = fam_short;
    e->src_port = sport_h;
    e->dst_port = dport_h;
    e->payload_len = 0;

    // Walk the iov to copy up to MAX_PAYLOAD bytes.
    struct iov_iter iter;
    if (bpf_core_read(&iter, sizeof(iter), &msg->msg_iter) < 0) return 0;

    // For 5.x kernels with iov_iter using `__iov`, prefer that field; otherwise fall back.
    const struct iovec *iov = NULL;
    if (bpf_core_field_exists(iter.__iov))
        iov = BPF_CORE_READ(&iter, __iov);
    else
        iov = BPF_CORE_READ(&iter, iov);

    if (!iov) return 0;

    void *base;
    __u64 len;
    base = BPF_CORE_READ(iov, iov_base);
    len  = BPF_CORE_READ(iov, iov_len);
    if (len > MAX_PAYLOAD) len = MAX_PAYLOAD;
    if (len == 0) return 0;

    // Read user/kernel memory into our scratch buffer.
    long n = bpf_probe_read(&e->payload, (u32)len, base);
    if (n < 0) {
        // Try kernel-mem variant — for some recv paths the iov is in kernel space.
        n = bpf_probe_read_kernel(&e->payload, (u32)len, base);
        if (n < 0) return 0;
    }
    e->payload_len = (u16)len;

    // Hand a copy off to the ringbuf.
    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!out) return 0;
    __builtin_memcpy(out, e, sizeof(*e));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_sendmsg_entry, struct sock *sk, struct msghdr *msg)
{
    return handle(sk, msg, DIR_SEND);
}

SEC("fentry/udp_recvmsg")
int BPF_PROG(udp_recvmsg_entry, struct sock *sk, struct msghdr *msg)
{
    return handle(sk, msg, DIR_RECV);
}
```

- [ ] **Step 3: Verify it compiles standalone**

```bash
cd internal/bpf
clang -O2 -g -target bpf -Iheaders -c dns2ipset.bpf.c -o dns2ipset.bpf.o
```

Expected: `.o` produced, no errors. (If you see warnings about `iov_iter` field detection, they're benign — `bpf_core_field_exists` resolves at load time.)

If clang is older than 10 or `vmlinux.h` is missing, this step fails — fix the toolchain before continuing.

- [ ] **Step 4: Commit**

```bash
git add internal/bpf/dns2ipset.bpf.c internal/bpf/headers/.gitkeep
git commit -m "feat(bpf): fentry udp_sendmsg/udp_recvmsg DNS payload capture into ringbuf"
```

---

## Task 12: bpf2go integration & ringbuf reader

**Files:**
- Create: `internal/bpf/gen.go`
- Create: `internal/bpf/loader.go`
- Modify: `Makefile` (add `bpf` target alias)
- Modify: `go.mod`

- [ ] **Step 1: Add cilium/ebpf and bpf2go**

```bash
go get github.com/cilium/ebpf
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

- [ ] **Step 2: Add the generate directive**

`internal/bpf/gen.go`:

```go
//go:build ignore
// +build ignore

// This file holds the bpf2go directive. The // +build ignore guard keeps it
// out of normal compilation; `go generate` still picks up the directive.

package bpf

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -Iheaders" Bpf dns2ipset.bpf.c
```

Wait — the `//go:generate` directive only fires when the file is part of the package. Use a separate non-ignored file for the directive:

Replace with two files. Delete the ignore-tagged one above; instead create `internal/bpf/generate.go`:

```go
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Iheaders" Bpf dns2ipset.bpf.c
```

(Using `go run` keeps the toolchain self-contained — no need to install bpf2go separately.)

- [ ] **Step 3: Generate**

```bash
make generate
```

Expected: produces `bpf_bpfel.go` and `bpf_bpfel.o` in `internal/bpf/` (these are gitignored).

- [ ] **Step 4: Implement loader**

`internal/bpf/loader.go`:

```go
package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/rightkick/dns2ipset/internal/metrics"
	"github.com/rightkick/dns2ipset/internal/source"
)

// Mirror of `struct event` in dns2ipset.bpf.c. Field offsets must match exactly.
// C layout: ts_ns(8) direction(1) family(1) src_port(2) dst_port(2) payload_len(2) payload[4096]
// Total header = 16 bytes; payload starts at offset 16. Go natural alignment matches: do
// NOT add padding here — uint8/uint8/uint16/uint16/uint16 packs to offset 16 with no gap.
type rawEvent struct {
	TsNs       uint64
	Direction  uint8
	Family     uint8
	SrcPort    uint16
	DstPort    uint16
	PayloadLen uint16
	Payload    [4096]byte
}

// Compile-time assertion of the layout.
const _rawEventHeaderSize = 16
var _ = [1]struct{}{}[unsafe.Sizeof(rawEvent{})-4096-_rawEventHeaderSize]

type Loader struct {
	objs    bpfObjects
	links   []link.Link
	rd      *ringbuf.Reader
	metrics *metrics.Metrics
}

func New(m *metrics.Metrics) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	send, err := link.AttachTracing(link.TracingOptions{Program: objs.UdpSendmsgEntry})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach udp_sendmsg: %w", err)
	}
	recv, err := link.AttachTracing(link.TracingOptions{Program: objs.UdpRecvmsgEntry})
	if err != nil {
		send.Close()
		objs.Close()
		return nil, fmt.Errorf("attach udp_recvmsg: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		send.Close()
		recv.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &Loader{
		objs:    objs,
		links:   []link.Link{send, recv},
		rd:      rd,
		metrics: m,
	}, nil
}

func (l *Loader) Run(ctx context.Context, out chan<- source.Event) error {
	go func() {
		<-ctx.Done()
		_ = l.rd.Close() // unblocks Read
	}()

	for {
		rec, err := l.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		if rec.LostSamples > 0 && l.metrics != nil {
			l.metrics.RingbufDrops.Add(float64(rec.LostSamples))
		}
		ev, ok := decode(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case out <- ev:
		}
	}
}

func (l *Loader) Close() error {
	if l.rd != nil {
		_ = l.rd.Close()
	}
	for _, lk := range l.links {
		_ = lk.Close()
	}
	l.objs.Close()
	return nil
}

func decode(b []byte) (source.Event, bool) {
	const headerSize = int(unsafe.Sizeof(rawEvent{})) - 4096
	if len(b) < headerSize {
		return source.Event{}, false
	}
	// Safe: rawEvent layout is fixed by the BPF C struct above.
	e := (*rawEvent)(unsafe.Pointer(&b[0]))
	plen := int(e.PayloadLen)
	if plen < 0 || plen > len(e.Payload) {
		return source.Event{}, false
	}
	payload := make([]byte, plen)
	copy(payload, e.Payload[:plen])
	return source.Event{
		NanoTS:    e.TsNs,
		Direction: source.Direction(e.Direction),
		Family:    e.Family,
		SrcPort:   e.SrcPort,
		DstPort:   e.DstPort,
		Payload:   payload,
	}, true
}

// Compile-time check that endian quirks of bpf2go (it always uses little-endian
// `_bpfel.o` on amd64/arm64) match the host.
var _ = binary.LittleEndian
```

- [ ] **Step 5: Build**

```bash
go build ./...
```

Expected: success on a host where `make generate` has run. On a host without BPF toolchain, this step fails — that's fine; build is supported only on Linux+BTF hosts.

- [ ] **Step 6: Smoke test on a real Linux host**

```bash
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+eip ./dns2ipset 2>/dev/null || true
# (or run as root in this smoke step)
```

Write a tiny `cmd/bpfprobe/main.go` (throwaway, NOT committed) that constructs a `bpf.Loader`, runs it, and prints the first 10 events. `dig @127.0.0.1 example.com` should produce events. Delete the throwaway after confirming.

- [ ] **Step 7: Commit**

```bash
git add internal/bpf/generate.go internal/bpf/loader.go go.mod go.sum
git commit -m "feat(bpf): cilium/ebpf loader, fentry attachments, ringbuf reader"
```

---

## Task 13: Entrypoint, flags, signals

**Files:**
- Modify: `cmd/dns2ipset/main.go`

- [ ] **Step 1: Replace stub with full entrypoint**

`cmd/dns2ipset/main.go`:

```go
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/rightkick/dns2ipset/internal/bpf"
	"github.com/rightkick/dns2ipset/internal/dedup"
	"github.com/rightkick/dns2ipset/internal/ipset"
	"github.com/rightkick/dns2ipset/internal/metrics"
	"github.com/rightkick/dns2ipset/internal/pipeline"
	"github.com/rightkick/dns2ipset/internal/rules"
)

func main() {
	rulesPath := flag.String("rules", "/etc/dns2ipset/rules.yaml", "path to rules YAML")
	ttlMin := flag.Duration("ttl-min", 60*time.Second, "minimum ipset entry TTL")
	ttlMax := flag.Duration("ttl-max", 168*time.Hour, "maximum ipset entry TTL")
	metricsAddr := flag.String("metrics-addr", "", "host:port for /metrics (empty disables)")
	logLevel := flag.String("log-level", "info", "debug|info|warn|error")
	dedupWindow := flag.Duration("dedup-window", 200*time.Millisecond, "deduplication window")
	flag.Parse()

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	m := metrics.New()

	rs, err := rules.Load(*rulesPath)
	if err != nil {
		log.Error("initial rules load", "err", err)
		os.Exit(2)
	}
	store := rules.NewStore()
	store.Replace(rs)
	m.RulesActive.Set(float64(len(rs.Rules)))

	reload := func(p string) {
		nrs, err := rules.Load(p)
		if err != nil {
			m.RulesReloadTotal.WithLabelValues("error").Inc()
			log.Warn("rules reload failed; keeping previous", "err", err)
			return
		}
		store.Replace(nrs)
		m.RulesReloadTotal.WithLabelValues("ok").Inc()
		m.RulesActive.Set(float64(len(nrs.Rules)))
		log.Info("rules reloaded", "rules", len(nrs.Rules))
	}

	watcher, err := rules.NewWatcher(*rulesPath, reload)
	if err != nil {
		log.Error("rules watcher", "err", err)
		os.Exit(2)
	}
	defer watcher.Close()

	d, err := dedup.New(4096, *dedupWindow)
	if err != nil {
		log.Error("dedup", "err", err)
		os.Exit(2)
	}

	ipsetClient := ipset.NewNetlink(func(set string) {
		log.Warn("ipset missing", "set", set)
	})
	defer ipsetClient.Close()

	loader, err := bpf.New(m)
	if err != nil {
		log.Error("bpf load", "err", err)
		os.Exit(2)
	}
	defer loader.Close()

	pl := pipeline.New(pipeline.Config{
		Workers: runtime.GOMAXPROCS(0),
		Store:   store,
		Source:  loader,
		IPSet:   ipsetClient,
		Dedup:   d,
		TTLMin:  *ttlMin,
		TTLMax:  *ttlMax,
		Metrics: m,
		Log:     log,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// SIGHUP → force reload (independent of inotify).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reload(*rulesPath)
		}
	}()

	go watcher.Run(ctx)

	if *metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", m.Handler())
		srv := &http.Server{Addr: *metricsAddr, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
		go func() {
			log.Info("metrics listening", "addr", *metricsAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server", "err", err)
			}
		}()
		defer srv.Shutdown(context.Background())
	}

	log.Info("dns2ipset starting", "rules", *rulesPath, "rule-count", len(rs.Rules))
	if err := pl.Run(ctx); err != nil {
		log.Error("pipeline exited", "err", err)
		os.Exit(1)
	}
	log.Info("dns2ipset stopped")
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}
```

- [ ] **Step 2: Build**

```bash
make build
```

Expected: success on a Linux host with the BPF toolchain available; otherwise the BPF object load fails at runtime, not at compile time.

- [ ] **Step 3: Commit**

```bash
git add cmd/dns2ipset/main.go
git commit -m "feat(cmd): main entrypoint with flags, signals, metrics, watchers wired"
```

---

## Task 14: Deploy artifacts

**Files:**
- Create: `deploy/dns2ipset.service`
- Create: `deploy/rules.example.yaml`
- Modify: `README.md`

- [ ] **Step 1: systemd unit**

`deploy/dns2ipset.service`:

```ini
[Unit]
Description=DNS-to-ipset snooper
After=network-online.target named.service dnsmasq.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dns2ipset --rules /etc/dns2ipset/rules.yaml --metrics-addr 127.0.0.1:9301
Restart=on-failure
RestartSec=2s
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryHigh=128M
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Example rules**

`deploy/rules.example.yaml`:

```yaml
version: 1
rules:
  - domain: facebook.com
    ipset_v4: snoop_fb_v4
    ipset_v6: snoop_fb_v6
  - domain: ads.example.org
    ipset_v4: snoop_ads_v4
```

- [ ] **Step 3: Expand README**

Append to `README.md`:

```markdown
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
```

- [ ] **Step 4: Commit**

```bash
git add deploy/dns2ipset.service deploy/rules.example.yaml README.md
git commit -m "feat(deploy): systemd unit, example rules, README install/smoke instructions"
```

---

## Task 15: CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: GitHub Actions workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-22.04]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - name: install bpf toolchain
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic ipset
          # bpftool ships under linux-tools-`uname -r` on ubuntu-22.04 runners.
          BPFTOOL=$(ls /usr/lib/linux-tools-*/bpftool | head -n1)
          sudo ln -sf "$BPFTOOL" /usr/local/bin/bpftool
      - run: make generate
      - run: go vet ./...
      - run: go test ./...
      - run: make build
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: GitHub Actions vet+test+build with BPF toolchain"
```

---

## Verification matrix

After all tasks complete, run on a real Linux gateway (NOT WSL2):

| Check | Command | Expected |
|---|---|---|
| Unit/integration | `go test ./...` | all PASS |
| Build | `make build` | `./dns2ipset` produced |
| BPF object | `make generate && file internal/bpf/*_bpfel.o` | `ELF 64-bit LSB relocatable, eBPF` |
| Smoke (matched) | `sudo ipset create snoop_fb_v4 hash:ip family inet timeout 86400` then run with rule for `facebook.com`, `dig @127.0.0.1 facebook.com` | resolved IP appears in `ipset list snoop_fb_v4` with TTL ≈ answer TTL |
| Smoke (subdomain) | `dig @127.0.0.1 www.facebook.com` | new IPs appended |
| Negative | `dig @127.0.0.1 example.com` (not in rules) | sets unchanged |
| Reload | `mv rules.new.yaml rules.yaml` (atomic) | next dig populates new rule's set; metric `dns2ipset_rules_reload_total{result="ok"}` ticks |
| iptables | `iptables -I OUTPUT -m set --match-set snoop_fb_v4 dst -j DROP`, `curl https://www.facebook.com` after fresh resolve | curl fails |
| Metrics | `curl http://127.0.0.1:9301/metrics` | counters present and increasing under traffic |

If any of these fail, stop and diagnose (per `superpowers:systematic-debugging`).

---

## Open questions for the engineer to flag

1. **Trie semantics:** The design says "first terminal match wins" walking right-to-left, which makes the *shortest* configured suffix dominate (e.g., `example.org` shadows `ads.example.org`). Tests in Task 2 lock this in. If longest-match was intended, only `Trie.Lookup` and `TestTrie_ShortestSuffixWins` change.
2. **Module path:** `github.com/rightkick/dns2ipset` is assumed. If a different path is wanted (e.g., a personal namespace), change it once in Task 1 before any package writes its imports.
3. **vishvananda/netlink ipset surface:** Task 8 Step 6 verifies. If it's missing the `Timeout` propagation or `IpsetAdd`, the implementation must switch to `mdlayher/netlink` with handcrafted NFNL_SUBSYS_IPSET attributes — not a fallback that silently drops the timeout.
