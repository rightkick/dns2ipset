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
  - domain: example.com
    ipset_v4: ipset_example_v4
    ipset_v6: ipset_example_v6
  - domain: ads.example.org
    ipset_v4: ipset_ads_v4
`)
	rs, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs.Rules))
	}
	tr := rs.BuildTrie()
	v, ok := tr.Lookup("www.example.com")
	if !ok {
		t.Fatal("expected example.com match")
	}
	r := v.(*Rule)
	if r.IPSetV4 != "ipset_example_v4" || r.IPSetV6 != "ipset_example_v6" {
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
