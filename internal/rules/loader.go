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
	Version  int      `yaml:"version"`
	Rules    []*Rule  `yaml:"rules"`
	Warnings []string `yaml:"-"`
}

func Load(path string) (*RuleSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	return loadFromBytes(b)
}

// LoadFromBytes parses and validates a RuleSet from an in-memory YAML blob.
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
