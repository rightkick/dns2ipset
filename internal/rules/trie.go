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
