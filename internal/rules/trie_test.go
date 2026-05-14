package rules

import "testing"

func TestTrie_ExactAndSubdomainMatch(t *testing.T) {
	tr := NewTrie()
	tr.Insert("example.com", "example")

	cases := []struct {
		name string
		want any
	}{
		{"example.com", "example"},
		{"www.example.com", "example"},
		{"a.b.example.com", "example"},
		{"EXAMPLE.com", "example"}, // case-insensitive
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
	tr.Insert("example.com", "example")

	for _, name := range []string{"notexample.com", "example.com.evil.org", "com"} {
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
	tr.Insert("example.com", "example")
	if got, ok := tr.Lookup("www.example.com."); !ok || got != "example" {
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
