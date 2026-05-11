package rules

import "sync/atomic"

type snapshot struct {
	rs   *RuleSet
	trie *Trie
}

// Store holds the active RuleSet and a pre-built Trie. Get/Replace/Trie are
// lock-free via atomic.Value.
type Store struct {
	v atomic.Value /* *snapshot */
}

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
		// Defensive no-op: atomic.Value rejects storing a typed-nil *snapshot,
		// and storing an untyped nil after a concrete value would panic.
		// Leave the store unchanged when called with nil.
		return
	}
	s.v.Store(&snapshot{rs: rs, trie: rs.BuildTrie()})
}
