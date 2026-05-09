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
