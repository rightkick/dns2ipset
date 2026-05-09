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
