package ipset

import (
	"net"
	"testing"
	"time"
)

type recCall struct {
	set string
	ip  net.IP
	ttl time.Duration
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
