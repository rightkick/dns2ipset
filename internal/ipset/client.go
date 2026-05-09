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
