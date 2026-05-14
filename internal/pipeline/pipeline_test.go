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
  - domain: example.com
    ipset_v4: ipset_example_v4
`))
	if err != nil {
		t.Fatal(err)
	}
	store.Replace(rs)

	payload := packResp(t, "www.example.com", []net.IP{net.ParseIP("1.2.3.4")}, 300)
	src := &fake.Source{Events: []source.Event{{Payload: payload}}}

	rec := &recIPSet{}
	d, _ := dedup.New(64, 100*time.Millisecond)
	p := New(Config{
		Workers: 1,
		Store:   store,
		Source:  src,
		IPSet:   rec,
		Dedup:   d,
		TTLMin:  60 * time.Second,
		TTLMax:  24 * time.Hour,
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
	if c.set != "ipset_example_v4" || !c.ip.Equal(net.ParseIP("1.2.3.4")) || c.ttl != 300*time.Second {
		t.Errorf("call mismatch: %+v", c)
	}
}

func TestPipeline_UnmatchedDomainNoOp(t *testing.T) {
	store := rules.NewStore()
	rs, _ := rules.LoadFromBytes([]byte("version: 1\nrules:\n  - {domain: example.com, ipset_v4: x}\n"))
	store.Replace(rs)

	payload := packResp(t, "unrelated.test", []net.IP{net.ParseIP("9.9.9.9")}, 30)
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
	rs, _ := rules.LoadFromBytes([]byte("version: 1\nrules:\n  - {domain: example.com, ipset_v4: x}\n"))
	store.Replace(rs)

	payload := packResp(t, "example.com", []net.IP{net.ParseIP("1.1.1.1")}, 60)
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
