package pipeline

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/rightkick/dns2ipset/internal/dedup"
	"github.com/rightkick/dns2ipset/internal/rules"
	"github.com/rightkick/dns2ipset/internal/source"
)

// Benchmarks call handle() directly to measure the hot path
// (dedup -> parse -> trie -> ipset.Add) without channel/goroutine overhead.
// Run: go test -bench=BenchmarkPipeline -benchmem ./internal/pipeline/

// noopIPSet absorbs Add calls with no synchronization. Bench-only.
type noopIPSet struct{}

func (noopIPSet) Add(string, net.IP, time.Duration) error { return nil }
func (noopIPSet) Close() error                            { return nil }

// packBenchResp builds a wire-format DNS response with a single A answer.
// The qname (and answer owner) is qname; IP is canned.
func packBenchResp(qname string) []byte {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	m.Response = true
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("203.0.113.1"),
	})
	b, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return b
}

// newBenchPipeline constructs a Pipeline with one rule, no metrics, and a
// noop ipset client — minimal external state for the hot-path measurement.
func newBenchPipeline(b *testing.B, ruleDomain string) *Pipeline {
	b.Helper()
	store := rules.NewStore()
	rs, err := rules.LoadFromBytes([]byte("version: 1\nrules:\n  - {domain: " + ruleDomain + ", ipset_v4: bench_v4}\n"))
	if err != nil {
		b.Fatal(err)
	}
	store.Replace(rs)
	d, err := dedup.New(4096, 200*time.Millisecond)
	if err != nil {
		b.Fatal(err)
	}
	return New(Config{
		Workers: 1,
		Store:   store,
		IPSet:   noopIPSet{},
		Dedup:   d,
		TTLMin:  60 * time.Second,
		TTLMax:  24 * time.Hour,
	})
}

// BenchmarkPipeline_Match measures the cost of a response that matches a
// rule and dispatches one ipset.Add call. The first 2 bytes of each payload
// are mutated each iteration so the dedup hash is unique — otherwise every
// call after the first hits the dedup fast path and we measure the wrong
// thing.
func BenchmarkPipeline_Match(b *testing.B) {
	p := newBenchPipeline(b, "facebook.com")
	base := packBenchResp("www.facebook.com")
	payload := make([]byte, len(base))

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(payload, base)
		// Mutate the DNS transaction ID (offset 0,1) to defeat dedup.
		payload[0] = byte(i)
		payload[1] = byte(i >> 8)
		p.handle(source.Event{Payload: payload, Direction: source.DirRecv})
	}
}

// BenchmarkPipeline_NoMatch is the same shape but the qname misses the trie.
// Exercises dedup + parse + trie miss; skips the ipset dispatch path.
func BenchmarkPipeline_NoMatch(b *testing.B) {
	p := newBenchPipeline(b, "facebook.com")
	base := packBenchResp("example.org")
	payload := make([]byte, len(base))

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(payload, base)
		payload[0] = byte(i)
		payload[1] = byte(i >> 8)
		p.handle(source.Event{Payload: payload, Direction: source.DirRecv})
	}
}

// BenchmarkPipeline_DedupHit is the degenerate case where every event is a
// dedup hit (same payload). Should be the fastest of the three — measures
// just the FNV hash + LRU lookup + early return.
func BenchmarkPipeline_DedupHit(b *testing.B) {
	p := newBenchPipeline(b, "facebook.com")
	payload := packBenchResp("www.facebook.com")
	// Prime the dedup so the first call is a hit too.
	p.handle(source.Event{Payload: payload, Direction: source.DirRecv})

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.handle(source.Event{Payload: payload, Direction: source.DirRecv})
	}
}
