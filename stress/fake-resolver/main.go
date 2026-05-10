// fake-resolver is a deterministic DNS server for stress-testing dns2ipset.
//
// It answers any A query with an IP from a rotating pool, and any AAAA query
// with a fixed IPv6 address. There is no recursion, no upstream, no caching:
// every query produces wire traffic, which is what dns2ipset needs.
//
// Usage:
//
//	fake-resolver --addr 127.0.0.1:53 --pool 256 --ttl 60
//
// The default pool size of 256 cycles through 203.0.113.0/24 (TEST-NET-3,
// non-routable per RFC 5737, safe for any host).
package main

import (
	"flag"
	"log"
	"net"
	"sync/atomic"

	"github.com/miekg/dns"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:53", "listen address (UDP)")
	poolSize := flag.Int("pool", 256, "number of distinct A IPs to rotate through")
	ttl := flag.Uint("ttl", 60, "TTL for returned records, in seconds")
	flag.Parse()

	// Pool of synthetic IPv4 addresses in TEST-NET-3.
	pool := make([]net.IP, *poolSize)
	for i := range pool {
		// 203.0.113.0/24, wrapping; pool > 256 just repeats but ipset.Add
		// is idempotent so that's fine.
		pool[i] = net.IPv4(203, 0, 113, byte(i&0xff))
	}
	v6 := net.ParseIP("2001:db8::1")

	var counter uint64

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				ip := pool[atomic.AddUint64(&counter, 1)%uint64(len(pool))]
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(*ttl)},
					A:   ip,
				})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(*ttl)},
					AAAA: v6,
				})
			}
		}
		// Best-effort: if the response is too large for UDP, the client will
		// retry over TCP — which dns2ipset doesn't snoop. Keep responses small
		// (single answer record) so this never happens for our test traffic.
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{Addr: *addr, Net: "udp", Handler: mux, ReusePort: true}
	log.Printf("fake-resolver listening on %s (pool=%d, ttl=%d)", *addr, *poolSize, *ttl)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("fake-resolver: %v", err)
	}
}
