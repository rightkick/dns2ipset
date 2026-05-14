package dnsparse

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func buildResp(t *testing.T, qname string, qtype uint16, answers []dns.RR, rcode int) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.Response = true
	m.Rcode = rcode
	m.Answer = answers
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse_ARecord(t *testing.T) {
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")}
	b := buildResp(t, "example.com", dns.TypeA, []dns.RR{a}, dns.RcodeSuccess)

	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.QName != "example.com" {
		t.Errorf("qname = %q", r.QName)
	}
	if len(r.Records) != 1 {
		t.Fatalf("len(records) = %d", len(r.Records))
	}
	rec := r.Records[0]
	if rec.Name != "example.com" || !rec.IP.Equal(net.ParseIP("1.2.3.4")) || rec.TTL != 300 || rec.Family != 4 {
		t.Errorf("record = %+v", rec)
	}
}

func TestParse_CNAMEChainProducesAllOwners(t *testing.T) {
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "star-mini.c10r.example.com."}
	a := &dns.A{Hdr: dns.RR_Header{Name: "star-mini.c10r.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("31.13.65.36")}
	b := buildResp(t, "www.example.com", dns.TypeA, []dns.RR{cname, a}, dns.RcodeSuccess)

	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, rec := range r.Records {
		got[rec.Name] = true
	}
	// QName + every owner-name in the answer chain must be available to caller.
	for _, want := range []string{"www.example.com", "star-mini.c10r.example.com"} {
		if !got[want] {
			t.Errorf("missing owner %q in records (got %v)", want, got)
		}
	}
}

func TestParse_AAAA(t *testing.T) {
	aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 90}, AAAA: net.ParseIP("2001:db8::1")}
	b := buildResp(t, "x.example", dns.TypeAAAA, []dns.RR{aaaa}, dns.RcodeSuccess)
	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Records) != 1 || r.Records[0].Family != 6 {
		t.Fatalf("got %+v", r.Records)
	}
}

func TestParse_DropsQueries(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("foo.example.", dns.TypeA)
	b, _ := m.Pack()
	if _, err := Parse(b); err == nil {
		t.Error("expected error for query (QR=0)")
	}
}

func TestParse_DropsNXDOMAIN(t *testing.T) {
	b := buildResp(t, "nope.example", dns.TypeA, nil, dns.RcodeNameError)
	if _, err := Parse(b); err == nil {
		t.Error("expected error for NXDOMAIN")
	}
}

func TestParse_DropsNoAnswers(t *testing.T) {
	b := buildResp(t, "x.example", dns.TypeA, nil, dns.RcodeSuccess)
	if _, err := Parse(b); err == nil {
		t.Error("expected error for empty answers")
	}
}

func TestParse_IgnoresNonAddrRRs(t *testing.T) {
	mx := &dns.MX{Hdr: dns.RR_Header{Name: "mail.example.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "x."}
	b := buildResp(t, "mail.example", dns.TypeMX, []dns.RR{mx}, dns.RcodeSuccess)
	if _, err := Parse(b); err == nil {
		t.Error("expected error: only MX records, none usable")
	}
}

func TestParse_CNAMEMirrorsAllTargetIPs(t *testing.T) {
	// CDN-style: CNAME owner points at a target with multiple A records.
	// All target IPs should be mirrored under the CNAME owner so a rule
	// matching the user-facing name captures every endpoint.
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "www.cdn.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge.cdn.example."}
	a1 := &dns.A{Hdr: dns.RR_Header{Name: "edge.cdn.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.1.1.1")}
	a2 := &dns.A{Hdr: dns.RR_Header{Name: "edge.cdn.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("2.2.2.2")}
	b := buildResp(t, "www.cdn.example", dns.TypeA, []dns.RR{cname, a1, a2}, dns.RcodeSuccess)

	r, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	cnameIPs := map[string]bool{}
	for _, rec := range r.Records {
		if rec.Name == "www.cdn.example" {
			cnameIPs[rec.IP.String()] = true
		}
	}
	if !cnameIPs["1.1.1.1"] || !cnameIPs["2.2.2.2"] {
		t.Errorf("CNAME owner missing IPs: got %v, want both 1.1.1.1 and 2.2.2.2", cnameIPs)
	}
}
