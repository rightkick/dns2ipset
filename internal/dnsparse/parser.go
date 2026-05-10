package dnsparse

import (
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type Record struct {
	Name   string // lowercase, no trailing dot
	Family int    // 4 or 6
	IP     net.IP
	TTL    uint32
}

type Response struct {
	TxID    uint16
	QName   string
	QType   uint16
	Records []Record
}

var (
	ErrNotResponse = errors.New("not a DNS response")
	ErrBadRcode    = errors.New("non-NOERROR rcode")
	ErrNoUsable    = errors.New("no usable A/AAAA records")
)

func Parse(b []byte) (*Response, error) {
	var m dns.Msg
	if err := m.Unpack(b); err != nil {
		return nil, err
	}
	if !m.Response {
		return nil, ErrNotResponse
	}
	if m.Rcode != dns.RcodeSuccess {
		return nil, ErrBadRcode
	}
	if len(m.Answer) == 0 {
		return nil, ErrNoUsable
	}
	r := &Response{TxID: m.Id}
	if len(m.Question) > 0 {
		r.QName = normalize(m.Question[0].Name)
		r.QType = m.Question[0].Qtype
	}

	// First pass: collect CNAME mappings and A/AAAA records
	cnames := make(map[string]string) // owner -> target
	var addrs []Record

	for _, rr := range m.Answer {
		owner := normalize(rr.Header().Name)
		switch v := rr.(type) {
		case *dns.A:
			addrs = append(addrs, Record{
				Name: owner, Family: 4, IP: v.A.To4(), TTL: rr.Header().Ttl,
			})
		case *dns.AAAA:
			addrs = append(addrs, Record{
				Name: owner, Family: 6, IP: v.AAAA.To16(), TTL: rr.Header().Ttl,
			})
		case *dns.CNAME:
			cnames[owner] = normalize(v.Target)
		}
	}

	// Add all address records
	r.Records = append(r.Records, addrs...)

	// Second pass: for each CNAME owner, mirror every A/AAAA record whose
	// owner matches the CNAME's target. CDNs often return multiple A records
	// per name, so iterate the full set rather than stopping at the first.
	for cnameOwner, cnameTarget := range cnames {
		for _, rec := range addrs {
			if rec.Name == cnameTarget {
				r.Records = append(r.Records, Record{
					Name: cnameOwner, Family: rec.Family, IP: rec.IP, TTL: rec.TTL,
				})
			}
		}
	}

	if len(r.Records) == 0 {
		return nil, ErrNoUsable
	}
	return r, nil
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}
