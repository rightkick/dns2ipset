package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rightkick/dns2ipset/internal/dedup"
	"github.com/rightkick/dns2ipset/internal/dnsparse"
	"github.com/rightkick/dns2ipset/internal/ipset"
	"github.com/rightkick/dns2ipset/internal/metrics"
	"github.com/rightkick/dns2ipset/internal/rules"
	"github.com/rightkick/dns2ipset/internal/source"
)

// Config holds all dependencies and tuning knobs for a Pipeline.
type Config struct {
	Workers int
	Store   *rules.Store
	Source  source.Source
	IPSet   ipset.Client
	Dedup   *dedup.Dedup
	TTLMin  time.Duration
	TTLMax  time.Duration
	Log     *slog.Logger     // nil-safe: defaults to slog.Default()
	Metrics *metrics.Metrics // nil-safe: when nil, no instrumentation
}

// Pipeline wires source events through dedup, DNS parse, trie lookup, and
// ipset.Add, using a fixed pool of worker goroutines.
type Pipeline struct{ cfg Config }

// New creates a Pipeline. Workers defaults to 1 when <= 0. Log defaults to
// slog.Default() when nil.
func New(cfg Config) *Pipeline {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Pipeline{cfg: cfg}
}

// Run starts the source and worker pool, then blocks until ctx is canceled or
// the source returns a fatal error. Workers are drained before Run returns.
func (p *Pipeline) Run(ctx context.Context) error {
	if p.cfg.Source == nil || p.cfg.IPSet == nil || p.cfg.Store == nil || p.cfg.Dedup == nil {
		return errors.New("pipeline: missing dependency")
	}
	events := make(chan source.Event, 1024)

	// Inflight gauge lives only for this Run; reading len(channel) is cheap
	// and only happens on Prometheus scrape via NewGaugeFunc.
	if m := p.m(); m != nil {
		gauge := prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "dns2ipset_pipeline_inflight",
				Help: "Current number of source events buffered between BPF reader and workers.",
			},
			func() float64 { return float64(len(events)) },
		)
		if err := m.Registry.Register(gauge); err == nil {
			defer m.Registry.Unregister(gauge)
		}
	}

	srcDone := make(chan error, 1)
	go func() { srcDone <- p.cfg.Source.Run(ctx, events) }()

	workerDone := make(chan struct{}, p.cfg.Workers)
	for i := 0; i < p.cfg.Workers; i++ {
		go p.worker(events, workerDone)
	}

	// Wait for source to finish (ctx done), then drain workers.
	err := <-srcDone
	close(events)
	for i := 0; i < p.cfg.Workers; i++ {
		<-workerDone
	}
	return err
}

func (p *Pipeline) m() *metrics.Metrics { return p.cfg.Metrics }

func (p *Pipeline) worker(events <-chan source.Event, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	// Workers exit only when the events channel is closed (which happens
	// after the source returns in Run). Watching ctx.Done() here would race
	// with channel reads on shutdown and silently drop buffered events.
	for ev := range events {
		p.handle(ev)
	}
}

func (p *Pipeline) handle(ev source.Event) {
	if m := p.m(); m != nil {
		switch ev.Direction {
		case source.DirSend:
			m.EventsTotal.WithLabelValues("send").Inc()
		case source.DirRecv:
			m.EventsTotal.WithLabelValues("recv").Inc()
		}
	}
	if p.cfg.Dedup.Seen(ev.Payload) {
		if m := p.m(); m != nil {
			m.DedupHits.Inc()
		}
		return
	}
	resp, err := dnsparse.Parse(ev.Payload)
	if err != nil {
		if m := p.m(); m != nil {
			m.ParseErrors.Inc()
		}
		return
	}
	tr := p.cfg.Store.Trie()
	if tr == nil {
		return
	}
	for _, name := range uniqueNames(resp) {
		v, ok := tr.Lookup(name)
		if !ok {
			continue
		}
		rule := v.(*rules.Rule)
		if m := p.m(); m != nil {
			m.Matches.WithLabelValues(rule.Domain).Inc()
		}
		for _, rec := range resp.Records {
			set := ""
			fam := ""
			switch rec.Family {
			case 4:
				set, fam = rule.IPSetV4, "v4"
			case 6:
				set, fam = rule.IPSetV6, "v6"
			}
			if set == "" {
				continue
			}
			ttl := ipset.ClampTTL(time.Duration(rec.TTL)*time.Second, p.cfg.TTLMin, p.cfg.TTLMax)
			if err := p.cfg.IPSet.Add(set, rec.IP, ttl); err != nil {
				if m := p.m(); m != nil {
					reason := "other"
					if isMissingErr(err) {
						reason = "missing"
					}
					m.IPSetErrors.WithLabelValues(reason).Inc()
				}
				p.cfg.Log.Debug("ipset add failed", "set", set, "ip", rec.IP, "err", err)
				continue
			}
			if m := p.m(); m != nil {
				m.IPSetWrites.WithLabelValues(set, fam).Inc()
			}
		}
	}
}

func isMissingErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "missing") || strings.Contains(s, "does not exist")
}

// uniqueNames returns the QName followed by any unique record owner names in
// the response, preserving order of first appearance.
func uniqueNames(r *dnsparse.Response) []string {
	seen := map[string]bool{r.QName: true}
	out := []string{r.QName}
	for _, rec := range r.Records {
		if !seen[rec.Name] {
			seen[rec.Name] = true
			out = append(out, rec.Name)
		}
	}
	return out
}
