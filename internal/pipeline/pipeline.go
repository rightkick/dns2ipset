package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rightkick/dns2ipset/internal/dedup"
	"github.com/rightkick/dns2ipset/internal/dnsparse"
	"github.com/rightkick/dns2ipset/internal/ipset"
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
	Log     *slog.Logger // nil-safe: defaults to slog.Default()
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

	srcDone := make(chan error, 1)
	go func() { srcDone <- p.cfg.Source.Run(ctx, events) }()

	workerDone := make(chan struct{}, p.cfg.Workers)
	for i := 0; i < p.cfg.Workers; i++ {
		go p.worker(ctx, events, workerDone)
	}

	// Wait for source to finish (ctx done), then drain workers.
	err := <-srcDone
	close(events)
	for i := 0; i < p.cfg.Workers; i++ {
		<-workerDone
	}
	return err
}

func (p *Pipeline) worker(ctx context.Context, events <-chan source.Event, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			p.handle(ev)
		}
	}
}

func (p *Pipeline) handle(ev source.Event) {
	if p.cfg.Dedup.Seen(ev.Payload) {
		return
	}
	resp, err := dnsparse.Parse(ev.Payload)
	if err != nil {
		return
	}
	tr := p.cfg.Store.Trie()
	if tr == nil {
		return
	}
	candidates := uniqueNames(resp)
	for _, name := range candidates {
		v, ok := tr.Lookup(name)
		if !ok {
			continue
		}
		rule := v.(*rules.Rule)
		for _, rec := range resp.Records {
			set := ""
			if rec.Family == 4 {
				set = rule.IPSetV4
			} else if rec.Family == 6 {
				set = rule.IPSetV6
			}
			if set == "" {
				continue
			}
			ttl := ipset.ClampTTL(time.Duration(rec.TTL)*time.Second, p.cfg.TTLMin, p.cfg.TTLMax)
			if err := p.cfg.IPSet.Add(set, rec.IP, ttl); err != nil {
				p.cfg.Log.Debug("ipset add failed", "set", set, "ip", rec.IP, "err", err)
			}
		}
	}
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
