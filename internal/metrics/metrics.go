package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Registry *prometheus.Registry

	EventsTotal      *prometheus.CounterVec // labels: direction
	ParseErrors      prometheus.Counter
	DedupHits        prometheus.Counter
	Matches          *prometheus.CounterVec // labels: rule
	IPSetWrites      *prometheus.CounterVec // labels: set, family
	IPSetErrors      *prometheus.CounterVec // labels: reason
	RingbufDrops     prometheus.Counter
	RulesReloadTotal *prometheus.CounterVec // labels: result
	RulesActive      prometheus.Gauge
}

func New() *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{
		Registry:         r,
		EventsTotal:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_events_total"}, []string{"direction"}),
		ParseErrors:      prometheus.NewCounter(prometheus.CounterOpts{Name: "dns2ipset_parse_errors_total"}),
		DedupHits:        prometheus.NewCounter(prometheus.CounterOpts{Name: "dns2ipset_dedup_hits_total"}),
		Matches:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_matches_total"}, []string{"rule"}),
		IPSetWrites:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_ipset_writes_total"}, []string{"set", "family"}),
		IPSetErrors:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_ipset_errors_total"}, []string{"reason"}),
		RingbufDrops:     prometheus.NewCounter(prometheus.CounterOpts{Name: "dns2ipset_ringbuf_drops_total"}),
		RulesReloadTotal: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns2ipset_rules_reload_total"}, []string{"result"}),
		RulesActive:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "dns2ipset_rules_active"}),
	}
	r.MustRegister(m.EventsTotal, m.ParseErrors, m.DedupHits, m.Matches,
		m.IPSetWrites, m.IPSetErrors, m.RingbufDrops, m.RulesReloadTotal, m.RulesActive)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
