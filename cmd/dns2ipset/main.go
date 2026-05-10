package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/rightkick/dns2ipset/internal/bpf"
	"github.com/rightkick/dns2ipset/internal/dedup"
	"github.com/rightkick/dns2ipset/internal/ipset"
	"github.com/rightkick/dns2ipset/internal/metrics"
	"github.com/rightkick/dns2ipset/internal/pipeline"
	"github.com/rightkick/dns2ipset/internal/rules"
)

func main() {
	rulesPath := flag.String("rules", "/etc/dns2ipset/rules.yaml", "path to rules YAML")
	ttlMin := flag.Duration("ttl-min", 60*time.Second, "minimum ipset entry TTL")
	ttlMax := flag.Duration("ttl-max", 168*time.Hour, "maximum ipset entry TTL")
	metricsAddr := flag.String("metrics-addr", "", "host:port for /metrics (empty disables)")
	logLevel := flag.String("log-level", "info", "debug|info|warn|error")
	dedupWindow := flag.Duration("dedup-window", 200*time.Millisecond, "deduplication window")
	flag.Parse()

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	m := metrics.New()

	rs, err := rules.Load(*rulesPath)
	if err != nil {
		log.Error("initial rules load", "err", err)
		os.Exit(2)
	}
	store := rules.NewStore()
	store.Replace(rs)
	m.RulesActive.Set(float64(len(rs.Rules)))

	reload := func(p string) {
		nrs, err := rules.Load(p)
		if err != nil {
			m.RulesReloadTotal.WithLabelValues("error").Inc()
			log.Warn("rules reload failed; keeping previous", "err", err)
			return
		}
		store.Replace(nrs)
		m.RulesReloadTotal.WithLabelValues("ok").Inc()
		m.RulesActive.Set(float64(len(nrs.Rules)))
		log.Info("rules reloaded", "rules", len(nrs.Rules))
	}

	watcher, err := rules.NewWatcher(*rulesPath, reload)
	if err != nil {
		log.Error("rules watcher", "err", err)
		os.Exit(2)
	}
	defer watcher.Close()

	d, err := dedup.New(4096, *dedupWindow)
	if err != nil {
		log.Error("dedup", "err", err)
		os.Exit(2)
	}

	ipsetClient := ipset.NewNetlink(func(set string) {
		log.Warn("ipset missing", "set", set)
	})
	defer ipsetClient.Close()

	loader, err := bpf.New(m)
	if err != nil {
		log.Error("bpf load", "err", err)
		os.Exit(2)
	}
	defer loader.Close()

	pl := pipeline.New(pipeline.Config{
		Workers: runtime.GOMAXPROCS(0),
		Store:   store,
		Source:  loader,
		IPSet:   ipsetClient,
		Dedup:   d,
		TTLMin:  *ttlMin,
		TTLMax:  *ttlMax,
		Metrics: m,
		Log:     log,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// SIGHUP → force reload (independent of inotify).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reload(*rulesPath)
		}
	}()

	go watcher.Run(ctx)

	if *metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", m.Handler())
		srv := &http.Server{Addr: *metricsAddr, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
		go func() {
			log.Info("metrics listening", "addr", *metricsAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server", "err", err)
			}
		}()
		defer srv.Shutdown(context.Background())
	}

	log.Info("dns2ipset starting", "rules", *rulesPath, "rule-count", len(rs.Rules))
	if err := pl.Run(ctx); err != nil {
		log.Error("pipeline exited", "err", err)
		os.Exit(1)
	}
	log.Info("dns2ipset stopped")
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}
