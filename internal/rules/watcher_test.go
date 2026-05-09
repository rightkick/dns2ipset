package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", d)
}

func TestWatcher_AtomicRenameTriggersReload(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rules.yaml")

	first := `
version: 1
rules:
  - domain: a.com
    ipset_v4: a4
`
	if err := os.WriteFile(target, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore()
	rs, err := Load(target)
	if err != nil {
		t.Fatal(err)
	}
	store.Replace(rs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := NewWatcher(target, func(path string) {
		rs, err := Load(path)
		if err != nil {
			return
		}
		store.Replace(rs)
	})
	if err != nil {
		t.Fatal(err)
	}
	go w.Run(ctx)
	defer w.Close()

	// Atomic rename: write tmp + os.Rename.
	second := `
version: 1
rules:
  - domain: b.com
    ipset_v4: b4
`
	tmp := filepath.Join(dir, "rules.yaml.tmp")
	if err := os.WriteFile(tmp, []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool {
		cur := store.Get()
		return cur != nil && len(cur.Rules) == 1 && cur.Rules[0].Domain == "b.com"
	})
}

func TestWatcher_InPlaceWriteTriggersReload(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rules.yaml")

	if err := os.WriteFile(target, []byte("version: 1\nrules:\n  - {domain: a.com, ipset_v4: a}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore()
	rs, _ := Load(target)
	store.Replace(rs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := NewWatcher(target, func(path string) {
		if rs, err := Load(path); err == nil {
			store.Replace(rs)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	go w.Run(ctx)
	defer w.Close()

	// In-place rewrite (no rename).
	if err := os.WriteFile(target, []byte("version: 1\nrules:\n  - {domain: c.com, ipset_v4: c}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 2*time.Second, func() bool {
		cur := store.Get()
		return cur != nil && cur.Rules[0].Domain == "c.com"
	})
}
