package rules

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// Watcher watches the parent directory of `path` and invokes onChange when
// the target file is replaced (atomic rename) or rewritten in place.
type Watcher struct {
	path     string
	dir      string
	target   string
	w        *fsnotify.Watcher
	onChange func(path string)
}

func NewWatcher(path string, onChange func(path string)) (*Watcher, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, target := filepath.Split(abs)
	dir = filepath.Clean(dir)

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fsnotify: %w", err)
	}
	if err := fw.Add(dir); err != nil {
		fw.Close()
		return nil, fmt.Errorf("watch %s: %w", dir, err)
	}
	return &Watcher{path: abs, dir: dir, target: target, w: fw, onChange: onChange}, nil
}

func (w *Watcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.w.Events:
			if !ok {
				return
			}
			if filepath.Base(ev.Name) != w.target {
				continue
			}
			// We care about: in-place writes (Write/Create) and atomic-rename arrivals (Rename target / Create).
			// fsnotify reports IN_MOVED_TO as Create, and IN_CLOSE_WRITE as Write on Linux.
			if ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) {
				w.onChange(w.path)
			}
		case _, ok := <-w.w.Errors:
			if !ok {
				return
			}
			// Errors are non-fatal; loop continues.
		}
	}
}

func (w *Watcher) Close() error { return w.w.Close() }
