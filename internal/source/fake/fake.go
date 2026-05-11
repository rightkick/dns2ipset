package fake

import (
	"context"

	"github.com/rightkick/dns2ipset/internal/source"
)

// Source replays a fixed list of events then blocks until the context is done.
type Source struct {
	Events []source.Event
}

func (f *Source) Run(ctx context.Context, out chan<- source.Event) error {
	for _, e := range f.Events {
		select {
		case <-ctx.Done():
			return nil
		case out <- e:
		}
	}
	<-ctx.Done()
	return nil
}

func (f *Source) Close() error { return nil }
