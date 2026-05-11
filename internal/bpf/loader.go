package bpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/rightkick/dns2ipset/internal/metrics"
	"github.com/rightkick/dns2ipset/internal/source"
)

// Mirror of `struct event` in dns2ipset.bpf.c. Field offsets must match exactly.
// C layout: ts_ns(8) direction(1) family(1) src_port(2) dst_port(2) payload_len(2) payload[4096]
// Total header = 16 bytes; payload starts at offset 16. Go natural alignment matches: do
// NOT add padding here — uint8/uint8/uint16/uint16/uint16 packs to offset 16 with no gap.
type rawEvent struct {
	TsNs       uint64
	Direction  uint8
	Family     uint8
	SrcPort    uint16
	DstPort    uint16
	PayloadLen uint16
	Payload    [4096]byte
}

// Compile-time assertion of the layout.
const _rawEventHeaderSize = 16

var _ = [1]struct{}{}[unsafe.Sizeof(rawEvent{})-4096-_rawEventHeaderSize]

// Loader attaches BPF programs and reads events from the ring buffer.
type Loader struct {
	objs  BpfObjects
	links []link.Link
	rd    *ringbuf.Reader
	// metrics is reserved for future drop accounting. cilium/ebpf v0.21's
	// ringbuf.Record exposes no per-record loss count (that's a perf-buffer
	// concept), so dns2ipset_ringbuf_drops_total currently never increments
	// from this loader. Drops, when wired, will route through this field.
	metrics *metrics.Metrics
}

// New loads BPF objects, attaches fentry programs, and opens the ring buffer reader.
func New(m *metrics.Metrics) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}
	var objs BpfObjects
	if err := LoadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	send, err := link.AttachTracing(link.TracingOptions{Program: objs.UdpSendmsgEntry})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach udp_sendmsg: %w", err)
	}
	recv, err := link.AttachTracing(link.TracingOptions{Program: objs.UdpRecvmsgEntry})
	if err != nil {
		send.Close()
		objs.Close()
		return nil, fmt.Errorf("attach udp_recvmsg: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		send.Close()
		recv.Close()
		objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return &Loader{
		objs:    objs,
		links:   []link.Link{send, recv},
		rd:      rd,
		metrics: m,
	}, nil
}

// Run reads events from the ring buffer and sends them on out until ctx is canceled.
func (l *Loader) Run(ctx context.Context, out chan<- source.Event) error {
	go func() {
		<-ctx.Done()
		_ = l.rd.Close() // unblocks Read
	}()

	for {
		rec, err := l.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		ev, ok := decode(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case out <- ev:
		}
	}
}

// Close releases all BPF resources.
func (l *Loader) Close() error {
	if l.rd != nil {
		_ = l.rd.Close()
	}
	for _, lk := range l.links {
		_ = lk.Close()
	}
	l.objs.Close()
	return nil
}

func decode(b []byte) (source.Event, bool) {
	const headerSize = int(unsafe.Sizeof(rawEvent{})) - 4096
	if len(b) < headerSize {
		return source.Event{}, false
	}
	// Safe: rawEvent layout is fixed by the BPF C struct above.
	e := (*rawEvent)(unsafe.Pointer(&b[0]))
	plen := int(e.PayloadLen)
	if plen < 0 || plen > len(e.Payload) {
		return source.Event{}, false
	}
	payload := make([]byte, plen)
	copy(payload, e.Payload[:plen])
	return source.Event{
		NanoTS:    e.TsNs,
		Direction: source.Direction(e.Direction),
		Family:    e.Family,
		SrcPort:   e.SrcPort,
		DstPort:   e.DstPort,
		Payload:   payload,
	}, true
}

// Compile-time check that endian quirks of bpf2go (it always uses little-endian
// `_bpfel.o` on amd64/arm64) match the host.
var _ = binary.LittleEndian

// Compile-time check that *Loader satisfies source.Source.
var _ source.Source = (*Loader)(nil)
