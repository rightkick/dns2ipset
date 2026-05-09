package source

import "context"

type Direction uint8

const (
	DirSend Direction = iota // udp_sendmsg (resolver -> client OR resolver -> upstream)
	DirRecv                  // udp_recvmsg (resolver receiving upstream answers)
)

// Event is one DNS UDP payload observed by the kernel side.
type Event struct {
	NanoTS    uint64
	Direction Direction
	Family    uint8 // 4 or 6 (IP family of the socket)
	SrcPort   uint16
	DstPort   uint16
	Payload   []byte
}

// Source produces Events. Run blocks until ctx is canceled or a fatal error occurs.
type Source interface {
	Run(ctx context.Context, out chan<- Event) error
	Close() error
}
