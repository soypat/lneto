package udp

import (
	_ "net"
	"net/netip"
	"sync"
	"time"
)

// lnetopacketconn is the lneto interpretation of
// [net.PacketConn], making use of better types.
type lnetopacketconn interface { // size=16 (0x10)
	ReadFrom(p []byte) (n int, addr netip.AddrPort, err error)
	WriteTo(p []byte, addr netip.AddrPort) (n int, err error)
	Close() error
	LocalAddr() netip.AddrPort
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// PacketConn is the tcp.Listener equivalent for UDP and
// implements the lnetopacketconn. It is thread safe.
type PacketConn struct {
	mu sync.Mutex
	m  muxHandler

	// deadlines, localaddr, close handling state.
}
