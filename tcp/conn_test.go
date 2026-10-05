package tcp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
)

func newConfiguredConn(t *testing.T) *Conn {
	t.Helper()
	var conn Conn
	err := conn.Configure(ConnConfig{
		RxBuf:             make([]byte, 512),
		TxBuf:             make([]byte, 512),
		TxPacketQueueSize: 4,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &conn
}

func TestConn_SetDeadline_Closed(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.SetDeadline(time.Now().Add(time.Second))
	if err == nil {
		t.Fatal("SetDeadline on closed conn should fail")
	}
}

func TestConn_SetReadDeadline_Closed(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.SetReadDeadline(time.Now().Add(time.Second))
	if err == nil {
		t.Fatal("SetReadDeadline on closed conn should fail")
	}
}

func TestConn_SetWriteDeadline_Closed(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err == nil {
		t.Fatal("SetWriteDeadline on closed conn should fail")
	}
}

func TestConn_OpenActive_InvalidAddr(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.OpenActive(1234, netip.AddrPort{}, 100)
	if err == nil {
		t.Fatal("OpenActive with invalid addr should fail")
	}
}

func TestConn_OpenListen(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.OpenListen(8080, 100)
	if err != nil {
		t.Fatal(err)
	}
	if conn.State() != StateListen {
		t.Fatalf("expected StateListen, got %s", conn.State())
	}
	if conn.LocalPort() != 8080 {
		t.Fatalf("expected port 8080, got %d", conn.LocalPort())
	}
}

func TestConn_Close_Abort(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.OpenListen(8080, 100)
	if err != nil {
		t.Fatal(err)
	}
	conn.Abort()
	if conn.State() != StateClosed {
		t.Fatalf("expected StateClosed after Abort, got %s", conn.State())
	}
}

func TestConn_ReadWrite_Closed(t *testing.T) {
	conn := newConfiguredConn(t)
	_, err := conn.Write([]byte("hello"))
	if err == nil {
		t.Fatal("Write on closed conn should fail")
	}
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("Read on closed conn should fail")
	}
}

func TestConn_Flush_Closed(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.Flush()
	if err == nil {
		t.Fatal("Flush on closed conn should fail")
	}
}

func TestConn_BufferedUnsent(t *testing.T) {
	conn := newConfiguredConn(t)
	if conn.BufferedUnsent() != 0 {
		t.Fatalf("expected 0, got %d", conn.BufferedUnsent())
	}
}

func TestConn_InternalHandler(t *testing.T) {
	conn := newConfiguredConn(t)
	h := conn.InternalHandler()
	if h == nil {
		t.Fatal("InternalHandler returned nil")
	}
}

func TestConn_Configure_Twice(t *testing.T) {
	conn := newConfiguredConn(t)
	err := conn.Configure(ConnConfig{
		RxBuf:             make([]byte, 1024),
		TxBuf:             make([]byte, 1024),
		TxPacketQueueSize: 8,
		RWBackoff:         backoffYield,
	})
	if err != nil {
		t.Fatalf("reconfigure should succeed: %v", err)
	}
}

func TestConn_OpenActive_IPv6(t *testing.T) {
	conn := newConfiguredConn(t)
	addr6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	remote := netip.AddrPortFrom(addr6, 443)
	err := conn.OpenActive(1234, remote, 200)
	if err != nil {
		t.Fatal(err)
	}
	raddr := conn.RemoteAddr()
	if len(raddr) != 16 {
		t.Fatalf("expected 16-byte remote addr, got %d", len(raddr))
	}
}

func TestConn_Protocol(t *testing.T) {
	var conn Conn
	if conn.Protocol() != 6 { // TCP protocol number
		t.Fatalf("expected protocol 6, got %d", conn.Protocol())
	}
}

func TestConn_ImplementsNetConn(t *testing.T) {
	conn := newConfiguredConn(t)
	var _ interface {
		SetDeadline(time.Time) error
		SetReadDeadline(time.Time) error
		SetWriteDeadline(time.Time) error
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	} = conn
	_ = net.ErrClosed
}

// A Pinned handle must not operate on the connection its Conn is reopened for.
func TestConn_PinnedStaleAfterReopen(t *testing.T) {
	conn := newConfiguredConn(t)
	raddrOld := netip.MustParseAddrPort("10.0.0.1:80")
	if err := conn.OpenActive(1234, raddrOld, 100); err != nil {
		t.Fatal(err)
	}
	stale := conn.Pin()
	if got := stale.RemoteAddrPort(); got != raddrOld {
		t.Fatalf("pinned RemoteAddrPort=%v, want %v", got, raddrOld)
	}
	conn.Abort()
	// Reopen in LISTEN, which is not a closed state: stale handle must fail on connection ID alone.
	if err := conn.OpenListen(1235, 200); err != nil {
		t.Fatal(err)
	}

	var buf [8]byte
	deadline := time.Now().Add(time.Hour)
	for name, fn := range map[string]func() error{
		"Write":            func() error { _, err := stale.Write([]byte("x")); return err },
		"Read":             func() error { _, err := stale.Read(buf[:]); return err },
		"Flush":            stale.Flush,
		"CloseRead":        stale.CloseRead,
		"Close":            stale.Close,
		"SetDeadline":      func() error { return stale.SetDeadline(deadline) },
		"SetReadDeadline":  func() error { return stale.SetReadDeadline(deadline) },
		"SetWriteDeadline": func() error { return stale.SetWriteDeadline(deadline) },
	} {
		if err := fn(); err != net.ErrClosed {
			t.Errorf("stale %s: got err %v, want net.ErrClosed", name, err)
		}
	}
	if got := stale.LocalPort(); got != 0 {
		t.Errorf("stale LocalPort=%d, want 0", got)
	}
	if got := stale.RemoteAddrPort(); got.IsValid() {
		t.Errorf("stale RemoteAddrPort=%v, want zero value", got)
	}

	// New connection is untouched by the stale handle.
	if st := conn.State(); st != StateListen {
		t.Fatalf("new connection state %s, want %s", st, StateListen)
	}
	fresh := conn.Pin()
	if err := fresh.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := fresh.LocalPort(); got != 1235 {
		t.Errorf("fresh LocalPort=%d, want 1235", got)
	}
}

func backoffYield(consecutiveBackoffs uint) time.Duration {
	return lneto.BackoffFlagGosched
}
