//go:build !tinygo && linux

package rawsock

import (
	"net"
	"runtime"
	"testing"
)

// TestAcceptConnDoesNotAllocate pins down what AcceptConn exists for. A server
// that owns its connection storage still pays an allocation per connection if
// accepting one allocates, which is what syscall.Accept does with the peer
// address it returns.
func TestAcceptConnDoesNotAllocate(t *testing.T) {
	var ln Listener
	err := ln.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	const n = 32
	dialed := make([]net.Conn, 0, n)
	defer func() {
		for _, c := range dialed {
			c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		dialed = append(dialed, c)
	}

	var conn Conn
	// The first accept warms whatever the runtime wants to warm, and is where
	// the peer address is checked: reading it hands a value to a net.Addr
	// interface, which allocates whatever the accept did.
	if err = ln.AcceptConn(&conn); err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr().String() != dialed[0].LocalAddr().String() {
		t.Errorf("accepted peer %s, dialer says %s", conn.RemoteAddr(), dialed[0].LocalAddr())
	}
	conn.Close()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 1; i < n; i++ {
		if err = ln.AcceptConn(&conn); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	runtime.ReadMemStats(&after)
	if allocs := after.Mallocs - before.Mallocs; allocs != 0 {
		t.Errorf("AcceptConn allocated %d times over %d accepts, want 0", allocs, n-1)
	}
}
