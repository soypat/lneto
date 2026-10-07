//go:build !tinygo && (linux || darwin)

package rawsock

import (
	"io"
	"net"
	"strconv"
	"testing"
)

// TestAcceptConn verifies an accepted connection reports the dialer's address
// and carries data both ways.
func TestAcceptConn(t *testing.T) {
	var l Listener
	if err := l.Listen(0); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dialed, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(l.Port()))))
	if err != nil {
		t.Fatal(err)
	}
	defer dialed.Close()
	var conn Conn
	if err := l.AcceptConn(&conn); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got, want := conn.RemoteAddr().String(), dialed.LocalAddr().String(); got != want {
		t.Errorf("RemoteAddr = %s, want %s", got, want)
	}
	if _, err := dialed.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(&conn, buf[:]); err != nil || string(buf[:]) != "ping" {
		t.Fatalf("Read = %q, %v; want ping", buf, err)
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(dialed, buf[:]); err != nil || string(buf[:]) != "pong" {
		t.Fatalf("dialer read = %q, %v; want pong", buf, err)
	}
}
