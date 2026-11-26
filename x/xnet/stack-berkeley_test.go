package xnet

import (
	"net"
	"testing"
	"time"
)

// deadlineConn records the deadlines set on it.
type deadlineConn struct {
	net.Conn
	read, write time.Time
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error  { c.read = t; return nil }
func (c *deadlineConn) SetWriteDeadline(t time.Time) error { c.write = t; return nil }
func (c *deadlineConn) Read(b []byte) (int, error)         { return 0, nil }
func (c *deadlineConn) Write(b []byte) (int, error)        { return len(b), nil }

// TestStackBerkeley_ZeroDeadlineClears checks that a zero deadline passed to
// Send and Recv clears the deadline an earlier call set.
func TestStackBerkeley_ZeroDeadlineClears(t *testing.T) {
	var s StackBerkeley
	c := &deadlineConn{}
	const fd = 3 // Descriptors 0 to 2 are reserved, see socket.isvalid.
	s.conns = append(s.conns, socket[net.Conn]{sockfd: fd, sock: c})

	soon := time.Now().Add(time.Second)
	s.Recv(fd, make([]byte, 1), 0, soon)
	s.Send(fd, []byte{1}, 0, soon)
	if !c.read.Equal(soon) || !c.write.Equal(soon) {
		t.Fatalf("deadlines not set: read %v write %v", c.read, c.write)
	}
	s.Recv(fd, make([]byte, 1), 0, time.Time{})
	s.Send(fd, []byte{1}, 0, time.Time{})
	if !c.read.IsZero() || !c.write.IsZero() {
		t.Fatalf("zero deadline did not clear: read %v write %v", c.read, c.write)
	}
}

type bufferedConn struct{ deadlineConn }

func (c *bufferedConn) BufferedData() (data0, data1 []byte, err error) { return nil, nil, nil }
func (c *bufferedConn) ReadDiscard(n int) (int, error)                 { return n, nil }
func (c *bufferedConn) LinearizeInput() bool                           { return false }
func (c *bufferedConn) SizeInput() int                                 { return 0 }
func (c *bufferedConn) WaitInput(n int) error                          { return nil }

func TestStackBerkeley_BufferedReader(t *testing.T) {
	var s StackBerkeley
	const plain, buffered = 3, 4
	s.conns = append(s.conns,
		socket[net.Conn]{sockfd: plain, sock: &deadlineConn{}},
		socket[net.Conn]{sockfd: buffered, sock: &bufferedConn{}},
	)
	if _, ok := s.BufferedReader(plain); ok {
		t.Error("plain conn has no buffered reader")
	}
	if _, ok := s.BufferedReader(5); ok {
		t.Error("unknown fd has no buffered reader")
	}
	if _, ok := s.BufferedReader(buffered); !ok {
		t.Error("buffered conn not found")
	}
	var _ BufferedConn = tcpconn{}
}
