package tcp

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
)

func TestConn_WaitInput(t *testing.T) {
	conn := newConfiguredConn(t)
	if err := conn.WaitInput(1); err != net.ErrClosed {
		t.Fatalf("want net.ErrClosed before open, got %v", err)
	}
	if err := conn.OpenActive(1234, netip.MustParseAddrPort("10.0.0.1:80"), 100); err != nil {
		t.Fatal(err)
	}
	if err := conn.WaitInput(conn.SizeInput() + 1); err != lneto.ErrBufferFull {
		t.Fatalf("want ErrBufferFull, got %v", err)
	} else if err = conn.WaitInput(0); err != nil {
		t.Fatalf("want nil for zero bytes, got %v", err)
	} else if err = conn.WaitInput(1); err != io.EOF {
		t.Fatalf("want io.EOF before established, got %v", err)
	}
	conn.h.scb._state = StateEstablished
	conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	if err := conn.WaitInput(1); err != errDeadlineExceeded {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestConn_ReaderBuffered(t *testing.T) {
	conn := newConfiguredConn(t)
	if err := conn.OpenListen(80, 100); err != nil {
		t.Fatal(err)
	}
	client := newHandler(t, 512, 3)
	if err := client.OpenActive(1234, conn.h.LocalPort(), 300); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	establish(t, client, &conn.h, buf)
	p := conn.HandleWith(nil)
	if p.SizeInput() != conn.h.SizeInput() {
		t.Fatalf("SizeInput=%d, want %d", p.SizeInput(), conn.h.SizeInput())
	}

	first := bytes.Repeat([]byte{'a'}, 300)
	deliver(t, client, &conn.h, buf, first)
	if err := conn.WaitInput(len(first)); err != nil {
		t.Fatal(err)
	} else if err = p.WaitInput(len(first)); err != nil {
		t.Fatal(err)
	}
	d0, d1, err := conn.BufferedData()
	if err != nil || !bytes.Equal(d0, first) || d1 != nil {
		t.Fatal("unexpected first data from Conn", err)
	}
	d0, d1, err = p.BufferedData()
	if err != nil || !bytes.Equal(d0, first) || d1 != nil {
		t.Fatal("unexpected first data from ConnHandle", err)
	}
	if n, err := conn.ReadDiscard(len(first)); n != len(first) || err != nil {
		t.Fatalf("ReadDiscard=(%d,%v)", n, err)
	}

	// The second write wraps the 512 byte ring.
	second := make([]byte, 400)
	for i := range second {
		second[i] = byte(i)
	}
	deliver(t, client, &conn.h, buf, second)
	if _, d1, _ = p.BufferedData(); len(d1) == 0 {
		t.Fatal("want wrapped data")
	}
	if !p.LinearizeInput() {
		t.Fatal("LinearizeInput did not move wrapped data")
	}
	if d0, d1, _ = conn.BufferedData(); len(d1) != 0 || !bytes.Equal(d0, second) {
		t.Fatal("LinearizeInput did not make data contiguous")
	}
	if n, err := p.ReadDiscard(len(second)); n != len(second) || err != nil {
		t.Fatalf("ReadDiscard=(%d,%v)", n, err)
	}

	if err := conn.CloseRead(); err != nil {
		t.Fatal(err)
	} else if err = conn.WaitInput(1); err != io.EOF {
		t.Fatalf("want io.EOF after CloseRead, got %v", err)
	}

	conn.Abort()
	if p.LinearizeInput() {
		t.Fatal("stale handle linearized")
	} else if d0, d1, err = p.BufferedData(); d0 != nil || d1 != nil || err != net.ErrClosed {
		t.Fatalf("stale BufferedData: got %q+%q, %v", d0, d1, err)
	} else if n, err := p.ReadDiscard(1); n != 0 || err != net.ErrClosed {
		t.Fatalf("stale ReadDiscard: want 0, net.ErrClosed, got %d, %v", n, err)
	} else if err = p.WaitInput(1); err != net.ErrClosed {
		t.Fatalf("stale WaitInput: want net.ErrClosed, got %v", err)
	}
}

func TestConn_WaitInputPeerClosedPartial(t *testing.T) {
	conn := newConfiguredConn(t)
	if err := conn.OpenListen(80, 100); err != nil {
		t.Fatal(err)
	}
	client := newHandler(t, 512, 3)
	if err := client.OpenActive(1234, conn.h.LocalPort(), 300); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	establish(t, client, &conn.h, buf)
	deliver(t, client, &conn.h, buf, []byte("abc"))
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := client.Send(buf)
	if err != nil || n == 0 {
		t.Fatal("client FIN:", n, err)
	} else if err = conn.h.Recv(buf[:n]); err != nil {
		t.Fatal("server recv FIN:", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if err := conn.WaitInput(10); err != io.EOF {
		t.Fatalf("want io.EOF for partial data after FIN, got %v", err)
	}
}

// deliver writes data on client and moves packets until server has it all buffered.
func deliver(t *testing.T, client, server *Handler, buf, data []byte) {
	t.Helper()
	want := server.BufferedInput() + len(data)
	if _, err := client.Write(data); err != nil {
		t.Fatal(err)
	}
	for server.BufferedInput() < want {
		n, err := client.Send(buf)
		if err != nil {
			t.Fatal("client send:", err)
		} else if n > 0 {
			if err = server.Recv(buf[:n]); err != nil {
				t.Fatal("server recv:", err)
			}
		}
		// Ack and window updates free the client transmit buffer.
		m, err := server.Send(buf)
		if err != nil {
			t.Fatal("server ack:", err)
		} else if m > 0 {
			if err = client.Recv(buf[:m]); err != nil {
				t.Fatal("client recv ack:", err)
			}
		} else if n == 0 {
			t.Fatal("no progress")
		}
	}
}
