package tcp

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
)

func TestHandler_ReaderBuffered(t *testing.T) {
	client, server := newHandler(t, 1024, 3), newHandler(t, 1024, 3)
	setupClientServer(t, rand.New(rand.NewSource(1)), client, server)
	buf := make([]byte, 2048)
	establish(t, client, server, buf)
	send := func(data []byte) { t.Helper(); deliver(t, client, server, buf, data) }
	first := bytes.Repeat([]byte{'a'}, 500)
	send(first)
	d0, d1 := server.BufferedData()
	if !bytes.Equal(d0, first) || d1 != nil {
		t.Fatal("unexpected first data")
	}
	if err := server.DiscardInput(len(first)); err != nil {
		t.Fatal(err)
	}
	// The second write wraps the 1024 byte ring.
	second := make([]byte, 700)
	for i := range second {
		second[i] = byte(i)
	}
	send(second)
	d0, d1 = server.BufferedData()
	if len(d1) == 0 || !bytes.Equal(append(append([]byte{}, d0...), d1...), second) {
		t.Fatalf("want wrapped data, got len(d0)=%d len(d1)=%d", len(d0), len(d1))
	}
	server.LinearizeInput()
	d0, d1 = server.BufferedData()
	if len(d1) != 0 || !bytes.Equal(d0, second) {
		t.Fatal("LinearizeInput did not make data contiguous")
	}
	if err := server.DiscardInput(len(second)); err != nil {
		t.Fatal(err)
	} else if server.BufferedInput() != 0 {
		t.Fatal("data left after discard")
	} else if err = server.DiscardInput(1); err == nil {
		t.Fatal("discard past buffered data should fail")
	}
}

func TestConn_WaitInput(t *testing.T) {
	conn := newConfiguredConn(t)
	if err := conn.WaitInput(1); err != net.ErrClosed {
		t.Fatalf("want net.ErrClosed before open, got %v", err)
	}
	if err := conn.OpenActive(1234, netip.MustParseAddrPort("10.0.0.1:80"), 100); err != nil {
		t.Fatal(err)
	}
	if err := conn.WaitInput(513); err != lneto.ErrBufferFull {
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

	first := bytes.Repeat([]byte{'a'}, 300)
	deliver(t, client, &conn.h, buf, first)
	if err := conn.WaitInput(len(first)); err != nil {
		t.Fatal(err)
	} else if err = p.WaitInput(len(first)); err != nil {
		t.Fatal(err)
	}
	d0, d1 := conn.BufferedData()
	if !bytes.Equal(d0, first) || d1 != nil {
		t.Fatal("unexpected first data from Conn")
	}
	d0, d1 = p.BufferedData()
	if !bytes.Equal(d0, first) || d1 != nil {
		t.Fatal("unexpected first data from ConnHandle")
	}
	if err := conn.DiscardInput(len(first)); err != nil {
		t.Fatal(err)
	}

	// The second write wraps the 512 byte ring.
	second := make([]byte, 400)
	for i := range second {
		second[i] = byte(i)
	}
	deliver(t, client, &conn.h, buf, second)
	if d0, d1 = p.BufferedData(); len(d1) == 0 {
		t.Fatal("want wrapped data")
	}
	p.LinearizeInput()
	conn.LinearizeInput()
	if d0, d1 = conn.BufferedData(); len(d1) != 0 || !bytes.Equal(d0, second) {
		t.Fatal("LinearizeInput did not make data contiguous")
	}
	if err := p.DiscardInput(len(second)); err != nil {
		t.Fatal(err)
	}

	if err := conn.CloseRead(); err != nil {
		t.Fatal(err)
	} else if err = conn.WaitInput(1); err != io.EOF {
		t.Fatalf("want io.EOF after CloseRead, got %v", err)
	}

	conn.Abort()
	p.LinearizeInput()
	if d0, d1 = p.BufferedData(); d0 != nil || d1 != nil {
		t.Fatal("stale handle returned data")
	} else if err := p.DiscardInput(1); err != net.ErrClosed {
		t.Fatalf("stale DiscardInput: want net.ErrClosed, got %v", err)
	} else if err = p.WaitInput(1); err != net.ErrClosed {
		t.Fatalf("stale WaitInput: want net.ErrClosed, got %v", err)
	}
}

// deliver writes data on client and moves packets until server has it all buffered.
func deliver(t *testing.T, client, server *Handler, buf, data []byte) {
	t.Helper()
	if _, err := client.Write(data); err != nil {
		t.Fatal(err)
	}
	for server.BufferedInput() < len(data) {
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
