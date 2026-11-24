package tlsauto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/soypat/lneto/crypto/tlsraw"
)

// TestHandlerWithoutConn drives a handshake and an echo against crypto/tls by
// moving bytes through handler.Send and handler.Recv in odd sizes. ReadBuf fits
// exactly one maximum record, so records wrap around the ring.
func TestHandlerWithoutConn(t *testing.T) {
	p := newPKI(t)
	cs, done := serve(t, p.serverConfig())
	defer cs.Close()
	cfg := p.clientConfig(t)
	cfg.ReadBuf = make([]byte, tlsraw.SizeHeaderRecord+tlsraw.MaxPlaintext+recordSlack)
	var h handler
	if err := h.Configure(cfg); err != nil {
		t.Fatal(err)
	} else if err := h.Open(); err != nil {
		t.Fatal(err)
	}
	var got []byte
	out := make([]byte, 97)
	in := make([]byte, 1500)
	plain := make([]byte, 700)
	pump := func() {
		t.Helper()
		for {
			n, err := h.Send(out)
			if err != nil {
				t.Fatal("send:", err)
			} else if n == 0 {
				return
			}
			cs.Write(out[:n])
		}
	}
	drain := func() {
		t.Helper()
		for h.HandshakeDone() {
			n, err := h.Read(plain)
			if err != nil {
				t.Fatal("read:", err)
			} else if n == 0 {
				return
			}
			got = append(got, plain[:n]...)
		}
	}
	recv := func() {
		t.Helper()
		n, err := cs.Read(in)
		if err != nil {
			t.Fatal("transport:", err)
		}
		for b := in[:n]; len(b) > 0; {
			k, err := h.Recv(b[:min(len(b), 333)])
			if err != nil {
				t.Fatal("recv:", err)
			} else if k == 0 && h.BufferedInput() == 0 {
				t.Fatal("recv made no progress")
			}
			b = b[k:]
			drain()
		}
	}

	for !h.HandshakeDone() {
		pump()
		recv()
	}
	pump()
	if h.ALPN() != "test/1" {
		t.Fatalf("ALPN %q", h.ALPN())
	}

	msg := make([]byte, 40000)
	rand.Read(msg)
	for rest := msg; len(rest) > 0; {
		n, err := h.Write(rest)
		if err != nil {
			t.Fatal("write:", err)
		}
		rest = rest[n:]
		pump()
	}
	for len(got) < len(msg) {
		recv()
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echo mismatch")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	pump()
	if err := <-done; err != nil {
		t.Fatal("server:", err)
	}
}
