package tlsauto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/tlsraw"
	"github.com/soypat/lneto/internal"
)

// scriptRing makes runScript read through a ringConn of this size when not zero.
var scriptRing int

// ringConn buffers a net.Conn in a ring like a TCP receive buffer and implements lneto.ReaderBuffered.
type ringConn struct {
	net.Conn
	r          internal.Ring
	tmp        [512]byte
	linearized int
	err        error
}

func newRingConn(c net.Conn, size int) *ringConn {
	return &ringConn{Conn: c, r: internal.Ring{Buf: make([]byte, size)}}
}

func (c *ringConn) fill() error {
	if c.err != nil {
		return c.err
	}
	n, err := c.Conn.Read(c.tmp[:min(c.r.Free(), len(c.tmp))])
	if n > 0 {
		c.r.Write(c.tmp[:n])
	}
	c.err = err
	return nil
}

func (c *ringConn) Read(p []byte) (int, error) {
	for c.r.Buffered() == 0 {
		if c.err != nil {
			return 0, c.err
		}
		c.fill()
	}
	return c.r.Read(p)
}

func (c *ringConn) BufferedData() (data0, data1 []byte) { return c.r.Data() }

func (c *ringConn) LinearizeInput() {
	if _, d1 := c.r.Data(); len(d1) > 0 {
		c.linearized++
	}
	c.r.Linearize()
}

func (c *ringConn) DiscardInput(n int) error { return c.r.ReadDiscard(n) }

func (c *ringConn) WaitInput(n int) error {
	if n > c.r.Size() {
		return lneto.ErrBufferFull
	}
	for c.r.Buffered() < n {
		if err := c.fill(); err != nil {
			return err
		}
	}
	return nil
}

func TestScriptsInPlace(t *testing.T) {
	for _, size := range []int{tlsraw.MaxRecord, 1031} {
		scriptRing = size
		t.Run("Handshake", TestScriptHandshake)
		t.Run("ServerHelloErrors", TestScriptServerHelloErrors)
		t.Run("EncryptedErrors", TestScriptEncryptedErrors)
		t.Run("RecordErrors", TestScriptRecordErrors)
		t.Run("CCSDropped", TestScriptCCSDropped)
		t.Run("AfterHandshake", TestScriptAfterHandshake)
		t.Run("SuiteErrors", TestScriptSuiteErrors)
		t.Run("ClientCert", TestScriptClientCert)
		t.Run("WriteErrors", TestWriteErrors)
		t.Run("SplitMessage", TestScriptSplitMessage)
	}
	scriptRing = 0
}

func TestEchoInPlace(t *testing.T) {
	p := newPKI(t)
	for _, tc := range []struct {
		name     string
		size     int
		wantRbuf bool
		wrap     bool
	}{
		{"fits", 2 * tlsraw.MaxRecord, false, false},
		{"wraps", tlsraw.MaxRecord + 333, false, true},
		{"fallback", 1024, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, done := serve(t, p.serverConfig())
			rc := newRingConn(cs, tc.size)
			var c Conn
			if err := c.Configure(p.clientConfig(t)); err != nil {
				t.Fatal(err)
			} else if err = c.Open(rc); err != nil {
				t.Fatal(err)
			} else if c.rbuf != nil {
				t.Fatal("rbuf allocated by Open")
			} else if err = c.Handshake(); err != nil {
				t.Fatal("handshake:", err)
			}
			msg := make([]byte, 60000)
			rand.Read(msg)
			wrote := make(chan error, 1)
			go func() {
				_, err := c.Write(msg)
				wrote <- err
			}()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(&c, got); err != nil {
				t.Fatal(err)
			} else if err = <-wrote; err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(got, msg) {
				t.Fatal("echo mismatch")
			}
			if (c.rbuf != nil) != tc.wantRbuf {
				t.Fatalf("rbuf allocated %v, want %v", c.rbuf != nil, tc.wantRbuf)
			} else if tc.wrap && rc.linearized == 0 {
				t.Fatal("no record wrapped the ring")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			} else if err = <-done; err != nil {
				t.Fatal("server:", err)
			}
			for i := 0; i+32 <= len(msg); i += 32 {
				if bytes.Contains(rc.r.Buf, msg[i:i+32]) {
					t.Fatal("plaintext left in the ring after Close")
				}
			}
		})
	}
}

func TestInPlaceEOF(t *testing.T) {
	ss, cs := bufPipe()
	ss.Write([]byte{22, 3, 3})
	ss.Close()
	rc := newRingConn(cs, 1024)
	var c Conn
	c.rb = rc
	c.rw = rc
	c.cfg.MaxRecord = tlsraw.MaxPlaintext
	if _, err := c.nextRecord(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
}
