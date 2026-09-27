package sshauto

import (
	"bytes"
	"errors"
	"fmt"
	"go/build"
	"io"
	"strings"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/sshraw"
)

// TestNoCryptoImports guards against linking Go's crypto packages, whose init
// functions carry FIPS self-tests TinyGo cannot eliminate.
func TestNoCryptoImports(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if imp == "crypto" || strings.HasPrefix(imp, "crypto/") {
			t.Errorf("sshauto must not import %q; take the primitive from the caller instead", imp)
		}
	}
}

// msg encodes a payload of type typ whose fields are written by fields.
func msg(typ sshraw.MsgType, fields func(e *sshraw.Encoder)) []byte {
	var e sshraw.Encoder
	buf := make([]byte, 256)
	e.Reset(buf, 0)
	e.Uint8(uint8(typ))
	if fields != nil {
		fields(&e)
	}
	if e.Err() != nil {
		panic(e.Err())
	}
	return buf[:e.Len()]
}

// serve opens a server Transport on sconn and runs client in a goroutine. It
// returns the transport, a function that reports the server error along with
// the client's and ends the test, and the client's result channel.
func serve(t *testing.T, client func(c *testClient) error, tweak func(c *testClient)) (*Transport, func(string, error), chan error) {
	t.Helper()
	hk := newHostKey()
	cconn, sconn := tcpPair(t)
	srv := new(Transport)
	if err := srv.Configure(testConfig(hk)); err != nil {
		t.Fatal("configure:", err)
	} else if err = srv.Open(sconn, false); err != nil {
		t.Fatal("open:", err)
	}
	c := newTestClient(cconn, hk)
	if tweak != nil {
		tweak(c)
	}
	clientErr := make(chan error, 1)
	go func() {
		err := client(c)
		if err != nil {
			cconn.Close() // Unblock the server.
		}
		clientErr <- err
	}()
	fatal := func(what string, err error) {
		t.Helper()
		sconn.Close()
		t.Fatalf("server %s: %v; client: %v", what, err, <-clientErr)
	}
	return srv, fatal, clientErr
}

// TestTransportRoundTrip runs a handshake, packets both ways, a client
// started rekey and a disconnect, with and without strict key exchange.
func TestTransportRoundTrip(t *testing.T) {
	for _, strict := range []bool{true, false} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) { testRoundTrip(t, strict) })
	}
}

func testRoundTrip(t *testing.T, strict bool) {
	serviceRequest := msg(sshraw.MsgServiceRequest, func(e *sshraw.Encoder) { e.Str(sshraw.ServiceUserauth) })
	serviceAccept := msg(sshraw.MsgServiceAccept, func(e *sshraw.Encoder) { e.Str(sshraw.ServiceUserauth) })
	sid := make(chan []byte, 1)
	srv, fatal, clientErr := serve(t, func(c *testClient) error {
		if err := c.handshake(); err != nil {
			return err
		}
		sid <- append([]byte{}, c.ks.SessionID()...)
		// Strict key exchange restarts sequence numbers after NEWKEYS, which
		// the server's SSH_MSG_UNIMPLEMENTED reports back.
		wantSeq := c.out.Seq()
		if strict != (wantSeq == 0) {
			return fmt.Errorf("client seq=%d after NEWKEYS with strict=%v", wantSeq, strict)
		} else if err := c.writePacket([]byte{200, 'h', 'i'}); err != nil {
			return err
		}
		p, err := c.readPacket()
		if err != nil {
			return err
		} else if seq, err := sshraw.ParseUnimplemented(p); err != nil || seq != wantSeq {
			return fmt.Errorf("UNIMPLEMENTED seq=%d %v, want %d", seq, err, wantSeq)
		}
		if err = c.writePacket(serviceRequest); err != nil {
			return err
		} else if p, err = c.readPacket(); err != nil {
			return err
		} else if !bytes.Equal(p, serviceAccept) {
			return fmt.Errorf("got %x, want SERVICE_ACCEPT", p)
		}
		if err = c.kex(); err != nil { // Rekey.
			return fmt.Errorf("rekey: %w", err)
		} else if err = c.writePacket([]byte{201, 'x'}); err != nil {
			return err
		} else if p, err = c.readPacket(); err != nil {
			return err
		} else if !bytes.Equal(p, []byte{201, 'y'}) {
			return fmt.Errorf("got %x after rekey", p)
		}
		return c.writePacket(msg(sshraw.MsgDisconnect, func(e *sshraw.Encoder) {
			e.Uint32(uint32(sshraw.DisconnectByApplication))
			e.Str("bye")
			e.Str("")
		}))
	}, func(c *testClient) {
		if !strict {
			c.kexList = sshraw.KexCurve25519SHA256
		}
	})

	if err := srv.Handshake(); err != nil {
		fatal("handshake", err)
	}
	select {
	case got := <-sid:
		if !bytes.Equal(got, srv.SessionID()) {
			t.Fatalf("session id=%x, client has %x", srv.SessionID(), got)
		}
	case err := <-clientErr:
		t.Fatal("client:", err)
	}
	kex, hostKey, cin, cout := srv.Algorithms()
	if kex != sshraw.KexCurve25519SHA256 || hostKey != sshraw.HostKeyEd25519 || cin != sshraw.CipherAES256GCM || cout != cin {
		t.Errorf("algorithms %q %q %q %q", kex, hostKey, cin, cout)
	}

	p, err := srv.ReadPacket()
	if err != nil {
		fatal("read", err)
	} else if !bytes.Equal(p, []byte{200, 'h', 'i'}) {
		t.Fatalf("got %x", p)
	} else if err = srv.WriteUnimplemented(); err != nil {
		fatal("unimplemented", err)
	}
	if p, err = srv.ReadPacket(); err != nil {
		fatal("read", err)
	} else if !bytes.Equal(p, serviceRequest) {
		t.Fatalf("got %x, want SERVICE_REQUEST", p)
	} else if err = srv.WritePacket(serviceAccept); err != nil {
		fatal("write", err)
	}
	sid0 := append([]byte{}, srv.SessionID()...)
	if p, err = srv.ReadPacket(); err != nil { // The client's rekey runs within.
		fatal("read across rekey", err)
	} else if !bytes.Equal(p, []byte{201, 'x'}) {
		t.Fatalf("got %x after rekey", p)
	} else if !bytes.Equal(srv.SessionID(), sid0) {
		t.Fatal("rekey changed the session id")
	}
	// Messages the transport owns are refused without failing the connection.
	for _, typ := range []sshraw.MsgType{0, sshraw.MsgDisconnect, sshraw.MsgKexInit, sshraw.MsgNewKeys, sshraw.MsgKexECDHReply} {
		if err = srv.WritePacket([]byte{byte(typ)}); !errors.Is(err, lneto.ErrInvalidField) {
			t.Errorf("WritePacket(%v) err=%v, want %v", typ, err, lneto.ErrInvalidField)
		}
	}
	if err = srv.WritePacket([]byte{201, 'y'}); err != nil {
		fatal("write after rekey", err)
	}
	_, err = srv.ReadPacket()
	var pd PeerDisconnectError
	if !errors.As(err, &pd) || sshraw.DisconnectReason(pd) != sshraw.DisconnectByApplication {
		fatal("read disconnect", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatal("client:", err)
	}
	if len(srv.SessionID()) != 0 {
		t.Error("session id kept after disconnect")
	}
}

// TestTransportStrictFirstPacket checks strict key exchange refuses anything
// before the client's KEXINIT, which the Terrapin attack relies on, while a
// client without it may send IGNORE first.
func TestTransportStrictFirstPacket(t *testing.T) {
	for _, strict := range []bool{true, false} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			srv, fatal, clientErr := serve(t, func(c *testClient) error {
				if err := c.ident(); err != nil {
					return err
				} else if err = c.writePacket(msg(sshraw.MsgIgnore, func(e *sshraw.Encoder) { e.Str("") })); err != nil {
					return err
				}
				return c.kex()
			}, func(c *testClient) {
				if !strict {
					c.kexList = sshraw.KexCurve25519SHA256
				}
			})
			err := srv.Handshake()
			if !strict {
				if err != nil {
					fatal("handshake", err)
				} else if err = <-clientErr; err != nil {
					t.Fatal("client:", err)
				}
				return
			}
			var d DisconnectError
			if !errors.As(err, &d) || sshraw.DisconnectReason(d) != sshraw.DisconnectProtocolError {
				fatal("handshake", err)
			}
			if err = <-clientErr; err == nil {
				t.Fatal("client completed a key exchange the server refused")
			}
		})
	}
}

// TestTransportStrictIgnoreInKex checks strict key exchange refuses IGNORE
// between KEXINIT and NEWKEYS of the first key exchange.
func TestTransportStrictIgnoreInKex(t *testing.T) {
	for _, strict := range []bool{true, false} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			srv, fatal, clientErr := serve(t, func(c *testClient) error { return c.handshake() }, func(c *testClient) {
				if !strict {
					c.kexList = sshraw.KexCurve25519SHA256
				}
				c.guess = func(c *testClient) error { // Right after KEXINIT.
					return c.writePacket(msg(sshraw.MsgIgnore, func(e *sshraw.Encoder) { e.Str("") }))
				}
			})
			err := srv.Handshake()
			var d DisconnectError
			if !strict && err != nil {
				fatal("handshake", err)
			} else if strict && (!errors.As(err, &d) || sshraw.DisconnectReason(d) != sshraw.DisconnectProtocolError) {
				fatal("handshake", err)
			}
			if err = <-clientErr; (err == nil) != !strict {
				t.Fatalf("client err=%v with strict=%v", err, strict)
			}
		})
	}
}

// TestTransportWrongGuess checks a key exchange packet sent on a wrong guess
// of the method is ignored, RFC 4253 7.
func TestTransportWrongGuess(t *testing.T) {
	srv, fatal, clientErr := serve(t, func(c *testClient) error { return c.handshake() }, func(c *testClient) {
		c.kexList = sshraw.KexECDHP256 + "," + sshraw.KexCurve25519SHA256
		c.follows = true
		c.guess = func(c *testClient) error {
			// An ecdh-sha2-nistp256 share would be 65 bytes; the server must not read it.
			return c.writePacket(append([]byte{byte(sshraw.MsgKexECDHInit), 0, 0, 0, 65}, make([]byte, 65)...))
		}
	})
	if err := srv.Handshake(); err != nil {
		fatal("handshake", err)
	} else if err = <-clientErr; err != nil {
		t.Fatal("client:", err)
	}
}

func TestTransportNoCommonAlgorithm(t *testing.T) {
	srv, fatal, clientErr := serve(t, func(c *testClient) error { return c.handshake() }, func(c *testClient) {
		c.cipher = "aes128-ctr"
	})
	var d DisconnectError
	if err := srv.Handshake(); !errors.As(err, &d) || sshraw.DisconnectReason(d) != sshraw.DisconnectKeyExchangeFailed {
		fatal("handshake", err)
	}
	if err := <-clientErr; err == nil || !strings.Contains(err.Error(), "SSH_MSG_DISCONNECT") {
		t.Errorf("client err=%v, want it to have read SSH_MSG_DISCONNECT", err)
	}
}

// TestTransportTruncated checks the stream ending at a packet boundary reads
// as io.EOF and mid packet as io.ErrUnexpectedEOF.
func TestTransportTruncated(t *testing.T) {
	for _, mid := range []bool{false, true} {
		t.Run(fmt.Sprintf("mid=%v", mid), func(t *testing.T) {
			srv, fatal, clientErr := serve(t, func(c *testClient) error {
				if err := c.handshake(); err != nil {
					return err
				}
				if mid {
					c.conn.Write([]byte{0, 0, 0, 32, 1, 2, 3})
				}
				return c.conn.Close()
			}, nil)
			if err := srv.Handshake(); err != nil {
				fatal("handshake", err)
			}
			want := io.EOF
			if mid {
				want = io.ErrUnexpectedEOF
			}
			if _, err := srv.ReadPacket(); err != want {
				fatal("read", fmt.Errorf("err=%v, want %v", err, want))
			} else if err = <-clientErr; err != nil {
				t.Fatal("client:", err)
			}
		})
	}
}

// TestTransportAllocs checks packets in steady state do not allocate, against
// a client echoing every packet back.
func TestTransportAllocs(t *testing.T) {
	const runs = 20
	srv, fatal, clientErr := serve(t, func(c *testClient) error {
		if err := c.handshake(); err != nil {
			return err
		}
		for range runs + 1 { // AllocsPerRun runs the function once more to warm up.
			p, err := c.readPacket()
			if err != nil {
				return err
			} else if err = c.writePacket(p); err != nil {
				return err
			}
		}
		return nil
	}, nil)
	if err := srv.Handshake(); err != nil {
		fatal("handshake", err)
	}
	payload := append([]byte{200}, bytes.Repeat([]byte{'z'}, 1000)...)
	var err error
	allocs := testing.AllocsPerRun(runs, func() {
		if err == nil {
			err = srv.WritePacket(payload)
		}
		if err == nil {
			_, err = srv.ReadPacket()
		}
	})
	if err != nil {
		fatal("echo", err)
	} else if err = <-clientErr; err != nil {
		t.Fatal("client:", err)
	} else if allocs != 0 {
		t.Errorf("WritePacket+ReadPacket allocs=%v, want 0", allocs)
	}
}

func TestConfigureInvalid(t *testing.T) {
	hk := newHostKey()
	for _, tc := range []struct {
		name  string
		tweak func(*Config)
	}{
		{"no rand", func(c *Config) { c.Rand = nil }},
		{"no software", func(c *Config) { c.Software = "" }},
		{"software with space", func(c *Config) { c.Software = "a b" }},
		{"no kex", func(c *Config) { c.KeyExchanges = nil }},
		{"no cipher", func(c *Config) { c.Ciphers = nil }},
		{"no host key", func(c *Config) { c.HostKeys = nil }},
		{"nil host key", func(c *Config) { c.HostKeys = []HostKey{nil} }},
		{"kex name list", func(c *Config) { c.KeyExchanges[0].Name = "a,b" }},
		{"kex pseudo name", func(c *Config) { c.KeyExchanges[0].Name = sshraw.KexStrictServer }},
		{"kex no exchanger", func(c *Config) { c.KeyExchanges[0].NewExchanger = nil }},
		{"kex no hash", func(c *Config) { c.KeyExchanges[0].NewHash = nil }},
		{"kex long share", func(c *Config) { c.KeyExchanges[0].ClientShareLen = maxKeyShare + 1 }},
		{"kex long secret", func(c *Config) { c.KeyExchanges[0].SharedLen = maxShared + 1 }},
		{"cipher long key", func(c *Config) { c.Ciphers[0].KeyLen = maxKeyLen + 1 }},
		{"cipher no aead", func(c *Config) { c.Ciphers[0].NewAEAD = nil }},
		{"cipher empty name", func(c *Config) { c.Ciphers[0].Name = "" }},
	} {
		cfg := testConfig(hk)
		tc.tweak(&cfg)
		var tr Transport
		if err := tr.Configure(cfg); !errors.Is(err, lneto.ErrInvalidConfig) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, lneto.ErrInvalidConfig)
		}
	}
}

func TestTransportStates(t *testing.T) {
	var tr Transport
	_, sconn := tcpPair(t)
	if err := tr.Open(sconn, false); !errors.Is(err, lneto.ErrBadState) {
		t.Errorf("Open before Configure err=%v, want %v", err, lneto.ErrBadState)
	} else if _, err = tr.ReadPacket(); !errors.Is(err, lneto.ErrBadState) {
		t.Errorf("ReadPacket before Open err=%v, want %v", err, lneto.ErrBadState)
	}
	if err := tr.Configure(testConfig(newHostKey())); err != nil {
		t.Fatal(err)
	} else if err = tr.Open(sconn, true); !errors.Is(err, lneto.ErrUnsupported) {
		t.Errorf("client Open err=%v, want %v", err, lneto.ErrUnsupported)
	} else if err = tr.Open(sconn, false); err != nil {
		t.Fatal(err)
	} else if err = tr.Configure(testConfig(newHostKey())); !errors.Is(err, lneto.ErrBadState) {
		t.Errorf("Configure while open err=%v, want %v", err, lneto.ErrBadState)
	}
}
