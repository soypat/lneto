package tls_test

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/soypat/lneto"
	ltls "github.com/soypat/lneto/x/tls"
)

// captureClientHello drives a standard library TLS client far enough to emit
// its first flight and returns the ClientHello handshake message body.
//
// Using a real client rather than a hand-written fixture means the parser is
// exercised against genuine extension ordering, a 32-byte compatibility
// session ID and GREASE-free but otherwise realistic content. Browser captures
// arrive at Stage 6; this covers the structure in the meantime.
func captureClientHello(t *testing.T) ltls.ClientHelloFrame {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		c := tls.Client(client, &tls.Config{
			ServerName: "example.com",
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		})
		_ = c.Handshake() // will fail; we only need the first flight
	}()

	server.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buf [4096]byte
	n, err := server.Read(buf[:])
	if err != nil {
		t.Fatalf("reading ClientHello: %v", err)
	}
	rec, err := ltls.NewRecordFrame(buf[:n])
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if rec.ContentType() != ltls.ContentTypeHandshake {
		t.Fatalf("first record is %v, want handshake", rec.ContentType())
	}
	if !rec.Complete() {
		t.Fatalf("ClientHello record split across reads: have %d want %d",
			n, rec.RecordLength())
	}
	hs, err := ltls.NewHandshakeFrame(rec.Payload())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if hs.MsgType() != ltls.HandshakeTypeClientHello {
		t.Fatalf("first message is %v, want client_hello", hs.MsgType())
	}
	if !hs.Complete() {
		t.Fatal("ClientHello spans multiple records")
	}
	ch, err := ltls.NewClientHelloFrame(hs.Body())
	if err != nil {
		t.Fatalf("client hello: %v", err)
	}
	return ch
}

func TestClientHelloParseRealHello(t *testing.T) {
	ch := captureClientHello(t)

	if ch.LegacyVersion() != ltls.VersionTLS12 {
		t.Errorf("legacy_version %#04x want 0x0303", ch.LegacyVersion())
	}
	if !ch.ValidateCompression() {
		t.Errorf("legacy_compression_methods % x, want exactly {0}",
			ch.LegacyCompressionMethods())
	}
	if n := len(ch.LegacySessionID()); n != 32 {
		// A TLS 1.3 client sends a fake 32-byte session ID to trigger
		// middlebox compatibility mode. The server must echo it.
		t.Errorf("session id len %d, want 32 for middlebox compat", n)
	}

	var sawTLS13, sawX25519, sawSNI, sawALPN bool
	var suites []ltls.CipherSuite
	err := ch.ForEachExtension(func(ext ltls.ExtensionType, data []byte) error {
		switch ext {
		case ltls.ExtSupportedVersions:
			return ltls.ForEachSupportedVersion(data, func(v uint16) error {
				if v == ltls.VersionTLS13 {
					sawTLS13 = true
				}
				return nil
			})
		case ltls.ExtKeyShare:
			return ltls.ForEachKeyShare(data, func(g ltls.NamedGroup, key []byte) error {
				if g == ltls.GroupX25519 && len(key) == 32 {
					sawX25519 = true
				}
				return nil
			})
		case ltls.ExtServerName:
			return ltls.ForEachServerName(data, func(nameType uint8, name []byte) error {
				if nameType == 0 && string(name) == "example.com" {
					sawSNI = true
				}
				return nil
			})
		case ltls.ExtALPN:
			return ltls.ForEachALPNProto(data, func(p []byte) error {
				if string(p) == "http/1.1" {
					sawALPN = true
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking extensions: %v", err)
	}

	if err := ltls.ForEachU16(ch.CipherSuites(), func(v uint16) error {
		suites = append(suites, ltls.CipherSuite(v))
		return nil
	}); err != nil {
		t.Fatalf("walking cipher suites: %v", err)
	}

	if !sawTLS13 {
		t.Error("supported_versions did not offer TLS 1.3")
	}
	if !sawX25519 {
		t.Error("no 32-byte x25519 key share found")
	}
	if !sawSNI {
		t.Error("SNI host not recovered")
	}
	if !sawALPN {
		t.Error("ALPN http/1.1 not recovered")
	}
	var mandatory bool
	for _, s := range suites {
		if s == ltls.SuiteAES128GCMSHA256 {
			mandatory = true
		}
	}
	if !mandatory {
		t.Errorf("TLS_AES_128_GCM_SHA256 not offered; got %v", suites)
	}
}

func TestClientHelloRejectsDuplicateExtension(t *testing.T) {
	// Duplicating supported_versions must be caught. Tolerating it lets this
	// parser and a middlebox act on different copies.
	ch := captureClientHello(t)
	exts := ch.Extensions()

	// Find the first extension and append a verbatim copy of it.
	var first []byte
	err := ltls.ForEachExtension(exts, func(ext ltls.ExtensionType, data []byte) error {
		if first == nil {
			first = make([]byte, 4+len(data))
			copy(first, exts)
		}
		return nil
	})
	if err != nil || first == nil {
		t.Fatalf("could not isolate first extension: %v", err)
	}

	dup := make([]byte, 0, len(exts)+len(first))
	dup = append(dup, exts...)
	dup = append(dup, first...)

	body := rebuildHelloWithExtensions(t, ch, dup)
	ch2, err := ltls.NewClientHelloFrame(body)
	if err != nil {
		t.Fatalf("rebuilt hello did not parse: %v", err)
	}
	err = ch2.ForEachExtension(func(ltls.ExtensionType, []byte) error { return nil })
	if !errors.Is(err, lneto.ErrInvalidField) {
		t.Errorf("duplicate extension got %v, want ErrInvalidField", err)
	}
}

// rebuildHelloWithExtensions re-encodes ch with a replacement extensions block,
// exercising Builder against a structure produced by a real client.
func rebuildHelloWithExtensions(t *testing.T, ch ltls.ClientHelloFrame, exts []byte) []byte {
	t.Helper()
	var b ltls.Builder
	b.Reset(make([]byte, 0, len(ch.RawData())+len(exts)+64))
	b.AddU16(ch.LegacyVersion())
	b.AddBytes(ch.Random()[:])
	b.OpenU8()
	b.AddBytes(ch.LegacySessionID())
	b.Close()
	b.OpenU16()
	b.AddBytes(ch.CipherSuites())
	b.Close()
	b.OpenU8()
	b.AddBytes(ch.LegacyCompressionMethods())
	b.Close()
	b.OpenU16()
	b.AddBytes(exts)
	b.Close()
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("rebuilding hello: %v", err)
	}
	return out
}

func TestClientHelloRejectsOversizeSessionID(t *testing.T) {
	// legacy_session_id feeds a fixed [32]byte echo buffer in the server, so
	// the bound must be enforced at parse time.
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, ltls.SizeRandom)...)
	body = append(body, 33)                     // session id length, one over
	body = append(body, make([]byte, 33)...)    //
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression
	body = append(body, 0x00, 0x00)             // extensions, empty
	_, err := ltls.NewClientHelloFrame(body)
	if !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("got %v want ErrInvalidLengthField", err)
	}
}

func TestClientHelloRejectsTrailingBytes(t *testing.T) {
	ch := captureClientHello(t)
	body := append(append([]byte{}, ch.RawData()...), 0xff)
	if _, err := ltls.NewClientHelloFrame(body); err == nil {
		t.Error("trailing byte after extensions block accepted")
	}
}

func TestClientHelloTruncatedAtEveryOffset(t *testing.T) {
	// Truncating a valid hello anywhere must produce an error, never a panic
	// and never a frame whose accessors read out of bounds.
	ch := captureClientHello(t)
	full := ch.RawData()
	for n := range len(full) {
		frame, err := ltls.NewClientHelloFrame(full[:n])
		if err == nil {
			// A shorter prefix must never parse as a complete hello.
			t.Errorf("truncation to %d/%d bytes parsed clean", n, len(full))
			_ = frame.Extensions()
		}
	}
}

func FuzzNewClientHelloFrame(f *testing.F) {
	f.Add([]byte{
		0x03, 0x03,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00,                   // no session id
		0x00, 0x02, 0x13, 0x01, // one cipher suite
		0x01, 0x00, // null compression
		0x00, 0x00, // no extensions
	})
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, err := ltls.NewClientHelloFrame(b)
		if err != nil {
			return
		}
		// Every accessor must stay inside the input.
		if len(ch.LegacySessionID()) > ltls.MaxSessionIDLen {
			t.Fatalf("session id %d bytes exceeds max", len(ch.LegacySessionID()))
		}
		if len(ch.CipherSuites())%2 != 0 {
			t.Fatal("cipher suites vector has odd length")
		}
		total := 2 + ltls.SizeRandom + 1 + len(ch.LegacySessionID()) +
			2 + len(ch.CipherSuites()) +
			1 + len(ch.LegacyCompressionMethods()) +
			2 + len(ch.Extensions())
		if total != len(b) {
			t.Fatalf("fields sum to %d but input is %d bytes", total, len(b))
		}
		_ = ch.ValidateCompression()
		_ = ch.ForEachExtension(func(ltls.ExtensionType, []byte) error { return nil })
	})
}
