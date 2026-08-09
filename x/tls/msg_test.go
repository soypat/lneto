package tls_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/soypat/lneto"
	ltls "github.com/soypat/lneto/x/tls"
)

// locates reports whether span points at want inside body.
func locates(body []byte, off int, want []byte) bool {
	return off >= 0 && off+len(want) <= len(body) && bytes.Equal(body[off:off+len(want)], want)
}

// Spans must locate every hello field, so decoders can map a field onto its wire
// position without re-walking the structure.
func TestClientHelloMsgSpans(t *testing.T) {
	msg := captureClientHello(t)
	body := msg.RawData()
	sp := msg.Spans()
	for _, tc := range []struct {
		name string
		span ltls.Span
		want []byte
	}{
		{"random", sp.Random, msg.Random()[:]},
		{"session id", sp.SessionID, msg.LegacySessionID()},
		{"compression", sp.Compression, msg.LegacyCompressionMethods()},
		{"extensions", sp.Extensions, msg.ExtensionBytes()},
	} {
		if tc.span.Len != len(tc.want) {
			t.Errorf("%s span len %d want %d", tc.name, tc.span.Len, len(tc.want))
		} else if !locates(body, tc.span.Off, tc.want) {
			t.Errorf("%s span %+v does not locate its field", tc.name, tc.span)
		}
	}
}

// Iterator keys are offsets into the hello body, at every nesting level, so a
// decoder can point at a cipher suite or an SNI hostname without arithmetic.
func TestClientHelloMsgIterators(t *testing.T) {
	msg := captureClientHello(t)
	body := msg.RawData()

	nsuites := 0
	for off, suite := range msg.CipherSuites {
		want := []byte{byte(suite >> 8), byte(suite)}
		if !locates(body, off, want) {
			t.Errorf("suite %v at offset %d does not match the wire", suite, off)
		}
		nsuites++
	}
	if nsuites == 0 {
		t.Fatal("no cipher suites walked")
	}

	var sawSNI, sawALPN, sawTLS13, sawX25519 bool
	for off, ext := range msg.Extensions {
		if !locates(body, off, ext.Data()) {
			t.Errorf("%v data at offset %d does not match the wire", ext.Type(), off)
		}
		switch ext.Type() {
		case ltls.ExtServerName:
			for noff, name := range ext.ServerNames {
				sawSNI = true
				if name.Type != 0 || string(name.Name) != "example.com" {
					t.Errorf("server name %d %q", name.Type, name.Name)
				}
				if !locates(body, noff, name.Name) {
					t.Errorf("server name at offset %d does not match the wire", noff)
				}
			}
		case ltls.ExtALPN:
			for poff, proto := range ext.ALPNProtos {
				sawALPN = true
				if !locates(body, poff, proto) {
					t.Errorf("alpn %q at offset %d does not match the wire", proto, poff)
				}
			}
		case ltls.ExtSupportedVersions:
			for _, v := range ext.SupportedVersions {
				sawTLS13 = sawTLS13 || v == ltls.VersionTLS13
			}
		case ltls.ExtKeyShare:
			for koff, ks := range ext.KeyShares {
				if ks.Group == ltls.GroupX25519 {
					sawX25519 = true
				}
				if !locates(body, koff, ks.Key) {
					t.Errorf("key share %v at offset %d does not match the wire", ks.Group, koff)
				}
			}
		case ltls.ExtSupportedGroups:
			for goff, g := range ext.SupportedGroups {
				if !locates(body, goff, []byte{byte(g >> 8), byte(g)}) {
					t.Errorf("group %v at offset %d does not match the wire", g, goff)
				}
			}
		case ltls.ExtSignatureAlgorithms:
			for soff, s := range ext.SignatureSchemes {
				if !locates(body, soff, []byte{byte(s >> 8), byte(s)}) {
					t.Errorf("scheme %v at offset %d does not match the wire", s, soff)
				}
			}
		}
	}
	if !sawSNI || !sawALPN || !sawTLS13 || !sawX25519 {
		t.Errorf("sni=%v alpn=%v tls13=%v x25519=%v", sawSNI, sawALPN, sawTLS13, sawX25519)
	}
}

// A sub-iterator reached from the wrong extension yields nothing rather than
// reinterpreting unrelated bytes.
func TestExtensionSubIteratorTypeMismatch(t *testing.T) {
	msg := captureClientHello(t)
	for _, ext := range msg.Extensions {
		if ext.Type() != ltls.ExtServerName {
			continue
		}
		for range ext.KeyShares {
			t.Error("KeyShares walked a server_name extension")
		}
		for range ext.SupportedVersions {
			t.Error("SupportedVersions walked a server_name extension")
		}
	}
}

// Walking a hello must not allocate: every iterator is a value type over the
// caller's buffer.
func TestClientHelloMsgZeroAlloc(t *testing.T) {
	msg := captureClientHello(t)
	body := msg.RawData()
	n := testing.AllocsPerRun(10, func() {
		m, err := ltls.ParseClientHello(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, suite := range m.CipherSuites {
			_ = suite
		}
		for _, ext := range m.Extensions {
			for _, name := range ext.ServerNames {
				_ = name
			}
			for _, ks := range ext.KeyShares {
				_ = ks
			}
			for _, p := range ext.ALPNProtos {
				_ = p
			}
			for _, v := range ext.SupportedVersions {
				_ = v
			}
		}
	})
	if n != 0 {
		t.Errorf("parse and walk allocated %v times, want 0", n)
	}
}

// A known extension whose inner framing is broken must fail the parse, since
// every iterator past construction is error-free.
func TestParseClientHelloRejectsMalformedKnownExtension(t *testing.T) {
	msg := captureClientHello(t)
	// server_name with a host name length one past the extension data.
	bad := []byte{
		0x00, 0x00, 0x00, 0x0b, // server_name, 11 bytes
		0x00, 0x09, // server_name_list length
		0x00,       // host_name
		0x00, 0x0a, // name length 10, but only 6 bytes follow
		'e', 'x', 'a', 'm', 'p', 'l',
	}
	body := rebuildHelloWithExtensions(t, msg, bad)
	if _, err := ltls.ParseClientHello(body); err == nil {
		t.Error("malformed server_name accepted")
	}
}

func TestParseClientHelloRejectsDuplicateExtension(t *testing.T) {
	// Duplicating an extension lets this parser and a middlebox act on
	// different copies, so it is rejected at parse time.
	msg := captureClientHello(t)
	exts := msg.ExtensionBytes()
	var first int
	for off, ext := range msg.Extensions {
		first = off + len(ext.Data())
		break
	}
	dup := make([]byte, 0, len(exts)+first)
	dup = append(dup, exts...)
	dup = append(dup, exts[:first-msg.Spans().Extensions.Off]...)

	body := rebuildHelloWithExtensions(t, msg, dup)
	_, err := ltls.ParseClientHello(body)
	if !errors.Is(err, lneto.ErrInvalidField) {
		t.Errorf("duplicate extension got %v want ErrInvalidField", err)
	}
}

// buildServerHello encodes a ServerHello body with supported_versions and a
// key_share, which in the server form is a single entry with no list prefix.
func buildServerHello(t *testing.T, sid []byte) []byte {
	t.Helper()
	var b ltls.Builder
	b.Reset(make([]byte, 0, 256))
	b.AddU16(ltls.VersionTLS12)
	for range ltls.SizeRandom {
		b.AddU8(0xab)
	}
	b.OpenU8()
	b.AddBytes(sid)
	b.Close()
	b.AddU16(uint16(ltls.SuiteAES128GCMSHA256))
	b.AddU8(0) // legacy_compression_method
	b.OpenU16()
	b.AddU16(uint16(ltls.ExtSupportedVersions))
	b.OpenU16()
	b.AddU16(ltls.VersionTLS13)
	b.Close()
	b.AddU16(uint16(ltls.ExtKeyShare))
	b.OpenU16()
	b.AddU16(uint16(ltls.GroupX25519))
	b.OpenU16()
	for range 32 {
		b.AddU8(0xee)
	}
	b.Close()
	b.Close()
	b.Close()
	body, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestServerHelloMsg(t *testing.T) {
	sid := bytes.Repeat([]byte{0xcd}, 32)
	body := buildServerHello(t, sid)
	msg, err := ltls.ParseServerHello(body)
	if err != nil {
		t.Fatal(err)
	}
	if msg.LegacyVersion() != ltls.VersionTLS12 {
		t.Errorf("legacy_version %#04x want 0x0303", msg.LegacyVersion())
	}
	if !bytes.Equal(msg.LegacySessionIDEcho(), sid) {
		t.Errorf("session id echo % x want % x", msg.LegacySessionIDEcho(), sid)
	}
	if msg.CipherSuite() != ltls.SuiteAES128GCMSHA256 {
		t.Errorf("cipher suite %v want TLS_AES_128_GCM_SHA256", msg.CipherSuite())
	}
	if msg.LegacyCompressionMethod() != 0 {
		t.Errorf("compression method %d want 0", msg.LegacyCompressionMethod())
	}

	var version uint16
	shares := 0
	for _, ext := range msg.Extensions {
		switch ext.Type() {
		case ltls.ExtSupportedVersions:
			// The ServerHello form is a bare uint16, not a list.
			if len(ext.Data()) != 2 {
				t.Fatalf("supported_versions %d bytes want 2", len(ext.Data()))
			}
			version = uint16(ext.Data()[0])<<8 | uint16(ext.Data()[1])
		case ltls.ExtKeyShare:
			for koff, ks := range ext.KeyShares {
				shares++
				if ks.Group != ltls.GroupX25519 || len(ks.Key) != 32 {
					t.Errorf("key share %v %d bytes", ks.Group, len(ks.Key))
				}
				if !locates(body, koff, ks.Key) {
					t.Errorf("key share at offset %d does not match the wire", koff)
				}
			}
		}
	}
	if version != ltls.VersionTLS13 {
		t.Errorf("negotiated version %#04x want 0x0304", version)
	}
	if shares != 1 {
		t.Errorf("walked %d key shares want 1, the server sends a single entry", shares)
	}

	sp := msg.Spans()
	if sp.CipherSuites.Len != 2 || !locates(body, sp.CipherSuites.Off, body[sp.CipherSuites.Off:sp.CipherSuites.Off+2]) {
		t.Errorf("cipher suite span %+v", sp.CipherSuites)
	}
	if sp.Compression.Len != 1 {
		t.Errorf("compression span len %d want 1", sp.Compression.Len)
	}
	if !locates(body, sp.Extensions.Off, msg.ExtensionBytes()) {
		t.Errorf("extensions span %+v does not locate the block", sp.Extensions)
	}
}

func TestParseServerHelloRejectsMalformed(t *testing.T) {
	body := buildServerHello(t, bytes.Repeat([]byte{0xcd}, 32))
	if _, err := ltls.ParseServerHello(append(append([]byte{}, body...), 0xff)); err == nil {
		t.Error("trailing byte after extensions block accepted")
	}
	// No truncation may parse clean, panic, or leave an accessor out of range.
	for n := range len(body) {
		msg, err := ltls.ParseServerHello(body[:n])
		if err == nil {
			t.Errorf("truncation to %d/%d bytes parsed clean", n, len(body))
			_ = msg.ExtensionBytes()
		}
	}
}
