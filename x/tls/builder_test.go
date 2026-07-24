package tls_test

import (
	"errors"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/tls"
)

// buildSupportedVersions writes the extension a TLS 1.3 ServerHello carries,
// exercising one level of nesting.
func buildSupportedVersions(b *tls.Builder) {
	b.AddU16(uint16(tls.ExtSupportedVersions))
	b.OpenU16()
	b.AddU16(tls.VersionTLS13)
	b.Close()
}

func TestBuilderRoundTripThroughParser(t *testing.T) {
	// Build an extensions block, then walk it back with the parser. Agreement
	// between the two is the property that matters.
	var b tls.Builder
	buf := make([]byte, 64)
	b.Reset(buf)
	b.OpenU16() // extensions block length
	buildSupportedVersions(&b)
	b.AddU16(uint16(tls.ExtKeyShare))
	b.OpenU16()
	b.OpenU16() // client_shares
	b.AddU16(uint16(tls.GroupX25519))
	b.OpenU16()
	b.AddBytes(make([]byte, 8))
	b.Close()
	b.Close()
	b.Close()
	b.Close()

	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// Strip the outer block length the way ClientHelloFrame.Extensions does.
	if len(out) < 2 {
		t.Fatal("output too short")
	}
	exts := out[2:]
	if int(out[0])<<8|int(out[1]) != len(exts) {
		t.Fatalf("outer length %d != %d", int(out[0])<<8|int(out[1]), len(exts))
	}

	var seen []tls.ExtensionType
	err = tls.ForEachExtension(exts, func(ext tls.ExtensionType, data []byte) error {
		seen = append(seen, ext)
		if ext == tls.ExtKeyShare {
			return tls.ForEachKeyShare(data, func(g tls.NamedGroup, key []byte) error {
				if g != tls.GroupX25519 || len(key) != 8 {
					t.Errorf("key share got %v len %d", g, len(key))
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != tls.ExtSupportedVersions || seen[1] != tls.ExtKeyShare {
		t.Errorf("walked %v", seen)
	}
}

func TestBuilderStickyShortBuffer(t *testing.T) {
	var b tls.Builder
	b.Reset(make([]byte, 4))
	b.AddU32(0x01020304) // exactly fills
	if b.Err() != nil {
		t.Fatalf("unexpected error filling buffer: %v", b.Err())
	}
	b.AddU8(0xff) // overflows
	if !errors.Is(b.Err(), lneto.ErrShortBuffer) {
		t.Fatalf("got %v want ErrShortBuffer", b.Err())
	}
	// Once failed, later writes must not panic, must not write, and must not
	// replace the original error.
	b.AddBytes(make([]byte, 100))
	b.OpenU16()
	b.Close()
	if !errors.Is(b.Err(), lneto.ErrShortBuffer) {
		t.Fatalf("error changed to %v", b.Err())
	}
	if _, err := b.Bytes(); !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("Bytes returned %v", err)
	}
}

func TestBuilderUnclosedPrefixIsAnError(t *testing.T) {
	// Returning bytes with an unpatched placeholder would emit a structurally
	// wrong record that looks valid.
	var b tls.Builder
	b.Reset(make([]byte, 16))
	b.OpenU16()
	b.AddU8(1)
	if _, err := b.Bytes(); err == nil {
		t.Error("Bytes accepted an unclosed length prefix")
	}
}

func TestBuilderUnbalancedClose(t *testing.T) {
	var b tls.Builder
	b.Reset(make([]byte, 16))
	b.Close()
	if b.Err() == nil {
		t.Error("Close without Open accepted")
	}
}

func TestBuilderNestingLimit(t *testing.T) {
	var b tls.Builder
	b.Reset(make([]byte, 64))
	for range 8 {
		b.OpenU8()
	}
	if b.Err() != nil {
		t.Fatalf("8 levels rejected: %v", b.Err())
	}
	b.OpenU8()
	if b.Err() == nil {
		t.Error("9th nesting level accepted")
	}
}

func TestBuilderLengthOverflowRejected(t *testing.T) {
	// 300 bytes cannot be described by a one-byte prefix. Truncating modulo 256
	// would produce a valid-looking but wrong structure, so this must fail.
	var b tls.Builder
	b.Reset(make([]byte, 512))
	b.OpenU8()
	b.AddBytes(make([]byte, 300))
	b.Close()
	if !errors.Is(b.Err(), lneto.ErrInvalidLengthField) {
		t.Errorf("got %v want ErrInvalidLengthField", b.Err())
	}
}

func TestBuilderU24RoundTrip(t *testing.T) {
	var b tls.Builder
	b.Reset(make([]byte, 8))
	b.AddU8(byte(tls.HandshakeTypeServerHello))
	b.OpenU24()
	b.AddBytes([]byte{1, 2, 3})
	b.Close()
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	hf, err := tls.NewHandshakeFrame(out)
	if err != nil {
		t.Fatal(err)
	}
	if hf.MsgType() != tls.HandshakeTypeServerHello {
		t.Errorf("type got %v", hf.MsgType())
	}
	if hf.Length() != 3 {
		t.Errorf("length got %d want 3", hf.Length())
	}
	if !hf.Complete() || len(hf.Body()) != 3 {
		t.Errorf("body got % x", hf.Body())
	}
}

func TestBuilderAddStringMatchesAddBytes(t *testing.T) {
	const label = "tls13 derived"
	var b1, b2 tls.Builder
	buf1, buf2 := make([]byte, 32), make([]byte, 32)
	b1.Reset(buf1)
	b1.AddString(label)
	b2.Reset(buf2)
	b2.AddBytes([]byte(label))
	out1, err1 := b1.Bytes()
	out2, err2 := b2.Bytes()
	if err1 != nil || err2 != nil {
		t.Fatalf("%v %v", err1, err2)
	}
	if string(out1) != string(out2) {
		t.Errorf("AddString %q != AddBytes %q", out1, out2)
	}
}

func TestBuilderZeroAlloc(t *testing.T) {
	// The whole point of not using cryptobyte. A regression here means the
	// outbound handshake path started allocating per connection.
	buf := make([]byte, 256)
	var b tls.Builder
	n := testing.AllocsPerRun(100, func() {
		b.Reset(buf)
		b.AddU8(byte(tls.HandshakeTypeServerHello))
		b.OpenU24()
		b.AddU16(tls.VersionTLS12)
		b.AddBytes(make([]byte, 0, 0)) // no-op, must not allocate
		b.OpenU16()
		buildSupportedVersions(&b)
		b.Close()
		b.AddString("x")
		b.Close()
		_, _ = b.Bytes()
	})
	if n != 0 {
		t.Errorf("Builder allocated %v times per run, want 0", n)
	}
}

func FuzzBuilderNeverEscapesBuffer(f *testing.F) {
	f.Add([]byte{1, 2, 3}, uint8(16))
	f.Fuzz(func(t *testing.T, payload []byte, size uint8) {
		buf := make([]byte, size)
		canary := make([]byte, len(buf))
		var b tls.Builder
		b.Reset(buf)
		b.OpenU16()
		b.AddBytes(payload)
		b.OpenU8()
		b.AddBytes(payload)
		b.Close()
		b.Close()
		out, err := b.Bytes()
		if err != nil {
			return
		}
		if len(out) > len(buf) {
			t.Fatalf("wrote %d bytes into a %d byte buffer", len(out), len(buf))
		}
		// Whatever was produced must parse back as a well-formed vector.
		if len(out) < 2 {
			t.Fatalf("output %d bytes is too short to hold its own prefix", len(out))
		}
		if declared := int(out[0])<<8 | int(out[1]); declared != len(out)-2 {
			t.Fatalf("declared %d != actual %d", declared, len(out)-2)
		}
		_ = canary
	})
}
