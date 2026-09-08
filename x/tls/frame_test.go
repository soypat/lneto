package tls_test

import (
	"errors"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/tls"
)

func TestRecordFrameHeaderBeforeBody(t *testing.T) {
	// A record layer sees the 5 byte header first and must be able to consult
	// the length to know how much more to read.
	hdr := []byte{22, 0x03, 0x01, 0x00, 0x10}
	rf, err := tls.NewRecordFrame(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if rf.ContentType() != tls.ContentTypeHandshake {
		t.Errorf("content type got %v want handshake", rf.ContentType())
	}
	if rf.Length() != 16 {
		t.Errorf("length got %d want 16", rf.Length())
	}
	if rf.RecordLength() != 21 {
		t.Errorf("record length got %d want 21", rf.RecordLength())
	}
	if rf.Complete() {
		t.Error("record with header only reported complete")
	}
	if rf.Payload() != nil {
		t.Error("payload of incomplete record must be nil, not a short slice")
	}

	full := append(hdr, make([]byte, 16)...)
	rf, err = tls.NewRecordFrame(full)
	if err != nil {
		t.Fatal(err)
	}
	if !rf.Complete() {
		t.Fatal("full record reported incomplete")
	}
	if len(rf.Payload()) != 16 {
		t.Errorf("payload len got %d want 16", len(rf.Payload()))
	}
}

func TestRecordFrameShortHeader(t *testing.T) {
	for n := range tls.SizeHeaderRecord {
		_, err := tls.NewRecordFrame(make([]byte, n))
		if !errors.Is(err, lneto.ErrTruncatedFrame) {
			t.Errorf("len=%d got %v want ErrTruncatedFrame", n, err)
		}
	}
}

func TestRecordFrameRejectsOversizeLength(t *testing.T) {
	// The length field is attacker controlled and must be refused before it is
	// ever used to size a read.
	hdr := []byte{23, 0x03, 0x03, 0xff, 0xff} // 65535 > MaxCiphertext
	rf, err := tls.NewRecordFrame(hdr)
	if err != nil {
		t.Fatal(err)
	}
	var v lneto.Validator
	rf.ValidateSize(&v)
	if err := v.ErrPop(); !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("got %v want ErrInvalidLengthField", err)
	}

	// Exactly at the limit is legal.
	maxCT := uint16(tls.MaxCiphertext)
	hdr[3], hdr[4] = byte(maxCT>>8), byte(maxCT)
	rf, _ = tls.NewRecordFrame(hdr)
	rf.ValidateSize(&v)
	if err := v.ErrPop(); err != nil {
		t.Errorf("MaxCiphertext rejected: %v", err)
	}
}

func TestInnerPlaintextStripsPadding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      []byte
		content string
		ctype   tls.ContentType
		padding int
	}{
		{"no padding", []byte{'h', 'i', 23}, "hi", tls.ContentTypeApplicationData, 0},
		{"padded", []byte{'h', 'i', 23, 0, 0, 0}, "hi", tls.ContentTypeApplicationData, 3},
		{"empty content", []byte{22}, "", tls.ContentTypeHandshake, 0},
		{"content ends in zero", []byte{'a', 0, 'b', 21, 0}, "a\x00b", tls.ContentTypeAlert, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, err := tls.NewInnerPlaintext(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(ip.Content()) != tc.content {
				t.Errorf("content got %q want %q", ip.Content(), tc.content)
			}
			if ip.ContentType() != tc.ctype {
				t.Errorf("type got %v want %v", ip.ContentType(), tc.ctype)
			}
			if ip.PaddingLen() != tc.padding {
				t.Errorf("padding got %d want %d", ip.PaddingLen(), tc.padding)
			}
		})
	}
}

func TestInnerPlaintextAllZeroRejected(t *testing.T) {
	// An all-zero inner plaintext carries no content type. Silently treating it
	// as empty would let a peer inject records the state machine cannot
	// classify; RFC 8446 5.4 requires unexpected_message.
	for _, n := range []int{0, 1, 8} {
		_, err := tls.NewInnerPlaintext(make([]byte, n))
		if err == nil {
			t.Errorf("len=%d: all-zero plaintext accepted", n)
		}
	}
}

func TestHandshakeFrame24BitLength(t *testing.T) {
	hdr := []byte{1, 0x01, 0x02, 0x03} // ClientHello, length 0x010203
	hf, err := tls.NewHandshakeFrame(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if hf.MsgType() != tls.HandshakeTypeClientHello {
		t.Errorf("type got %v", hf.MsgType())
	}
	if hf.Length() != 0x010203 {
		t.Errorf("length got %#x want 0x010203", hf.Length())
	}
	if hf.Complete() {
		t.Error("header-only message reported complete")
	}
	if hf.Body() != nil {
		t.Error("body of incomplete message must be nil")
	}
}

func TestHandshakeFrameRoundTripLength(t *testing.T) {
	buf := make([]byte, tls.SizeHeaderHandshake)
	hf, err := tls.NewHandshakeFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int32{0, 1, 255, 256, 65535, 65536, 0xffffff} {
		hf.SetLength(n)
		if got := hf.Length(); got != n {
			t.Errorf("SetLength(%d) round-tripped to %d", n, got)
		}
	}
}

func TestHandshakeFrameRawDataIncludesHeader(t *testing.T) {
	// The transcript hash covers the header plus body, exactly once per
	// message. Getting this wrong breaks Finished verification.
	msg := []byte{20, 0, 0, 2, 0xaa, 0xbb}
	hf, err := tls.NewHandshakeFrame(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got := hf.RawData(); len(got) != 6 {
		t.Errorf("RawData len got %d want 6", len(got))
	}
	if got := hf.Body(); len(got) != 2 || got[0] != 0xaa {
		t.Errorf("Body got % x", got)
	}
}

func TestIsGREASE(t *testing.T) {
	// The 16 reserved values of RFC 8701.
	for i := range 16 {
		v := uint16(i)<<12 | 0x0a00 | uint16(i)<<4 | 0x0a
		if !tls.IsGREASE(v) {
			t.Errorf("%#04x not detected as GREASE", v)
		}
	}
	for _, v := range []uint16{
		0x0000, 0x1301, 0x001d, 0x0403, 0x0a0b, 0x0b0a, 0x1a2a, 0xffff,
	} {
		if tls.IsGREASE(v) {
			t.Errorf("%#04x falsely detected as GREASE", v)
		}
	}
}

func FuzzNewRecordFrame(f *testing.F) {
	f.Add([]byte{22, 3, 1, 0, 5, 1, 2, 3, 4, 5})
	f.Add([]byte{23, 3, 3, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		rf, err := tls.NewRecordFrame(b)
		if err != nil {
			return
		}
		var v lneto.Validator
		rf.ValidateSize(&v)
		// Accessors must stay in bounds regardless of validation outcome.
		_ = rf.ContentType()
		_ = rf.LegacyVersion()
		_ = rf.Length()
		if p := rf.Payload(); p != nil && len(p) != int(rf.Length()) {
			t.Fatalf("payload len %d != declared %d", len(p), rf.Length())
		}
		if raw := rf.RawData(); len(raw) > len(b) {
			t.Fatalf("RawData %d longer than input %d", len(raw), len(b))
		}
	})
}

func FuzzNewHandshakeFrame(f *testing.F) {
	f.Add([]byte{1, 0, 0, 2, 3, 4})
	f.Add([]byte{20, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		hf, err := tls.NewHandshakeFrame(b)
		if err != nil {
			return
		}
		var v lneto.Validator
		hf.ValidateSize(&v)
		if hf.Length() < 0 {
			t.Fatalf("negative 24-bit length %d", hf.Length())
		}
		if body := hf.Body(); body != nil && len(body) != int(hf.Length()) {
			t.Fatalf("body len %d != declared %d", len(body), hf.Length())
		}
		if raw := hf.RawData(); len(raw) > len(b) {
			t.Fatalf("RawData %d longer than input %d", len(raw), len(b))
		}
	})
}

func FuzzNewInnerPlaintext(f *testing.F) {
	f.Add([]byte{1, 2, 23, 0, 0})
	f.Add([]byte{0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		ip, err := tls.NewInnerPlaintext(b)
		if err != nil {
			return
		}
		if ip.ContentType() == 0 {
			t.Fatal("accepted a zero content type")
		}
		if len(ip.Content())+ip.PaddingLen()+1 != len(b) {
			t.Fatalf("content %d + padding %d + 1 != input %d",
				len(ip.Content()), ip.PaddingLen(), len(b))
		}
	})
}
