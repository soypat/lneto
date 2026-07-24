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

func TestForEachExtensionWalksAndToleratesGREASE(t *testing.T) {
	// Two extensions: a GREASE type with empty data, then supported_versions.
	exts := []byte{
		0x0a, 0x0a, 0x00, 0x00, // GREASE, len 0
		0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, // supported_versions
	}
	var types []tls.ExtensionType
	err := tls.ForEachExtension(exts, func(ext tls.ExtensionType, data []byte) error {
		types = append(types, ext)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 2 || types[1] != tls.ExtSupportedVersions {
		t.Fatalf("got %v", types)
	}
	if !tls.IsGREASE(uint16(types[0])) {
		t.Errorf("first extension %#x not recognized as GREASE", types[0])
	}
}

func TestForEachExtensionTruncated(t *testing.T) {
	for _, tc := range [][]byte{
		{0x00},                               // partial type
		{0x00, 0x2b, 0x00},                   // partial length
		{0x00, 0x2b, 0x00, 0x05, 0x02, 0x03}, // length overruns
	} {
		err := tls.ForEachExtension(tc, func(tls.ExtensionType, []byte) error { return nil })
		if !errors.Is(err, lneto.ErrTruncatedFrame) {
			t.Errorf("% x: got %v want ErrTruncatedFrame", tc, err)
		}
	}
}

func TestForEachExtensionPropagatesCallbackError(t *testing.T) {
	sentinel := errors.New("stop")
	exts := []byte{0x00, 0x2b, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00}
	n := 0
	err := tls.ForEachExtension(exts, func(tls.ExtensionType, []byte) error {
		n++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("got %v want sentinel", err)
	}
	if n != 1 {
		t.Errorf("walk continued after callback error: %d calls", n)
	}
}

func TestForEachKeyShareAcceptsGREASEEntry(t *testing.T) {
	// Chrome sends a GREASE key share whose key_exchange is a single byte.
	// Rejecting it as malformed breaks Chrome outright.
	extData := []byte{
		0x00, 0x0b, // client_shares length 11
		0x1a, 0x1a, 0x00, 0x01, 0x00, // GREASE group, 1 byte body
		0x00, 0x1d, 0x00, 0x02, 0xab, 0xcd, // x25519, 2 byte body
	}
	type share struct {
		g tls.NamedGroup
		n int
	}
	var got []share
	err := tls.ForEachKeyShare(extData, func(g tls.NamedGroup, key []byte) error {
		got = append(got, share{g, len(key)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d shares want 2", len(got))
	}
	if !tls.IsGREASE(uint16(got[0].g)) || got[0].n != 1 {
		t.Errorf("GREASE share mishandled: %+v", got[0])
	}
	if got[1].g != tls.GroupX25519 || got[1].n != 2 {
		t.Errorf("x25519 share mishandled: %+v", got[1])
	}
}

func TestForEachALPNProtoRejectsEmptyName(t *testing.T) {
	// A zero-length protocol name would make the walk unable to advance.
	extData := []byte{0x00, 0x01, 0x00}
	err := tls.ForEachALPNProto(extData, func([]byte) error { return nil })
	if !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("got %v want ErrInvalidLengthField", err)
	}
}

func TestForEachALPNProto(t *testing.T) {
	extData := []byte{
		0x00, 0x0c,
		0x02, 'h', '2',
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
	}
	var names []string
	err := tls.ForEachALPNProto(extData, func(b []byte) error {
		names = append(names, string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "h2" || names[1] != "http/1.1" {
		t.Errorf("got %q", names)
	}
}

func TestForEachSupportedVersionUsesU8Prefix(t *testing.T) {
	// supported_versions is the one hello list with a single byte prefix.
	extData := []byte{0x04, 0x1a, 0x1a, 0x03, 0x04}
	var vers []uint16
	err := tls.ForEachSupportedVersion(extData, func(v uint16) error {
		vers = append(vers, v)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(vers) != 2 || vers[1] != tls.VersionTLS13 {
		t.Errorf("got %#x", vers)
	}
}

func TestVectorRejectsTrailingBytes(t *testing.T) {
	// A prefix that under-describes its buffer leaves bytes whose meaning this
	// parser and a middlebox could disagree about.
	err := tls.ForEachSupportedGroup([]byte{0x00, 0x02, 0x00, 0x1d, 0xff}, func(tls.NamedGroup) error { return nil })
	if err == nil {
		t.Error("trailing bytes after vector accepted")
	}
}

func TestForEachU16RejectsOddLength(t *testing.T) {
	err := tls.ForEachU16([]byte{0x00, 0x1d, 0x00}, func(uint16) error { return nil })
	if !errors.Is(err, lneto.ErrInvalidLengthField) {
		t.Errorf("got %v want ErrInvalidLengthField", err)
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

func FuzzForEachExtension(f *testing.F) {
	f.Add([]byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04})
	f.Add([]byte{0x0a, 0x0a, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		total := 0
		err := tls.ForEachExtension(b, func(ext tls.ExtensionType, data []byte) error {
			total += 4 + len(data)
			if total > len(b) {
				t.Fatalf("walked %d bytes past input length %d", total, len(b))
			}
			// Sub-walkers must also never escape their slice.
			_ = tls.ForEachKeyShare(data, func(tls.NamedGroup, []byte) error { return nil })
			_ = tls.ForEachALPNProto(data, func([]byte) error { return nil })
			_ = tls.ForEachSupportedGroup(data, func(tls.NamedGroup) error { return nil })
			_ = tls.ForEachSupportedVersion(data, func(uint16) error { return nil })
			_ = tls.ForEachServerName(data, func(uint8, []byte) error { return nil })
			return nil
		})
		if err == nil && total != len(b) {
			t.Fatalf("clean walk consumed %d of %d bytes", total, len(b))
		}
	})
}
