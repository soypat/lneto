package ntp

import (
	"testing"

	"github.com/soypat/lneto"
)

func TestNextExtField_Empty(t *testing.T) {
	field, n, err := NextExtField(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(field.RawData()) != 0 {
		t.Errorf("NextExtField(nil) RawData len = %d; want 0", len(field.RawData()))
	}
	if n != 0 {
		t.Errorf("NextExtField(nil) n = %d; want 0", n)
	}
}

func TestAppendAndIterateExtFields(t *testing.T) {
	uid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	cookie := []byte{0xAA, 0xBB, 0xCC}

	var buf []byte
	buf = AppendExtField(buf, ExtNTSUniqueID, uid)
	buf = AppendExtField(buf, ExtNTSCookie, cookie)

	// Each field should be padded to 4-byte boundary.
	// UID: 4 header + 16 value = 20 bytes (already aligned)
	// Cookie: 4 header + 3 value + 1 padding = 8 bytes
	const wantLen = 20 + 8
	if len(buf) != wantLen {
		t.Fatalf("AppendExtField total len = %d; want %d", len(buf), wantLen)
	}

	off := 0
	field, n, err := NextExtField(buf[off:])
	if err != nil {
		t.Fatal(err)
	}
	off += n
	if field.Type() != ExtNTSUniqueID {
		t.Errorf("field 1 Type() = %#x; want ExtNTSUniqueID (%#x)", field.Type(), ExtNTSUniqueID)
	}
	if string(field.Value()) != string(uid) {
		t.Errorf("field 1 Value() mismatch")
	}

	field, n, err = NextExtField(buf[off:])
	if err != nil {
		t.Fatal(err)
	}
	off += n
	if field.Type() != ExtNTSCookie {
		t.Errorf("field 2 Type() = %#x; want ExtNTSCookie (%#x)", field.Type(), ExtNTSCookie)
	}
	// Value() includes the 4-byte-aligned body (RFC 7822 §2.1 length includes padding).
	wantCookiePadded := []byte{0xAA, 0xBB, 0xCC, 0x00}
	if string(field.Value()) != string(wantCookiePadded) {
		t.Errorf("field 2 Value() = %v; want %v", field.Value(), wantCookiePadded)
	}

	field, n, err = NextExtField(buf[off:])
	if err != nil {
		t.Fatal(err)
	}
	if len(field.RawData()) != 0 {
		t.Errorf("NextExtField after last: RawData len = %d; want 0", len(field.RawData()))
	}
	_ = n
}

func TestNextExtField_Errors(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{name: "truncated/2bytes", buf: []byte{0x01, 0x04}},
		{name: "length_below_min", buf: []byte{0x01, 0x04, 0x00, 0x02}},
		{name: "length_unaligned", buf: []byte{0x01, 0x04, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{name: "length_exceeds_buf", buf: []byte{0x01, 0x04, 0x00, 0x08, 0x00}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := NextExtField(tc.buf)
			if err == nil {
				t.Errorf("NextExtField(%x) = nil error; want error", tc.buf)
			}
		})
	}
}

func TestFrameExtensionFields(t *testing.T) {
	t.Run("with_extensions", func(t *testing.T) {
		buf := make([]byte, SizeHeader+8)
		frm, err := NewFrame(buf)
		if err != nil {
			t.Fatal(err)
		}
		p := frm.ExtensionFields()
		if len(p) != 8 {
			t.Errorf("ExtensionFields() len = %d; want 8", len(p))
		}
	})
	t.Run("header_only", func(t *testing.T) {
		buf := make([]byte, SizeHeader)
		frm, _ := NewFrame(buf)
		if len(frm.ExtensionFields()) != 0 {
			t.Errorf("ExtensionFields() len = %d; want 0 for header-only frame", len(frm.ExtensionFields()))
		}
	})
}

func TestFrameValidateSize(t *testing.T) {
	t.Run("header_only", func(t *testing.T) {
		var v lneto.Validator
		buf := make([]byte, SizeHeader)
		frm, _ := NewFrame(buf)
		frm.ValidateSize(&v)
		if v.HasError() {
			t.Errorf("ValidateSize(header-only) = %v; want no error", v.ErrPop())
		}
	})
	t.Run("valid_extension", func(t *testing.T) {
		var v lneto.Validator
		ext := AppendExtField(nil, ExtNTSUniqueID, make([]byte, 16))
		buf := make([]byte, SizeHeader+len(ext))
		copy(buf[SizeHeader:], ext)
		frm, _ := NewFrame(buf)
		frm.ValidateSize(&v)
		if v.HasError() {
			t.Errorf("ValidateSize(valid ext) = %v; want no error", v.ErrPop())
		}
	})
	t.Run("malformed_extension", func(t *testing.T) {
		var v lneto.Validator
		buf := make([]byte, SizeHeader+4)
		buf[SizeHeader+2] = 0x00
		buf[SizeHeader+3] = 0x05 // length = 5, not 4-byte aligned
		frm, _ := NewFrame(buf)
		frm.ValidateSize(&v)
		if !v.HasError() {
			t.Errorf("ValidateSize(malformed ext) = no error; want error")
		}
		v.ErrPop()
	})
}

func FuzzNextExtField(f *testing.F) {
	f.Add(AppendExtField(nil, ExtNTSUniqueID, make([]byte, 16)))
	f.Add(AppendExtField(nil, ExtNTSCookie, make([]byte, 64)))
	two := AppendExtField(nil, ExtNTSUniqueID, make([]byte, 32))
	two = AppendExtField(two, ExtNTSCookie, make([]byte, 8))
	f.Add(two)
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0, 1, 0, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		off := 0
		for off < len(data) {
			field, n, err := NextExtField(data[off:])
			if err != nil {
				return
			}
			if len(field.RawData()) == 0 {
				return
			}
			_ = field.Type()
			_ = field.TotalLen()
			_ = field.Value()
			off += n
		}
	})
}
