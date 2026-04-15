package ntp

import (
	"testing"

	"github.com/soypat/lneto"
)

func TestNextExtField_Empty(t *testing.T) {
	field, rest, err := NextExtField(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(field.RawData()) != 0 {
		t.Fatal("expected empty field for nil buf")
	}
	if rest != nil {
		t.Fatal("expected nil rest for nil buf")
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
		t.Fatalf("buf len = %d; want %d", len(buf), wantLen)
	}

	field, rest, err := NextExtField(buf)
	if err != nil {
		t.Fatal(err)
	}
	if field.Type() != ExtNTSUniqueID {
		t.Errorf("field 1 type = %#x; want ExtNTSUniqueID (%#x)", field.Type(), ExtNTSUniqueID)
	}
	if string(field.Value()) != string(uid) {
		t.Errorf("field 1 value mismatch")
	}

	field, rest, err = NextExtField(rest)
	if err != nil {
		t.Fatal(err)
	}
	if field.Type() != ExtNTSCookie {
		t.Errorf("field 2 type = %#x; want ExtNTSCookie (%#x)", field.Type(), ExtNTSCookie)
	}
	// Value() includes the 4-byte-aligned body (RFC 7822 §2.1 length includes padding).
	wantCookiePadded := []byte{0xAA, 0xBB, 0xCC, 0x00}
	if string(field.Value()) != string(wantCookiePadded) {
		t.Errorf("field 2 value mismatch: got %v, want %v", field.Value(), wantCookiePadded)
	}

	field, rest, err = NextExtField(rest)
	if err != nil {
		t.Fatal(err)
	}
	if len(field.RawData()) != 0 {
		t.Fatal("expected empty field after last extension")
	}
	_ = rest
}

func TestNextExtField_Truncated(t *testing.T) {
	// Only 2 bytes — too short for a header.
	_, _, err := NextExtField([]byte{0x01, 0x04})
	if err == nil {
		t.Fatal("expected error for truncated buffer")
	}
}

func TestNextExtField_InvalidLength(t *testing.T) {
	// Length field = 2 (less than minimum sizeExtHeader=4).
	buf := []byte{0x01, 0x04, 0x00, 0x02}
	_, _, err := NextExtField(buf)
	if err == nil {
		t.Fatal("expected error for invalid length < 4")
	}
}

func TestNextExtField_UnalignedLength(t *testing.T) {
	// Length field = 5 (not a multiple of 4).
	buf := []byte{0x01, 0x04, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	_, _, err := NextExtField(buf)
	if err == nil {
		t.Fatal("expected error for unaligned length")
	}
}

func TestFramePayload(t *testing.T) {
	buf := make([]byte, SizeHeader+8)
	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	p := frm.Payload()
	if len(p) != 8 {
		t.Fatalf("Payload len = %d; want 8", len(p))
	}

	frm2, _ := NewFrame(buf[:SizeHeader])
	if frm2.Payload() != nil {
		t.Fatal("Payload on header-only frame should be nil")
	}
}

func TestFrameValidateSize(t *testing.T) {
	var v lneto.Validator

	// Valid: header only.
	buf := make([]byte, SizeHeader)
	frm, _ := NewFrame(buf)
	frm.ValidateSize(&v)
	if v.HasError() {
		t.Fatal(v.ErrPop())
	}

	// Valid: header + one well-formed extension field.
	ext := AppendExtField(nil, ExtNTSUniqueID, make([]byte, 16))
	buf2 := make([]byte, SizeHeader+len(ext))
	copy(buf2[SizeHeader:], ext)
	frm2, _ := NewFrame(buf2)
	frm2.ValidateSize(&v)
	if v.HasError() {
		t.Fatal(v.ErrPop())
	}

	// Invalid: malformed extension field (length not 4-byte aligned).
	buf3 := make([]byte, SizeHeader+4)
	buf3[SizeHeader+2] = 0x00
	buf3[SizeHeader+3] = 0x05 // length = 5
	frm3, _ := NewFrame(buf3)
	frm3.ValidateSize(&v)
	if !v.HasError() {
		t.Fatal("expected error for malformed extension field")
	}
	v.ErrPop()
}
