package internal

import "testing"

// TestIPECNRoundTrip verifies the ECN codepoint is read and written in the right bits
// of both IP versions, and that the differentiated services bits sharing the field are
// left alone. The two versions place the field differently: IPv4 has it in the low two
// bits of one octet, while IPv6's Traffic Class straddles two, putting the same bits
// four places higher.
func TestIPECNRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name    string
		version byte
		hdr     []byte
	}{
		{name: "IPv4", version: 4, hdr: make([]byte, 20)},
		{name: "IPv6", version: 6, hdr: make([]byte, 40)},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, ecn := range []uint8{ECNNotECT, ECNECT1, ECNECT0, ECNCE} {
				hdr := append([]byte(nil), test.hdr...)
				// A differentiated services value sharing the field, all bits set so
				// that clobbering any of them shows up.
				hdr[0] = test.version<<4 | 0x0f
				hdr[1] = 0xff
				if err := SetIPECN(hdr, ecn); err != nil {
					t.Fatalf("SetIPECN(%02b): %s", ecn, err)
				}
				got, err := GetIPECN(hdr)
				if err != nil {
					t.Fatalf("GetIPECN: %s", err)
				}
				if got != ecn {
					t.Errorf("read back %02b, want %02b", got, ecn)
				}
				// Everything outside the two ECN bits must be untouched.
				want := append([]byte(nil), test.hdr...)
				want[0] = test.version<<4 | 0x0f
				want[1] = 0xff
				if err = SetIPECN(want, ecn); err != nil {
					t.Fatal(err)
				}
				if hdr[0] != want[0] {
					t.Errorf("octet 0 = %08b, want %08b", hdr[0], want[0])
				}
				switch test.version {
				case 4:
					if hdr[1]>>2 != 0xff>>2 {
						t.Errorf("IPv4 differentiated services bits changed: %08b", hdr[1])
					}
				case 6:
					if hdr[1]&0b1111 != 0xff&0b1111 || hdr[1]>>6 != 0xff>>6 {
						t.Errorf("IPv6 traffic class bits outside ECN changed: %08b", hdr[1])
					}
				}
			}
		})
	}
}

// TestIPECNRejectsUnknown verifies a header that is neither IPv4 nor IPv6, and a
// codepoint that does not fit the field, are refused rather than corrupting the frame.
func TestIPECNRejectsUnknown(t *testing.T) {
	bogus := make([]byte, 40)
	bogus[0] = 5 << 4
	if _, err := GetIPECN(bogus); err == nil {
		t.Error("read an ECN codepoint from a header of unknown version")
	}
	if err := SetIPECN(bogus, ECNECT0); err == nil {
		t.Error("wrote an ECN codepoint into a header of unknown version")
	}
	v4 := make([]byte, 20)
	v4[0] = 4 << 4
	if err := SetIPECN(v4, 0b100); err == nil {
		t.Error("accepted a codepoint too wide for the field")
	}
}
