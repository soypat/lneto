package internal

import "testing"

func TestIsMulticastIPAddr(t *testing.T) {
	tests := []struct {
		name string
		addr []byte
		want bool
	}{
		{"ipv4 multicast", []byte{224, 0, 0, 1}, true},
		{"ipv4 multicast upper", []byte{239, 255, 255, 255}, true},
		{"ipv4 unicast", []byte{192, 0, 2, 1}, false},
		{"ipv6 multicast", []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, true},
		{"ipv6 unicast", []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false},
		{"invalid length", []byte{224}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsMulticastIPAddr(tt.addr); got != tt.want {
				t.Fatalf("got %t; want %t", got, tt.want)
			}
		})
	}
}

// TestIPECN verifies the ECN codepoint is set and read in the bits of both IP
// versions, leaving the rest of the header alone, and refused for other
// versions and codepoints that do not fit.
func TestIPECN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version byte
		ecn     uint8
		want1   byte // Octet 1, all other bits set.
		wantErr bool
	}{
		{name: "ipv4-ce", version: 4, ecn: ECNCE, want1: 0xff},
		{name: "ipv4-ect0", version: 4, ecn: ECNECT0, want1: 0xfe},
		{name: "ipv4-not-ect", version: 4, ecn: ECNNotECT, want1: 0xfc},
		{name: "ipv6-ect0", version: 6, ecn: ECNECT0, want1: 0xef},
		{name: "ipv6-not-ect", version: 6, ecn: ECNNotECT, want1: 0xcf},
		{name: "ipv6-ect1", version: 6, ecn: ECNECT1, want1: 0xdf},
		{name: "too-wide", version: 4, ecn: 0b100, want1: 0xff, wantErr: true},
		{name: "unknown-version", version: 5, ecn: ECNECT0, want1: 0xff, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := make([]byte, 40)
			hdr[0], hdr[1] = tc.version<<4|0x0f, 0xff
			err := SetIPECN(hdr, tc.ecn)
			if (err != nil) != tc.wantErr || hdr[0] != tc.version<<4|0x0f || hdr[1] != tc.want1 {
				t.Fatalf("SetIPECN = %v, header %08b %08b; want error %v, %08b %08b", err, hdr[0], hdr[1], tc.wantErr, tc.version<<4|0x0f, tc.want1)
			}
			if got, err := GetIPECN(hdr); !tc.wantErr && (err != nil || got != tc.ecn) {
				t.Errorf("GetIPECN = %02b, %v; want %02b", got, err, tc.ecn)
			}
		})
	}
	if _, err := GetIPECN([]byte{5 << 4, 0}); err == nil {
		t.Error("GetIPECN read a header of IP version 5")
	}
}
