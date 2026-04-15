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
