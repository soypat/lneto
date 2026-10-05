package internal

import "testing"

func TestSipHash24(t *testing.T) {
	// Reference vectors from the SipHash paper and reference implementation:
	// key = 00 01 .. 0f, message = 00 01 .. (len-1).
	tests := []struct {
		len  int
		want uint64
	}{
		{len: 0, want: 0x726fdb47dd0e0e31},
		{len: 1, want: 0x74f839c593dc67fd},
		{len: 2, want: 0x0d6c8009d9a94f5a},
		{len: 3, want: 0x85676696d7fb7e2d},
		{len: 7, want: 0xab0200f58b01d137},
		{len: 8, want: 0x93f5f5799a932462},
		{len: 15, want: 0xa129ca6149be45e5},
	}
	var key [16]byte
	var msg [64]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range msg {
		msg[i] = byte(i)
	}
	for _, tt := range tests {
		got := SipHash24(&key, msg[:tt.len])
		if got != tt.want {
			t.Errorf("len %d: got %#016x, want %#016x", tt.len, got, tt.want)
		}
	}
}
