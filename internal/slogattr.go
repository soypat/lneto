package internal

import (
	"encoding/binary"
	"log/slog"
)

// SlogAddr4 returns a slog.Attr for a 4-byte IPv4 address
// packed into a uint64 without allocating a string.
func SlogAddr4(key string, addr *[4]byte) slog.Attr {
	u64Addr := uint64(binary.BigEndian.Uint32(addr[:]))
	return slog.Uint64(key, u64Addr)
}

// SlogAddr6 returns a slog.Attr for a 6-byte hardware (MAC) address
// packed into a uint64 without allocating a string.
func SlogAddr6(key string, addr *[6]byte) slog.Attr {
	var buf [8]byte
	copy(buf[2:], addr[:])
	u64Addr := binary.BigEndian.Uint64(buf[:])
	return slog.Uint64(key, u64Addr)
}
