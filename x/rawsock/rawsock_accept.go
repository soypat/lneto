//go:build !tinygo && (darwin || (linux && !386))

package rawsock

import (
	"net/netip"
	"syscall"
	"unsafe"
)

// accept accepts a connection on fd. The syscall is made by hand because
// [syscall.Accept] allocates the [syscall.Sockaddr] it returns, one per
// accepted connection: the kernel is given address storage this call owns
// instead, and the address is read out of it.
func accept(fd int) (nfd int, remote Addr, err error) {
	var rsa syscall.RawSockaddrAny
	salen := uint32(unsafe.Sizeof(rsa))
	r1, _, errno := syscall.Syscall6(sysaccept, uintptr(fd),
		uintptr(unsafe.Pointer(&rsa)), uintptr(unsafe.Pointer(&salen)), 0, 0, 0)
	if errno != 0 {
		return -1, remote, errno
	}
	if rsa.Addr.Family == syscall.AF_INET {
		sa4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&rsa))
		// Port is in network byte order whatever the host byte order.
		p := (*[2]byte)(unsafe.Pointer(&sa4.Port))
		port := uint16(p[0])<<8 | uint16(p[1])
		remote = Addr(netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), port))
	}
	return int(r1), remote, nil
}
