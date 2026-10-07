//go:build !tinygo

package rawsock

import (
	"net/netip"
	"syscall"
)

// accept accepts a connection on fd. linux/386 has no accept4 syscall number:
// socket calls go through socketcall(2), which only the syscall package wraps,
// so this allocates the returned [syscall.Sockaddr].
func accept(fd int) (nfd int, remote Addr, err error) {
	nfd, sa, err := syscall.Accept4(fd, 0)
	if err != nil {
		return -1, remote, err
	}
	if sa4, ok := sa.(*syscall.SockaddrInet4); ok {
		remote = Addr(netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), uint16(sa4.Port)))
	}
	return nfd, remote, nil
}
