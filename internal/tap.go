//go:build linux && !baremetal

package internal

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

type Tap struct {
	fd   int
	name string
}

func NewTap(name string, ip netip.Prefix) (*Tap, error) {
	if len(name) >= syscall.IFNAMSIZ {
		return nil, errors.New("name too large")
	}
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0777)
	if err != nil {
		return nil, fmt.Errorf("failed to open tun device: %w", err)
	}

	var ifr [syscall.IFNAMSIZ + 64]byte // extra space for compatibility

	// Set the name; it will be zero-padded automatically.
	copy(ifr[:syscall.IFNAMSIZ-1], name)

	// Set the flags (starting at offset IFNAMSIZ).
	flags := uint16(syscall.IFF_TAP | syscall.IFF_NO_PI)
	*(*uint16)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ])) = flags
	// Issue the ioctl to create the interface.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return nil, fmt.Errorf("creating tap interface: %w", errno)
	}
	if ip.IsValid() {
		// Optionally, bring the interface up and assign an IP address.
		// You can do this using the 'ip' command for simplicity.
		err = exec.Command("ip", "link", "set", "dev", name, "up").Run()
		if err != nil {
			return nil, fmt.Errorf("failed to set ip link: %w", err)
		}

		err = exec.Command("ip", "addr", "add", ip.String(), "dev", name).Run()
		if err != nil {
			return nil, fmt.Errorf("failed to assign IP address: %w", err)
		}
	}
	return &Tap{fd: fd, name: name}, nil
}

func (tap *Tap) Read(b []byte) (int, error) {
	return syscall.Read(tap.fd, b)
}

func (tap *Tap) Write(b []byte) (int, error) {
	return syscall.Write(tap.fd, b)
}

func (tap *Tap) Close() error {
	return syscall.Close(tap.fd)
}
