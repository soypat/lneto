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
	fd   int // points to /dev/net/tun device.
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
	tap := Tap{
		name: name,
		fd:   fd,
	}
	ifr := tap.ifreq()

	// Set the flags (starting at offset IFNAMSIZ).
	flags := uint16(syscall.IFF_TAP | syscall.IFF_NO_PI)
	ifr.setflags(flags)
	// Issue the ioctl to create the interface.
	err = ioctl(fd, syscall.TUNSETIFF, ifr.ptr())
	if err != nil {
		return nil, fmt.Errorf("creating tap interface: %w", err)
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

func ioctl(fd int, request uintptr, argp unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(argp))
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func (tap *Tap) HardwareAddress6() (hw [6]byte, err error) {
	// We cannot use tap.sock to query the hardware address, this is something known by the network stack, so get a sock to network stack.
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if err != nil {
		return hw, fmt.Errorf("socket open: %w", err)
	}
	defer syscall.Close(sock)
	ifr := tap.ifreq()

	err = ioctl(sock, syscall.SIOCGIFHWADDR, ifr.ptr())
	if err != nil {
		return hw, err
	}
	sa_family := *(*uint16)(unsafe.Pointer(&ifr.Data[0]))
	if sa_family != 1 {
		return hw, fmt.Errorf("expecting sa_family=1 got %d", sa_family)
	}
	copy(hw[:], ifr.Data[2:]) // first two bytes are sa_family
	return hw, nil
}

type ifreq struct {
	Name [syscall.IFNAMSIZ]byte
	Data [64]byte // union data (covers ifr_hwaddr, etc.)
}

func (ifr *ifreq) setflags(flags uint16) {
	*(*uint16)(unsafe.Pointer(&ifr.Data[0])) = flags
}

func (ifr *ifreq) ptr() unsafe.Pointer { return unsafe.Pointer(ifr) }

func (tap *Tap) ifreq() ifreq {
	// Set the name; it will be zero-padded automatically.
	var ifr ifreq
	copy(ifr.Name[:], tap.name)
	return ifr
}
