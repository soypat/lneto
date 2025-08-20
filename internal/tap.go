//go:build linux && !baremetal

package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const safamily_hw6 = 1

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
	ifr := makeifreq(name)
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

func (tap *Tap) IPMask() (netip.Prefix, error) {
	sockfd, err := tap.getSock()
	if err != nil {
		return netip.Prefix{}, err
	}
	return getSocketMask(sockfd, tap.name)
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

func (tap *Tap) MTU() (int, error) {
	sock, err := tap.getSock()
	if err != nil {
		return 0, err
	}
	defer syscall.Close(sock)
	return getSocketMTU(sock, tap.name)
}

func (tap *Tap) HardwareAddress6() (hw [6]byte, err error) {
	// We cannot use tap.sock to query the hardware address, this is something known by the network stack, so get a sock to network stack.
	sock, err := tap.getSock()
	if err != nil {
		return hw, err
	}
	defer syscall.Close(sock)
	return getSocketHW(sock, tap.name)
}

func (tap *Tap) getSock() (int, error) {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if err != nil {
		return 0, fmt.Errorf("tap socket open: %w", err)
	}
	return sock, err
}

func getSocketMTU(sockfd int, ifaceName string) (int, error) {
	ifr := makeifreq(ifaceName)
	err := ioctl(sockfd, syscall.SIOCGIFMTU, ifr.ptr())
	if err != nil {
		return 0, err
	}
	mtu := *(*int32)(unsafe.Pointer(&ifr.Data[0]))
	return int(mtu), nil
}

func getSocketHW(sockfd int, ifaceName string) (hw [6]byte, err error) {
	ifr := makeifreq(ifaceName)
	err = ioctl(sockfd, syscall.SIOCGIFHWADDR, ifr.ptr())
	if err != nil {
		return hw, err
	}
	sa_family := *(*uint16)(unsafe.Pointer(&ifr.Data[0])) // Host order.
	if sa_family != safamily_hw6 {
		return hw, fmt.Errorf("expecting sa_family=1 got %d", sa_family)
	}
	copy(hw[:], ifr.Data[2:]) // first two bytes are sa_family
	return hw, nil
}

func getSocketMask(sockfd int, ifaceName string) (netip.Prefix, error) {
	addrp, err := getSocketIP(sockfd, ifaceName)
	if err != nil {
		return netip.Prefix{}, err
	}
	ifr := makeifreq(ifaceName)
	err = ioctl(sockfd, syscall.SIOCGIFNETMASK, ifr.ptr())
	if err != nil {
		return netip.Prefix{}, err
	}
	addr32 := binary.BigEndian.Uint32(ifr.Data[4:8])
	cidr := bits.OnesCount32(addr32)
	return netip.PrefixFrom(addrp.Addr(), cidr), nil
}

func setSocketHW(sockfd int, ifaceName string, hw [6]byte) error {
	ifr := makeifreq(ifaceName)
	*(*uint16)(unsafe.Pointer(&ifr.Data[0])) = safamily_hw6
	copy(ifr.Data[2:], hw[:])
	err := ioctl(sockfd, syscall.SIOCSIFHWADDR, ifr.ptr())
	if err != nil {
		return fmt.Errorf("setting hw addr: %w", err)
	}
	return nil
}

func getSocketIP(sockfd int, ifaceName string) (addrp netip.AddrPort, err error) {
	ifr := makeifreq(ifaceName)
	err = ioctl(sockfd, syscall.SIOCGIFADDR, ifr.ptr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	safamily := *(*uint16)(unsafe.Pointer(&ifr.Data[0]))
	port := *(*uint16)(unsafe.Pointer(&ifr.Data[2]))
	switch safamily {
	case 2:
		addr, _ := netip.AddrFromSlice(ifr.Data[4:8])
		addrp = netip.AddrPortFrom(addr, port)
	default:
		return addrp, fmt.Errorf("unsupported IP addr sa_family=%d", safamily)
	}
	return addrp, nil
}

func makeifreq(name string) ifreq {
	// Set the name; it will be zero-padded automatically.
	var ifr ifreq
	copy(ifr.Name[:], name)
	return ifr
}

type ifreq struct {
	Name [syscall.IFNAMSIZ]byte
	Data [64]byte // union data (covers ifr_hwaddr, etc.)
}

func (ifr *ifreq) setflags(flags uint16) {
	*(*uint16)(unsafe.Pointer(&ifr.Data[0])) = flags
}

func (ifr *ifreq) ptr() unsafe.Pointer { return unsafe.Pointer(ifr) }

// Bridge serves as a virtual socket that "bridges" to an existing interface (could be TAP or an actual NIC that connects to internet).
// Bridge is used in this project to
type Bridge struct {
	fd    int
	name  string
	index int
}

func NewBridge(name string) (*Bridge, error) {
	iface, err := interfaceByName(name)
	if err != nil {
		return nil, err
	}
	proto := htons(syscall.ETH_P_ALL)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return nil, err
	}
	ll := syscall.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &ll); err != nil {
		return nil, err
	}
	return &Bridge{fd: fd, name: iface.Name, index: iface.Index}, nil
}

func (br *Bridge) Write(frame []byte) (int, error) {
	return syscall.Write(br.fd, frame)
}

func (br *Bridge) Read(frame []byte) (int, error) {
	return syscall.Read(br.fd, frame)
}

func (br *Bridge) Close() error {
	return syscall.Close(br.fd)
}

func (br *Bridge) HardwareAddress6() (hw [6]byte, err error) {
	return getSocketHW(br.fd, br.name)
}

func (br *Bridge) SetHardwareAddress6(hw [6]byte) error {
	return setSocketHW(br.fd, br.name, hw)
}

func (br *Bridge) IPMask() (netip.Prefix, error) {
	return getSocketMask(br.fd, br.name)
}

func (br *Bridge) Addr() (netip.Addr, error) {
	addrp, err := getSocketIP(br.fd, br.name)
	if err != nil {
		return netip.Addr{}, err
	}
	return addrp.Addr(), nil
}

func (br *Bridge) MTU() (int, error) {
	return getSocketMTU(br.fd, br.name)
}

// htons converts a uint16 from host to network byte order.
func htons(i uint16) uint16 { return (i<<8)&0xff00 | i>>8 }
