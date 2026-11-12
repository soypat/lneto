//go:build !tinygo && linux && (amd64 || arm64)

package rawsock

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	errXDPNotOpen   = errors.New("xdp: socket not open")
	errXDPFrameSize = errors.New("xdp: frame size out of range")
	errXDPTxFull    = errors.New("xdp: all transmit frames in flight")
)

// XDP is an AF_XDP socket bound to one NIC queue. Frames its XDP program
// redirects skip the kernel network stack and arrive only here. XDP is a
// netdev.DevEthernet and also reads and writes frames like a TAP device.
//
// The receive methods (EthPoll, Read, Poll) may run concurrently with the
// transmit methods (SendOffsetEthFrame, Write), but neither group is safe
// for concurrent use by itself.
type XDP struct {
	fd        int
	name      string
	mtu       int
	hw        [6]byte
	mode      XDPMode
	frameSize uint32
	umem      []byte
	fill, rx  xskRing // Receive path.
	tx, comp  xskRing // Transmit path.
	// txFree holds UMEM addresses of transmit frames the kernel is done with.
	txFree  []uint64
	prog    xdpProg
	mu      sync.Mutex // Held while handler runs.
	handler func(rxEthframe []byte)
}

// Open binds the socket to cfg.Interface and attaches an XDP program
// redirecting every frame on cfg.Queue to it. The kernel sees none of that
// queue's traffic until Close or process exit. Needs CAP_NET_ADMIN,
// CAP_NET_RAW and CAP_BPF.
func (x *XDP) Open(cfg XDPConfig) error {
	if x.umem != nil {
		return errors.New("xdp: already open")
	}
	cfg, err := cfg.withDefaults()
	if err != nil {
		return err
	}
	ifc, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return err
	} else if len(ifc.HardwareAddr) != 6 {
		return errors.New("xdp: interface has no 6-byte hardware address")
	}
	*x = XDP{
		fd:        -1,
		prog:      xdpProg{mapFD: -1, progFD: -1, linkFD: -1},
		name:      ifc.Name,
		mtu:       ifc.MTU,
		frameSize: cfg.FrameSize,
	}
	copy(x.hw[:], ifc.HardwareAddr)
	err = x.open(cfg, ifc.Index)
	if err != nil {
		x.release()
		*x = XDP{}
	}
	return err
}

func (x *XDP) open(cfg XDPConfig, ifindex int) error {
	zeroCopy, err := x.bind(cfg, ifindex)
	if err != nil {
		return err
	}
	return x.attach(cfg, ifindex, zeroCopy)
}

// bind sets up UMEM and rings and binds the socket to the interface queue.
// Reports whether the kernel bound in zero-copy mode.
func (x *XDP) bind(cfg XDPConfig, ifindex int) (zeroCopy bool, err error) {
	x.fd, err = syscall.Socket(afXDP, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		x.fd = -1
		return false, fmt.Errorf("xdp socket: %w", err)
	}
	x.umem, err = syscall.Mmap(-1, 0, int(cfg.NumFrames)*int(cfg.FrameSize), syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_POPULATE)
	if err != nil {
		return false, fmt.Errorf("xdp umem: %w", err)
	}
	reg := xdpUmemReg{addr: uint64(uintptr(unsafe.Pointer(&x.umem[0]))), len: uint64(len(x.umem)), chunkSize: cfg.FrameSize}
	if err = setsockopt(x.fd, xdpOptUmemReg, unsafe.Pointer(&reg), unsafe.Sizeof(reg)); err == syscall.ENOBUFS {
		return false, fmt.Errorf("xdp umem register: %w: UMEM exceeds RLIMIT_MEMLOCK, raise it or grant CAP_IPC_LOCK", err)
	} else if err != nil {
		return false, fmt.Errorf("xdp umem register: %w", err)
	}
	half := cfg.NumFrames / 2
	if err = x.mapRings(half); err != nil {
		return false, err
	}

	// Without a copy or zero-copy flag the kernel tries zero-copy first.
	flags := uint16(xdpBindUseNeedWakeup)
	switch cfg.Mode {
	case XDPModeZeroCopy:
		flags |= xdpBindZeroCopy
	case XDPModeDriver, XDPModeGeneric:
		flags |= xdpBindCopy
	}
	sa := sockaddrXDP{family: afXDP, flags: flags, ifindex: uint32(ifindex), queueID: cfg.Queue}
	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(x.fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		return false, fmt.Errorf("xdp bind %s queue %d: %w", x.name, cfg.Queue, errno)
	}
	var opts uint32
	if _, err = getsockopt(x.fd, xdpOptOptions, unsafe.Pointer(&opts), unsafe.Sizeof(opts)); err != nil {
		return false, fmt.Errorf("xdp options: %w", err)
	}

	// Hand the kernel every receive frame before traffic is redirected.
	frameSize := uint64(cfg.FrameSize)
	for i := range half {
		*x.fill.addr(i) = uint64(i) * frameSize
	}
	x.fill.storeProducer(half)
	x.txFree = make([]uint64, half)
	for i := range x.txFree {
		x.txFree[i] = uint64(int(half)+i) * frameSize
	}
	return opts&xdpOptionsZeroCopy != 0, nil
}

// attach loads the program redirecting the socket's queue to it and attaches
// it to the interface in the fastest mode cfg allows.
func (x *XDP) attach(cfg XDPConfig, ifindex int, zeroCopy bool) (err error) {
	if err = x.prog.load(xdpRules{}, x.fd, cfg.Queue); err != nil {
		return err
	}
	if cfg.Mode == XDPModeGeneric {
		x.mode = XDPModeGeneric
		err = x.prog.link(ifindex, xdpFlagsSKBMode)
	} else {
		x.mode = XDPModeDriver
		if zeroCopy {
			x.mode = XDPModeZeroCopy
		}
		err = x.prog.link(ifindex, xdpFlagsDrvMode)
		if err != nil && cfg.Mode == XDPModeAuto && !zeroCopy {
			x.mode = XDPModeGeneric // Driver has no native XDP.
			err = x.prog.link(ifindex, xdpFlagsSKBMode)
		}
	}
	if err != nil {
		return fmt.Errorf("xdp attach %s in %s mode: %w", x.name, x.mode, err)
	}
	return nil
}

// Mode returns the mode the socket attached in.
func (x *XDP) Mode() XDPMode { return x.mode }

// Close detaches the XDP program, handing the queue back to the kernel, and
// frees the socket and its memory.
func (x *XDP) Close() error {
	if x.umem == nil {
		return errXDPNotOpen
	}
	err := x.release()
	*x = XDP{}
	return err
}

// release frees whatever Open acquired. The program goes first so the kernel
// stops redirecting before the socket goes away.
func (x *XDP) release() error {
	err := x.prog.close()
	if x.fd >= 0 {
		err = errors.Join(err, syscall.Close(x.fd))
	}
	x.fill.unmap()
	x.rx.unmap()
	x.tx.unmap()
	x.comp.unmap()
	if x.umem != nil {
		err = errors.Join(err, syscall.Munmap(x.umem))
	}
	return err
}

// HardwareAddr6 returns the interface's MAC address.
func (x *XDP) HardwareAddr6() ([6]byte, error) {
	if x.umem == nil {
		return [6]byte{}, errXDPNotOpen
	}
	return x.hw, nil
}

// MaxFrameSizeAndOffset returns the largest Ethernet frame the interface MTU
// and UMEM frames allow, at offset zero.
func (x *XDP) MaxFrameSizeAndOffset() (maxFrameSize int, sendEthFrameOff int) {
	return min(int(x.frameSize)-xdpPacketHeadroom, x.mtu+14), 0
}

// SendOffsetEthFrame copies frame into a transmit UMEM frame and hands it to
// the kernel. Fails if every transmit frame is still in flight.
func (x *XDP) SendOffsetEthFrame(frame []byte) error {
	if x.umem == nil {
		return errXDPNotOpen
	} else if maxFrame, _ := x.MaxFrameSizeAndOffset(); len(frame) < 14 || len(frame) > maxFrame {
		return errXDPFrameSize
	}
	x.reapTx()
	if len(x.txFree) == 0 {
		if err := x.kick(syscall.SYS_SENDTO); err != nil {
			return err
		}
		x.reapTx()
		if len(x.txFree) == 0 {
			return errXDPTxFull
		}
	}
	addr := x.txFree[len(x.txFree)-1]
	x.txFree = x.txFree[:len(x.txFree)-1]
	copy(x.umem[addr:], frame)
	prod := x.tx.loadProducer()
	*x.tx.desc(prod) = xdpDesc{addr: addr, len: uint32(len(frame))}
	x.tx.storeProducer(prod + 1)
	if x.mode != XDPModeZeroCopy || x.tx.needWakeup() {
		return x.kick(syscall.SYS_SENDTO) // Copy mode only transmits on syscall.
	}
	return nil
}

// reapTx moves transmit frames the kernel completed back to txFree.
func (x *XDP) reapTx() {
	cons := x.comp.loadConsumer()
	prod := x.comp.loadProducer()
	if cons == prod {
		return
	}
	for i := cons; i != prod; i++ {
		x.txFree = append(x.txFree, *x.comp.addr(i))
	}
	x.comp.storeConsumer(prod)
}

// SetEthRecvHandler sets the function EthPoll passes received frames to. The
// frame aliases UMEM and must not be retained. Does not return while the
// previous handler is running.
func (x *XDP) SetEthRecvHandler(handler func(rxEthframe []byte)) {
	x.mu.Lock()
	x.handler = handler
	x.mu.Unlock()
}

// EthPoll receives without blocking. With no handler set it copies one frame
// into buf. With a handler set it passes every pending frame to the handler
// and ignores buf.
func (x *XDP) EthPoll(buf []byte) (ethFrameOff, ethernetBytes int, err error) {
	if x.umem == nil {
		return 0, 0, errXDPNotOpen
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	cons := x.rx.loadConsumer()
	prod := x.rx.loadProducer()
	if cons == prod {
		if x.fill.needWakeup() {
			return 0, 0, x.kick(syscall.SYS_RECVFROM)
		}
		return 0, 0, nil
	}
	if x.handler == nil {
		prod = cons + 1
	}
	fillProd := x.fill.loadProducer()
	for i := cons; i != prod; i++ {
		d := x.rx.desc(i)
		frame := x.umem[d.addr : d.addr+uint64(d.len)]
		if x.handler != nil {
			x.handler(frame)
		} else if ethernetBytes = copy(buf, frame); ethernetBytes < len(frame) {
			ethernetBytes, err = 0, io.ErrShortBuffer // Frame dropped.
		}
		*x.fill.addr(fillProd) = d.addr &^ uint64(x.frameSize-1)
		fillProd++
	}
	x.rx.storeConsumer(prod)
	x.fill.storeProducer(fillProd)
	return 0, ethernetBytes, err
}

// Read blocks until a frame arrives and copies it into b.
func (x *XDP) Read(b []byte) (int, error) {
	for {
		_, n, err := x.EthPoll(b)
		if n > 0 || err != nil {
			return n, err
		}
		if _, err = x.Poll(-1); err != nil {
			return 0, err
		}
	}
}

// Write sends b as one Ethernet frame.
func (x *XDP) Write(b []byte) (int, error) {
	if err := x.SendOffsetEthFrame(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Poll waits up to timeout for a frame to receive. A negative timeout waits
// indefinitely. Returns false if timeout was reached.
func (x *XDP) Poll(timeout time.Duration) (bool, error) {
	if x.umem == nil {
		return false, errXDPNotOpen
	} else if x.rx.loadProducer() != x.rx.loadConsumer() {
		return true, nil
	}
	return ppoll(x.fd, timeout)
}

// HardwareAddress6 returns the interface's MAC address.
func (x *XDP) HardwareAddress6() ([6]byte, error) { return x.HardwareAddr6() }

// MTU returns the interface's MTU.
func (x *XDP) MTU() (int, error) {
	if x.umem == nil {
		return 0, errXDPNotOpen
	}
	return x.mtu, nil
}

// IPMask returns the IPv4 address and subnet the kernel has configured on
// the interface.
func (x *XDP) IPMask() (netip.Prefix, error) {
	if x.umem == nil {
		return netip.Prefix{}, errXDPNotOpen
	}
	ifc, err := net.InterfaceByName(x.name)
	if err != nil {
		return netip.Prefix{}, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipn.IP)
		if addr = addr.Unmap(); ok && addr.Is4() {
			ones, _ := ipn.Mask.Size()
			return netip.PrefixFrom(addr, ones), nil
		}
	}
	return netip.Prefix{}, errors.New("xdp: interface has no IPv4 address")
}
