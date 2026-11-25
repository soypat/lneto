//go:build !tinygo && linux && (amd64 || arm64)

package rawsock

import (
	"fmt"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	afXDP  = 44
	solXDP = 283

	// Socket options at level solXDP.
	xdpOptMmapOffsets    = 1
	xdpOptRxRing         = 2
	xdpOptTxRing         = 3
	xdpOptUmemReg        = 4
	xdpOptFillRing       = 5
	xdpOptCompletionRing = 6
	xdpOptOptions        = 8
	xdpOptionsZeroCopy   = 1 << 0
	xdpRingNeedWakeup    = 1 << 0

	// sockaddrXDP flags.
	xdpBindCopy          = 1 << 1
	xdpBindZeroCopy      = 1 << 2
	xdpBindUseNeedWakeup = 1 << 3

	// mmap offsets selecting each ring.
	xdpPgoffRxRing         = 0
	xdpPgoffTxRing         = 0x80000000
	xdpPgoffFillRing       = 0x100000000
	xdpPgoffCompletionRing = 0x180000000

	// xdpPacketHeadroom is the space the kernel reserves before each received frame.
	xdpPacketHeadroom = 256

	pollIn = 0x1
)

type (
	xdpUmemReg struct {
		addr, len           uint64
		chunkSize, headroom uint32
	}
	xdpRingOffset struct {
		producer, consumer, desc, flags uint64
	}
	xdpMmapOffsets struct {
		rx, tx, fill, completion xdpRingOffset
	}
	xdpDesc struct {
		addr    uint64
		len     uint32
		options uint32
	}
	sockaddrXDP struct {
		family, flags                  uint16
		ifindex, queueID, sharedUmemFD uint32
	}
	pollFd struct {
		fd              int32
		events, revents int16
	}
)

// xskRing is a single-producer single-consumer ring shared with the kernel.
// Fill and completion rings hold UMEM addresses, rx and tx rings hold
// descriptors. Indices run free and wrap through mask.
type xskRing struct {
	mem      []byte
	producer *uint32
	consumer *uint32
	flags    *uint32
	entries  unsafe.Pointer
	mask     uint32
}

// mapRing maps the ring at pgoff with the given number of entries.
func mapRing(fd int, pgoff int64, off xdpRingOffset, entries uint32, entrySize uintptr) (xskRing, error) {
	size := int(off.desc) + int(entries)*int(entrySize)
	mem, err := syscall.Mmap(fd, pgoff, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		return xskRing{}, fmt.Errorf("xdp ring mmap: %w", err)
	}
	return xskRing{
		mem:      mem,
		producer: (*uint32)(unsafe.Pointer(&mem[off.producer])),
		consumer: (*uint32)(unsafe.Pointer(&mem[off.consumer])),
		flags:    (*uint32)(unsafe.Pointer(&mem[off.flags])),
		entries:  unsafe.Pointer(&mem[off.desc]),
		mask:     entries - 1,
	}, nil
}

func (r *xskRing) loadProducer() uint32   { return atomic.LoadUint32(r.producer) }
func (r *xskRing) loadConsumer() uint32   { return atomic.LoadUint32(r.consumer) }
func (r *xskRing) storeProducer(i uint32) { atomic.StoreUint32(r.producer, i) }
func (r *xskRing) storeConsumer(i uint32) { atomic.StoreUint32(r.consumer, i) }

// needWakeup reports whether the kernel waits on a syscall to process the ring.
func (r *xskRing) needWakeup() bool { return atomic.LoadUint32(r.flags)&xdpRingNeedWakeup != 0 }

// addr returns fill or completion ring entry i.
func (r *xskRing) addr(i uint32) *uint64 {
	return (*uint64)(unsafe.Add(r.entries, uintptr(i&r.mask)*unsafe.Sizeof(uint64(0))))
}

// desc returns rx or tx ring entry i.
func (r *xskRing) desc(i uint32) *xdpDesc {
	return (*xdpDesc)(unsafe.Add(r.entries, uintptr(i&r.mask)*unsafe.Sizeof(xdpDesc{})))
}

func (r *xskRing) unmap() {
	if r.mem != nil {
		syscall.Munmap(r.mem)
	}
}

// mapRings sizes all four rings to entries and maps them.
func (x *XDP) mapRings(entries uint32) (err error) {
	for _, opt := range [...]int{xdpOptRxRing, xdpOptTxRing, xdpOptFillRing, xdpOptCompletionRing} {
		if err = syscall.SetsockoptInt(x.fd, solXDP, opt, int(entries)); err != nil {
			return fmt.Errorf("xdp ring size: %w", err)
		}
	}
	var off xdpMmapOffsets
	n, err := getsockopt(x.fd, xdpOptMmapOffsets, unsafe.Pointer(&off), unsafe.Sizeof(off))
	if err != nil {
		return fmt.Errorf("xdp mmap offsets: %w", err)
	} else if n != unsafe.Sizeof(off) {
		return fmt.Errorf("xdp mmap offsets: got %d bytes, kernel too old", n)
	}
	const descSize, addrSize = unsafe.Sizeof(xdpDesc{}), unsafe.Sizeof(uint64(0))
	if x.rx, err = mapRing(x.fd, xdpPgoffRxRing, off.rx, entries, descSize); err != nil {
		return err
	}
	if x.tx, err = mapRing(x.fd, xdpPgoffTxRing, off.tx, entries, descSize); err != nil {
		return err
	}
	if x.fill, err = mapRing(x.fd, xdpPgoffFillRing, off.fill, entries, addrSize); err != nil {
		return err
	}
	x.comp, err = mapRing(x.fd, xdpPgoffCompletionRing, off.completion, entries, addrSize)
	return err
}

// kick makes the kernel process the rx (recvfrom) or tx (sendto) ring.
// Busy and retry errors are dropped: the next kick picks up the rest.
func (x *XDP) kick(syscallNum uintptr) error {
	_, _, errno := syscall.Syscall6(syscallNum, uintptr(x.fd), 0, 0, syscall.MSG_DONTWAIT, 0, 0)
	switch errno {
	case 0, syscall.EAGAIN, syscall.EBUSY, syscall.ENOBUFS:
		return nil
	}
	return fmt.Errorf("xdp kick: %w", errno)
}

func setsockopt(fd, opt int, p unsafe.Pointer, size uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), solXDP, uintptr(opt), uintptr(p), size, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// getsockopt reads option opt into p and returns the size the kernel wrote.
func getsockopt(fd, opt int, p unsafe.Pointer, size uintptr) (uintptr, error) {
	n := uint32(size)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), solXDP, uintptr(opt), uintptr(p), uintptr(unsafe.Pointer(&n)), 0)
	if errno != 0 {
		return 0, errno
	}
	return uintptr(n), nil
}

// ppoll waits up to timeout for fd to be readable. A negative timeout waits
// indefinitely.
func ppoll(fd int, timeout time.Duration) (bool, error) {
	pfd := pollFd{fd: int32(fd), events: pollIn}
	deadline := time.Now().Add(timeout)
	for {
		var ts *syscall.Timespec
		if timeout >= 0 {
			t := syscall.NsecToTimespec(int64(max(time.Until(deadline), 0)))
			ts = &t
		}
		n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&pfd)), 1, uintptr(unsafe.Pointer(ts)), 0, 0, 0)
		if errno == syscall.EINTR {
			continue // Runtime signal; wait out the rest.
		} else if errno != 0 {
			return false, errno
		}
		return n > 0, nil
	}
}
