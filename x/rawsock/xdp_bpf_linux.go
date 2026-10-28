//go:build !tinygo && linux && (amd64 || arm64)

package rawsock

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// bpf(2) commands.
	bpfCmdMapCreate     = 0
	bpfCmdMapUpdateElem = 2
	bpfCmdProgLoad      = 5
	bpfCmdLinkCreate    = 28

	bpfMapTypeXSKMap   = 17
	bpfProgTypeXDP     = 6
	bpfAttachXDP       = 37
	bpfPseudoMapFD     = 1
	bpfFuncRedirectMap = 51

	// XDP attach flags for bpfCmdLinkCreate.
	xdpFlagsSKBMode = 1 << 1
	xdpFlagsDrvMode = 1 << 2

	xdpActPass = 2
	// xdpMdRxQueueIndex is the offset of rx_queue_index in struct xdp_md.
	xdpMdRxQueueIndex = 16
)

// xdpLicense must be GPL compatible for the kernel to accept the program.
var xdpLicense = []byte("Dual BSD/GPL\x00")

// xdpRules selects the in-kernel verdict for each frame on the socket's
// queue. The zero value redirects every frame to the socket.
type xdpRules struct{}

// appendProgram appends the XDP program enforcing r to dst. The program
// redirects to the socket stored in XSKMAP xskmapFD at the frame's queue.
func (r xdpRules) appendProgram(dst []bpfInsn, xskmapFD int) []bpfInsn {
	ld, ldhi := bpfLdMapFD(1, xskmapFD)
	return append(dst,
		bpfLdxW(2, 1, xdpMdRxQueueIndex), // r2 = ctx->rx_queue_index.
		ld, ldhi,                         // r1 = xskmap.
		bpfMov64Imm(3, xdpActPass),  // r3 = verdict when the queue has no socket.
		bpfCall(bpfFuncRedirectMap), // r0 = bpf_redirect_map(r1, r2, r3).
		bpfExit(),                   // return r0.
	)
}

// bpfInsn is one eBPF instruction, laid out as struct bpf_insn.
type bpfInsn struct {
	op   uint8
	regs uint8 // dst register in the low nibble, src in the high nibble.
	off  int16
	imm  int32
}

// bpfLdxW is dst = *(u32 *)(src + off).
func bpfLdxW(dst, src uint8, off int16) bpfInsn {
	return bpfInsn{op: 0x61, regs: src<<4 | dst, off: off}
}

// bpfLdMapFD is dst = map fd. Takes two instruction slots.
func bpfLdMapFD(dst uint8, fd int) (lo, hi bpfInsn) {
	return bpfInsn{op: 0x18, regs: bpfPseudoMapFD<<4 | dst, imm: int32(fd)}, bpfInsn{}
}

// bpfMov64Imm is dst = imm.
func bpfMov64Imm(dst uint8, imm int32) bpfInsn { return bpfInsn{op: 0xb7, regs: dst, imm: imm} }

// bpfCall calls helper fn with arguments in r1-r5, result in r0.
func bpfCall(fn int32) bpfInsn { return bpfInsn{op: 0x85, imm: fn} }

// bpfExit returns r0.
func bpfExit() bpfInsn { return bpfInsn{op: 0x95} }

// xdpProg is an XDP program redirecting to an XSKMAP, attached by a bpf link.
// Closing the link fd, or exiting the process, detaches the program.
type xdpProg struct {
	mapFD, progFD, linkFD int
}

// load creates the XSKMAP holding socket xsk at queue and loads the program
// enforcing rules.
func (p *xdpProg) load(rules xdpRules, xsk int, queue uint32) (err error) {
	mattr := bpfMapCreateAttr{mapType: bpfMapTypeXSKMap, keySize: 4, valueSize: 4, maxEntries: queue + 1}
	p.mapFD, err = bpf(bpfCmdMapCreate, unsafe.Pointer(&mattr), unsafe.Sizeof(mattr))
	if err != nil {
		return fmt.Errorf("xdp xskmap create: %w", err)
	}
	val := uint32(xsk)
	uattr := bpfMapUpdateAttr{mapFD: uint32(p.mapFD), key: unsafe.Pointer(&queue), value: unsafe.Pointer(&val)}
	_, err = bpf(bpfCmdMapUpdateElem, unsafe.Pointer(&uattr), unsafe.Sizeof(uattr))
	if err != nil {
		return fmt.Errorf("xdp xskmap update: %w", err)
	}
	var insns [8]bpfInsn
	p.progFD, err = bpfProgLoadXDP(rules.appendProgram(insns[:0], p.mapFD))
	return err
}

// link attaches the loaded program to ifindex with XDP attach flags.
func (p *xdpProg) link(ifindex int, flags uint32) (err error) {
	attr := bpfLinkCreateAttr{progFD: uint32(p.progFD), targetIfindex: uint32(ifindex), attachType: bpfAttachXDP, flags: flags}
	p.linkFD, err = bpf(bpfCmdLinkCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

// close detaches the program, then frees it and the map.
func (p *xdpProg) close() (err error) {
	for _, fd := range [...]int{p.linkFD, p.progFD, p.mapFD} {
		if fd >= 0 {
			err = errors.Join(err, syscall.Close(fd))
		}
	}
	return err
}

// bpfProgLoadXDP loads insns as an XDP program. On failure the error carries
// the verifier log.
func bpfProgLoadXDP(insns []bpfInsn) (int, error) {
	attr := bpfProgLoadAttr{
		progType:           bpfProgTypeXDP,
		insnCnt:            uint32(len(insns)),
		insns:              unsafe.Pointer(&insns[0]),
		license:            unsafe.Pointer(&xdpLicense[0]),
		expectedAttachType: bpfAttachXDP,
	}
	copy(attr.progName[:], "lneto_xsk")
	fd, err := bpf(bpfCmdProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err == nil {
		return fd, nil
	}
	// Load again with the verifier log on so the error says why.
	log := make([]byte, 64*1024)
	attr.logLevel, attr.logSize, attr.logBuf = 1, uint32(len(log)), unsafe.Pointer(&log[0])
	if fd, lerr := bpf(bpfCmdProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr)); lerr == nil {
		return fd, nil
	}
	if n := bytes.IndexByte(log, 0); n >= 0 {
		log = log[:n]
	}
	return -1, fmt.Errorf("xdp program load: %w: %s", err, log)
}

func bpf(cmd uintptr, attr unsafe.Pointer, size uintptr) (int, error) {
	fd, _, errno := syscall.Syscall(sysBPF, cmd, uintptr(attr), size)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// bpf(2) attributes, each a prefix of union bpf_attr. Pointer fields are
// unsafe.Pointer so the GC tracks them; this file builds only on 64-bit
// platforms, where they match the kernel's aligned u64.
type (
	bpfMapCreateAttr struct {
		mapType, keySize, valueSize, maxEntries, mapFlags uint32
	}
	bpfMapUpdateAttr struct {
		mapFD      uint32
		_          uint32
		key, value unsafe.Pointer
		flags      uint64
	}
	bpfProgLoadAttr struct {
		progType, insnCnt      uint32
		insns, license         unsafe.Pointer
		logLevel, logSize      uint32
		logBuf                 unsafe.Pointer
		kernVersion, progFlags uint32
		progName               [16]byte
		progIfindex            uint32
		expectedAttachType     uint32
	}
	bpfLinkCreateAttr struct {
		progFD, targetIfindex, attachType, flags uint32
	}
)
