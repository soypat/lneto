package udp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

type MuxConfig struct {
	// Configure receive buffer. If not set will use previously set buffer in [MuxHandler.Configure].
	RxBuf []byte
	// Configure transmit buffer. If not set will use previously set buffer in [MuxHandler.Configure].
	TxBuf       []byte
	RxQueueSize int
	TxQueueSize int
}

// MuxHandler
type MuxHandler struct {
	connid uint64
	// filterLPorts stores rx port ranges over which Handler can receive data.
	// If not set will not filter UDP data.
	filterLPorts []struct {
		startPort uint16
		nports    uint16 // must be at least 1 to be valid.
	}
	// filterRAddrs. If not set will receive any data.
	// filterRAddrs []struct {
	// 	addr netip.Prefix
	// }
	rxRing   internal.Ring
	rxDgrams []struct {
		length uint16
		lport  uint16
		rport  uint16
		raddr  netip.Addr
	}
	txRing   internal.Ring
	txDgrams []struct {
		length uint16
		lport  uint16
		rport  uint16
		raddr  netip.Addr
	}
	closeCalled bool
}

// Configure initializes the handler with the given buffer and queue configuration.
// Increments the connection ID, invalidating any prior stack registration.
func (mh *MuxHandler) Configure(cfg MuxConfig) error {
	if cfg.RxBuf == nil {
		cfg.RxBuf = mh.rxRing.Buf
	}
	if cfg.TxBuf == nil {
		cfg.TxBuf = mh.txRing.Buf
	}
	if len(cfg.RxBuf) < sizeHeader || len(cfg.TxBuf) < sizeHeader || cfg.RxQueueSize <= 0 || cfg.TxQueueSize <= 0 {
		return lneto.ErrInvalidConfig
	}
	mh.connid++
	mh.rxRing = internal.Ring{Buf: cfg.RxBuf}
	mh.txRing = internal.Ring{Buf: cfg.TxBuf}
	internal.SliceReuse(&mh.rxDgrams, cfg.RxQueueSize)
	internal.SliceReuse(&mh.txDgrams, cfg.TxQueueSize)
	mh.closeCalled = false
	return nil
}

// LocalPort not applicable to mux. Mux is a multi Rx/Tx port abstraction.
func (mh *MuxHandler) LocalPort() uint16 { return 0 }

func (mh *MuxHandler) FilterLocalPort(lport uint16) (filtered bool) {
	filtered = len(mh.filterLPorts) > 0
	for i := range mh.filterLPorts {
		maxPort := mh.filterLPorts[i].startPort + mh.filterLPorts[i].nports
		if lport >= mh.filterLPorts[i].startPort && lport < maxPort {
			filtered = false
			break
		}
	}
	return filtered
}

var X lneto.StackNode

// Recv parses a UDP frame from buf, validates the ports and length fields,
// and enqueues the payload into the rx ring buffer. Returns [lneto.ErrMismatch]
// if source/destination ports don't match the configured ports.
func (mh *MuxHandler) Demux(carrierData []byte, frameOffset int) error {
	if mh.closeCalled {
		return net.ErrClosed
	}
	ufrm, err := NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	// Rx port filter.
	lport := ufrm.DestinationPort()
	if mh.FilterLocalPort(lport) {
		return lneto.ErrMismatch
	}

	// Header size validation.
	// No CRC validation at this level.
	ul := ufrm.Length()
	if ul < sizeHeader {
		return lneto.ErrInvalidLengthField
	} else if int(ul) > len(ufrm.RawData()) {
		return lneto.ErrTruncatedFrame
	}

	free := cap(mh.rxDgrams) - len(mh.rxDgrams)
	if free == 0 {
		return lneto.ErrExhausted
	}

	payload := ufrm.Payload()
	_, err = mh.rxRing.Write(payload)
	if err != nil {
		return err
	}
	dgram := internal.SliceReclaim(&mh.rxDgrams)
	dgram.length = uint16(len(payload))
	dgram.lport = lport
	dgram.rport = ufrm.SourcePort()
	if frameOffset >= 20 {
		src, _, _, _, _ := internal.GetIPAddr(carrierData)
		dgram.raddr, _ = netip.AddrFromSlice(src)
	}
	return nil
}

func (mh *MuxHandler) Encapsulate(carrierData []byte, ipOffset, frameOffset int) (int, error) {
	if mh.closeCalled {
		return 0, net.ErrClosed
	} else if len(mh.txDgrams) == 0 {
		return 0, nil // No data to send.
	}
	buf := carrierData[frameOffset:]
	ufrm, err := NewFrame(buf)
	if err != nil {
		return 0, err
	}

	dgram := internal.SliceDequeueFront(&mh.txDgrams)
	avail := len(buf) - 8
	if avail < int(dgram.length) {
		// TODO(soypat): If packet is too long we discard it entirely. Maybe we prefer sending incomplete data? How do other stacks deal with this?
		mh.txRing.ReadDiscard(int(dgram.length))
		return 0, lneto.ErrShortBuffer
	}

	n, err := mh.txRing.Read(buf[8 : 8+dgram.length])
	if err != nil || n != int(dgram.length) {
		panic(fmt.Sprintf("udp send handler failure %d %s", n, err))
	}
	ufrm.SetSourcePort(dgram.lport)
	ufrm.SetDestinationPort(dgram.rport)
	ufrm.SetLength(8 + dgram.length)
	if ipOffset >= 0 && dgram.raddr.IsValid() {
		// Address write. Version check.
		var addroffset int
		switch carrierData[ipOffset] >> 4 {
		case 4:
			if !dgram.raddr.Is4() {
				return 0, lneto.ErrUnsupported
			}
			addroffset = ipOffset + 16

		case 6:
			if !dgram.raddr.Is6() {
				return 0, lneto.ErrUnsupported
			}
			addroffset = ipOffset + 24
		default:
			return 0, lneto.ErrUnsupported
		}
		dgram.raddr.AppendBinary(carrierData[addroffset:])
	}
	return int(8 + dgram.length), nil
}

func (mh *MuxHandler) WriteTo(lport uint16, raddr netip.AddrPort, buf []byte) error {
	if mh.closeCalled {
		return net.ErrClosed
	} else if raddr.Port() == 0 || raddr.IsValid() {
		return lneto.ErrZeroDestination
	} else if lport == 0 {
		return lneto.ErrZeroSource
	}
	avail := cap(mh.txDgrams) - len(mh.txDgrams)
	if avail == 0 {
		return lneto.ErrExhausted
	} else if mh.txRing.Free() < len(buf) {
		return lneto.ErrBufferFull
	}
	n, err := mh.txRing.Write(buf)
	if err != nil || n != len(buf) {
		return lneto.ErrBug
	}
	dgram := internal.SliceReclaim(&mh.txDgrams)
	dgram.length = uint16(len(buf))
	dgram.raddr = raddr.Addr()
	dgram.lport = lport
	dgram.rport = raddr.Port()
	return nil
}

// ReadNext dequeues the next received datagram into b. If b is smaller than the
// datagram, the remaining bytes are discarded (SOCK_DGRAM semantics).
// The port the datagram was destined to and address it was received from are returned.
// If bytes are discarded completeRead=false.
func (mh *MuxHandler) ReadNext(buf []byte) (n int, completeRead bool, lport uint16, raddr netip.AddrPort) {
	if len(mh.rxDgrams) == 0 {
		return 0, false, 0, raddr
	}
	dgram := internal.SliceDequeueFront(&mh.rxDgrams)
	dlen := int(dgram.length)
	maxRead := min(dlen, len(buf))
	n, _ = mh.rxRing.Read(buf[:maxRead])
	if n < dlen {
		mh.rxRing.ReadDiscard(dlen - n)
	}
	return n, n == dlen, dgram.lport, netip.AddrPortFrom(dgram.raddr, dgram.rport)
}

// BufferedInputNext returns the size of the next datagram to read. A call
// to [Handler.ReadNext] will read up to this amount of bytes.
func (mh *MuxHandler) BufferedInputNext() uint16 {
	if len(mh.rxDgrams) > 0 {
		return mh.rxDgrams[0].length
	}
	return 0
}

// BufferedInput returns the number of unread bytes in the receive buffer.
func (h *MuxHandler) BufferedInput() int {
	return h.rxRing.Buffered()
}

// BufferedUnsent returns the number of written but unsent bytes in the transmit buffer.
func (h *MuxHandler) BufferedOutput() int {
	return h.txRing.Buffered()
}

// SizeInput returns the total size of the receive ring buffer.
func (h *MuxHandler) SizeInput() int {
	return h.rxRing.Size()
}

// SizeOutput returns the total size of the transmit ring buffer.
func (h *MuxHandler) SizeOutput() int {
	return h.txRing.Size()
}

// FreeOutput returns the number of free bytes in the transmit buffer.
// This tells the user how many bytes can be written with Write method before write failing.
func (h *MuxHandler) FreeOutput() int {
	return h.txRing.Free()
}

// FreeInput returns the number of free bytes in the receive buffer.
func (h *MuxHandler) FreeInput() int {
	return h.rxRing.Free()
}

func (mh *MuxHandler) IsOpen() bool {
	return cap(mh.rxDgrams) > 0 && !mh.closeCalled
}

func (mh *MuxHandler) Close() {
	mh.closeCalled = true
}

func (mh *MuxHandler) Abort() {
	*mh = MuxHandler{
		connid:       mh.connid + 1,
		filterLPorts: mh.filterLPorts[:0],
		rxRing:       mh.rxRing,
		rxDgrams:     mh.rxDgrams[:0],
		txRing:       mh.txRing,
		txDgrams:     mh.txDgrams[:0],
	}
	mh.rxRing.Reset()
	mh.txRing.Reset()
}
