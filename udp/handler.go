package udp

import (
	"fmt"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

type Handler struct {
	connid   uint64
	rxRing   internal.Ring
	rxDgrams []struct {
		length uint16
	}

	txRing   internal.Ring
	txDgrams []struct {
		length uint16
	}
	closeCalled bool
	lport       uint16
	rport       uint16
}

func (h *Handler) Configure(cfg ConnConfig) error {
	if len(cfg.RxBuf) < sizeHeader || len(cfg.TxBuf) < sizeHeader || cfg.RxQueueSize <= 0 || cfg.TxQueueSize <= 0 {
		return lneto.ErrInvalidConfig
	}
	h.connid++
	h.rxRing = internal.Ring{Buf: cfg.RxBuf}
	h.txRing = internal.Ring{Buf: cfg.TxBuf}
	internal.SliceReuse(&h.rxDgrams, cfg.RxQueueSize)
	internal.SliceReuse(&h.txDgrams, cfg.TxQueueSize)
	h.closeCalled = false
	h.lport = 0
	h.rport = 0
	return nil
}

// Open sets the local port and remote address for the connection.
func (h *Handler) SetPorts(localPort, remotePort uint16) error {
	if localPort == 0 {
		return lneto.ErrZeroSource
	} else if remotePort == 0 {
		return lneto.ErrZeroDestination
	}
	h.lport = localPort
	h.rport = remotePort
	return nil
}

func (h *Handler) LocalPort() uint16 {
	return h.lport
}

func (h *Handler) Recv(buf []byte) error {
	if h.closeCalled {
		return net.ErrClosed
	}
	ufrm, err := NewFrame(buf)
	if err != nil {
		return err
	} else if ufrm.DestinationPort() != h.lport || ufrm.SourcePort() != h.rport {
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

	free := cap(h.rxDgrams) - len(h.rxDgrams)
	if free == 0 {
		return lneto.ErrExhausted
	}
	payload := ufrm.Payload()
	_, err = h.rxRing.Write(payload)
	if err != nil {
		return err
	}
	dgram := internal.SliceReclaim(&h.rxDgrams)
	dgram.length = uint16(len(payload))
	return nil
}

func (h *Handler) Send(buf []byte) (int, error) {
	if h.closeCalled {
		return 0, net.ErrClosed
	} else if len(h.txDgrams) == 0 {
		return 0, nil
	}
	ufrm, err := NewFrame(buf)
	if err != nil {
		return 0, err
	}
	dgram := internal.SliceDequeueFront(&h.txDgrams)
	avail := len(buf) - 8
	if avail < int(dgram.length) {
		return 0, lneto.ErrShortBuffer
	}
	n, err := h.txRing.Read(buf[8 : 8+dgram.length])
	if err != nil || n != int(dgram.length) {
		panic(fmt.Sprintf("udp send handler failure %d %s", n, err))
	}
	ufrm.SetSourcePort(h.lport)
	ufrm.SetDestinationPort(h.rport)
	ufrm.SetLength(8 + dgram.length)
	return int(8 + dgram.length), nil
}

func (h *Handler) Write(b []byte) (int, error) {
	free := cap(h.txDgrams) - len(h.txDgrams)
	if free == 0 {
		return 0, lneto.ErrExhausted
	}
	_, err := h.txRing.Write(b)
	if err != nil {
		return 0, err
	}
	dgram := internal.SliceReclaim(&h.txDgrams)
	dgram.length = uint16(len(b))
	return len(b), nil
}

func (h *Handler) Read(b []byte) (int, error) {
	avail := cap(h.rxDgrams) - len(h.rxDgrams)
	if avail == 0 {
		return 0, nil
	}
	// SOCK_DGRAM semantics. Read up to len(b) bytes and discard unread portion of datagram.
	dgram := internal.SliceDequeueFront(&h.rxDgrams)
	n, err := h.rxRing.Read(b[:min(len(b), int(dgram.length))])
	if err != nil {
		panic(fmt.Sprintf("udp read handler failure %d %s", n, err))
	}
	discard := int(dgram.length) - len(b)
	if discard > 0 {
		err = h.rxRing.ReadDiscard(discard)
		if err != nil {
			panic(fmt.Sprintf("udp readdiscard handler failure %d %s", n, err))
		}
	}
	return n, nil
}

// Close closes the connection. Calls to [Handler.Send] and [Handler.Recv] will
// return [net.ErrClosed] after Close is called.
func (h *Handler) Close() {
	h.closeCalled = true
}

func (h *Handler) Abort() {
	*h = Handler{
		connid:   h.connid + 1,
		rxRing:   h.rxRing,
		rxDgrams: h.rxDgrams[:0],
		txRing:   h.txRing,
		txDgrams: h.txDgrams,
	}
	h.txRing.Reset()
	h.rxRing.Reset()
}

// BufferedInputNext returns the size of the next datagram to read. A call
// to [Handler.Read] will read up to this amount of bytes.
func (h *Handler) BufferedInputNext() int {
	if len(h.rxDgrams) == 0 {
		return 0
	}
	return int(h.rxDgrams[0].length)
}

// BufferedInput returns the number of unread bytes in the receive buffer.
func (h *Handler) BufferedInput() int {
	return h.rxRing.Buffered()
}

// BufferedUnsent returns the number of written but unsent bytes in the transmit buffer.
func (h *Handler) BufferedOutput() int {
	return h.txRing.Buffered()
}

// SizeInput returns the total size of the receive ring buffer.
func (h *Handler) SizeInput() int {
	return h.rxRing.Size()
}

// SizeOutput returns the total size of the transmit ring buffer.
func (h *Handler) SizeOutput() int {
	return h.txRing.Size()
}
