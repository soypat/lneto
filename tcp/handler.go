package tcp

import (
	"errors"
	"io"
	"net"

	"log/slog"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

var (
	errMismatchedSrcPort = errors.New("source port mismatch")
	errMismatchedDstPort = errors.New("destination port mismatch")
)

// Handler is a low level TCP handling data structure. It implements logic
// related to data buffering, frame sequencing and connection state handling.
// Does NOT implement IP related logic, so no CRC calculation/validation or pseudo header logic.
// Does NOT implement connection lifetime handling, so NO deadlines, keepalives, backoffs or anything that requires use of time package.
//
// See [Conn] for a higher level abstraction of a TCP connection, and see [ControlBlock] for the lower level bits of a TCP connection.
type Handler struct {
	connid uint64
	scb    ControlBlock
	bufTx  ringTx
	bufRx  internal.Ring
	logger
	validator  lneto.Validator
	localPort  uint16
	remotePort uint16
	// connid is a conenction counter that is incremented each time a new
	// connection is established via Open calls. This disambiguate's whether
	// Read and Write calls belong to the current connection.

	optcodec OptionCodec
	closing  bool
}

func (h *Handler) SetLoggers(handler, scb *slog.Logger) {
	h.logger.log = handler
	h.scb.logger.log = scb
}

// ConnectionID returns the connection identifier which is incremented every time the connection is closed or open.
func (h *Handler) ConnectionID() *uint64 {
	return &h.connid
}

// State returns the state of the TCP state machine as per RFC9293. See [State].
func (h *Handler) State() State { return h.scb.State() }

// SetBuffers sets the internal buffers used to receive and transmit bytes asynchronously via [Handler.Write] and [Handler.Read] calls.
// If the argument buffer is nil then the respective currently set buffer will be reused.
func (h *Handler) SetBuffers(txbuf, rxbuf []byte, packets int) error {
	if h.bufRx.Buf == nil && (len(rxbuf) < minBufferSize || len(txbuf) < minBufferSize) {
		return errors.New("tcp: short buffer")
	}
	if !h.scb.State().IsClosed() {
		return errors.New("tcp.Handler must be closed before setting buffers")
	}
	if rxbuf != nil {
		h.bufRx.Buf = rxbuf
	}
	h.scb.SetRecvWindow(Size(h.bufRx.Size()))
	h.bufRx.Reset()
	return h.bufTx.ResetOrReuse(txbuf, packets, 0)
}

// LocalPort returns the local port of the connection. Returns 0 if the connection is closed and uninitialized.
func (h *Handler) LocalPort() uint16 {
	return h.localPort
}

// RemotePort returns the remote port of the connection if it is set.
// If the connection is passive and has not yet been established it will return 0.
func (h *Handler) RemotePort() uint16 {
	return h.remotePort
}

// OpenActive opens an "active" TCP connection to a known remote port. The caller holds knowledge of the IP address.
// OpenActive is used by TCP Clients to initiate a connection.
func (h *Handler) OpenActive(localPort, remotePort uint16, iss Value) error {
	if remotePort == 0 {
		return lneto.ErrZeroDestination
	} else if h.bufRx.Size() < minBufferSize || h.bufTx.Size() < minBufferSize {
		return errBufferTooSmall
	} else if h.scb.State() != StateClosed && h.scb.State() != StateTimeWait {
		return errNeedClosedTCBToOpen
	}
	// reset/Abort prepares a SCB for active connection by resetting state to closed.
	h.scb.reset()
	h.reset(localPort, remotePort, iss)
	h.scb.SetRecvWindow(Size(h.bufRx.Size()))
	return nil
}

// OpenListen prepares a passive TCP connection where the Handler acts as a server.
// OpenListen is used by TCP Servers to begin listening for remote connections.
func (h *Handler) OpenListen(localPort uint16, iss Value) error {
	if localPort == 0 {
		return lneto.ErrZeroSource
	} else if h.bufRx.Size() < minBufferSize || h.bufTx.Size() < minBufferSize {
		return errBufferTooSmall
	}
	// Open will fail unless SCB in closed state.
	err := h.scb.Open(iss, Size(h.bufRx.Size()))
	if err != nil {
		return err
	}
	h.reset(localPort, 0, iss)
	return nil
}

// Abort forcibly terminates all state associated to current connection.
// After a call to abort no more data can be sent nor received over the connection.
func (h *Handler) Abort() {
	h.info("tcp.Handler.Abort")
	h.scb.Abort()
	h.reset(0, 0, 0)
}

func (h *Handler) reset(localPort, remotePort uint16, iss Value) {
	*h = Handler{
		connid:     h.connid + 1,
		scb:        h.scb,
		bufTx:      h.bufTx,
		bufRx:      h.bufRx,
		localPort:  localPort,
		remotePort: remotePort,
		validator:  h.validator,
		logger:     h.logger,
		closing:    false,
	}
	h.bufTx.ResetOrReuse(nil, 0, iss)
	h.bufRx.Reset()
}

// Recv receives an incoming TCP packet frame with the first byte being the first octet of the TCP frame.
// The [Handler]'s internal state is updated if the packet is admitted successfully.
func (h *Handler) Recv(incomingPacket []byte) error {
	if h.IsTxOver() {
		return net.ErrClosed
	}
	tfrm, err := NewFrame(incomingPacket)
	if err != nil {
		return err
	}
	tfrm.ValidateExceptCRC(&h.validator)
	err = h.validator.ErrPop()
	if err != nil {
		return err
	}

	remotePort := tfrm.SourcePort()
	if h.remotePort != 0 && remotePort != h.remotePort {
		return errMismatchedSrcPort
	}
	dstPort := tfrm.DestinationPort()
	if h.localPort != dstPort {
		return errMismatchedDstPort
	}
	payload := tfrm.Payload()
	if len(payload) > h.bufRx.Free() {
		return errors.New("rx buffer full")
	}
	segIncoming := tfrm.Segment(len(payload))
	if h.scb.IncomingIsKeepalive(segIncoming) {
		h.info("tcp.Handler:rx-keepalive", slog.Uint64("port", uint64(h.localPort)))
		return nil
	}
	prevState := h.scb.State()
	err = h.scb.Recv(segIncoming)
	if err != nil {
		if h.scb.State() == StateClosed {
			// TODO(soypat): Should return EOF/ErrClosed?
			err = err // Connection closed by reset.
		}
		return err
	}
	if h.scb.State() == StateClosed {
		// TCB aborted, likely because it received an ACK in LastAck state.
		// Clean up connection now unless read pending.
		return net.ErrClosed
	}
	if prevState != h.scb.State() {
		h.info("tcp.Handler:rx-statechange", slog.Uint64("port", uint64(h.localPort)), slog.String("old", prevState.String()), slog.String("new", h.scb.State().String()), slog.String("rxflags", segIncoming.Flags.String()))
	}
	if segIncoming.DATALEN != 0 {
		_, err = h.bufRx.Write(payload)
		if err != nil {
			return err
		}
	}
	if segIncoming.Flags.HasAny(FlagSYN) && h.remotePort == 0 {
		// Remote reached out and has given us their port, set it on our side.
		h.debug("tcp.Handler:rx-remoteport-set", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("remoteport", uint64(remotePort)))
		h.remotePort = remotePort
	}
	if h.logenabled(internal.LevelTrace) {
		h.trace("tcp.Handler:rx-done", slog.Uint64("port", uint64(h.localPort)), slog.Uint64("remoteport", uint64(remotePort)), slog.String("seg", segIncoming.String()))
	}
	return nil
}

func (h *Handler) Close() error {
	h.trace("tcp.Handler.Close")
	if h.closing {
		return errConnectionClosing
	} else if h.State().IsClosed() {
		return net.ErrClosed
	}
	h.closing = true
	return nil
}

// Send writes TCP frame to be sent over the network to the remote peer to `b`.
// It does no IP interfacing or CRC calculation of packet, which is left to the caller to perform.
// The returned integer is the length written to the argument buffer.
func (h *Handler) Send(b []byte) (int, error) {
	h.trace("tcp.Handler:start", slog.Uint64("port", uint64(h.localPort)))
	if h.IsTxOver() {
		return 0, net.ErrClosed
	}
	tfrm, err := NewFrame(b)
	if err != nil {
		return 0, err
	}
	buffered := h.bufTx.BufferedUnsent()
	if buffered == 0 && h.closing {
		// If Close called and no more data to be sent, terminate connection!
		h.closing = false
		err = h.scb.Close()
		if err != nil {
			h.logerr("tcp.Handler.Close", slog.String("err", errstr(err)), slog.String("state", h.State().String()))
			h.Abort()
			return 0, io.EOF
		}
	}
	offset := uint8(5)
	var segment Segment
	if h.AwaitingSynSend() {
		// Handling init syn segment.
		segment = ClientSynSegment(h.bufTx.iss, Size(h.bufRx.Size()))
		h.optcodec.PutOption16(b[sizeHeaderTCP:], OptMaxSegmentSize, uint16(len(b)))
		offset++
	} else {
		var ok bool
		available := min(buffered, len(b)-sizeHeaderTCP)
		segment, ok = h.scb.PendingSegment(available)
		if !ok {
			// No pending control segment or data to send. Yield.
			return 0, nil
		}
		if available > 0 {
			n, err := h.bufTx.MakePacket(b[sizeHeaderTCP:sizeHeaderTCP+segment.DATALEN], segment.SEQ)
			if err != nil {
				return 0, err
			} else if n != int(segment.DATALEN) {
				panic("expected n == available")
			}
		} else if segment.Flags == synack {
			h.optcodec.PutOption16(b[sizeHeaderTCP:], OptMaxSegmentSize, uint16(len(b)))
			offset++
		}
	}
	prevState := h.scb.State()
	err = h.scb.Send(segment)
	if err != nil {
		return 0, err
	} else if prevState != h.scb.State() && h.logenabled(slog.LevelInfo) {
		h.info("tcp.Handler:tx-statechange", slog.Uint64("port", uint64(h.localPort)), slog.String("oldState", prevState.String()), slog.String("newState", h.scb.State().String()), slog.String("txflags", segment.Flags.String()))
	}
	tfrm.SetSourcePort(h.localPort)
	tfrm.SetDestinationPort(h.remotePort)
	tfrm.SetSegment(segment, offset)
	tfrm.SetUrgentPtr(0)
	datalen := int(offset)*4 + int(segment.DATALEN)
	closedSuccess := prevState == StateTimeWait && segment.Flags.HasAny(FlagACK)
	if closedSuccess {
		h.reset(0, 0, 0)
	}
	return datalen, nil
}

// FreeTx returns the amount of space free in the transmit buffer. A call to [Handler.Write] with a larger buffer will fail.
func (h *Handler) FreeTx() int {
	return h.bufTx.Free()
}

// FreeRx returns the amount of space free in the receive buffer.
func (h *Handler) FreeRx() int {
	return h.bufRx.Free()
}

// SizeRx returns the size of the TCP receive ring buffer.
func (h *Handler) SizeRx() int {
	return h.bufRx.Size()
}

// Write implements [io.Writer] by copying b to a internal buffer to be sent over the network on the next
// [Handler.Send] call that can send data to remote peer. Use [Handler.Free] to know the maximum length the argument slice can be before erroring.
func (h *Handler) Write(b []byte) (int, error) {
	state := h.State()
	if h.closing {
		return 0, errConnectionClosing
	} else if !state.TxDataOpen() { // Reject write call if data cannot be sent.
		return 0, net.ErrClosed
	}
	return h.bufTx.Write(b)
}

// Read implements [io.Reader] by reading received data from remote peer in internal buffer.
func (h *Handler) Read(b []byte) (n int, err error) {
	if h.bufRx.Buffered() > 0 {
		n, err = h.bufRx.Read(b)
	}
	if n == 0 && err == nil {
		state := h.State()
		if state.IsClosed() {
			err = net.ErrClosed
		} else if !state.RxDataOpen() {
			err = io.EOF
		}
	}
	return n, err
}

// BufferedInput returns amount of bytes buffered in receive(input) buffer and ready to read
// with a [Handler.Read] call.
func (h *Handler) BufferedInput() int {
	return h.bufRx.Buffered()
}

// BufferedUnsent returns the number of bytes in the socket's transmit(output) buffer
// that has yet to be sent.
func (h *Handler) BufferedUnsent() int {
	return h.bufTx.BufferedUnsent()
}

// AvailableOutput returns amount of bytes available to write to output
// before [Handler.Write] returns an error.
func (h *Handler) AvailableOutput() int {
	return h.bufTx.Free()
}

// AwaitingSynResponse returns true if the Handler is an active client opened with [Handler.OpenActive] and has already sent out the first SYN packet to the remote client.
func (h *Handler) AwaitingSynResponse() bool {
	return h.remotePort != 0 && h.scb.State() == StateSynSent
}

// AwaitingSynAck returns true if the Handler is a passive server opened with [Handler.OpenListen] and not yet received a valid SYN remote packet.
func (h *Handler) AwaitingSynAck() bool {
	return h.remotePort == 0 && h.scb.State() == StateListen
}

// AwaitingSynSend returns true if the Handler is an active client opened with [Handler.OpenActive] and not yet sent out the first SYN packet to the remote client.
func (h *Handler) AwaitingSynSend() bool {
	return h.remotePort != 0 && h.scb.State() == StateClosed
}

// IsTxOver returns true if there is no more frames to encapsulate over the network.
// The connection is pretty much over in this case if packets made it succesfully to remote.
func (h *Handler) IsTxOver() bool {
	state := h.State()
	return state == StateClosed && !h.AwaitingSynSend() ||
		state == StateTimeWait && !h.scb.HasPending()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func errstr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
