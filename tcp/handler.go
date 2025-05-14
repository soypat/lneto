package tcp

import (
	"errors"
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
type Handler struct {
	scb   ControlBlock
	bufTx ringTx
	bufRx internal.Ring
	logger
	validator  lneto.Validator
	localPort  uint16
	remotePort uint16
	// connid is a conenction counter that is incremented each time a new
	// connection is established via Open calls. This disambiguate's whether
	// Read and Write calls belong to the current connection.
	connid  uint8
	closing bool
}

func (h *Handler) SetLoggers(handler, scb *slog.Logger) {
	h.logger.log = handler
	h.scb.logger.log = scb
}

// State returns the state of the TCP state machine as per RFC9293. See [State].
func (h *Handler) State() State { return h.scb.State() }

// SetBuffers sets the internal buffers used to receive and transmit bytes asynchronously via [Handler.Write] and [Handler.Read] calls.
func (h *Handler) SetBuffers(txbuf, rxbuf []byte, packets int) error {
	if !h.scb.State().IsClosed() {
		return errors.New("tcp.Handler must be closed before setting buffers")
	}
	if rxbuf != nil {
		h.bufRx.Buf = rxbuf
	}
	if len(h.bufRx.Buf) < minBufferSize {
		return errors.New("short rx buffer")
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
	if h.bufRx.Size() < minBufferSize || h.bufTx.Size() < minBufferSize {
		return errBufferTooSmall
	}
	if h.scb.State() != StateClosed {
		return errNeedClosedTCBToOpen
	} else if remotePort == 0 {
		return errors.New("zero port on open call")
	}
	h.reset(localPort, remotePort, iss)
	return nil
}

// OpenListen prepares a passive TCP connection where the Handler acts as a server.
// OpenListen is used by TCP Servers to begin listening for remote connections.
func (h *Handler) OpenListen(localPort uint16, iss Value) error {
	if h.bufRx.Size() < minBufferSize || h.bufTx.Size() < minBufferSize {
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

func (h *Handler) reset(localPort, remotePort uint16, iss Value) {
	*h = Handler{
		scb:        h.scb,
		bufTx:      h.bufTx,
		bufRx:      h.bufRx,
		connid:     h.connid + 1,
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
	if h.isClosed() {
		return net.ErrClosed
	}
	tfrm, err := NewFrame(incomingPacket)
	if err != nil {
		return err
	}
	tfrm.ValidateExceptCRC(&h.validator)
	err = h.validator.Err()
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

// Send writes TCP frame to be sent over the network to the remote peer to `b`.
// It does no IP interfacing or CRC calculation of packet, which is left to the caller to perform.
// The returned integer is the length written to the argument buffer.
func (h *Handler) Send(b []byte) (int, error) {
	h.trace("tcp.Handler:start", slog.Uint64("port", uint64(h.localPort)))
	if h.isClosed() && !h.AwaitingSynSend() {
		return 0, net.ErrClosed
	}
	tfrm, err := NewFrame(b)
	if err != nil {
		return 0, err
	}
	var segment Segment
	if h.AwaitingSynSend() {
		// Handling init syn segment.
		segment = ClientSynSegment(h.scb.ISS(), h.scb.RecvWindow())
	} else {
		var ok bool
		available := min(h.bufTx.Buffered(), len(b)-sizeHeaderTCP)
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
	tfrm.SetSegment(segment, 5) // No TCP options.
	tfrm.SetUrgentPtr(0)
	return sizeHeaderTCP + int(segment.DATALEN), nil
}

// Free returns the amount of space free in the transmit buffer. A call to [Handler.Write] with a larger buffer will fail.
func (h *Handler) Free() int {
	return h.bufTx.Free()
}

// Write implements [io.Writer] by copying b to a internal buffer to be sent over the network on the next
// [Handler.Send] call that can send data to remote peer. Use [Handler.Free] to know the maximum length the argument slice can be before erroring.
func (h *Handler) Write(b []byte) (int, error) {
	if h.State().IsClosed() { // Reject write call if data cannot be sent.
		return 0, net.ErrClosed
	}
	return h.bufTx.Write(b)
}

// Read implements [io.Reader] by reading received data from remote peer in internal buffer.
func (h *Handler) Read(b []byte) (int, error) {
	if h.State().IsClosed() { // Reject read call if state is at StateClosed. Note this is less strict than Write call condition.
		return 0, net.ErrClosed
	}
	return h.bufRx.Read(b)
}

// BufferedInput returns amount of bytes buffered in receive buffer.
func (h *Handler) BufferedInput() int {
	if h.State().IsClosed() {
		return 0
	}
	return h.bufRx.Buffered()
}

// AwaitingSynResponse checks if the Handler is waiting for a Syn to arrive.
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

func (h *Handler) isClosed() bool {
	return h.closing || h.scb.State().IsClosed()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
