package tcp

import (
	"errors"
	"net"

	"log/slog"

	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/lneto2"
)

var (
	errMismatchedPort = errors.New("mismatched port")
)

// Handler is a low level TCP handling data structure. It implements logic
// related to data buffering, frame sequencing and connection state handling.
// Does NOT implement IP related logic, so no CRC calculation/validation or pseudo header logic.
// Does NOT implement connection lifetime handling, so NO deadlines, keepalives, backoffs or anything that requires use of time package.
type Handler struct {
	scb        ControlBlock
	bufTx      ringTx
	bufRx      internal.Ring
	localPort  uint16
	remotePort uint16
	// connid is a conenction counter that is incremented each time a new
	// connection is established via Open calls. This disambiguate's whether
	// Read and Write calls belong to the current connection.
	connid    uint8
	closing   bool
	validator lneto2.Validator
	logger
}

func (h *Handler) Reset() error {
	*h = Handler{
		connid: h.connid + 1,
		bufTx:  h.bufTx,
		bufRx:  h.bufRx,
	}
	h.bufRx.Reset()
	h.bufTx.ResetOrReuse(nil, 0, 0)
	return nil
}

func (h *Handler) Recv(b []byte) error {
	if h.isClosed() {
		return net.ErrClosed
	}
	tfrm, err := NewFrame(b)
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
		return errMismatchedPort
	}
	dstPort := tfrm.DestinationPort()
	if h.localPort != dstPort {
		return errMismatchedPort
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
	return nil
}

func (h *Handler) Handle(b []byte) (int, error) {
	h.trace("tcp.Handler:start", slog.Uint64("port", uint64(h.localPort)))
	if h.isClosed() {
		return 0, net.ErrClosed
	} else if h.AwaitingSyn() {
		return h.sendInitSyn(b)
	}
	tfrm, err := NewFrame(b)
	if err != nil {
		return 0, err
	}

	tfrm.SetSourcePort(h.localPort)
	tfrm.SetDestinationPort(h.remotePort)

	return 0, nil
}

func (h *Handler) sendInitSyn(b []byte) (int, error) {
	return 0, nil
}

// AwaitingSyn checks if the Handler is waiting for a Syn to arrive.
func (h *Handler) AwaitingSyn() bool {
	return h.remotePort != 0 && h.scb.State() == StateSynSent
}

func (h *Handler) isClosed() bool {
	return h.closing || h.scb.State().IsClosed()
}
