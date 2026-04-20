package ntp

import (
	"time"

	"github.com/soypat/lneto"
)

// ServerConfig configures an NTP [Server].
type ServerConfig struct {
	Now        func() time.Time
	Stratum    Stratum
	Precision  int8
	RefID      [4]byte
	MaxPending int
}

// Server is a basic NTP server implementing [lneto.StackNode].
// It receives client requests via [Server.Demux] and builds server
// responses via [Server.Encapsulate].
//
// Server is not safe for concurrent use.
type Server struct {
	connID  uint64
	_now    func() time.Time
	stratum Stratum
	prec    int8
	refID   [4]byte
	pending []pendingRequest
}

type pendingRequest struct {
	origin Timestamp
}

// Reset re-initialises the server with cfg. Increments connID.
func (h *Server) Reset(cfg ServerConfig) error {
	if cfg.Now == nil {
		return lneto.ErrInvalidConfig
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 4
	}
	pending := h.pending[:0]
	if cap(pending) < cfg.MaxPending {
		pending = make([]pendingRequest, 0, cfg.MaxPending)
	}
	*h = Server{
		connID:  h.connID + 1,
		_now:    cfg.Now,
		stratum: cfg.Stratum,
		prec:    cfg.Precision,
		refID:   cfg.RefID,
		pending: pending,
	}
	return nil
}

// ConnectionID implements [lneto.StackNode].
func (h *Server) ConnectionID() *uint64 { return &h.connID }

// Protocol implements [lneto.StackNode].
func (h *Server) Protocol() uint64 { return 0 }

// LocalPort implements [lneto.StackNode].
func (h *Server) LocalPort() uint16 { return ServerPort }

// Encapsulate implements [lneto.StackNode]. It writes one pending NTP server
// response into carrierData. Returns 0 when no pending requests exist.
func (h *Server) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if len(h.pending) == 0 {
		return 0, nil
	}
	buf := carrierData[offsetToFrame:]
	frm, err := NewFrame(buf)
	if err != nil {
		return 0, err
	}

	req := h.pending[len(h.pending)-1]
	h.pending = h.pending[:len(h.pending)-1]

	now := h.now()
	xmt, err := TimestampFromTime(now)
	if err != nil {
		return 0, err
	}

	frm.ClearHeader()
	frm.SetFlags(ModeServer, Version4, LeapNoWarning)
	frm.SetStratum(h.stratum)
	frm.SetPrecision(h.prec)
	frm.SetPoll(6)
	*frm.ReferenceID() = h.refID
	frm.SetOriginTime(req.origin)
	frm.SetReceiveTime(xmt)
	frm.SetTransmitTime(xmt)
	return SizeHeader, nil
}

// Demux implements [lneto.StackNode]. It validates an incoming NTP client
// request and queues it for response via [Server.Encapsulate].
func (h *Server) Demux(carrierData []byte, frameOffset int) error {
	buf := carrierData[frameOffset:]
	frm, err := NewFrame(buf)
	if err != nil {
		return err
	}

	mode, version, _ := frm.Flags()
	if mode != ModeClient {
		return lneto.ErrPacketDrop
	}
	if version != Version4 {
		return lneto.ErrPacketDrop
	}

	if len(h.pending) == cap(h.pending) {
		return lneto.ErrExhausted
	}

	h.pending = append(h.pending, pendingRequest{
		origin: frm.TransmitTime(),
	})
	return nil
}

func (h *Server) now() time.Time {
	if h._now == nil {
		return time.Now()
	}
	return h._now()
}
