package xforward

import (
	"log/slog"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

// TCPHandler terminates TCP flows addressed to any IP:port, answering as the
// original destination. A SYN is held until [TCPHandler.Accept] or [TCPHandler.Reject].
// Not safe for concurrent use; see [TCPForwarder].
type TCPHandler struct {
	flows      []tcpFlow // len MaxFlows, fixed at Configure.
	table      flowTable
	dirty      []uint32 // bitset over slots: may have a segment to send.
	cursor     uint16   // round-robin start of the dirty scan.
	npending   uint16
	maxPending uint16
	txQueue    int // TxPacketQueueSize passed to SetBuffers on Accept.
	rst        rstQueue
	mono       internal.Monotonic
	key        [16]byte // ISN (RFC 6528) and flow table hash key.

	pendingTimeout int64
	closeTimeout   int64
	// nextScan is the earliest timer; Encapsulate runs maintenance once due.
	nextScan int64
	release  func(rx, tx []byte)
	ipID     uint16
	vld      lneto.Validator
	log      *slog.Logger
}

type flowState uint8

const (
	flowFree flowState = iota
	flowPending
	flowOpen
	flowReleased
)

type tcpFlow struct {
	h      tcp.Handler
	policy tcp.Policy // one per slot from NewPolicy; NextDeadline read directly.
	rx, tx []byte     // Accept's buffers, passed to ReleaseBuffers on reap.
	syn    [60]byte   // held SYN TCP header; its data offset gives the length.
	at     int64      // pending: SYN arrival. released: release time.
	rxPkts uint32
	txPkts uint32
	gen    uint16 // bumped on reap; stale TCPFlow fails with net.ErrClosed.
	// state stores whether flow is released: caller intent not derivable from tcp.Handler's public API.
	state flowState
}

// TCPFlow is a handle to a forwarded TCP flow, pending or accepted.
// It becomes stale once its slot is reaped.
type TCPFlow struct {
	ID   FlowID
	slot uint16
	gen  uint16
}

// Slot returns the flow's slot index in [0, MaxFlows) so callers can keep per-flow data in their own slice.
func (f TCPFlow) Slot() int { return int(f.slot) }

// TCPHandlerConfig configures a [TCPHandler]. All memory is sized from it at Configure.
type TCPHandlerConfig struct {
	// MaxFlows bounds pending, open and released flows. At most 1<<15.
	MaxFlows uint16
	// MaxPending bounds SYNs held awaiting Accept or Reject. Extra SYNs are dropped so the peer retries.
	MaxPending uint16
	// TxPacketQueueSize is the per-flow retransmit queue length. See [tcp.ConnConfig].
	TxPacketQueueSize int
	// NewPolicy creates one Policy per slot at Configure (RTO, SACK, congestion control).
	// A Policy with a NextDeadline method schedules retransmits. nil disables policies.
	NewPolicy func() tcp.Policy
	// PendingTimeout rejects a held SYN not accepted in time. Must exceed the caller's upstream dial timeout.
	PendingTimeout time.Duration
	// CloseTimeout aborts a released flow that has not finished closing in time.
	CloseTimeout time.Duration
	// ReleaseBuffers, if set, receives Accept's buffers when a flow slot is reaped.
	// Called with handler state held: must not call back into the handler.
	ReleaseBuffers func(rx, tx []byte)
	// NanoTime returns monotonic time in nanoseconds. Required.
	NanoTime func() int64
	// Key seeds ISNs and flow table hashing. Must be secret and non-zero.
	Key    [16]byte
	Logger *slog.Logger
}

// Configure sizes the handler for cfg and resets it.
func (th *TCPHandler) Configure(cfg TCPHandlerConfig) error {
	if cfg.NanoTime == nil {
		return lneto.ErrMissingHALConfig
	} else if cfg.MaxFlows == 0 || cfg.MaxFlows > maxFlows || cfg.MaxPending == 0 || cfg.MaxPending > cfg.MaxFlows ||
		cfg.TxPacketQueueSize <= 0 || cfg.PendingTimeout <= 0 || cfg.CloseTimeout <= 0 || internal.IsZeroed(cfg.Key) {
		return lneto.ErrInvalidConfig
	}
	return lneto.ErrUnsupported
}

// Abort reaps every flow. All handles become stale.
func (th *TCPHandler) Abort() {}

// Demux processes a TCP packet. A hit feeds the flow's [tcp.Handler].
// A SYN for an unknown flow is held and returned with isNew=true: caller must Accept or Reject it.
// Other segments for unknown flows queue a stateless RST and return [lneto.ErrPacketDrop].
func (th *TCPHandler) Demux(pkt Packet) (flow TCPFlow, isNew bool, err error) {
	return TCPFlow{}, false, lneto.ErrUnsupported
}

// Accept opens the held SYN's flow with the given buffers and queues the SYN-ACK.
// nil buffers reuse the slot's previous ones. On failure a RST is queued and the slot freed.
func (th *TCPHandler) Accept(flow TCPFlow, rxbuf, txbuf []byte) error {
	return lneto.ErrUnsupported
}

// Reject refuses the held SYN with RST|ACK and frees its slot.
func (th *TCPHandler) Reject(flow TCPFlow) error {
	return lneto.ErrUnsupported
}

// Encapsulate writes the next IP+TCP packet to carrierData[offsetToIP:] and returns its length, 0 when idle.
// len(carrierData[offsetToIP:]) is taken as the MTU; the SYN-ACK MSS derives from it.
func (th *TCPHandler) Encapsulate(carrierData []byte, offsetToIP int) (int, error) {
	return 0, lneto.ErrUnsupported
}

// NextDeadline returns the earliest pending timer in monotonic nanoseconds, or 0 if none.
// Calling Encapsulate once it passes drives retransmits and timeouts.
func (th *TCPHandler) NextDeadline() int64 {
	return 0
}

// Read reads received flow data into b. Returns 0, nil when none is buffered and io.EOF after the peer's FIN.
func (th *TCPHandler) Read(flow TCPFlow, b []byte) (int, error) {
	return 0, lneto.ErrUnsupported
}

// Write queues b for sending on flow. Short writes happen when the tx buffer is full.
func (th *TCPHandler) Write(flow TCPFlow, b []byte) (int, error) {
	return 0, lneto.ErrUnsupported
}

// CloseWrite queues a FIN once buffered data is sent. Reads keep working.
func (th *TCPHandler) CloseWrite(flow TCPFlow) error {
	return lneto.ErrUnsupported
}

// Release closes flow and discards further received data. The slot is reaped once sending ends.
func (th *TCPHandler) Release(flow TCPFlow) error {
	return lneto.ErrUnsupported
}

// Stats returns the number of segments received and sent on flow.
func (th *TCPHandler) Stats(flow TCPFlow) (rxPkts, txPkts uint32, err error) {
	return 0, 0, lneto.ErrUnsupported
}
