package xforward

import (
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

// UDPHandler tracks forwarded UDP flows and frames replies sourced from the
// original destination. It holds no payload. Not safe for concurrent use.
type UDPHandler struct {
	table flowTable
	flows []struct { // parallel to table slots.
		lastSeen int64
		rxPkts   uint32
		txPkts   uint32
		gen      uint16
	}
	idle int64
	mono internal.Monotonic
	ipID uint16
}

// UDPHandlerConfig configures a [UDPHandler]. All memory is sized from it at Configure.
type UDPHandlerConfig struct {
	// MaxFlows bounds tracked flows. At most 1<<15.
	MaxFlows uint16
	// IdleTimeout expires flows with no traffic in either direction. See [UDPHandler.NextExpired].
	IdleTimeout time.Duration
	// NanoTime returns monotonic time in nanoseconds. Required.
	NanoTime func() int64
	// Key seeds flow table hashing. Must be secret and non-zero.
	Key [16]byte
}

// UDPFlow is a handle to a forwarded UDP flow. It becomes stale once removed or expired.
type UDPFlow struct {
	ID   FlowID
	slot uint16
	gen  uint16
}

// Slot returns the flow's slot index in [0, MaxFlows) so callers can keep per-flow data in their own slice.
func (f UDPFlow) Slot() int { return int(f.slot) }

// HeaderLen returns the IP+UDP header length preceding payload in [UDPHandler.Encapsulate].
func (f UDPFlow) HeaderLen() int {
	if f.ID.Remote.Addr().Is4() {
		return sizeIPv4Header + sizeUDPHeader
	}
	return sizeIPv6Header + sizeUDPHeader
}

// Configure sizes the handler for cfg and resets it.
func (uh *UDPHandler) Configure(cfg UDPHandlerConfig) error {
	if cfg.NanoTime == nil {
		return lneto.ErrMissingHALConfig
	} else if cfg.MaxFlows == 0 || cfg.MaxFlows > maxFlows || cfg.IdleTimeout <= 0 || internal.IsZeroed(cfg.Key) {
		return lneto.ErrInvalidConfig
	}
	return lneto.ErrUnsupported
}

// Demux returns pkt's flow and its payload, which aliases pkt (zero-copy).
// An unknown flow is inserted and returned with isNew=true so caller can dial upstream.
// Returns [lneto.ErrExhausted] when no slot is free.
func (uh *UDPHandler) Demux(pkt Packet) (flow UDPFlow, payload []byte, isNew bool, err error) {
	return UDPFlow{}, nil, false, lneto.ErrUnsupported
}

// Encapsulate frames IP and UDP headers around the payloadLen bytes already at
// carrierData[offsetToIP+flow.HeaderLen():] and returns the packet length. Refreshes idle time.
func (uh *UDPHandler) Encapsulate(carrierData []byte, offsetToIP int, flow UDPFlow, payloadLen int) (int, error) {
	return 0, lneto.ErrUnsupported
}

// Remove frees flow's slot, e.g. after a failed upstream dial.
func (uh *UDPHandler) Remove(flow UDPFlow) error {
	return lneto.ErrUnsupported
}

// NextExpired removes and returns one flow idle past IdleTimeout. ok=false when none.
func (uh *UDPHandler) NextExpired() (flow UDPFlow, ok bool) {
	return UDPFlow{}, false
}

// Abort removes every flow. All handles become stale.
func (uh *UDPHandler) Abort() {}
