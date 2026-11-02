package xforward

import (
	"math"
	"net"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/udp"
)

// UDPHandler tracks forwarded UDP flows and frames replies sourced from the
// original destination. It holds no payload. Not safe for concurrent use.
type UDPHandler struct {
	table flowTable
	flows []struct { // parallel to table slots.
		lastSeen int64
		rxPkts   uint32
		txPkts   uint32
		gen      uint16 // bumped on removal; stale UDPFlow fails with net.ErrClosed.
	}
	idle  int64
	mono  internal.Monotonic
	ipID  uint16
	sweep uint16 // slot NextExpired resumes from.
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

// Configure sizes the handler for cfg and resets it. Handles from before become stale.
func (uh *UDPHandler) Configure(cfg UDPHandlerConfig) error {
	if cfg.NanoTime == nil {
		return lneto.ErrMissingHALConfig
	} else if cfg.MaxFlows == 0 || cfg.MaxFlows > maxFlows || cfg.IdleTimeout <= 0 || internal.IsZeroed(cfg.Key) {
		return lneto.ErrInvalidConfig
	}
	n := int(cfg.MaxFlows)
	uh.table.reset(n, cfg.Key)
	internal.SliceReuse(&uh.flows, n)
	uh.flows = uh.flows[:n]
	for i := range uh.flows {
		uh.flows[i].gen = nextGen(uh.flows[i].gen)
	}
	uh.idle = int64(cfg.IdleTimeout)
	uh.mono.Config(cfg.NanoTime)
	uh.sweep = 0
	return nil
}

// Demux returns pkt's flow and its payload, which aliases pkt (zero-copy).
// An unknown flow is inserted and returned with isNew=true so caller can dial upstream.
// Returns [lneto.ErrExhausted] when no slot is free.
func (uh *UDPHandler) Demux(pkt Packet) (flow UDPFlow, payload []byte, isNew bool, err error) {
	if pkt.proto != lneto.IPProtoUDP {
		return flow, nil, false, lneto.ErrMismatch
	}
	k := pkt.key()
	slot := uh.table.lookup(&k)
	if slot < 0 {
		slot = uh.table.insert(&k)
		if slot < 0 {
			return flow, nil, false, lneto.ErrExhausted
		}
		isNew = true
		uh.flows[slot].rxPkts = 0
		uh.flows[slot].txPkts = 0
	}
	f := &uh.flows[slot]
	f.lastSeen = uh.mono.Nanotime()
	f.rxPkts++
	flow = UDPFlow{ID: k.id(), slot: uint16(slot), gen: f.gen}
	ufrm, _ := udp.NewFrame(pkt.buf[pkt.toff:])
	return flow, ufrm.RawData()[sizeUDPHeader:ufrm.Length()], isNew, nil
}

// Encapsulate frames IP and UDP headers around the payloadLen bytes already at
// carrierData[offsetToIP+flow.HeaderLen():] and returns the packet length. Refreshes idle time.
func (uh *UDPHandler) Encapsulate(carrierData []byte, offsetToIP int, flow UDPFlow, payloadLen int) (int, error) {
	slot := uh.slotOf(flow)
	if slot < 0 {
		return 0, net.ErrClosed
	}
	k := &uh.table.keys[slot]
	ulen := sizeUDPHeader + payloadLen
	total := sizeIPv6Header + ulen
	if k.is4() {
		total = sizeIPv4Header + ulen
	}
	if payloadLen < 0 || total > math.MaxUint16 {
		return 0, lneto.ErrInvalidLengthField
	} else if offsetToIP < 0 || offsetToIP+total > len(carrierData) {
		return 0, lneto.ErrShortBuffer
	}
	pkt := carrierData[offsetToIP : offsetToIP+total]
	uh.ipID = internal.Prand16(uh.ipID + 1)
	hl := putIPHeader(pkt, k, lneto.IPProtoUDP, uh.ipID)
	ufrm, _ := udp.NewFrame(pkt[hl:])
	ufrm.SetSourcePort(k.lport)
	ufrm.SetDestinationPort(k.rport)
	ufrm.SetLength(uint16(ulen))
	finishIP(pkt, hl, ulen, lneto.IPProtoUDP)
	f := &uh.flows[slot]
	f.lastSeen = uh.mono.Nanotime()
	f.txPkts++
	return total, nil
}

// Remove frees flow's slot, e.g. after a failed upstream dial.
func (uh *UDPHandler) Remove(flow UDPFlow) error {
	slot := uh.slotOf(flow)
	if slot < 0 {
		return net.ErrClosed
	}
	uh.free(slot)
	return nil
}

// Stats returns the number of datagrams received from the peer and sent to it on flow.
func (uh *UDPHandler) Stats(flow UDPFlow) (rxPkts, txPkts uint32, err error) {
	slot := uh.slotOf(flow)
	if slot < 0 {
		return 0, 0, net.ErrClosed
	}
	return uh.flows[slot].rxPkts, uh.flows[slot].txPkts, nil
}

// NextExpired removes and returns one flow idle past IdleTimeout. ok=false when none.
// The returned handle is already stale; use its ID and Slot to release caller state.
func (uh *UDPHandler) NextExpired() (flow UDPFlow, ok bool) {
	now := uh.mono.Nanotime()
	for slot := int(uh.sweep); slot < len(uh.flows); slot++ {
		k := &uh.table.keys[slot]
		f := &uh.flows[slot]
		if k.lport != 0 && now-f.lastSeen >= uh.idle {
			flow = UDPFlow{ID: k.id(), slot: uint16(slot), gen: f.gen}
			uh.free(slot)
			uh.sweep = uint16(slot + 1)
			return flow, true
		}
	}
	uh.sweep = 0
	return flow, false
}

// Abort removes every flow. All handles become stale.
func (uh *UDPHandler) Abort() {
	for slot := range uh.flows {
		if uh.table.keys[slot].lport != 0 {
			uh.flows[slot].gen = nextGen(uh.flows[slot].gen)
		}
	}
	uh.table.reset(len(uh.flows), uh.table.hashKey)
	uh.sweep = 0
}

// slotOf returns flow's slot, or -1 if the handle is stale.
func (uh *UDPHandler) slotOf(flow UDPFlow) int {
	slot := int(flow.slot)
	if slot >= len(uh.flows) || uh.flows[slot].gen != flow.gen || uh.table.keys[slot].lport == 0 {
		return -1
	}
	return slot
}

// free removes slot from the table and invalidates its handles.
func (uh *UDPHandler) free(slot int) {
	uh.table.remove(slot)
	uh.flows[slot].gen = nextGen(uh.flows[slot].gen)
}
