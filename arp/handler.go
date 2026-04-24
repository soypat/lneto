package arp

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

type Handler struct {
	connID       uint64
	cache        cache
	vld          lneto.Validator
	ourProtoAddr []byte
	onresolve    func(hw, proto []byte)

	htype     uint16
	protoType ethernet.Type
	ourHWAddr [6]byte
}

type HandlerConfig struct {
	HardwareAddr []byte
	ProtocolAddr []byte
	MaxQueries   int
	MaxPending   int
	HardwareType uint16
	ProtocolType ethernet.Type
}

func (h *Handler) LocalPort() uint16 { return 0 }

func (h *Handler) Protocol() uint64 { return uint64(ethernet.TypeARP) }

func (h *Handler) ConnectionID() *uint64 { return &h.connID }

func (h *Handler) UpdateProtoAddr(protoAddr []byte) error {
	if len(protoAddr) != len(h.ourProtoAddr) {
		return lneto.ErrMismatchLen
	}
	copy(h.ourProtoAddr, protoAddr)
	return nil
}

func (h *Handler) SetOnResolveCallback(cb func(hwAddr, protoAddr []byte)) {
	h.onresolve = cb
}

func (h *Handler) Reset(cfg HandlerConfig) error {
	if len(cfg.HardwareAddr) == 0 || len(cfg.HardwareAddr) > 255 ||
		len(cfg.ProtocolAddr) == 0 || len(cfg.ProtocolAddr) > 255 {
		return lneto.ErrInvalidConfig
	} else if cfg.MaxQueries <= 0 || cfg.MaxPending <= 0 {
		return lneto.ErrInvalidConfig
	}
	if cfg.HardwareType != 1 || cfg.ProtocolType != ethernet.TypeIPv4 && cfg.ProtocolType != ethernet.TypeIPv6 {
		return lneto.ErrUnsupported // We only support common for now.
	}
	*h = Handler{
		connID:       h.connID + 1,
		ourHWAddr:    h.ourHWAddr,
		ourProtoAddr: h.ourProtoAddr[:0],
		htype:        cfg.HardwareType,
		protoType:    cfg.ProtocolType,
		cache:        h.cache,
	}
	h.cache.reset(cfg.MaxPending + cfg.MaxQueries)

	h.ourHWAddr = [6]byte(cfg.HardwareAddr)
	h.ourProtoAddr = append(h.ourProtoAddr, cfg.ProtocolAddr...)
	return nil
}

// AbortPending drops pending queries and incoming requests.
func (h *Handler) AbortPending() {
	h.cache.clearFlags(eflagPendingResponse|eflagIncomplete, eflagInUse)
}

// CacheSeed pre-populates the cache with a known proto→hardware mapping, making it
// immediately resolvable via [Handler.CacheLookup] without an ARP exchange.
// Seeded entries are evicted before active user queries when the cache is full.
func (h *Handler) CacheSeed(protoAddr, hwAddr []byte) error {
	if len(hwAddr) != 6 {
		return lneto.ErrUnsupported
	}
	e := h.cache.acquireNext()
	e.use([6]byte(hwAddr), protoAddr, 0)
	return nil
}

// CacheLookup returns the hardware address for protoAddr if it is resolved in the cache.
// Returns [errQueryPending] if a query is in flight, [errQueryNotFound] if no entry exists.
func (h *Handler) CacheLookup(protoAddr []byte) (hwAddr []byte, err error) {
	e := h.cache.Lookup(protoAddr)
	if e == nil {
		return nil, errQueryNotFound
	} else if e.flags.hasAny(eflagIncomplete) {
		return nil, errQueryPending
	}
	return e.mac[:], nil
}

// CacheRemove cancels a pending query or evicts a cached entry for protoAddr.
func (h *Handler) CacheRemove(protoAddr []byte) error {
	e := h.cache.Lookup(protoAddr)
	if e == nil {
		return errQueryNotFound
	}
	e.destroy()
	return nil
}

// StartQuery queues a query to perform over ARP for the protocol address `proto`.
// Use [Handler.SetOnResolveCallback] to asynchronously set an ARP request result.
func (h *Handler) StartQuery(proto []byte, triggerCallback bool) error {
	if len(proto) != len(h.ourProtoAddr) {
		return lneto.ErrMismatchLen
	}
	e := h.cache.acquireNext()
	e.use([6]byte{}, proto, eflagIncomplete|eflagIncompletePendingQuery|eflagPriority)
	if triggerCallback {
		e.flags |= eflagResolveTriggersCallback
	}
	return nil
}

func (h *Handler) Encapsulate(carrierData []byte, _, offsetToFrame int) (int, error) {
	b := carrierData[offsetToFrame:]
	afrm, err := h.newframe(b)
	if err != nil {
		return 0, err
	}
	op := OpReply
	e := h.cache.getNextFlagged(eflagPendingResponse) // Prioritize responses.
	if e == nil {
		e = h.cache.getNextFlagged(eflagIncompletePendingQuery)
		if e == nil {
			return 0, nil // No action to perform
		}
		e.flags &^= eflagIncompletePendingQuery
		op = OpRequest
	} else {
		e.flags &^= eflagPendingResponse
	}
	// Write Request or Reply, depending on which entry we got.
	n, err := e.put(b, h.ourProtoAddr, h.ourHWAddr, op)
	if err != nil {
		return 0, err
	}
	switch op {
	case OpRequest:
		broadcast := ethernet.BroadcastAddr()
		trySetEthernetDst(carrierData[:offsetToFrame], broadcast[:])
	case OpReply:
		tgt, _ := afrm.Target()
		trySetEthernetDst(carrierData[:offsetToFrame], tgt)
	}
	return n, nil
}

func (h *Handler) Demux(ethFrame []byte, frameOffset int) error {
	b := ethFrame[frameOffset:]
	afrm, err := h.newframe(b)
	if err != nil {
		return err
	}
	afrm.ValidateSize(&h.vld)
	if h.vld.HasError() {
		return h.vld.ErrPop()
	}
	htype, hlen := afrm.Hardware()
	if htype != h.htype || int(hlen) != len(h.ourHWAddr) {
		return lneto.ErrMismatch
	}
	protoType, protoLen := afrm.Protocol()
	if protoType != h.protoType || int(protoLen) != len(h.ourProtoAddr) {
		return lneto.ErrMismatch
	}
	switch afrm.Operation() {
	case OpRequest:
		_, protoaddr := afrm.Target()
		if !internal.BytesEqual(protoaddr, h.ourProtoAddr) {
			return nil // Not for us.
		}
		hw, proto := afrm.Sender()
		e := h.cache.acquireNext()
		e.use([6]byte(hw), proto, eflagPendingResponse)

	case OpReply:
		hwaddr, protoaddr := afrm.Sender()
		e := h.cache.Lookup(protoaddr)
		if e == nil {
			return nil
		}
		copy(e.mac[:], hwaddr)
		e.flags &^= eflagIncomplete | eflagIncompletePendingQuery
		if e.flags.hasAny(eflagResolveTriggersCallback) && h.onresolve != nil {
			h.onresolve(e.mac[:], protoaddr)
		}
	default:
		return errARPUnsupported
	}
	return nil
}

func (h *Handler) newframe(b []byte) (Frame, error) {
	f, err := NewFrame(b)
	if err != nil {
		return f, err
	} else if h.protoType == ethernet.TypeIPv6 && len(b) < sizeHeaderv6 {
		return f, lneto.ErrMismatch
	}
	return f, nil
}

func trySetEthernetDst(ethFrame []byte, dst []byte) {
	if len(ethFrame) >= 14 {
		copy(ethFrame[:6], dst)
	}
}
