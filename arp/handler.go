package arp

import (
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

type Handler struct {
	connID       uint64
	ourHWAddr    []byte
	ourProtoAddr []byte
	htype        uint16
	protoType    ethernet.Type
	vld          lneto.Validator
	cache        cache
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
		ourHWAddr:    h.ourHWAddr[:0],
		ourProtoAddr: h.ourProtoAddr[:0],
		htype:        cfg.HardwareType,
		protoType:    cfg.ProtocolType,
		cache:        h.cache,
	}
	h.cache.reset(cfg.MaxPending + cfg.MaxQueries)
	h.ourHWAddr = append(h.ourHWAddr, cfg.HardwareAddr...)
	h.ourProtoAddr = append(h.ourProtoAddr, cfg.ProtocolAddr...)
	return nil
}

// AbortPending drops pending queries and incoming requests.
func (h *Handler) AbortPending() {
	h.cache.clearFlags(eflagPendingResponse|eflagIncomplete, eflagInUse)
}

func (h *Handler) QueryResult(protoAddr []byte) (hwAddr []byte, err error) {
	e := h.cache.queryAddr(protoAddr)
	if e == nil {
		return nil, errQueryNotFound
	} else if e.flags.hasAny(eflagIncomplete) {
		return nil, errQueryPending
	}
	return e.mac[:], nil
}

func (h *Handler) DiscardQuery(protoAddr []byte) error {
	e := h.cache.queryAddr(protoAddr)
	if e == nil {
		return errQueryNotFound
	}
	e.destroy()
	return nil
}

// StartQuery queues a query to perform over ARP for the protocol address `proto`.
// The user can additionally specify an dstHWAddr to write query result to on completion.
// If dstHWAddr is nil then query still occurs but no external buffer is written on query completion.
// dstHWAddr must be zeroed out (invalid MAC).
func (h *Handler) StartQuery(dstHWAddr, proto []byte) error {
	if len(proto) != len(h.ourProtoAddr) {
		return lneto.ErrMismatchLen
	} else if dstHWAddr != nil && len(dstHWAddr) != len(h.ourHWAddr) {
		return lneto.ErrMismatchLen
	} else if dstHWAddr != nil && !internal.IsZeroed(dstHWAddr...) {
		return lneto.ErrInvalidConfig
	}
	e := h.cache.acquireNext()
	e.use([6]byte{}, proto, eflagIncomplete|eflagIncompletePendingQuery|eflagPriority)
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
	n, err := e.put(b, h.ourHWAddr, h.ourProtoAddr, op)
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
		e := h.cache.queryAddr(protoaddr)
		if e == nil {
			return nil
		}
		copy(e.mac[:], hwaddr)
		e.flags &^= eflagIncomplete | eflagIncompletePendingQuery

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
