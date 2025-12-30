package arp

import (
	"bytes"
	"errors"
	"log/slog"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

type Handler struct {
	connID          uint64
	ourHWAddr       []byte
	ourProtoAddr    []byte
	htype           uint16
	protoType       ethernet.Type
	pendingResponse [][sizeHeaderv6]byte
	queries         []queryResult
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
		return errors.New("mismatch ARP proto size")
	}
	copy(h.ourProtoAddr, protoAddr)
	return nil
}

func (h *Handler) Reset(cfg HandlerConfig) error {
	if len(cfg.HardwareAddr) == 0 || len(cfg.HardwareAddr) > 255 ||
		len(cfg.ProtocolAddr) == 0 || len(cfg.ProtocolAddr) > 255 {
		return errors.New("invalid Handler address config")
	} else if cfg.MaxQueries <= 0 || cfg.MaxPending <= 0 {
		return errors.New("invalid Handler query or pending config")
	}
	*h = Handler{
		connID:          h.connID,
		ourHWAddr:       h.ourHWAddr[:0],
		ourProtoAddr:    h.ourProtoAddr[:0],
		htype:           cfg.HardwareType,
		protoType:       cfg.ProtocolType,
		pendingResponse: h.pendingResponse[:0],
		queries:         h.queries[:0],
	}
	h.ourHWAddr = append(h.ourHWAddr, cfg.HardwareAddr...)
	h.ourProtoAddr = append(h.ourProtoAddr, cfg.ProtocolAddr...)
	if cap(h.pendingResponse) < cfg.MaxPending {
		h.pendingResponse = make([][52]byte, cfg.MaxPending)[:0]
	}
	if cap(h.queries) < cfg.MaxQueries {
		h.queries = make([]queryResult, cfg.MaxQueries)[:0]
	}
	return nil
}

type queryResult struct {
	protoaddr []byte
	hwaddr    []byte
	dstHw     []byte
	querysent bool
}

func (qr *queryResult) destroy() {
	*qr = queryResult{protoaddr: qr.protoaddr[:0], hwaddr: qr.hwaddr[:0]}
}

func (qr *queryResult) response() []byte {
	if len(qr.hwaddr) == 0 {
		return nil
	}
	return qr.hwaddr[:]
}
func (qr *queryResult) isInvalid() bool { return len(qr.protoaddr) == 0 }

// AbortPending drops pending queries and incoming requests.
func (h *Handler) AbortPending() {
	h.pendingResponse = h.pendingResponse[:0]
	h.queries = h.queries[:0]
}

func (h *Handler) expectSize() int {
	return sizeHeader + 2*len(h.ourHWAddr) + 2*len(h.ourProtoAddr)
}

func (h *Handler) QueryResult(protoAddr []byte) (hwAddr []byte, err error) {
	for i := range h.queries {
		if bytes.Equal(protoAddr, h.queries[i].protoaddr) {
			if !h.queries[i].querysent {
				return nil, errors.New("query not yet sent")
			}
			mac := h.queries[i].response()
			if mac == nil {
				return nil, errors.New("no response yet")
			}
			return mac, nil
		}
	}
	return nil, errors.New("query not exist or dropped")
}

func (h *Handler) DiscardQuery(protoAddr []byte) error {
	for i := range h.queries {
		q := &h.queries[i]
		if bytes.Equal(protoAddr, q.protoaddr) {
			q.destroy()
			return nil
		}
	}
	return errors.New("query not found")
}

func (h *Handler) compactQueries() {
	validOff := 0
	for i := 0; i < len(h.queries); i++ {
		if h.queries[i].isInvalid() {
			h.queries[validOff] = h.queries[i]
			validOff++
		}
	}
	h.queries = h.queries[:validOff]
}

// StartQuery queues a query to perform over ARP for the protocol address `proto`.
// The user can additionally specify an dstHWAddr to write query result to on completion.
// If dstHWAddr is nil then query still occurs but no external buffer is written on query completion.
// dstHWAddr must be zeroed out (invalid MAC).
func (h *Handler) StartQuery(dstHWAddr, proto []byte) error {
	if len(h.queries) == cap(h.queries) {
		h.compactQueries()
		if len(h.queries) == cap(h.queries) {
			return errors.New("too many ongoing queries")
		}
	}
	if len(proto) != len(h.ourProtoAddr) {
		return errors.New("bad protocol address length")
	} else if dstHWAddr != nil && len(dstHWAddr) != len(h.ourHWAddr) {
		return errors.New("mismatch hardware size")
	} else if dstHWAddr != nil && !internal.IsZeroed(dstHWAddr...) {
		return errors.New("write-to buffer must be zeroed out")
	}
	h.queries = h.queries[:len(h.queries)+1]
	q := &h.queries[len(h.queries)-1]
	*q = queryResult{
		protoaddr: append(q.protoaddr[:0], proto...),
		hwaddr:    q.hwaddr[:0],
		dstHw:     dstHWAddr,
	}
	return nil
}

func (h *Handler) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	b := carrierData[offsetToFrame:]
	n := h.expectSize()
	if len(b) < n {
		return 0, errShortARP
	}
	if len(h.pendingResponse) > 0 {
		// pop frame.
		afrm, _ := NewFrame(h.pendingResponse[len(h.pendingResponse)-1][:])
		h.pendingResponse = h.pendingResponse[:len(h.pendingResponse)-1]
		afrm.SetOperation(OpReply)
		afrm.SwapTargetSender()
		hwsender, _ := afrm.Sender()
		copy(hwsender, h.ourHWAddr)
		n := copy(b, afrm.Clip().RawData())
		tgt, _ := afrm.Target()
		trySetEthernetDst(carrierData[:offsetToFrame], tgt)
		return n, nil
	}
	for i := range h.queries {
		if !h.queries[i].querysent {
			h.queries[i].querysent = true
			afrm, _ := NewFrame(b)
			afrm.SetHardware(h.htype, uint8(len(h.ourHWAddr)))
			afrm.SetProtocol(h.protoType, uint8(len(h.ourProtoAddr)))
			afrm.SetOperation(OpRequest)
			hwSender, protoSender := afrm.Sender()
			copy(hwSender, h.ourHWAddr)
			copy(protoSender, h.ourProtoAddr)
			hwTarget, protoTarget := afrm.Target()
			copy(protoTarget, h.queries[i].protoaddr)
			for j := range hwTarget {
				hwTarget[j] = 0
			}
			broadcast := ethernet.BroadcastAddr()
			trySetEthernetDst(carrierData[:offsetToFrame], broadcast[:])
			return n, nil
		}
	}
	return 0, nil
}

func (h *Handler) Demux(ethFrame []byte, frameOffset int) error {
	if len(h.pendingResponse) == cap(h.pendingResponse) {
		return errARPBufferFull
	}

	b := ethFrame[frameOffset:]
	afrm, err := NewFrame(b)
	if err != nil {
		return err
	}
	var vld lneto.Validator
	afrm.ValidateSize(&vld)
	if vld.HasError() {
		return vld.ErrPop()
	}
	htype, hlen := afrm.Hardware()
	if htype != h.htype || int(hlen) != len(h.ourHWAddr) {
		return errors.New("bad ARP hardware")
	}
	protoType, protoLen := afrm.Protocol()
	if protoType != h.protoType || int(protoLen) != len(h.ourProtoAddr) {
		return errors.New("bad ARP proto")
	}
	switch afrm.Operation() {
	case OpRequest:
		_, protoaddr := afrm.Target()
		if !bytes.Equal(protoaddr, h.ourProtoAddr) {
			return nil // Not for us.
		}
		h.pendingResponse = h.pendingResponse[:len(h.pendingResponse)+1] // Extend pending buffer.
		copy(h.pendingResponse[len(h.pendingResponse)-1][:], afrm.buf)   // Set pending buffer.

	case OpReply:
		hwaddr, protoaddr := afrm.Sender()
		for i := range h.queries {
			q := &h.queries[i]
			mac := q.response()
			if mac == nil && bytes.Equal(q.protoaddr, protoaddr) {
				q.hwaddr = append(q.hwaddr, hwaddr...)
				if q.dstHw != nil {
					if !internal.IsZeroed(q.dstHw...) {
						slog.Error("race-condition:ARP-reused-buffer")
					}
					copy(q.dstHw, hwaddr) // External write to user buffer.
				}
				return nil
			}
		}

	default:
		return errARPUnsupported
	}
	return nil
}

func trySetEthernetDst(ethFrame []byte, dst []byte) {
	if len(ethFrame) >= 14 {
		copy(ethFrame[:6], dst)
	}
}
