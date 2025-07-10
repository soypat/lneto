package arp

import (
	"bytes"
	"errors"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
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

func (h *Handler) Reset(cfg HandlerConfig) error {
	if len(cfg.HardwareAddr) == 0 || len(cfg.HardwareAddr) > 255 ||
		len(cfg.ProtocolAddr) == 0 || len(cfg.ProtocolAddr) > 255 {
		return errors.New("invalid Handler address config")
	} else if cfg.MaxQueries <= 0 || cfg.MaxPending <= 0 {
		return errors.New("invalid Handler query or pending config")
	}
	*h = Handler{
		connID:          h.connID + 1,
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
	querysent bool
}

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
			} else if len(h.queries[i].hwaddr) == 0 {
				return nil, errors.New("no response yet")
			}
			return h.queries[i].hwaddr, nil
		}
	}
	return nil, errors.New("query not exist or dropped")
}

func (h *Handler) StartQuery(proto []byte) error {
	if len(proto) != len(h.ourProtoAddr) {
		return errors.New("bad protocol address length")
	} else if len(h.queries) == cap(h.queries) {
		return errors.New("too many ongoing queries")
	}
	h.queries = h.queries[:len(h.queries)+1]
	q := &h.queries[len(h.queries)-1]
	q.hwaddr = q.hwaddr[:0]
	q.querysent = false
	q.protoaddr = append(q.protoaddr[:0], proto...)
	return nil
}

func (h *Handler) Encapsulate(eth []byte, frameOffset int) (int, error) {
	b := eth[frameOffset:]
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
		trySetEthernetDst(eth[:frameOffset], tgt)
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
			trySetEthernetDst(eth[:frameOffset], broadcast[:])
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
			if len(h.queries[i].hwaddr) == 0 && bytes.Equal(h.queries[i].protoaddr, protoaddr) {
				h.queries[i].hwaddr = append(h.queries[i].hwaddr[:0], hwaddr...)
				return nil
			}
		}

	default:
		return errARPUnsupported
	}
	return nil
}

func trySetEthernetDst(ethFrame []byte, dst []byte) {
	if len(ethFrame) > 14 {
		copy(ethFrame[:6], dst)
	}
}
