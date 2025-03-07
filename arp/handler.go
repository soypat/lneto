package arp

import (
	"bytes"
	"errors"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

type Handler struct {
	ourHWAddr    []byte
	ourProtoAddr []byte
	htype        uint16
	protoType    ethernet.Type
	pending      [][sizeHeaderv6]byte
	queries      []queryResult
}

type HandlerConfig struct {
	HardwareAddr []byte
	ProtocolAddr []byte
	MaxQueries   int
	MaxPending   int
	HardwareType uint16
	ProtocolType ethernet.Type
}

func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if len(cfg.HardwareAddr) == 0 || len(cfg.HardwareAddr) > 255 ||
		len(cfg.ProtocolAddr) == 0 || len(cfg.ProtocolAddr) > 255 {
		return nil, errors.New("invalid Handler address config")
	} else if cfg.MaxQueries <= 0 || cfg.MaxPending <= 0 {
		return nil, errors.New("invalid Handler query or pending config")
	}
	h := &Handler{
		pending:      make([][sizeHeaderv6]byte, 0, cfg.MaxPending),
		htype:        cfg.HardwareType,
		protoType:    cfg.ProtocolType,
		ourHWAddr:    cfg.HardwareAddr,
		ourProtoAddr: cfg.ProtocolAddr,
		queries:      make([]queryResult, 0, cfg.MaxQueries),
	}
	return h, nil
}

type queryResult struct {
	protoaddr []byte
	hwaddr    []byte
	querysent bool
}

// ResetState drops pending queries and incoming requests.
func (c *Handler) ResetState() {
	c.pending = c.pending[:0]
	c.queries = c.queries[:0]
}

func (c *Handler) expectSize() int {
	return sizeHeader + 2*len(c.ourHWAddr) + 2*len(c.ourProtoAddr)
}

func (c *Handler) QueryResult(protoAddr []byte) (hwAddr []byte, err error) {
	for i := range c.queries {
		if bytes.Equal(protoAddr, c.queries[i].protoaddr) {
			if !c.queries[i].querysent {
				return nil, errors.New("query not yet sent")
			} else if len(c.queries[i].hwaddr) == 0 {
				return nil, errors.New("no response yet")
			}
			return c.queries[i].hwaddr, nil
		}
	}
	return nil, errors.New("query not exist or dropped")
}

func (c *Handler) StartQuery(proto []byte) error {
	if len(proto) != len(c.ourProtoAddr) {
		return errors.New("bad protocol address length")
	} else if len(c.queries) == cap(c.queries) {
		return errors.New("too many ongoing queries")
	}
	c.queries = c.queries[:len(c.queries)+1]
	q := &c.queries[len(c.queries)-1]
	q.hwaddr = q.hwaddr[:0]
	q.querysent = false
	q.protoaddr = append(q.protoaddr[:0], proto...)
	return nil
}

func (c *Handler) Send(b []byte) (int, error) {
	n := c.expectSize()
	if len(b) < n {
		return 0, errShortARP
	}
	if len(c.pending) > 0 {
		// pop frame.
		afrm, _ := NewFrame(c.pending[len(c.pending)-1][:])
		c.pending = c.pending[:len(c.pending)-1]
		afrm.SetOperation(OpReply)
		afrm.SwapTargetSender()
		hwsender, _ := afrm.Sender()
		copy(hwsender, c.ourHWAddr)
		n := copy(b, afrm.Clip().RawData())
		return n, nil
	}
	for i := range c.queries {
		if !c.queries[i].querysent {
			c.queries[i].querysent = true
			afrm, _ := NewFrame(b)
			afrm.SetHardware(c.htype, uint8(len(c.ourHWAddr)))
			afrm.SetProtocol(c.protoType, uint8(len(c.ourProtoAddr)))
			afrm.SetOperation(OpRequest)
			hwSender, protoSender := afrm.Sender()
			copy(hwSender, c.ourHWAddr)
			copy(protoSender, c.ourProtoAddr)
			hwTarget, protoTarget := afrm.Target()
			copy(protoTarget, c.queries[i].protoaddr)
			for j := range hwTarget {
				hwTarget[j] = 0
			}
			return n, nil
		}
	}
	return 0, nil
}

func (c *Handler) Recv(b []byte) error {
	if len(c.pending) == cap(c.pending) {
		return errARPBufferFull
	}
	afrm, err := NewFrame(b)
	if err != nil {
		return err
	}
	var vld lneto.Validator
	afrm.ValidateSize(&vld)
	if vld.HasError() {
		return vld.Err()
	}
	htype, hlen := afrm.Hardware()
	if htype != c.htype || int(hlen) != len(c.ourHWAddr) {
		return errors.New("bad ARP hardware")
	}
	protoType, protoLen := afrm.Protocol()
	if protoType != c.protoType || int(protoLen) != len(c.ourProtoAddr) {
		return errors.New("bad ARP proto")
	}
	switch afrm.Operation() {
	case OpRequest:
		_, protoaddr := afrm.Target()
		if !bytes.Equal(protoaddr, c.ourProtoAddr) {
			return nil // Not for us.
		}
		c.pending = c.pending[:len(c.pending)+1]       // Extend pending buffer.
		copy(c.pending[len(c.pending)-1][:], afrm.buf) // Set pending buffer.

	case OpReply:
		hwaddr, protoaddr := afrm.Sender()
		for i := range c.queries {
			if len(c.queries[i].hwaddr) == 0 && bytes.Equal(c.queries[i].protoaddr, protoaddr) {
				c.queries[i].hwaddr = append(c.queries[i].hwaddr[:0], hwaddr...)
				return nil
			}
		}

	default:
		return errARPUnsupported
	}
	return nil
}
