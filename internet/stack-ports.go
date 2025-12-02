package internet

import (
	"encoding/binary"
	"io"
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

type StackPorts struct {
	connID     uint64
	handlers   handlers
	dstPortOff uint16
	protocol   uint16
}

func (ps *StackPorts) ResetUDP(maxNodes int) error {
	return ps.Reset(uint64(lneto.IPProtoUDP), 2, maxNodes)
}

func (ps *StackPorts) ResetTCP(maxNodes int) error {
	return ps.Reset(uint64(lneto.IPProtoTCP), 2, maxNodes)
}

func (ps *StackPorts) Reset(protocol uint64, dstPortOffset uint16, maxNodes int) error {
	if protocol > math.MaxUint16 {
		return errInvalidProto
	} else if maxNodes <= 0 {
		return errZeroMaxNodesArg
	}
	ps.handlers.Reset(maxNodes)
	*ps = StackPorts{
		connID:     ps.connID + 1,
		handlers:   ps.handlers,
		dstPortOff: dstPortOffset,
		protocol:   uint16(protocol),
	}
	return nil
}

func (ps *StackPorts) LocalPort() uint16 { return 0 }

func (ps *StackPorts) Protocol() uint64 { return uint64(ps.protocol) }

func (ps *StackPorts) ConnectionID() *uint64 { return &ps.connID }

func (ps *StackPorts) CheckEncapsulate(ed *internal.EncData) bool {
	for range ps.handlers.Len() {
		if node := ps.handlers.GetNext(); node != nil && !node.IsInvalid() && node.checkEncapsulate(ed) {
			return true
		}
	}
	return false
}

func (ps *StackPorts) DoEncapsulate(b []byte, offset int) (n int, err error) {
	if int(ps.dstPortOff)+offset+2 > len(b) {
		return 0, io.ErrShortBuffer
	}
	if h := ps.handlers.GetCurrent(); h != nil {
		n, err = h.doEncapsulate(b, offset)
		if err != nil || n > 0 {
			if ps.handleResult(h, err) {
				err = nil // Handler discarded.
			}
		}
	}
	return n, err
}

func (ps *StackPorts) Demux(b []byte, offset int) (err error) {
	if int(ps.dstPortOff)+offset+2 > len(b) {
		return io.ErrShortBuffer
	}
	port := binary.BigEndian.Uint16(b[int(ps.dstPortOff)+offset:])
	for i := range ps.handlers.Len() {
		h := ps.handlers.Node(i)
		if port != h.port {
			continue
		}
		err = h.demux(b, offset)
		if err != nil {
			if ps.handleResult(h, err) {
				err = nil // Handler discarded. Keep looking for other maybe available handlers.
				continue
			}
			break
		}
	}
	return err
}

func (ps *StackPorts) Register(h StackNode) error {
	port := h.LocalPort()
	proto := h.Protocol()

	if port <= 0 {
		return errZeroPort
	} else if proto != uint64(ps.protocol) {
		return errInvalidProto
	}
	var cid uint64
	cidPtr := h.ConnectionID()
	if cidPtr != nil {
		cid = *cidPtr
	}
	return ps.handlers.Register(node{
		demux:            h.Demux,
		checkEncapsulate: h.CheckEncapsulate,
		doEncapsulate:    h.DoEncapsulate,
		port:             port,
		currConnID:       cid,
		connID:           cidPtr,
		proto:            uint16(proto),
	})
}

func (ps *StackPorts) handleResult(h *node, err error) (discarded bool) {
	if handleNodeError(h, err) {
		discarded = true
		println("DISCARD port", h.port, "witherr", err.Error())
	}
	return discarded
}
