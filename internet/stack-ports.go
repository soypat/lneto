package internet

import (
	"encoding/binary"
	"io"
	"math"
	"slices"

	"github.com/soypat/lneto"
)

type StackPorts struct {
	connID     uint64
	handlers   []node
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
	}
	ps.handlers = slices.Grow(ps.handlers[:0], maxNodes)
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

func (ps *StackPorts) Encapsulate(b []byte, offset int) (n int, err error) {
	if int(ps.dstPortOff)+offset+2 > len(b) {
		return 0, io.ErrShortBuffer
	}
	var i int
	for i = 0; i < len(ps.handlers); i++ {
		n, err = ps.handlers[i].encapsulate(b, offset)
		if err != nil || n > 0 {
			if ps.handleResult(i, n, err) {
				err = nil // Handler discarded. Keep looking for other handlers.
				continue
			}
			break
		}
	}
	return n, err
}

func (ps *StackPorts) Demux(b []byte, offset int) (err error) {
	if int(ps.dstPortOff)+offset+2 > len(b) {
		return io.ErrShortBuffer
	}
	port := binary.BigEndian.Uint16(b[int(ps.dstPortOff)+offset:])
	var i int
	for i = 0; i < len(ps.handlers); i++ {
		if port != ps.handlers[i].port {
			continue
		}
		err = ps.handlers[i].demux(b, offset)
		if err != nil {
			if ps.handleResult(i, 0, err) {
				err = nil // Handler discarded. Keep looking for other maybe available handlers.
				continue
			}
			break
		}
	}
	ps.handleResult(i, 0, err)
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
	return registerNode(&ps.handlers, node{
		demux:       h.Demux,
		encapsulate: h.Encapsulate,
		port:        port,
	})
}

func (ps *StackPorts) handleResult(handlerIdx, n int, err error) (discarded bool) {
	if handleNodeError(&ps.handlers, handlerIdx, err) {
		discarded = true
		println("DISCARD", handlerIdx, "witherr", err.Error())
	}
	return discarded
}
