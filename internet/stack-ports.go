package internet

import (
	"encoding/binary"
	"io"
	"math"
)

type StackPorts struct {
	connID     uint64
	handlers   []node
	dstPortOff int
	protocol   uint16
}

func (ps *StackPorts) Reset(protocol uint64, dstPortOffset int) error {
	if protocol > math.MaxUint16 {
		return errInvalidProto
	}
	*ps = StackPorts{
		connID:     ps.connID + 1,
		handlers:   ps.handlers[:0],
		dstPortOff: dstPortOffset,
		protocol:   uint16(protocol),
	}
	return nil
}

func (ps *StackPorts) LocalPort() uint16 { return 0 }

func (ps *StackPorts) Protocol() uint64 { return uint64(ps.protocol) }

func (ps *StackPorts) ConnectionID() *uint64 { return &ps.connID }

func (ps *StackPorts) Encapsulate(b []byte, offset int) (n int, err error) {
	if ps.dstPortOff+offset+2 > len(b) {
		return 0, io.ErrShortBuffer
	}
	var i int
	for i = 0; i < len(ps.handlers); i++ {
		n, err = ps.handlers[i].encapsulate(b, offset)
		if err != nil || n > 0 {
			break
		}
	}
	ps.handleResult(i, n, err)
	return n, err
}

func (ps *StackPorts) Demux(b []byte, offset int) (err error) {
	if ps.dstPortOff+offset+2 > len(b) {
		return io.ErrShortBuffer
	}
	port := binary.BigEndian.Uint16(b[ps.dstPortOff+offset:])
	var i int
	for i = 0; i < len(ps.handlers); i++ {
		if port != ps.handlers[i].port {
			continue
		}
		err = ps.handlers[i].demux(b, offset)
		if err != nil {
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
	ps.handlers = append(ps.handlers, node{
		demux:       h.Demux,
		encapsulate: h.Encapsulate,
		port:        port,
	})
	return nil
}

func (ps *StackPorts) handleResult(handlerIdx, n int, err error) {
	if handleNodeError(&ps.handlers, handlerIdx, err) {
		println("DISCARD", handlerIdx, "witherr", err.Error())
	}
}
