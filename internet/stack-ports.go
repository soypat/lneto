package internet

import (
	"encoding/binary"
	"io"
)

type StackPorts struct {
	connID     uint64
	protocol   uint64
	handlers   []node
	dstPortOff int
}

func (ps *StackPorts) Reset(protocol uint64, dstPortOffset int) {
	*ps = StackPorts{
		connID:     ps.connID + 1,
		handlers:   ps.handlers[:0],
		dstPortOff: dstPortOffset,
		protocol:   protocol,
	}
}
func (ps *StackPorts) LocalPort() uint16 { return 0 }

func (ps *StackPorts) Protocol() uint64 { return ps.protocol }

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
	} else if proto != ps.protocol {
		return errInvalidProto
	}
	ps.handlers = append(ps.handlers, node{
		demux:       h.Demux,
		encapsulate: h.Encapsulate,
		port:        uint16(port),
	})
	return nil
}

func (ps *StackPorts) handleResult(handlerIdx, n int, err error) {
	handleNodeError(&ps.handlers, handlerIdx, err)
}
