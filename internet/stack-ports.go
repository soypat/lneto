package internet

import (
	"encoding/binary"
	"io"
	"math"
	"strconv"

	"github.com/soypat/lneto"
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
	ps.handlers.reset("StackPorts(proto="+strconv.Itoa(int(protocol))+")", maxNodes)
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
	_, n, err = ps.handlers.encapsulateAny(b, offset)
	return n, err
}

func (ps *StackPorts) Demux(b []byte, offset int) (err error) {
	if int(ps.dstPortOff)+offset+2 > len(b) {
		return io.ErrShortBuffer
	}
	port := binary.BigEndian.Uint16(b[int(ps.dstPortOff)+offset:])
	_, err = ps.handlers.demuxByPort(b, offset, port)
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
	return ps.handlers.registerByPortProto(nodeFromStackNode(h, port, proto, nil))
}
