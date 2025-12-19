package internet

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strconv"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
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

func (ps *StackPorts) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	if int(ps.dstPortOff)+offsetToFrame+2 > len(carrierData) {
		return 0, io.ErrShortBuffer
	}
	var node *node
	node, n, err = ps.handlers.encapsulateAny(carrierData, offsetToIP, offsetToFrame)
	if n > 0 && len(node.remoteAddr) == 6 && offsetToIP >= 14 {
		efrm, _ := ethernet.NewFrame(carrierData[offsetToIP-14:])
		*efrm.DestinationHardwareAddr() = [6]byte(node.remoteAddr)
	}
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

// Register registers a port StackNode on StackPorts.
// If dstMAC is set to non-nil, length six buffer then
func (ps *StackPorts) Register(h StackNode, dstMAC []byte) error {
	port := h.LocalPort()
	proto := h.Protocol()
	if port <= 0 {
		return errZeroPort
	} else if proto != uint64(ps.protocol) {
		return errInvalidProto
	} else if dstMAC != nil && len(dstMAC) != 6 {
		return errors.New("invalid MAC")
	}
	return ps.handlers.registerByPortProto(nodeFromStackNode(h, port, proto, dstMAC))
}
