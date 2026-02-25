package internet

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math"
	"strconv"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/tcp"
)

type StackPorts struct {
	connID     uint64
	handlers   handlers
	dstPortOff uint16
	protocol   uint16
	// rstQueue stores pending RST responses for TCP SYNs to unregistered ports.
	rstQueue tcp.RSTQueue
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
	_, n, err = ps.handlers.encapsulateAny(carrierData, offsetToIP, offsetToFrame)
	if n == 0 {
		n, _ = ps.rstQueue.Drain(carrierData, offsetToIP, offsetToFrame)
	}
	return n, err
}

func (ps *StackPorts) Demux(b []byte, offset int) (err error) {
	if int(ps.dstPortOff)+offset+2 > len(b) {
		return io.ErrShortBuffer
	}
	port := binary.BigEndian.Uint16(b[int(ps.dstPortOff)+offset:])
	_, err = ps.handlers.demuxByPort(b, offset, port)
	if err == lneto.ErrPacketDrop && ps.protocol == uint16(lneto.IPProtoTCP) && offset+14 <= len(b) {
		// RFC 9293 §3.10.7.1: RST for SYN to port with no listener.
		flags := binary.BigEndian.Uint16(b[offset+12:]) & 0x01ff
		const flagSYN, flagRST, flagACK = 0x02, 0x04, 0x10
		if flags&flagSYN != 0 && flags&(flagRST|flagACK) == 0 {
			srcaddr, _, _, _, iperr := internal.GetIPAddr(b)
			if iperr == nil {
				remotePort := binary.BigEndian.Uint16(b[offset:])
				segSeq := tcp.Value(binary.BigEndian.Uint32(b[offset+4:]))
				ps.rstQueue.Queue(srcaddr, remotePort, port, 0, segSeq+1, tcp.FlagRST|tcp.FlagACK)
			}
		}
	}
	return err
}

// Register registers a port StackNode on StackPorts.
// If dstMAC is set to non-nil, length six buffer then
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

// StackPortsMACFiltered is a StackPorts implementation but that avoids calling encapsulate on nodes
// with a non-nil MAC address registered via Register method that is set to all zero values.
// If the address is set to nil no filtering occurs. MAC Address is set automatically on the ethernet frame by StackPortsMACFiltered when non-nil.
type StackPortsMACFiltered struct {
	sp StackPorts
}

func (mfsp *StackPortsMACFiltered) Register(h StackNode, addr []byte) error {
	port := h.LocalPort()
	proto := h.Protocol()
	if port <= 0 {
		return errZeroPort
	} else if proto != uint64(mfsp.sp.protocol) {
		return errInvalidProto
	} else if addr != nil && len(addr) != 6 {
		return errors.New("invalid MAC")
	}
	return mfsp.sp.handlers.registerByPortProto(nodeFromStackNode(h, port, proto, addr))
}

func (ps *StackPortsMACFiltered) ResetUDP(maxNodes int) error {
	return ps.sp.ResetUDP(maxNodes)
}

func (ps *StackPortsMACFiltered) ResetTCP(maxNodes int) error {
	return ps.sp.ResetTCP(maxNodes)
}

func (ps *StackPortsMACFiltered) Reset(protocol uint64, dstPortOffset uint16, maxNodes int) error {
	return ps.sp.Reset(protocol, dstPortOffset, maxNodes)
}

func (ps *StackPortsMACFiltered) LocalPort() uint16 { return 0 }

func (ps *StackPortsMACFiltered) Protocol() uint64 { return uint64(ps.sp.protocol) }

func (ps *StackPortsMACFiltered) ConnectionID() *uint64 { return &ps.sp.connID }

func (ps *StackPortsMACFiltered) Demux(b []byte, offset int) (err error) {
	// No MAC Filtering on ingress. TODO?
	return ps.sp.Demux(b, offset)
}

func (ps *StackPortsMACFiltered) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	if int(ps.sp.dstPortOff)+offsetToFrame+2 > len(carrierData) {
		return 0, io.ErrShortBuffer
	}
	h := &ps.sp.handlers
	for i := range h.nodes {
		node := &h.nodes[i]
		if node.IsInvalid() || (len(node.remoteAddr) > 0 && internal.IsZeroed(node.remoteAddr...)) {
			continue
		}
		n, err = node.callbacks.Encapsulate(carrierData, offsetToIP, offsetToFrame)
		if h.tryHandleError(node, err) {
			err = nil // CLOSE error handled gracefully by deleting node.
		}
		if n > 0 {
			if len(node.remoteAddr) == 6 && offsetToIP >= 14 {
				efrm, _ := ethernet.NewFrame(carrierData[offsetToIP-14:])
				*efrm.DestinationHardwareAddr() = [6]byte(node.remoteAddr)
			}
			return n, err
		} else if err != nil {
			// Make sure not to hang on one handler that keeps returning an error.
			h.error("handlers:encapsulate", slog.String("func", "encapsulateAny"), slog.String("ctx", h.context), slog.String("err", err.Error()))
		}
	}
	if n, _ := ps.sp.rstQueue.Drain(carrierData, offsetToIP, offsetToFrame); n > 0 {
		return n, nil
	}
	return 0, err // Return last written error.
}
