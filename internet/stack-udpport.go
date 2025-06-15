package internet

import (
	"log/slog"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/udp"
)

type StackUDPPort struct {
	h      node
	vld    lneto.Validator
	rmport uint16
}

func (sudp *StackUDPPort) SetStackNode(node StackNode, rmport uint16) {
	sudp.h = nodeFromStackNode(node, node.LocalPort(), node.Protocol())
	sudp.rmport = rmport
}

func (sudp *StackUDPPort) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

func (sudp *StackUDPPort) LocalPort() uint16 { return sudp.h.port }

func (sudp *StackUDPPort) ConnectionID() *uint64 { return sudp.h.connID }

func (sudp *StackUDPPort) Demux(carrierData []byte, frameOffset int) error {
	if checkNode(&sudp.h) {
		sudp.h.destroy()
		return net.ErrClosed
	}
	ufrm, err := udp.NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	ufrm.ValidateSize(&sudp.vld)
	if sudp.vld.HasError() {
		return sudp.vld.ErrPop()
	}
	dst := ufrm.DestinationPort()
	if dst != sudp.h.port {
		return nil // Not meant for us.
	}

	src := ufrm.SourcePort()
	if sudp.rmport != 0 && src != sudp.rmport {
		return nil // Not from our target remote port.
	}
	err = sudp.h.demux(ufrm.Payload(), 8)
	if err != nil {
		if checkNodeErr(&sudp.h, err) {
			sudp.h.destroy()
		}
		slog.Error("stackudp:demux", slog.String("err", err.Error()))
	}
	return err
}

func (sudp *StackUDPPort) Encapsulate(carrierData []byte, frameOffset int) (int, error) {
	if checkNode(&sudp.h) {
		sudp.h.destroy()
		return 0, net.ErrClosed
	}
	ufrm, err := udp.NewFrame(carrierData[frameOffset:])
	if err != nil {
		return 0, err
	}
	ufrm.SetSourcePort(sudp.h.port)
	ufrm.SetDestinationPort(sudp.rmport)
	n, err := sudp.h.encapsulate(carrierData[frameOffset:], 8)
	if err != nil {
		slog.Error("stackudp:demux", slog.String("err", err.Error()))
	}
	ufrm.SetLength(8 + uint16(n))
	// UDP CRC left to IP layer.
	return n, err
}
