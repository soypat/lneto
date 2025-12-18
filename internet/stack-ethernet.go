package internet

import (
	"errors"
	"io"
	"log/slog"
	"math"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

type StackEthernet struct {
	connID   uint64
	handlers handlers
	logger
	mac   [6]byte
	gwmac [6]byte
	mtu   uint16
}

func (ls *StackEthernet) SetGateway6(gw [6]byte) {
	ls.gwmac = gw
}

func (ls *StackEthernet) Gateway6() (gw [6]byte) {
	return ls.gwmac
}

func (ls *StackEthernet) SetHardwareAddr6(mac [6]byte) {
	ls.mac = mac
}

func (ls *StackEthernet) HardwareAddr6() [6]byte {
	return ls.mac
}

func (ls *StackEthernet) Reset6(mac, gateway [6]byte, mtu, maxNodes int) error {
	if mtu > math.MaxUint16 || mtu < 256 {
		return errors.New("invalid MTU")
	} else if maxNodes <= 0 {
		return errZeroMaxNodesArg
	}
	ls.handlers.reset(maxNodes)
	*ls = StackEthernet{
		connID:   ls.connID + 1,
		handlers: ls.handlers,
		logger:   ls.logger,
		mac:      mac,
		gwmac:    gateway,
		mtu:      uint16(mtu),
	}
	return nil
}

func (ls *StackEthernet) MTU() int { return int(ls.mtu) }

func (ls *StackEthernet) ConnectionID() *uint64 { return &ls.connID }

func (ls *StackEthernet) LocalPort() uint16 { return 0 }

func (ls *StackEthernet) Protocol() uint64 { return 1 }

func (ls *StackEthernet) Register(h StackNode) error {
	proto := h.Protocol()
	if proto > math.MaxUint16 || proto <= 1500 {
		return errInvalidProto
	}
	return ls.handlers.registerByProto(nodeFromStackNode(h, 0, proto, nil))
}

func (ls *StackEthernet) Demux(carrierData []byte, frameOffset int) (err error) {
	pkt := carrierData[frameOffset:]
	efrm, err := ethernet.NewFrame(pkt)
	if err != nil {
		return err
	}
	etype := efrm.EtherTypeOrSize()
	dstaddr := efrm.DestinationHardwareAddr()
	var vld lneto.Validator
	if !efrm.IsBroadcast() && ls.mac != *dstaddr {
		goto DROP
	}
	efrm.ValidateSize(&vld)
	if vld.HasError() {
		return vld.ErrPop()
	}
	{
		h := ls.handlers.nodeByProto(uint16(etype))
		if h != nil {
			err := h.demux(efrm.Payload(), 0)
			if ls.handlers.tryHandleError(h, err) {
				err = nil
			}
			return err
		}
	}
DROP:
	ls.info("LinkStack:drop-packet", slog.String("dsthw", net.HardwareAddr(dstaddr[:]).String()), slog.String("ethertype", efrm.EtherTypeOrSize().String()))
	return lneto.ErrPacketDrop
}

func (ls *StackEthernet) Encapsulate(carrierData []byte, frameOffset int) (n int, err error) {
	mtu := ls.mtu
	dst := carrierData[frameOffset:]
	if len(dst) < int(mtu) {
		return 0, io.ErrShortBuffer
	}
	efrm, err := ethernet.NewFrame(dst)
	if err != nil {
		return 0, err
	}
	*efrm.DestinationHardwareAddr() = ls.gwmac
	var h *node
	h, n, err = ls.handlers.encapsulateAny(dst[:mtu], 14)
	if n > 0 {
		// Found packet
		*efrm.SourceHardwareAddr() = ls.mac
		efrm.SetEtherType(ethernet.Type(h.proto))
		n += 14
		if err != nil {
			ls.error("Ethernet:encapuslate", slog.String("err", err.Error()))
		}
	}
	return n, err
}
