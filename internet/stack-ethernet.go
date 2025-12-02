package internet

import (
	"errors"
	"io"
	"log/slog"
	"math"
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
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
	ls.handlers.Reset(maxNodes)
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
	eproto := uint16(proto)
	for i := range ls.handlers.Len() {
		hgot := ls.handlers.Node(i)
		if hgot.proto == eproto {
			return errProtoRegistered
		}
	}
	return ls.handlers.Register(node{
		demux:            h.Demux,
		checkEncapsulate: h.CheckEncapsulate,
		doEncapsulate:    h.DoEncapsulate,
		proto:            eproto,
	})
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

	for i := range ls.handlers.Len() {
		h := ls.handlers.Node(i)
		if h.proto == uint16(etype) {
			return h.demux(efrm.Payload(), 0)
		}
	}
DROP:
	ls.info("LinkStack:drop-packet", slog.String("dsthw", net.HardwareAddr(dstaddr[:]).String()), slog.String("ethertype", efrm.EtherTypeOrSize().String()))
	return lneto.ErrPacketDrop
}

func (ls *StackEthernet) CheckEncapsulate(ed *internal.EncData) bool {
	return ls.handlers.CheckEncapsulate(ed)
}

func (ls *StackEthernet) DoEncapsulate(carrierData []byte, frameOffset int) (n int, err error) {
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
	if h := ls.handlers.GetCurrent(); h != nil {
		n, err = h.doEncapsulate(dst[:mtu], 14)
		if err != nil {
			ls.error("handling", slog.String("proto", ethernet.Type(h.proto).String()), slog.String("err", err.Error()))
			err = nil
		} else if n > 0 {
			// Found packet
			*efrm.SourceHardwareAddr() = ls.mac
			efrm.SetEtherType(ethernet.Type(h.proto))
			return n + 14, nil
		}
	}
	return 0, err
}
