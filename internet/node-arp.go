package internet

import (
	"log/slog"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
)

type NodeARP struct {
	handler arp.Handler
	vld     lneto.Validator
}

func (narp *NodeARP) Reset(cfg arp.HandlerConfig) error {
	return narp.handler.Reset(cfg)
}

func (narp *NodeARP) LocalPort() uint16 { return 0 }

func (narp *NodeARP) Protocol() uint64 { return uint64(ethernet.TypeARP) }

func (narp *NodeARP) ConnectionID() *uint64 { return narp.handler.ConnectionID() }

func (narp *NodeARP) Demux(EtherFrame []byte, arpOff int) error {
	afrm, err := arp.NewFrame(EtherFrame[arpOff:])
	if err != nil {
		slog.Error("bad-ARP", slog.String("err", err.Error()))
		return nil
	}
	afrm.ValidateSize(&narp.vld)
	if narp.vld.HasError() {
		slog.Error("invalid-ARP", slog.String("err", narp.vld.Err().Error()))
		return nil
	}
	return narp.handler.Recv(EtherFrame[arpOff:])
}

func (narp *NodeARP) Encapsulate(EtherFrame []byte, arpOff int) (int, error) {
	n, err := narp.handler.Send(EtherFrame[arpOff:])
	if err != nil || n == 0 {
		return 0, err // end with error.
	}
	afrm, _ := arp.NewFrame(EtherFrame[arpOff:])
	hwaddr, _ := afrm.Target()
	efrm, _ := ethernet.NewFrame(EtherFrame)
	copy(efrm.DestinationHardwareAddr()[:], hwaddr)
	slog.Info("handle", slog.String("out", afrm.String()))
	return n, err
}
