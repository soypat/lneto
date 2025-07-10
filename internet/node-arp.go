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
	return narp.handler.Demux(EtherFrame, arpOff)
}

func (narp *NodeARP) Encapsulate(EtherFrame []byte, arpOff int) (int, error) {
	n, err := narp.handler.Encapsulate(EtherFrame, arpOff)
	if err != nil || n == 0 {
		return 0, err // end with error.
	}
	afrm, _ := arp.NewFrame(EtherFrame[arpOff:])
	slog.Info("handle", slog.String("out", afrm.String()))
	return n, err
}

func (narp *NodeARP) StartQuery(proto []byte) error {
	return narp.handler.StartQuery(proto)
}

func (narp *NodeARP) QueryResult(proto []byte) ([]byte, error) {
	return narp.handler.QueryResult(proto)
}
