package internet

import (
	"log/slog"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

var _ lneto.StackNode = (*StackIP)(nil)

type StackIP struct {
	connID uint64
	stackip4
	stackip6
}

func (stackip *StackIP) Reset(vld *lneto.Validator, maxNodes4, maxNodes6 int) error {
	if maxNodes4 <= 0 && maxNodes6 <= 0 || vld == nil {
		return lneto.ErrInvalidConfig
	}
	stackip.connID++
	stackip.reset4(vld, maxNodes4)
	stackip.reset6(vld, maxNodes6)
	return nil
}

func (stackip *StackIP) ConnectionID() *uint64 {
	return &stackip.connID
}

func (stackip *StackIP) Protocol() uint64 {
	return uint64(ethernet.TypeIPv4) // Only support ipv4 for now.
}

func (stackip *StackIP) LocalPort() uint16 { return 0 }

func (stackip *StackIP) SetLogger(logger *slog.Logger) {
	stackip.stackip4.handlers.log = logger
	stackip.stackip6.handlers.log = logger
}

func (stackip *StackIP) Demux(carrierData []byte, offset int) error {
	debugLog("ip:demux")
	if len(carrierData) < 1 {
		return lneto.ErrTruncatedFrame
	}
	version := carrierData[offset] >> 4
	switch version {
	case 4:
		return stackip.stackip4.demux4(carrierData, offset)
	case 6:
		return stackip.stackip6.demux6(carrierData, offset)
	default:
		return lneto.ErrUnsupported
	}
}

func (stackip *StackIP) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	if offsetToFrame != offsetToIP {
		return 0, lneto.ErrBug
	}
	n, err = stackip.stackip4.encapsulate4(carrierData, offsetToIP)
	// Support IPv6
	return n, err
}
