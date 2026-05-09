package internet

import (
	"log/slog"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
)

var _ lneto.StackNode = (*StackIP)(nil)

type StackIP struct {
	connID uint64
	stackip4
	stackip6
}

func (sb *StackIP) Reset(addr netip.Addr, maxNodes int) error {
	if maxNodes <= 0 {
		return lneto.ErrInvalidConfig
	} else if !addr.Is4() {
		return lneto.ErrUnsupported
	}
	sb.connID++
	sb.reset4(new(lneto.Validator), maxNodes)
	sb.SetAddr4(addr.As4())
	return nil
}

func (sb *StackIP) Resetv2(vld *lneto.Validator, maxNodes4, maxNodes6 int) error {
	if maxNodes4 <= 0 && maxNodes6 <= 0 || vld == nil {
		return lneto.ErrInvalidConfig
	}
	sb.connID++
	sb.reset4(vld, maxNodes4)
	sb.reset6(vld, maxNodes6)
	return nil
}

func (sb *StackIP) ConnectionID() *uint64 {
	return &sb.connID
}

func (sb *StackIP) Protocol() uint64 {
	return uint64(ethernet.TypeIPv4) // Only support ipv4 for now.
}

func (sb *StackIP) LocalPort() uint16 { return 0 }

func (sb *StackIP) SetLogger(logger *slog.Logger) {
	sb.stackip4.handlers.log = logger
	sb.stackip6.handlers.log = logger
}

func (sb *StackIP) Demux(carrierData []byte, offset int) error {
	debugLog("ip:demux")
	if len(carrierData) < 1 {
		return lneto.ErrTruncatedFrame
	}
	version := carrierData[offset] >> 4
	switch version {
	case 4:
		return sb.stackip4.demux4(carrierData, offset)
	case 6:
		return sb.stackip6.demux6(carrierData, offset)
	default:
		return lneto.ErrUnsupported
	}
}

func (sb *StackIP) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	if offsetToFrame != offsetToIP {
		return 0, lneto.ErrBug
	}
	n, err = sb.stackip4.encapsulate4(carrierData, offsetToIP)
	// Support IPv6
	return n, err
}

type logger struct {
	log *slog.Logger
}

func (l logger) error(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelError, msg, attrs...)
}
func (l logger) info(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelInfo, msg, attrs...)
}
func (l logger) warn(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelWarn, msg, attrs...)
}
func (l logger) debug(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, slog.LevelDebug, msg, attrs...)
}
func (l logger) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.log, internal.LevelTrace, msg, attrs...)
}

const enableAllocLog = internal.HeapAllocDebugging

func debugLog(msg string) {
	if enableAllocLog {
		internal.LogAllocs(msg)
	}
}
