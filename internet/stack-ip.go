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
}

func (sb *StackIP) Reset(addr netip.Addr, maxNodes int) error {
	if maxNodes <= 0 {
		return lneto.ErrInvalidConfig
	}
	sb.reset(new(lneto.Validator), maxNodes)
	sb.connID++
	return sb.SetAddr(addr)
}

// SetAddr deprecated
//
// Deprecated: use SetAddr4.
func (sb *StackIP) SetAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return lneto.ErrInvalidAddr
	} else if !addr.Is4() {
		return lneto.ErrUnsupported
	}
	sb.SetAddr4(addr.As4())
	return nil
}

func (sb *StackIP) ConnectionID() *uint64 {
	return &sb.connID
}

func (sb *StackIP) Protocol() uint64 {
	return uint64(ethernet.TypeIPv4) // Only support ipv4 for now.
}

func (sb *StackIP) LocalPort() uint16 { return 0 }

func (sb *StackIP) Addr() netip.Addr {
	return netip.AddrFrom4(sb.Addr4())
}

func (sb *StackIP) SetAcceptMulticast(accept bool) {
	sb.stackip4.acceptMulticast = accept
}

func (sb *StackIP) SetLogger(logger *slog.Logger) {
	sb.stackip4.handlers.log = logger
}

func (sb *StackIP) Demux(carrierData []byte, offset int) error {
	debugLog("ip:demux")
	sb.handlers.info("StackIP.Demux:start")
	version := carrierData[offset] >> 4
	switch version {
	case 4:
		return sb.stackip4.Demux(carrierData, offset)
	case 6:
		// Support IPv6
		fallthrough
	default:
		return lneto.ErrUnsupported
	}
}

func (sb *StackIP) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (n int, err error) {
	n, err = sb.stackip4.Encapsulate(carrierData, offsetToIP, offsetToFrame)
	// Support IPv6
	return n, err
}

func (sb *StackIP) Register(h lneto.StackNode) error {
	proto := h.Protocol()
	if proto > 255 {
		return lneto.ErrInvalidConfig
	}
	return sb.handlers.registerByPortProto(nodeFromStackNode(h, h.LocalPort(), proto, nil))
}

func (sb *StackIP) IsRegistered(proto lneto.IPProto) bool {
	return sb.handlers.nodeByProto(uint16(proto)) != nil
}

func (sb *StackIP) recvicmp(icmpData []byte) error {
	var crc lneto.CRC791
	if crc.PayloadSum16(icmpData) != 0 {
		return lneto.ErrBadCRC
	}
	return nil
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
