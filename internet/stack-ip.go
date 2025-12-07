package internet

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/netip"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/lrucache"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

var _ StackNode = (*StackIP)(nil)

type (
	queueARPFunc func([4]byte) error
	checkARPFunc func([4]byte) ([6]byte, error)
)

type StackIP struct {
	connID      uint64
	ipID        uint16
	ip          [4]byte
	subMask32   uint32
	validator   lneto.Validator
	handlers    handlers
	pendingICMP [][]byte
	arpCache    lrucache.Cache[[4]byte, [6]byte]
	queueARP    queueARPFunc
	checkARP    checkARPFunc
	logger
}

func (sb *StackIP) Reset(addr netip.Addr, subnetMask netip.Addr, maxNodes int, arpCacheSize int,
	queueARP queueARPFunc, checkARP checkARPFunc) error {
	if maxNodes <= 0 {
		return errZeroMaxNodesArg
	}
	err := sb.SetAddr(addr, subnetMask)
	if err != nil {
		return err
	}
	sb.handlers.Reset(maxNodes)
	*sb = StackIP{
		connID:      sb.connID + 1,
		validator:   sb.validator,
		handlers:    sb.handlers,
		logger:      sb.logger,
		ip:          sb.ip,
		subMask32:   sb.subMask32,
		pendingICMP: make([][]byte, maxNodes*4),
		arpCache:    lrucache.New[[4]byte, [6]byte](arpCacheSize),
		queueARP:    queueARP,
		checkARP:    checkARP,
	}
	return nil
}

func (sb *StackIP) SetAddr(addr netip.Addr, subnetMask netip.Addr) error {
	if !addr.IsValid() {
		return errors.New("invalid IP")
	}
	if !subnetMask.IsValid() {
		return errors.New("invalid subnet mask")
	}
	if !addr.Is4() || !subnetMask.Is4() {
		return errors.New("require IPv4")
	}
	sb.ip = addr.As4()
	sb.subMask32 = asUint32(subnetMask.As4())
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
	return netip.AddrFrom4(sb.ip)
}

func (sb *StackIP) SetLogger(logger *slog.Logger) {
	sb.logger.log = logger
}

func (sb *StackIP) Demux(carrierData []byte, offset int) error {
	sb.info("StackIP.Demux:start")
	frame := carrierData[offset:] // we don't care about carrier data in IP.
	ifrm, err := ipv4.NewFrame(frame)
	if err != nil {
		return err
	}
	dst := ifrm.DestinationAddr()
	if sb.ip != ([4]byte{}) && *dst != sb.ip {
		return errors.New("not meant for us") // Not meant for us.
	}

	sb.validator.ResetErr()
	ifrm.ValidateExceptCRC(&sb.validator)
	if err = sb.validator.ErrPop(); err != nil {
		return err
	}
	gotCRC := ifrm.CRC()
	wantCRC := ifrm.CalculateHeaderCRC()
	if gotCRC != wantCRC {
		sb.error("StackIP:Demux:crc-mismatch", slog.Uint64("want", uint64(wantCRC)), slog.Uint64("got", uint64(gotCRC)))
		return errors.New("IPv4 CRC mismatch")
	}
	off := ifrm.HeaderLength()
	totalLen := ifrm.TotalLength()
	proto := ifrm.Protocol()
	if proto == lneto.IPProtoICMP {
		return sb.recvicmp(ifrm.RawData(), ifrm.HeaderLength())
	}

	node := sb.handlers.GetByProto(uint16(proto))
	if node == nil {
		// Drop packet.
		sb.info("iprecv:drop", slog.String("dstaddr", netip.AddrFrom4(*ifrm.DestinationAddr()).String()), slog.String("proto", ifrm.Protocol().String()))
		return nil
	}
	// Incoming CRC Validation of common IP Protocols.
	var crc lneto.CRC791
	switch proto {
	case lneto.IPProtoTCP:
		ifrm.CRCWriteTCPPseudo(&crc)
		tfrm, err := tcp.NewFrame(ifrm.Payload())
		if err != nil {
			return err
		}
		tfrm.CRCWrite(&crc)
		if crc.Sum16() != tfrm.CRC() {
			return errors.New("TCP CRC mismatch")
		}
	case lneto.IPProtoUDP:
		ifrm.CRCWriteUDPPseudo(&crc)
		ufrm, err := udp.NewFrame(ifrm.Payload())
		if err != nil {
			return err
		}
		ufrm.CRCWriteIPv4(&crc)
		if crc.Sum16() != ufrm.CRC() {
			return errors.New("UDP CRC mismatch")
		}
	}
	sb.info("ipDemux", slog.String("ipproto", proto.String()), slog.Int("plen", int(totalLen)))
	err = node.demux(frame[:totalLen], off)
	if handleNodeError(node, err) {
		sb.info("ipclose", slog.String("proto", proto.String()))
		err = nil
	}
	return err
}

func (sb *StackIP) ipv4Addr(addr []byte) ([4]byte, bool) {
	if len(addr) != 4 {
		sb.error("StackIP:ipv4Addr invalid address", slog.Any("addr", addr))
		return [4]byte{}, false
	}
	return *(*[4]byte)(addr), true
}

func asUint32(addr [4]byte) uint32 {
	return binary.BigEndian.Uint32(addr[:])
}

func (sb *StackIP) isLocal(addr [4]byte) bool {
	return (asUint32(sb.ip)^asUint32(addr))&sb.subMask32 == 0
}

func (sb *StackIP) CheckEncapsulate(ed *internal.EncData) bool {
	for range sb.handlers.Len() {
		node := sb.handlers.GetNext()
		if node.checkEncapsulate(ed) {
			if len(ed.RemoteAddr) == 0 {
				return true
			}
			if addr, ok := sb.ipv4Addr(ed.RemoteAddr); ok {
				if !sb.isLocal(addr) {
					return true
				}
				if _, ok := sb.arpCache.Get(addr); ok {
					return true
				}
				if hwAddr, err := sb.checkARP(addr); err != nil {
					if err == arp.ErrARPQueryNotFound {
						if err = sb.queueARP(addr); err != nil {
							sb.error("StackIP:queueARP", slog.String("err", err.Error()))
						}
					} else {
						sb.error("StackIP:checkARP", slog.String("err", err.Error()))
					}
				} else {
					sb.arpCache.Push(addr, hwAddr)
					return true
				}
			}
		}
	}
	return false
}

func (sb *StackIP) DoEncapsulate(carrierData []byte, frameOffset int) (int, error) {
	frame := carrierData[frameOffset:]
	if len(frame) < 256 {
		return 0, io.ErrShortBuffer
	}
	ifrm, _ := ipv4.NewFrame(frame)
	const ihl = 5
	const headerlen = ihl * 4
	const dontFrag = 0x4000
	ifrm.SetVersionAndIHL(4, ihl)
	ifrm.SetToS(0)
	seed := sb.ipID + uint16(sb.connID)
	id := internal.Prand16(seed)
	ifrm.SetID(id)
	ifrm.SetFlags(dontFrag)
	ifrm.SetTTL(64)
	*ifrm.SourceAddr() = sb.ip
	sb.ipID = id
	if h := sb.handlers.GetCurrent(); h != nil {
		proto := lneto.IPProto(h.proto)
		n, err := h.doEncapsulate(frame[:], headerlen)
		if err != nil {
			if handleNodeError(h, err) {
				println("IP NODE REMOVED", proto.String(), h.port)
				h.destroy()
			}
			sb.error("StackIP:encapsulate", slog.String("proto", proto.String()), slog.String("err", err.Error()))
			return 0, nil
		}
		if n == 0 {
			// this shouldn't normally happen
			return 0, nil
		}
		totalLen := n + headerlen
		ifrm.SetTotalLength(uint16(totalLen))
		ifrm.SetProtocol(proto)
		ifrm.SetCRC(ifrm.CalculateHeaderCRC())
		// Calculate CRC for our newly generated packet.
		var crc lneto.CRC791
		switch proto {
		case lneto.IPProtoTCP:
			ifrm.CRCWriteTCPPseudo(&crc)
			tfrm, _ := tcp.NewFrame(ifrm.Payload())
			tfrm.CRCWrite(&crc)
			tfrm.SetCRC(crc.Sum16())
		case lneto.IPProtoUDP:
			ifrm.CRCWriteUDPPseudo(&crc)
			ufrm, _ := udp.NewFrame(ifrm.Payload())
			ufrm.SetLength(uint16(n))
			ufrm.CRCWriteIPv4(&crc)
			ufrm.SetCRC(crc.Sum16())
			if n != int(ufrm.Length()) {
				sb.error("StackIP:encaps", slog.Int("n", n), slog.Int("un", int(ufrm.Length())))
				return 0, errors.New("invalid UDP length")
			}
		}

		_, destAddrSlice, _, _, err := internal.GetIPAddr(frame)
		if err != nil {
			sb.error("StackIP:encapsulate", slog.String("err", err.Error()))
			return 0, err
		}
		destAddr, ok := sb.ipv4Addr(destAddrSlice)
		if !ok {
			err = errors.New("unsupported IP address")
			sb.error("StackIP:encapsulate", slog.String("err", err.Error()))
			return 0, err
		}
		if sb.isLocal(destAddr) {
			destHwAddr, ok := sb.arpCache.Get(destAddr)
			if !ok {
				err = errors.New("ARP cache entry unexpectedly not found")
				sb.error("StackIP:encapsulate", slog.String("err", err.Error()))
				return 0, err
			}
			internal.SetDestHWAddr(carrierData[:frameOffset], destHwAddr)
		}

		return totalLen, nil
	}
	return 0, nil
}

func (sb *StackIP) Register(h StackNode) error {
	proto := h.Protocol()
	if proto > 255 {
		return errInvalidProto
	}
	connID := h.ConnectionID()
	var currConnID uint64
	if connID != nil {
		currConnID = *connID
	}
	return sb.handlers.Register(node{
		demux:            h.Demux,
		doEncapsulate:    h.DoEncapsulate,
		checkEncapsulate: h.CheckEncapsulate,
		proto:            uint16(proto),
		port:             h.LocalPort(),
		currConnID:       currConnID,
		connID:           connID,
	})
}

func (sb *StackIP) recvicmp(carrierData []byte, offset int) error {
	var crc lneto.CRC791
	cfrm, err := icmpv4.NewFrame(carrierData[offset:])
	if err != nil {
		return err
	}
	cfrm.CRCWrite(&crc)
	if crc.Sum16() != cfrm.CRC() {
		return errors.New("ICMP CRC mismatch")
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
