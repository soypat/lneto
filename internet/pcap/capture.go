package pcap

//go:generate stringer -type=FieldClass -linecomment -output stringers.go .
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

const unknownPayloadProto = "payload?"

var (
	ErrFieldByClassNotFound = errors.New("pcap: field by class not found")
)

type proto string

const (
	ProtoEthernet proto = "Ethernet"
)

type PacketBreakdown struct {
	hdr  httpraw.Header
	dmsg dns.Message
	vld  lneto.Validator
	// SubfieldLimit will limit the number of captured subfields to the value it has.
	// Typically this means option fields of DHCP,IPv4,TCP.
	SubfieldLimit int
}

func (pc *PacketBreakdown) CaptureEthernet(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("ethernet must be parsed at byte boundary")
	}
	efrm, err := ethernet.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	efrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().ErrPop()
	}

	finfo := Frame{
		Protocol:        ProtoEthernet,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseEthernetFields[:]...)
	etype := efrm.EtherTypeOrSize()
	end := 14*octet + bitOffset
	if etype.IsSize() {
		finfo.Fields[len(finfo.Fields)-1].Class = FieldClassSize
		dst = append(dst, finfo)
		dst = append(dst, remainingFrameInfo("Ethernet payload", FieldClassPayload, end, octet*len(pkt)))
		return dst, nil
	}
	dst = append(dst, finfo)
	if efrm.IsVLAN() {
		finfo.Fields = append(finfo.Fields, FrameField{Name: "VLAN Tag", Class: FieldClassType, FrameBitOffset: end, BitLength: 2 * octet})
		dst = append(dst, remainingFrameInfo("Ethernet VLAN", FieldClassPayload, end+2*octet, octet*len(pkt)))
		return dst, nil
	}
	switch etype {
	case ethernet.TypeARP:
		dst, err = pc.CaptureARP(dst, pkt, end)
	case ethernet.TypeIPv4:
		dst, err = pc.CaptureIPv4(dst, pkt, end)
	case ethernet.TypeIPv6:
		dst, err = pc.CaptureIPv6(dst, pkt, end)
	default:
		dst = append(dst, remainingFrameInfo(etype, FieldClassPayload, end, octet*len(pkt)))
	}
	return dst, err
}

func (pc *PacketBreakdown) CaptureARP(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("ARP must be parsed at byte boundary")
	}
	afrm, err := arp.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	afrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().ErrPop()
	}

	finfo := Frame{
		Protocol:        ethernet.TypeARP,
		PacketBitOffset: bitOffset,
	}

	const varstart = 8 * octet
	finfo.Fields = append(finfo.Fields, baseARPFields[:]...)
	_, hlen := afrm.Hardware()
	_, plen := afrm.Protocol()
	finfo.Fields = append(finfo.Fields,
		FrameField{
			Name:           "Sender hardware address",
			Class:          FieldClassSrc,
			FrameBitOffset: varstart,
			BitLength:      int(hlen) * octet,
		},
		FrameField{
			Name:           "Sender protocol address",
			Class:          FieldClassSrc,
			FrameBitOffset: int(hlen)*octet + varstart,
			BitLength:      int(plen) * octet,
		},
		FrameField{
			Name:           "Target hardware address",
			Class:          FieldClassSrc,
			FrameBitOffset: int(hlen+plen)*octet + varstart,
			BitLength:      int(hlen) * octet,
		},
		FrameField{
			Name:           "Target protocol address",
			Class:          FieldClassSrc,
			FrameBitOffset: (2*int(hlen)+int(plen))*octet + varstart,
			BitLength:      int(plen) * octet,
		},
	)
	dst = append(dst, finfo)
	return dst, nil
}

func (pc *PacketBreakdown) CaptureIPv6(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("IPv6 must be parsed at byte boundary")
	}
	ifrm6, err := ipv6.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	ifrm6.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().ErrPop()
	}
	finfo := Frame{
		Protocol:        ethernet.TypeIPv6,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseIPv6Fields[:]...)
	dst = append(dst, finfo)
	proto := ifrm6.NextHeader()
	end := bitOffset + 40*octet
	var protoErrs []error
	var crc lneto.CRC791
	ifrm6.CRCWritePseudo(&crc)
	switch proto {
	case lneto.IPProtoTCP:
		if crc.PayloadSum16(ifrm6.Payload()) != 0 {
			protoErrs = append(protoErrs, lneto.ErrBadCRC)
		}
	case lneto.IPProtoUDP, lneto.IPProtoUDPLite:
		ufrm, err := udp.NewFrame(ifrm6.Payload())
		if err != nil {
			protoErrs = append(protoErrs, err)
			break
		}
		ufrm.ValidateSize(pc.validator())
		if err = pc.validator().ErrPop(); err != nil {
			protoErrs = append(protoErrs, err)
			break
		}
		frameLen := ufrm.Length()
		if crc.PayloadSum16(ufrm.RawData()[:frameLen]) != 0 {
			protoErrs = append(protoErrs, lneto.ErrBadCRC)
		}
	}
	return pc.captureIPProto(proto, dst, pkt, end, protoErrs...)
}

func (pc *PacketBreakdown) CaptureIPv4(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("IPv4 must be parsed at byte boundary")
	}
	ifrm4, err := ipv4.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	ifrm4.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().ErrPop()
	}
	// limit packet to the actual IPv4 frame size
	pkt = pkt[:bitOffset/8+int(ifrm4.TotalLength())]
	finfo := Frame{
		Protocol:        ethernet.TypeIPv4,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseIPv4Fields[:]...)
	options := ifrm4.Options()
	if len(options) > 0 {
		finfo.Fields = append(finfo.Fields, FrameField{
			Class:          FieldClassOptions,
			FrameBitOffset: 20 * octet,
			BitLength:      octet * len(options),
		})
	}
	if ifrm4.CalculateHeaderCRC() != 0 {
		finfo.Errors = append(finfo.Errors, lneto.ErrBadCRC)
	}
	dst = append(dst, finfo)
	proto := ifrm4.Protocol()
	end := bitOffset + octet*ifrm4.HeaderLength()
	var protoErrs []error
	var crc lneto.CRC791
	payload := ifrm4.Payload()
	switch proto {
	case lneto.IPProtoTCP:
		tfrm, err := tcp.NewFrame(payload)
		if err == nil {
			tfrm.ValidateSize(pc.validator())
			if pc.vld.HasError() {
				return dst, pc.vld.ErrPop()
			}
			ifrm4.CRCWriteTCPPseudo(&crc)
			if crc.PayloadSum16(payload) != 0 {
				protoErrs = append(protoErrs, lneto.ErrBadCRC)
			}
		}
	case lneto.IPProtoUDP:
		ufrm, err := udp.NewFrame(payload)
		if err == nil {
			ufrm.ValidateSize(pc.validator())
			if pc.vld.HasError() {
				return dst, pc.vld.ErrPop()
			}
			if ufrm.CRC() != 0 {
				frameLen := ufrm.Length()
				ifrm4.CRCWriteUDPPseudo(&crc, frameLen)
				if crc.PayloadSum16(ufrm.RawData()[:frameLen]) != 0 {
					protoErrs = append(protoErrs, lneto.ErrBadCRC)
				}
			}
		}
	case lneto.IPProtoICMP:
		_, err := icmpv4.NewFrame(payload)
		if err == nil {
			if crc.PayloadSum16(payload) != 0 {
				protoErrs = append(protoErrs, lneto.ErrBadCRC)
			}
		}
	}
	return pc.captureIPProto(proto, dst, pkt, end, protoErrs...)
}

func (pc *PacketBreakdown) captureIPProto(proto lneto.IPProto, dst []Frame, pkt []byte, bitOffset int, ipProtoErrs ...error) (_ []Frame, err error) {
	nextFrame := len(dst)
	switch proto {
	case lneto.IPProtoTCP:
		dst, err = pc.CaptureTCP(dst, pkt, bitOffset)
	case lneto.IPProtoUDP:
		dst, err = pc.CaptureUDP(dst, pkt, bitOffset)
	case lneto.IPProtoUDPLite:
		dst, err = pc.CaptureUDP(dst, pkt, bitOffset)
		if len(dst) > nextFrame {
			dst[nextFrame].Protocol = lneto.IPProtoUDPLite
		}
	case lneto.IPProtoICMP:
		dst, err = pc.CaptureICMPv4(dst, pkt, bitOffset)
	default:
		dst = append(dst, remainingFrameInfo(proto, 0, bitOffset, octet*len(pkt)))
	}
	if len(ipProtoErrs) > 0 && len(dst) > nextFrame {
		dst[nextFrame].Errors = append(dst[nextFrame].Errors, ipProtoErrs...)
	}
	return dst, err
}

func (pc *PacketBreakdown) CaptureTCP(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("TCP must be parsed at byte boundary")
	}
	tfrm, err := tcp.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	tfrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().ErrPop()
	}
	end := bitOffset + octet*tfrm.HeaderLength()
	finfo := Frame{
		Protocol:        lneto.IPProtoTCP,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseTCPFields[:]...)
	options := tfrm.Options()
	if len(options) > 0 {
		finfo.Fields = append(finfo.Fields, FrameField{
			Class:          FieldClassOptions,
			FrameBitOffset: 20 * octet,
			BitLength:      octet * len(options),
		})
	}
	dst = append(dst, finfo)
	payload := tfrm.Payload()
	if len(payload) > 0 {
		dst, err = pc.CaptureHTTP(dst, pkt, end)
		if err != nil {
			dst = append(dst, remainingFrameInfo(unknownPayloadProto, FieldClassPayload, end, octet*len(pkt)))
		}
	}
	return dst, nil
}

// func (pc *PacketBreakdown) CaptureDHCPv4(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
// }

func (pc *PacketBreakdown) CaptureUDP(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("UDP must be parsed at byte boundary")
	}
	ufrm, err := udp.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	ufrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().ErrPop()
	}
	finfo := Frame{
		Protocol:        lneto.IPProtoUDP,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseUDPFields[:]...)
	dst = append(dst, finfo)
	end := bitOffset + 8*octet
	payload := ufrm.Payload()
	dstport := ufrm.DestinationPort()
	srcport := ufrm.SourcePort()
	if dhcpv4.PayloadIsDHCPv4(payload) {
		dst, err = pc.CaptureDHCPv4(dst, pkt, end)
	} else if dstport == dns.ServerPort || srcport == dns.ServerPort {
		dst, err = pc.CaptureDNS(dst, pkt, end)
	} else if dstport == ntp.ServerPort || srcport == ntp.ServerPort {
		dst, err = pc.CaptureNTP(dst, pkt, end)
	}
	if err != nil {
		dst = append(dst, remainingFrameInfo(unknownPayloadProto, FieldClassPayload, end, octet*len(pkt)))
	}
	return dst, nil
}

func (pc *PacketBreakdown) CaptureICMPv4(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("ICMPv4 must be parsed at byte boundary")
	}
	icmpData := pkt[bitOffset/8:]
	ifrm, err := icmpv4.NewFrame(icmpData)
	if err != nil {
		return dst, err
	}

	finfo := Frame{
		Protocol:        lneto.IPProtoICMP,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseICMPv4Fields[:]...)

	// Add type-specific fields.
	switch ifrm.Type() {
	case icmpv4.TypeEcho, icmpv4.TypeEchoReply:
		finfo.Fields = append(finfo.Fields, icmpv4EchoFields[:]...)
		if len(icmpData) > 8 {
			finfo.Fields = append(finfo.Fields, FrameField{
				Name:           "Data",
				Class:          FieldClassPayload,
				FrameBitOffset: 8 * octet,
				BitLength:      (len(icmpData) - 8) * octet,
			})
		}
	case icmpv4.TypeRedirect:
		finfo.Fields = append(finfo.Fields, icmpv4RedirectFields[:]...)
		if len(icmpData) > 8 {
			finfo.Fields = append(finfo.Fields, FrameField{
				Name:           "Original Datagram",
				Class:          FieldClassPayload,
				FrameBitOffset: 8 * octet,
				BitLength:      (len(icmpData) - 8) * octet,
			})
		}
	case icmpv4.TypeDestinationUnreachable, icmpv4.TypeTimeExceeded,
		icmpv4.TypeSourceQuench, icmpv4.TypeParameterProblem:
		// 4 bytes unused, then original datagram.
		if len(icmpData) > 8 {
			finfo.Fields = append(finfo.Fields, FrameField{
				Name:           "Original Datagram",
				Class:          FieldClassPayload,
				FrameBitOffset: 8 * octet,
				BitLength:      (len(icmpData) - 8) * octet,
			})
		}
	case icmpv4.TypeTimestamp, icmpv4.TypeTimestampReply:
		finfo.Fields = append(finfo.Fields, icmpv4TimestampFields[:]...)
	default:
		// Unknown type - add generic payload.
		if len(icmpData) > 4 {
			finfo.Fields = append(finfo.Fields, FrameField{
				Class:          FieldClassPayload,
				FrameBitOffset: 4 * octet,
				BitLength:      (len(icmpData) - 4) * octet,
			})
		}
	}
	dst = append(dst, finfo)
	return dst, nil
}

func (pc *PacketBreakdown) CaptureDNS(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return nil, errors.New("DNS must be parsed at byte boundary")
	}
	dnsData := pkt[bitOffset/8:]
	pc.dmsg.LimitResourceDecoding(20, 20, 20, 20)
	off, incomplete, err := pc.dmsg.Decode(dnsData)
	if err != nil && !incomplete {
		return dst, err
	}
	finfo := Frame{
		Protocol:        "DNS",
		PacketBitOffset: bitOffset,
	}
	if incomplete {
		finfo.Errors = append(finfo.Errors, errors.New("pcap: could not parse all DNS resources; add higher limit"))
	}
	finfo.Fields = append(finfo.Fields, FrameField{
		Name:           "Data",
		FrameBitOffset: 0,
		BitLength:      int(off) * octet,
	})
	dst = append(dst, finfo)
	return dst, nil
}

func (pc *PacketBreakdown) CaptureNTP(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return nil, errors.New("NTP must be parsed at byte boundary")
	}
	ntpData := pkt[bitOffset/8:]
	_, err := ntp.NewFrame(ntpData)
	if err != nil {
		return dst, err
	}
	finfo := Frame{
		Protocol:        "NTP",
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseNTPFields[:]...)
	dst = append(dst, finfo)
	return dst, nil
}

func (pc *PacketBreakdown) CaptureDHCPv4(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	if bitOffset%8 != 0 {
		return nil, errors.New("DHCP must be parsed at byte boundary")
	}
	dhcpData := pkt[bitOffset/8:]
	dfrm, err := dhcpv4.NewFrame(dhcpData)
	if err != nil {
		return nil, err
	}
	finfo := Frame{
		Protocol:        "DHCPv4",
		PacketBitOffset: bitOffset,
	}
	magic := dfrm.MagicCookie()
	if magic != dhcpv4.MagicCookie {
		finfo.Errors = append(finfo.Errors, errors.New("incorrect DHCPv4 magic cookie"))
	}
	finfo.Fields = append(finfo.Fields, baseDHCPv4Fields[:]...)
	options := dfrm.OptionsPayload()

	if len(options) > 0 && pc.SubfieldLimit > 0 {
		var optfield FrameField
		optfield.Class = FieldClassOptions
		optfield.Name = "options"
		err = dfrm.ForEachOption(func(optoff int, opt dhcpv4.OptNum, data []byte) error {
			if len(optfield.SubFields) >= pc.SubfieldLimit {
				return errors.New("option cap limit surpassed for DHCP")
			}
			// optoff points to start of length and num bytes, skip over them with FrameBitOffset.
			field := FrameField{Name: opt.String(), FrameBitOffset: (optoff + 2) * octet, BitLength: len(data) * octet}
			switch opt {
			// Text options.
			case dhcpv4.OptHostName, dhcpv4.OptDomainName, dhcpv4.OptMessage, dhcpv4.OptRootPath:
				field.Class = FieldClassText

			// Address options (single or multiple IP addresses).
			case dhcpv4.OptSubnetMask, dhcpv4.OptRouter, dhcpv4.OptDNSServers,
				dhcpv4.OptBroadcastAddress, dhcpv4.OptServerIdentification,
				dhcpv4.OptRequestedIPaddress, dhcpv4.OptNTPServersAddresses,
				dhcpv4.OptTimeServers, dhcpv4.OptNameServers, dhcpv4.OptLogServers:
				field.Class = FieldClassAddress

			// Size options.
			case dhcpv4.OptMaximumMessageSize, dhcpv4.OptInterfaceMTUSize, dhcpv4.OptBootFileSize:
				field.Class = FieldClassSize

			// Time/duration options (seconds).
			case dhcpv4.OptIPAddressLeaseTime, dhcpv4.OptRenewTimeValue, dhcpv4.OptRebindingTimeValue,
				dhcpv4.OptTimeOffset, dhcpv4.OptARPCacheTimeout, dhcpv4.OptPathMTUAgingTimeout,
				dhcpv4.OptTCPKeepaliveInterval, dhcpv4.OptDefaultIPTTL, dhcpv4.OptDefaultTCPTimetoLive:
				field.Class = FieldClassTimestamp

			// Operation/type options.
			case dhcpv4.OptMessageType:
				field.Class = FieldClassOperation

			// Identifier options.
			case dhcpv4.OptClientIdentifier, dhcpv4.OptClientIdentifier1:
				field.Class = FieldClassText
				for _, c := range data {
					if c < 32 || c > 127 { // If clientID is ascii, print as is.
						field.Class = FieldClassID
						break
					}
				}
			// Parameter list (list of option codes).
			case dhcpv4.OptParameterRequestList:
				field.Class = FieldClassOptions

			default:
				field.Class = FieldClassPayload
			}
			optfield.SubFields = append(optfield.SubFields, field)
			return nil
		})
		finfo.Fields = append(finfo.Fields, optfield)
		if err != nil {
			finfo.Errors = append(finfo.Errors, err)
		}
	}
	dst = append(dst, finfo)
	return dst, nil
}

// httpBodyClass returns FieldClassText if the HTTP body appears to be human-readable text
// based on the Content-Type header, falling back to byte inspection when Content-Type is absent.
func httpBodyClass(contentType, body []byte) FieldClass {
	if len(contentType) > 0 {
		// Strip parameters (e.g. "; charset=utf-8") for media type matching.
		mediaType := contentType
		if i := bytes.IndexByte(contentType, ';'); i >= 0 {
			mediaType = contentType[:i]
		}
		mediaType = bytes.TrimSpace(mediaType)
		switch {
		case bytes.HasPrefix(mediaType, []byte("text/")):
			return FieldClassText
		case bytes.Equal(mediaType, []byte("application/json")),
			bytes.Equal(mediaType, []byte("application/javascript")),
			bytes.Equal(mediaType, []byte("application/xml")):
			return FieldClassText
		case bytes.HasSuffix(mediaType, []byte("+json")),
			bytes.HasSuffix(mediaType, []byte("+xml")):
			return FieldClassText
		}
		return FieldClassPayload
	}
	// No Content-Type: inspect bytes for printable ASCII.
	for _, c := range body {
		if c >= 32 && c <= 126 || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return FieldClassPayload
	}
	return FieldClassText
}

func (pc *PacketBreakdown) CaptureHTTP(dst []Frame, pkt []byte, bitOffset int) ([]Frame, error) {
	const httpProtocol = "HTTP"
	if bitOffset%8 != 0 {
		return nil, errors.New("HTTP must be parsed at byte boundary")
	}
	const asResponse = true
	const asRequest = false
	httpData := pkt[bitOffset/8:]
	pc.hdr.Reset(httpData)
	err := pc.hdr.Parse(asResponse)
	if err != nil {
		pc.hdr.Reset(httpData)
		err = pc.hdr.Parse(asRequest) // try as request.
	}
	if err != nil {
		return dst, err
	}
	hdrLen := pc.hdr.BufferParsed()
	body, _ := pc.hdr.Body()
	bodyClass := httpBodyClass(pc.hdr.Get("Content-Type"), body)
	dst = append(dst, Frame{
		Protocol:        httpProtocol,
		PacketBitOffset: bitOffset,
		Fields: []FrameField{
			{
				Name:           "HTTP Header",
				Class:          FieldClassText,
				FrameBitOffset: 0,
				BitLength:      hdrLen * octet,
			},
			{
				Name:           "HTTP Body",
				Class:          bodyClass,
				FrameBitOffset: hdrLen * octet,
				BitLength:      len(body) * octet,
			},
		},
	})
	return dst, err
}

func (pc *PacketBreakdown) validator() *lneto.Validator {
	return &pc.vld
}

type FrameField struct {
	Name           string
	Class          FieldClass
	FrameBitOffset int
	BitLength      int
	SubFields      []FrameField

	Flags Flags
}

// Flags stores frame field interpretation bits.
type Flags uint32

const (
	FlagRightAligned Flags = 1 << iota
	FlagLegacy
)

func (ff Flags) IsLegacy() bool       { return ff&FlagLegacy != 0 }
func (ff Flags) IsRightAligned() bool { return ff&FlagRightAligned != 0 }

type Frame struct {
	Protocol        any
	Fields          []FrameField
	PacketBitOffset int
	Errors          []error
}

// FieldByClass gets the frame field index with the argument FieldClass Class field set.
// If there are multiple fields with same class it will get the one with empty name.
// If there are multiple fields with same class and none have empty name then it will return an error.
func (frm Frame) FieldByClass(c FieldClass) (int, error) {
	Nfields := len(frm.Fields)
	selected := -1
	multiple := false
	for i := range Nfields {
		field := &frm.Fields[i]
		if field.Class != c {
			continue
		}
		if field.Name == "" { // Prioritize "canonical" fields with no name.
			if selected >= 0 && frm.Fields[selected].Name == "" {
				return -1, errors.New("multiple class fields with no name")
			}
			selected = i
		} else if selected >= 0 {
			multiple = true
		} else {
			selected = i
		}
	}
	if selected < 0 {
		return -1, ErrFieldByClassNotFound
	}
	if multiple && frm.Fields[selected].Name != "" {
		return -1, errors.New("multiple classes found and none have empty name")
	}
	return selected, nil
}

// FieldAsUint evaluates the field as a 64-bit integer.
func (frm Frame) FieldAsUint(fieldIdx int, pkt []byte) (uint64, error) {
	const badUint64 = math.MaxUint64
	if fieldIdx < 0 || fieldIdx >= len(frm.Fields) {
		return badUint64, errors.New("invalid field index")
	}
	field := frm.Fields[fieldIdx]
	return fieldAsUint(pkt, frm.PacketBitOffset+field.FrameBitOffset, field.BitLength, field.Flags.IsRightAligned())
}

// AppendField appends the binary on-the-wire representation of the field and aligns the field so it starts at the first bit of appended data.
func (frm Frame) AppendField(dst []byte, fieldIdx int, pkt []byte) ([]byte, error) {
	if fieldIdx < 0 || fieldIdx >= len(frm.Fields) {
		return dst, errors.New("invalid field index")
	}
	field := frm.Fields[fieldIdx]
	return appendField(dst, pkt, frm.PacketBitOffset+field.FrameBitOffset, field.BitLength, field.Flags.IsRightAligned())
}

func fieldAsUint(pkt []byte, fieldBitStart, bitlen int, rightAligned bool) (uint64, error) {
	const badUint64 = math.MaxUint64
	octets := (bitlen + 7) / 8
	if octets > 8 {
		return badUint64, errors.New("field too long to be represented by uint64")
	}
	var buf [8]byte
	_, err := appendField(buf[8-octets:8-octets], pkt, fieldBitStart, bitlen, rightAligned)
	if err != nil {
		return badUint64, err
	}
	v := binary.BigEndian.Uint64(buf[:])
	return v, nil
}

func appendField(dst, pkt []byte, fieldBitStart, bitlen int, rightAligned bool) ([]byte, error) {
	fieldBitEnd := fieldBitStart + bitlen
	octets := (bitlen + 7) / 8 // total octets needed to represent field.
	octetsStart := fieldBitStart / 8
	if octets+octetsStart > len(pkt) {
		return dst, errors.New("buffer overflow")
	}
	firstBitOffset := fieldBitStart % 8
	lastOctetExcessBits := fieldBitEnd % 8
	if firstBitOffset == 0 {
		if rightAligned {
			return dst, errors.New("invalid right aligned set for fully aligned field")
		}
		// Optimized path: field starts at byte boundary.
		dst = append(dst, pkt[octetsStart:octetsStart+octets]...)
		if lastOctetExcessBits != 0 {
			dst[len(dst)-1] >>= lastOctetExcessBits
		}
		return dst, nil
	}

	mask := byte(1<<firstBitOffset) - 1
	if rightAligned {
		if lastOctetExcessBits == 0 {
			// Right aligned with no loose trailing bits. i.e: TCP flags.
			dst = append(dst, pkt[octetsStart]&mask)
			dst = append(dst, pkt[octetsStart+1:octetsStart+octets]...)
			return dst, nil
		}
		// Right aligned with trailing bits. i.e: IPv6 Traffic Class.
		// Field spans an extra byte, so need octets+1 bytes from packet.
		if octets+octetsStart+1 > len(pkt) {
			return dst, errors.New("buffer overflow")
		}
		for i := 0; i < octets; i++ {
			b := (pkt[octetsStart+i] & mask) << (8 - firstBitOffset)
			b |= pkt[octetsStart+i+1] >> firstBitOffset
			dst = append(dst, b)
		}
		return dst, nil
	}

	// LEFT ALIGNED: TODO: test this.
	for i := 0; i < octets-1; i++ {
		// Append all octets except last one due to excess bits special handling.
		b := pkt[i+octetsStart] & mask
		b |= pkt[i+octetsStart+1] >> firstBitOffset
		dst = append(dst, b)
	}
	lastOctet := pkt[octetsStart+octets-1] & mask
	lastOctet >>= lastOctetExcessBits
	dst = append(dst, lastOctet)
	return dst, nil
}

func (frm Frame) String() string {
	return string(frm.AppendString(nil))
}

func (frm Frame) AppendString(b []byte) []byte {
	bitlen := frm.LenBits()
	b = fmt.Appendf(b, "%s", frm.Protocol)
	if bitlen%8 == 0 {
		b = fmt.Appendf(b, " len=%d", bitlen/8)
	} else {
		b = fmt.Appendf(b, " bits=%d", bitlen)
	}
	iopt, err := frm.FieldByClass(FieldClassOptions)
	if err == nil {
		b = fmt.Appendf(b, " optlen=%d", (frm.Fields[iopt].BitLength+7)/8)
	}
	for _, err := range frm.Errors {
		b = fmt.Appendf(b, " %s", err.Error())
	}
	return b
}

func (frm Frame) LenBits() (totalBitlen int) {
	for i := range frm.Fields {
		totalBitlen = max(totalBitlen, frm.Fields[i].FrameBitOffset+frm.Fields[i].BitLength)
	}
	return totalBitlen
}

func (ff FrameField) String() string {
	if ff.Class == FieldClassPayload {
		return fmt.Sprintf("Payload len=%d", ff.BitLength/8)
	}
	if ff.Name != "" {
		return fmt.Sprintf("%s (%s)", ff.Name, ff.Class.String())
	}
	return ff.Class.String()
}

type FieldClass uint8

const (
	fieldClassUndefined FieldClass = iota // undefined
	FieldClassSrc                         // source
	FieldClassDst                         // destination
	FieldClassProto                       // protocol
	FieldClassVersion                     // version
	FieldClassType                        // type
	FieldClassSize                        // size
	FieldClassFlags                       // flags
	FieldClassID                          // identification
	FieldClassChecksum                    // checksum
	FieldClassOptions                     // options
	FieldClassPayload                     // payload
	FieldClassText                        // text
	FieldClassAddress                     // address
	// FieldClassBinaryText represents long stretches of binary data such as BOOTP DHCPv4 field.
	FieldClassBinaryText // binary-text
	FieldClassOperation  // op
	FieldClassTimestamp  // timestamp
)

const octet = 8

var baseEthernetFields = [...]FrameField{
	{
		Class:          FieldClassDst,
		FrameBitOffset: 0,
		BitLength:      6 * octet,
	},
	{
		Class:          FieldClassSrc,
		FrameBitOffset: 6 * octet,
		BitLength:      6 * octet,
	},
	{
		Class:          FieldClassProto,
		FrameBitOffset: 12 * octet,
		BitLength:      2 * octet,
	},
}

var baseARPFields = [...]FrameField{
	{
		Name:           "Hardware type",
		Class:          FieldClassType,
		FrameBitOffset: 0,
		BitLength:      2 * octet,
	},
	{
		Name:           "Protocol type",
		Class:          FieldClassType,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Hardware size",
		Class:          FieldClassSize,
		FrameBitOffset: 4 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Protocol size",
		Class:          FieldClassSize,
		FrameBitOffset: 5 * octet,
		BitLength:      1 * octet,
	},
	{
		Class:          FieldClassOperation,
		FrameBitOffset: 6 * octet,
		BitLength:      2 * octet,
	},
}

var baseIPv6Fields = [...]FrameField{
	{
		Class:          FieldClassVersion,
		FrameBitOffset: 0,
		BitLength:      4,
	},
	{
		Name:           "Type of Service",
		Class:          FieldClassFlags,
		FrameBitOffset: 4,
		BitLength:      1 * octet,
		Flags:          FlagRightAligned,
	},
	{
		Name:           "Flow Label",
		Class:          FieldClassID,
		FrameBitOffset: 12,
		BitLength:      20,
		Flags:          FlagRightAligned,
	},
	{
		Name:           "Total Length",
		Class:          FieldClassSize,
		FrameBitOffset: 4 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Next Header",
		Class:          0,
		FrameBitOffset: 6 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Hop Limit",
		Class:          0,
		FrameBitOffset: 7 * octet,
		BitLength:      1 * octet,
	},
	{
		Class:          FieldClassSrc,
		FrameBitOffset: 8 * octet,
		BitLength:      16 * octet,
	},
	{
		Class:          FieldClassSrc,
		FrameBitOffset: 24 * octet,
		BitLength:      16 * octet,
	},
}

var baseIPv4Fields = [...]FrameField{
	{
		Class:          FieldClassVersion,
		FrameBitOffset: 0,
		BitLength:      4,
	},
	{
		Name:           "Header Length",
		Class:          FieldClassSize,
		FrameBitOffset: 4,
		BitLength:      4,
	},
	{
		Name:           "Type of Service",
		Class:          FieldClassFlags,
		FrameBitOffset: 1 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Total Length",
		Class:          FieldClassSize,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          FieldClassID,
		FrameBitOffset: 4 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          FieldClassFlags,
		FrameBitOffset: 6 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Time to live",
		FrameBitOffset: 8 * octet,
		BitLength:      1 * octet,
	},
	{
		Class:          FieldClassProto,
		FrameBitOffset: 9 * octet,
		BitLength:      1 * octet,
	},
	{
		Class:          FieldClassChecksum,
		FrameBitOffset: 10 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          FieldClassSrc,
		FrameBitOffset: 12 * octet,
		BitLength:      4 * octet,
	},
	{
		Class:          FieldClassDst,
		FrameBitOffset: 16 * octet,
		BitLength:      4 * octet,
	},
}

var baseTCPFields = [...]FrameField{
	{
		Name:           "Source port",
		Class:          FieldClassSrc,
		FrameBitOffset: 0,
		BitLength:      2 * octet,
	},
	{
		Name:           "Destination port",
		Class:          FieldClassDst,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Sequence number",
		Class:          FieldClassID,
		FrameBitOffset: 4 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Acknowledgement number",
		Class:          FieldClassID,
		FrameBitOffset: 8 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Header length",
		Class:          FieldClassSize,
		FrameBitOffset: 12 * octet,
		BitLength:      4,
	},
	{
		Class:          FieldClassFlags,
		FrameBitOffset: 12*octet + 4,
		BitLength:      12,
		Flags:          FlagRightAligned,
	},
	{
		Name:           "Window",
		Class:          0,
		FrameBitOffset: 14 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          FieldClassChecksum,
		FrameBitOffset: 16 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Urgent pointer",
		Class:          0,
		FrameBitOffset: 18 * octet,
		BitLength:      2 * octet,
		Flags:          FlagLegacy,
	},
}

var baseUDPFields = [...]FrameField{
	{
		Name:           "Source port",
		Class:          FieldClassSrc,
		FrameBitOffset: 0,
		BitLength:      2 * octet,
	},
	{
		Name:           "Destination port",
		Class:          FieldClassDst,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          FieldClassSize,
		FrameBitOffset: 4 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          FieldClassChecksum,
		FrameBitOffset: 6 * octet,
		BitLength:      2 * octet,
	},
}

var baseICMPv4Fields = [...]FrameField{
	{
		Class:          FieldClassType,
		FrameBitOffset: 0,
		BitLength:      1 * octet,
	},
	{
		Name:           "Code",
		Class:          fieldClassUndefined,
		FrameBitOffset: 1 * octet,
		BitLength:      1 * octet,
	},
	{
		Class:          FieldClassChecksum,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
}

var icmpv4EchoFields = [...]FrameField{
	{
		Name:           "Identifier",
		Class:          FieldClassID,
		FrameBitOffset: 4 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Sequence Number",
		Class:          FieldClassID,
		FrameBitOffset: 6 * octet,
		BitLength:      2 * octet,
	},
}

var icmpv4RedirectFields = [...]FrameField{
	{
		Name:           "Gateway Address",
		Class:          FieldClassAddress,
		FrameBitOffset: 4 * octet,
		BitLength:      4 * octet,
	},
}

var icmpv4TimestampFields = [...]FrameField{
	{
		Name:           "Identifier",
		Class:          FieldClassID,
		FrameBitOffset: 4 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Sequence Number",
		Class:          FieldClassID,
		FrameBitOffset: 6 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Originate Timestamp",
		Class:          FieldClassTimestamp,
		FrameBitOffset: 8 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Receive Timestamp",
		Class:          FieldClassTimestamp,
		FrameBitOffset: 12 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Transmit Timestamp",
		Class:          FieldClassTimestamp,
		FrameBitOffset: 16 * octet,
		BitLength:      4 * octet,
	},
}

var baseDHCPv4Fields = [...]FrameField{
	{
		Class:          FieldClassOperation,
		FrameBitOffset: 0,
		BitLength:      1 * octet,
	},
	{
		Name:           "Hardware Address Type",
		Class:          FieldClassProto,
		FrameBitOffset: 1 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Hardware Address Length",
		Class:          FieldClassSize,
		FrameBitOffset: 2 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Hops",
		Class:          fieldClassUndefined,
		FrameBitOffset: 3 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Transaction ID",
		Class:          FieldClassID,
		FrameBitOffset: 4 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Start Time",
		Class:          fieldClassUndefined,
		FrameBitOffset: 8 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Flags",
		Class:          FieldClassFlags,
		FrameBitOffset: 10 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Client Address",
		Class:          FieldClassAddress,
		FrameBitOffset: 12 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Offered Address",
		Class:          FieldClassAddress,
		FrameBitOffset: 16 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Server Next Address",
		Class:          FieldClassAddress,
		FrameBitOffset: 20 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Relay Agent Address",
		Class:          FieldClassAddress,
		FrameBitOffset: 24 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Client Hardware Address",
		Class:          FieldClassAddress,
		FrameBitOffset: 28 * octet,
		BitLength:      6 * octet, // Ethernet MAC is 6 bytes, remaining 10 in chaddr are padding
	},
	{
		Name:           "Padding",
		Class:          FieldClassBinaryText,
		FrameBitOffset: (28 + 6) * octet, // Part of Client Hardware Address(16 bytes) but unused.
		BitLength:      10 * octet,
		Flags:          FlagLegacy,
	},
	{
		Name:           "BOOTP",
		Class:          FieldClassBinaryText,
		FrameBitOffset: (28 + 16) * octet,
		BitLength:      (dhcpv4.OptionsOffset - (28 + 16)) * octet,
		Flags:          FlagLegacy,
	},
}

var baseNTPFields = [...]FrameField{
	{
		Name:           "Mode",
		Class:          FieldClassType,
		FrameBitOffset: 0,
		BitLength:      3,
	},
	{
		Class:          FieldClassVersion,
		FrameBitOffset: 3,
		BitLength:      2,
	},
	{
		Name:           "Leap Indicator",
		Class:          fieldClassUndefined,
		FrameBitOffset: 5,
		BitLength:      3,
	},
	{
		Name:           "Stratum",
		Class:          fieldClassUndefined,
		FrameBitOffset: 1 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Poll",
		Class:          fieldClassUndefined,
		FrameBitOffset: 2 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "System Precision",
		Class:          fieldClassUndefined,
		FrameBitOffset: 3 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Root Delay",
		Class:          fieldClassUndefined,
		FrameBitOffset: 4 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Root Dispersion",
		Class:          fieldClassUndefined,
		FrameBitOffset: 8 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Reference ID",
		Class:          FieldClassText,
		FrameBitOffset: 12 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Reference Time",
		Class:          FieldClassTimestamp,
		FrameBitOffset: 16 * octet,
		BitLength:      8 * octet,
	},
	{
		Name:           "Origin Time",
		Class:          FieldClassTimestamp,
		FrameBitOffset: 24 * octet,
		BitLength:      8 * octet,
	},
	{
		Name:           "Receive Time",
		Class:          FieldClassTimestamp,
		FrameBitOffset: 32 * octet,
		BitLength:      8 * octet,
	},
	{
		Name:           "Transit Time",
		Class:          FieldClassTimestamp,
		FrameBitOffset: 40 * octet,
		BitLength:      8 * octet,
	},
}

func remainingFrameInfo(proto any, class FieldClass, pktBitOffset, pktBitLen int) Frame {
	return Frame{
		Protocol:        proto,
		PacketBitOffset: pktBitOffset,
		Fields: []FrameField{
			{
				Class:     class,
				BitLength: pktBitLen - pktBitOffset,
			}},
	}
}
