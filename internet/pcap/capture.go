package pcap

//go:generate stringer -type=FieldClass -linecomment -output stringers.go .
import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/ipv4"
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
	if proto == lneto.IPProtoTCP {
		ifrm6.CRCWritePseudo(&crc)
		tfrm, err := tcp.NewFrame(ifrm6.Payload())
		if err == nil {
			tfrm.CRCWrite(&crc)
			wantSum := crc.Sum16()
			gotSum := tfrm.CRC()
			if wantSum != gotSum {
				protoErrs = append(protoErrs, &crcError16{protocol: "ipv6+tcp", want: wantSum, got: gotSum})
			}
		}
	} else if proto == lneto.IPProtoUDP || proto == lneto.IPProtoUDPLite {
		ifrm6.CRCWritePseudo(&crc)
		ufrm, err := udp.NewFrame(ifrm6.Payload())
		if err == nil {
			ufrm.CRCWriteIPv6(&crc)
			wantSum := crc.Sum16()
			gotSum := ufrm.CRC()
			if wantSum != gotSum {
				protoErrs = append(protoErrs, &crcError16{protocol: "ipv6+udp", want: wantSum, got: gotSum})
			}
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
	gotSum := ifrm4.CRC()
	wantSum := ifrm4.CalculateHeaderCRC()
	if gotSum != wantSum {
		finfo.Errors = append(finfo.Errors, &crcError16{protocol: "ipv4", want: wantSum, got: gotSum})
	}
	dst = append(dst, finfo)
	proto := ifrm4.Protocol()
	end := bitOffset + octet*ifrm4.HeaderLength()
	var protoErrs []error
	var crc lneto.CRC791
	switch proto {
	case lneto.IPProtoTCP:
		ifrm4.CRCWriteTCPPseudo(&crc)
		tfrm, err := tcp.NewFrame(ifrm4.Payload())
		if err == nil {
			tfrm.ValidateSize(pc.validator())
			if pc.vld.HasError() {
				println("BAD TCP")
				return dst, pc.vld.ErrPop()
			}
			tfrm.CRCWrite(&crc)
			wantSum := crc.Sum16()
			gotSum := tfrm.CRC()
			if wantSum != gotSum {
				protoErrs = append(protoErrs, &crcError16{protocol: "ipv4+tcp", want: wantSum, got: gotSum})
			}
		}
	case lneto.IPProtoUDP:
		ifrm4.CRCWriteUDPPseudo(&crc)
		ufrm, err := udp.NewFrame(ifrm4.Payload())
		if err == nil {
			ufrm.ValidateSize(pc.validator())
			if pc.vld.HasError() {
				println("BAD UDP")
				return dst, pc.vld.ErrPop()
			}
			ufrm.CRCWriteIPv4(&crc)
			wantSum := crc.Sum16()
			gotSum := ufrm.CRC()
			if wantSum != gotSum {
				protoErrs = append(protoErrs, &crcError16{protocol: "ipv4+udp", want: wantSum, got: gotSum})
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
	if len(options) > 0 {
		err = dfrm.ForEachOption(func(optoff int, op dhcpv4.OptNum, data []byte) error {
			finfo.Fields = append(finfo.Fields, FrameField{
				Name:           op.String(),
				Class:          FieldClassOptions,
				FrameBitOffset: optoff * octet,
				BitLength:      (2 + len(data)) * octet,
			})
			return nil
		})
		if err != nil {
			finfo.Errors = append(finfo.Errors, err)
		}
	}
	dst = append(dst, finfo)
	return dst, nil
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
				Class:          FieldClassPayload,
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
	RightAligned   bool
}

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
	return fieldAsUint(pkt, frm.PacketBitOffset+field.FrameBitOffset, field.BitLength, field.RightAligned)
}

func (frm Frame) AppendField(dst []byte, fieldIdx int, pkt []byte) ([]byte, error) {
	if fieldIdx < 0 || fieldIdx >= len(frm.Fields) {
		return dst, errors.New("invalid field index")
	}
	field := frm.Fields[fieldIdx]
	return appendField(dst, pkt, frm.PacketBitOffset+field.FrameBitOffset, field.BitLength, field.RightAligned)
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
		// Right aligned with trailing bits. i.e: ???
		for i := 1; i < octets; i++ {
			b := pkt[octetsStart+i] >> (8 - lastOctetExcessBits)
			b |= pkt[octetsStart+i-1] & mask
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

type Formatter struct {
	FieldSep      string
	FrameSep      string
	FilterClasses []FieldClass
	buf           []byte
}

func (f *Formatter) FormatFrames(dst []byte, frms []Frame, pkt []byte) (_ []byte, err error) {
	sep := f.FrameSep
	if sep == "" {
		sep = " | "
	}
	for ifrm := range frms {
		if ifrm != 0 {
			dst = append(dst, sep...)
		}
		dst, err = f.FormatFrame(dst, frms[ifrm], pkt)
		if err != nil {
			return dst, err
		}
	}
	return dst, nil
}

func (f *Formatter) FormatFrame(dst []byte, frm Frame, pkt []byte) (_ []byte, err error) {
	sep := f.FieldSep
	if sep == "" {
		sep = "; " // default field separator
	}
	bitlen := frm.LenBits()
	if bitlen%8 == 0 {
		dst = fmt.Appendf(dst, "%s len=%d", frm.Protocol, bitlen/8)
	} else {
		dst = fmt.Appendf(dst, "%s bitlen=%d", frm.Protocol, bitlen)
	}

	for ifield := range frm.Fields {
		field := frm.Fields[ifield]
		if f.filterField(field) {
			continue
		}
		dst = append(dst, sep...)
		if field.Class == FieldClassFlags && frm.Protocol == lneto.IPProtoTCP {
			dst = append(dst, "flags="...)
			v, err := fieldAsUint(pkt, frm.PacketBitOffset+field.FrameBitOffset, field.BitLength, field.RightAligned)
			if err != nil {
				return dst, err
			}
			dst = tcp.Flags(v).AppendFormat(dst)
			continue
		}
		dst, err = f.formatField(dst, frm.PacketBitOffset, field, pkt)
		if err != nil {
			return dst, err
		}
	}
	return dst, nil
}

func (f *Formatter) filterField(field FrameField) bool {
	return f.FilterClasses != nil && !slices.Contains(f.FilterClasses, field.Class)
}

func (f *Formatter) FormatField(dst []byte, pktStartOff int, field FrameField, pkt []byte) (_ []byte, err error) {
	return f.formatField(dst, pktStartOff, field, pkt)
}

func (f *Formatter) formatField(dst []byte, pktStartOff int, field FrameField, pkt []byte) (_ []byte, err error) {
	name := field.Name
	if name == "" {
		name = field.Class.String()
	}
	hasSpaces := strings.IndexByte(name, ' ') >= 0
	if hasSpaces {
		dst = append(dst, '(')
	}
	dst = append(dst, name...)
	if hasSpaces {
		dst = append(dst, ')')
	}
	dst = append(dst, '=')
	f.buf, err = appendField(f.buf[:0], pkt, field.FrameBitOffset+pktStartOff, field.BitLength, field.RightAligned)
	if err != nil {
		return dst, err
	}
	fieldBitStart := pktStartOff + field.FrameBitOffset
	switch field.Class {
	default:
		fallthrough
	case FieldClassChecksum, FieldClassID, FieldClassFlags, FieldClassOptions, FieldClassAddress:
		// Binary data to be printed as hexadecimal.
		dst = append(dst, "0x"...)
		dst = hex.AppendEncode(dst, f.buf)
	case FieldClassDst, FieldClassSrc, FieldClassSize:
		// IP, MAC addresses and ports.
		if field.BitLength <= 16 {
			v, err := fieldAsUint(pkt, fieldBitStart, field.BitLength, field.RightAligned)
			if err != nil {
				return dst, err
			}
			dst = strconv.AppendUint(dst, v, 10)
		} else if field.BitLength == 4*8 {
			dst = netip.AddrFrom4([4]byte(f.buf)).AppendTo(dst)
		} else if field.BitLength == 6*8 {
			for i := range f.buf {
				if i != 0 {
					dst = append(dst, ':')
				}
				if f.buf[i] < 16 {
					dst = append(dst, '0')
				}
				dst = strconv.AppendUint(dst, uint64(f.buf[i]), 16)
			}
		} else if field.BitLength == 16*8 {
			dst = netip.AddrFrom16([16]byte(f.buf)).AppendTo(dst)
		} else {
			dst = append(dst, "0x"...)
			dst = hex.AppendEncode(dst, f.buf)
		}
	}
	return dst, err
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
	FieldClassSize                        // field size
	FieldClassFlags                       // flags
	FieldClassID                          // identification
	FieldClassChecksum                    // checksum
	FieldClassOptions                     // options
	FieldClassPayload                     // payload
	FieldClassText                        // text
	FieldClassAddress                     // address
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
		Name:           "Opcode",
		Class:          FieldClassType,
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
		RightAligned:   true,
	},
	{
		Name:           "Flow Label",
		Class:          FieldClassID,
		FrameBitOffset: 12,
		BitLength:      20,
		RightAligned:   true,
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
		RightAligned:   true,
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

var baseDHCPv4Fields = [...]FrameField{
	{
		Name:           "Opcode",
		Class:          FieldClassType,
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
		BitLength:      16 * octet,
	},
	{
		Name:           "BOOTP",
		Class:          FieldClassAddress,
		FrameBitOffset: (28 + 16) * octet,
		BitLength:      (dhcpv4.OptionsOffset - (28 + 16)) * octet,
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
		Class:          FieldClassText,
		FrameBitOffset: 16 * octet,
		BitLength:      8 * octet,
	},
	{
		Name:           "Origin Time",
		Class:          FieldClassText,
		FrameBitOffset: 24 * octet,
		BitLength:      8 * octet,
	},
	{
		Name:           "Receive Time",
		Class:          FieldClassText,
		FrameBitOffset: 32 * octet,
		BitLength:      8 * octet,
	},
	{
		Name:           "Transit Time",
		Class:          FieldClassText,
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

type crcError16 struct {
	protocol string
	want     uint16
	got      uint16
}

func (cerr *crcError16) Error() string {
	return fmt.Sprintf("%s:incorrect checksum. want 0x%x, got 0x%x", cerr.protocol, cerr.want, cerr.got)
}
