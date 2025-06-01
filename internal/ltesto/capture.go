package ltesto

import (
	"errors"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
)

type PacketBreakdown struct {
	hdr httpraw.Header
	vld lneto.Validator
}

func (pc *PacketBreakdown) CaptureEthernet(dst []FrameInfo, pkt []byte, bitOffset int) ([]FrameInfo, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("Ethernet must be parsed at byte boundary")
	}
	efrm, err := ethernet.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	efrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().Err()
	}

	finfo := FrameInfo{
		Protocol:        "Ethernet",
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseEthernetFields[:]...)
	etype := efrm.EtherTypeOrSize()
	end := 14*octet + bitOffset
	if etype.IsSize() {
		finfo.Fields[len(finfo.Fields)-1].Class = classSize
		dst = append(dst, finfo)
		dst = append(dst, remainingFrameInfo("Ethernet payload", classPayload, end, octet*len(pkt)))
		return dst, nil
	}
	dst = append(dst, finfo)
	if efrm.IsVLAN() {
		finfo.Fields = append(finfo.Fields, FrameField{Name: "VLAN Tag", Class: classType, FrameBitOffset: end, BitLength: 2 * octet})
		dst = append(dst, remainingFrameInfo("Ethernet VLAN", classPayload, end+2*octet, octet*len(pkt)))
		return dst, nil
	}
	switch etype {
	case ethernet.TypeARP:
	case ethernet.TypeIPv4:
		dst, err = pc.CaptureIPv4(dst, pkt, end)
	}
	return dst, err
}

func (pc *PacketBreakdown) CaptureARP(dst []FrameInfo, pkt []byte, bitOffset int) ([]FrameInfo, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("ARP must be parsed at byte boundary")
	}
	afrm, err := arp.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	afrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().Err()
	}

	finfo := FrameInfo{
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
			Class:          classSrc,
			FrameBitOffset: varstart,
			BitLength:      int(hlen) * octet,
		},
		FrameField{
			Name:           "Sender protocol address",
			Class:          classSrc,
			FrameBitOffset: int(hlen)*octet + varstart,
			BitLength:      int(plen) * octet,
		},
		FrameField{
			Name:           "Target hardware address",
			Class:          classSrc,
			FrameBitOffset: int(hlen+plen)*octet + varstart,
			BitLength:      int(hlen) * octet,
		},
		FrameField{
			Name:           "Target protocol address",
			Class:          classSrc,
			FrameBitOffset: (2*int(hlen)+int(plen))*octet + varstart,
			BitLength:      int(plen) * octet,
		},
	)
	dst = append(dst, finfo)
	return dst, nil
}

func (pc *PacketBreakdown) CaptureIPv4(dst []FrameInfo, pkt []byte, bitOffset int) ([]FrameInfo, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("IPv4 must be parsed at byte boundary")
	}
	ifrm4, err := ipv4.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	ifrm4.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().Err()
	}
	finfo := FrameInfo{
		Protocol:        ethernet.TypeIPv4,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseIPv4Fields[:]...)
	options := ifrm4.Options()
	finfo.Fields = append(finfo.Fields, FrameField{
		Class:          classOptions,
		FrameBitOffset: 20 * octet,
		BitLength:      octet * len(options),
	})
	proto := ifrm4.Protocol()
	dst = append(dst, finfo)
	end := bitOffset + octet*ifrm4.HeaderLength()
	switch proto {
	case lneto.IPProtoTCP:
		dst, err = pc.CaptureTCP(dst, pkt, end)
	default:
		dst = append(dst, remainingFrameInfo(proto, 0, end, octet*len(pkt)))
	}
	return dst, err
}

func (pc *PacketBreakdown) CaptureTCP(dst []FrameInfo, pkt []byte, bitOffset int) ([]FrameInfo, error) {
	if bitOffset%8 != 0 {
		return dst, errors.New("TCP must be parsed at byte boundary")
	}
	tfrm, err := tcp.NewFrame(pkt[bitOffset/8:])
	if err != nil {
		return dst, err
	}
	tfrm.ValidateSize(pc.validator())
	if pc.validator().HasError() {
		return dst, pc.validator().Err()
	}
	end := bitOffset + octet*tfrm.HeaderLength()
	finfo := FrameInfo{
		Protocol:        lneto.IPProtoTCP,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseTCPFields[:]...)
	options := tfrm.Options()
	finfo.Fields = append(finfo.Fields, FrameField{
		Class:          classOptions,
		FrameBitOffset: 20 * octet,
		BitLength:      octet * len(options),
	})
	dst = append(dst, finfo)
	payload := tfrm.Payload()
	if len(payload) > 0 {
		dst, err = pc.CaptureHTTP(dst, pkt, end)
		if err != nil {
			dst = append(dst, remainingFrameInfo(nil, classPayload, end, len(pkt)))
		}
	}
	return dst, nil
}

func (pc *PacketBreakdown) CaptureHTTP(dst []FrameInfo, pkt []byte, bitOffset int) ([]FrameInfo, error) {
	if bitOffset%8 != 0 {
		return nil, errors.New("HTTP must be parsed at byte boundary")
	}
	const asResponse = true
	const asRequest = false
	httpData := pkt[bitOffset/8:]
	pc.hdr.Reset(httpData)
	err := pc.hdr.Parse(asResponse)
	if err == nil {
		dst = append(dst, remainingFrameInfo("HTTP Response", classText, bitOffset, len(pkt)))
		return dst, nil
	}
	pc.hdr.Reset(httpData)
	err = pc.hdr.Parse(asRequest)
	if err == nil {
		dst = append(dst, remainingFrameInfo(string(pc.hdr.Protocol()), classText, bitOffset, len(pkt)))
		return dst, nil
	}
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
}

type FrameInfo struct {
	Protocol        any
	Fields          []FrameField
	PacketBitOffset int
}

type FieldClass uint16

const (
	_             FieldClass = iota
	classSrc                 // Source
	classDst                 // Destination
	classProto               // Protocol
	classType                // Type
	classSize                // Field Size
	classFlags               // Flags
	classID                  // Identification
	classChecksum            // Checksum
	classOptions             // Options
	classPayload             // Payload
	classText                // Text
)

const octet = 8

var baseEthernetFields = [...]FrameField{
	{
		Class:          classDst,
		FrameBitOffset: 0,
		BitLength:      6 * octet,
	},
	{
		Class:          classSrc,
		FrameBitOffset: 6 * octet,
		BitLength:      6 * octet,
	},
	{
		Class:          classProto,
		FrameBitOffset: 12 * octet,
		BitLength:      2 * octet,
	},
}

var baseARPFields = [...]FrameField{
	{
		Name:           "Hardware type",
		Class:          classType,
		FrameBitOffset: 0,
		BitLength:      2 * octet,
	},
	{
		Name:           "Protocol type",
		Class:          classType,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Hardware size",
		Class:          classSize,
		FrameBitOffset: 4 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Protocol size",
		Class:          classSize,
		FrameBitOffset: 5 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Opcode",
		Class:          classType,
		FrameBitOffset: 6 * octet,
		BitLength:      2 * octet,
	},
}

var baseIPv4Fields = [...]FrameField{
	{
		Name:           "Version",
		Class:          classType,
		FrameBitOffset: 0,
		BitLength:      4,
	},
	{
		Name:           "Header Length",
		Class:          classSize,
		FrameBitOffset: 4,
		BitLength:      4,
	},
	{
		Name:           "Differentiated services",
		Class:          classFlags,
		FrameBitOffset: 1 * octet,
		BitLength:      1 * octet,
	},
	{
		Name:           "Total Length",
		Class:          classSize,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          classID,
		FrameBitOffset: 4 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          classID,
		FrameBitOffset: 4 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          classFlags,
		FrameBitOffset: 6 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Time to live",
		FrameBitOffset: 8 * octet,
		BitLength:      1 * octet,
	},
	{
		Class:          classProto,
		FrameBitOffset: 9 * octet,
		BitLength:      1 * octet,
	},
	{
		Class:          classChecksum,
		FrameBitOffset: 10 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          classSrc,
		FrameBitOffset: 12 * octet,
		BitLength:      4 * octet,
	},
	{
		Class:          classDst,
		FrameBitOffset: 16 * octet,
		BitLength:      4 * octet,
	},
}

var baseTCPFields = [...]FrameField{
	{
		Name:           "Source port",
		Class:          classSrc,
		FrameBitOffset: 0,
		BitLength:      2 * octet,
	},
	{
		Name:           "Destination port",
		Class:          classSrc,
		FrameBitOffset: 2 * octet,
		BitLength:      2 * octet,
	},
	{
		Name:           "Sequence number",
		Class:          classID,
		FrameBitOffset: 4 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Acknowledgement number",
		Class:          classID,
		FrameBitOffset: 8 * octet,
		BitLength:      4 * octet,
	},
	{
		Name:           "Header length",
		Class:          classID,
		FrameBitOffset: 12 * octet,
		BitLength:      4,
	},
	{
		Class:          classFlags,
		FrameBitOffset: 12*octet + 4,
		BitLength:      12,
	},
	{
		Name:           "Window",
		Class:          classSize,
		FrameBitOffset: 14 * octet,
		BitLength:      2 * octet,
	},
	{
		Class:          classChecksum,
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

func remainingFrameInfo(proto any, class FieldClass, pktBitOffset, pktBitLen int) FrameInfo {
	return FrameInfo{
		Protocol:        "Ethernet data payload",
		PacketBitOffset: pktBitOffset,
		Fields: []FrameField{
			{
				Class:     class,
				BitLength: pktBitLen - pktBitOffset,
			}},
	}
}
