package pcap

import (
	"encoding/binary"
	"errors"
	"math"

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
		return dst, pc.validator().Err()
	}

	finfo := Frame{
		Protocol:        "Ethernet",
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
	default:
		dst = append(dst, remainingFrameInfo(nil, FieldClassPayload, end, octet*len(pkt)))
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
		return dst, pc.validator().Err()
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
		return dst, pc.validator().Err()
	}
	finfo := Frame{
		Protocol:        ethernet.TypeIPv4,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseIPv4Fields[:]...)
	options := ifrm4.Options()
	finfo.Fields = append(finfo.Fields, FrameField{
		Class:          FieldClassOptions,
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
		return dst, pc.validator().Err()
	}
	end := bitOffset + octet*tfrm.HeaderLength()
	finfo := Frame{
		Protocol:        lneto.IPProtoTCP,
		PacketBitOffset: bitOffset,
	}
	finfo.Fields = append(finfo.Fields, baseTCPFields[:]...)
	options := tfrm.Options()
	finfo.Fields = append(finfo.Fields, FrameField{
		Class:          FieldClassOptions,
		FrameBitOffset: 20 * octet,
		BitLength:      octet * len(options),
	})
	dst = append(dst, finfo)
	payload := tfrm.Payload()
	if len(payload) > 0 {
		dst, err = pc.CaptureHTTP(dst, pkt, end)
		if err != nil {
			dst = append(dst, remainingFrameInfo(nil, FieldClassPayload, end, len(pkt)))
		}
	}
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
		return -1, errors.New("field by class not found")
	}
	if multiple && frm.Fields[selected].Name != "" {
		return -1, errors.New("multiple classes found and none have empty name")
	}
	return selected, nil
}

// FieldAsUint evaluates the field as a 64-bit integer.
func (frm *Frame) FieldAsUint(fieldIdx int, pkt []byte) (uint64, error) {
	const badUint64 = math.MaxUint64
	if fieldIdx < 0 || fieldIdx >= len(frm.Fields) {
		return badUint64, errors.New("invalid field index")
	}
	field := frm.Fields[fieldIdx]
	octets := (field.BitLength + 7) / 8
	if octets > 8 {
		return badUint64, errors.New("field too long to be represented by uint64")
	}
	var buf [8]byte
	_, err := frm.AppendField(buf[8-octets:8-octets], fieldIdx, pkt)
	if err != nil {
		return badUint64, err
	}
	v := binary.BigEndian.Uint64(buf[:])
	return v, nil
}

func (frm *Frame) AppendField(dst []byte, fieldIdx int, pkt []byte) ([]byte, error) {
	if fieldIdx < 0 || fieldIdx >= len(frm.Fields) {
		return dst, errors.New("invalid field index")
	}
	field := frm.Fields[fieldIdx]
	fieldBitStart := frm.PacketBitOffset + field.FrameBitOffset
	fieldBitEnd := fieldBitStart + field.BitLength
	octets := (field.BitLength + 7) / 8 // total octets needed to represent field.
	octetsStart := fieldBitStart / 8
	if octets+octetsStart > len(pkt) {
		return dst, errors.New("buffer overflow")
	}
	firstBitOffset := fieldBitStart % 8
	lastOctetExcessBits := fieldBitEnd % 8
	if firstBitOffset == 0 {
		if field.RightAligned {
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
	if field.RightAligned {
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
		Class:          FieldClassSrc,
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
