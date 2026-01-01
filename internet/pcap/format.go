package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	_ "time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/tcp"
)

type Formatter struct {
	FieldSep      string
	FrameSep      string
	FilterClasses []FieldClass
	buf           []byte
}

// FormatFrames appends the formatted frame data to the destination buffer according the Formatter state.
// Is equivalent to [Formatter.FormatFrame] called on each Frame with the FrameSep inserted between frames.
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

// FormatFrame
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
			// TCP flags pretty print special case.
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
	case FieldClassTimestamp:
		// inspired by [time.RFC3339]
		const littlerfc3339 = "2006-01-02T15:04:05.9999"
		ts := ntp.TimestampFromUint64(binary.BigEndian.Uint64(f.buf))
		dst = ts.Time().AppendFormat(dst, littlerfc3339)
	case FieldClassChecksum, FieldClassID, FieldClassFlags, FieldClassOptions:
		// Binary data to be printed as hexadecimal.
		dst = append(dst, "0x"...)
		dst = hex.AppendEncode(dst, f.buf)
	case FieldClassText:
		dst = strconv.AppendQuote(dst, string(f.buf))
	case FieldClassDst, FieldClassSrc, FieldClassSize, FieldClassAddress, FieldClassOperation:
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
			dst = ethernet.AppendAddr(dst, [6]byte(f.buf))
		} else if field.BitLength == 16*8 {
			dst = netip.AddrFrom16([16]byte(f.buf)).AppendTo(dst)
		} else {
			dst = append(dst, "0x"...)
			dst = hex.AppendEncode(dst, f.buf)
		}
	}
	return dst, err
}
