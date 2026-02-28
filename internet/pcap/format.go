package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"errors"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	_ "time"
	"unsafe"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/tcp"
)

type Formatter struct {
	FrameSep      string
	FieldSep      string
	SubfieldSep   string
	FilterClasses []FieldClass
	// SubfieldLimit limits the amount of subfields formatted.
	SubfieldLimit int
	// Formatter by default filters out printing legacy fields such as DHCP BOOTP field which
	// may be very large in size but meaningless to the actual network functioning.
	// Enabling DisableLegacyFilter means these fields will be printed as is.
	DisableLegacyFilter bool
	mubuf               sync.Mutex
	buf                 []byte
	uintBuf             [8]byte // scratch buffer for fieldAsUint to avoid TinyGo heap escape.
}

// FormatFrames appends the formatted frame data to the destination buffer according the Formatter state.
// Is equivalent to [Formatter.FormatFrame] called on each Frame with the FrameSep inserted between frames.
func (f *Formatter) FormatFrames(dst []byte, frms []Frame, pkt []byte) (_ []byte, err error) {
	debuglog("pcap:fmt:start")
	sep := f.frameSep()
	for ifrm := range frms {
		if ifrm != 0 {
			dst = append(dst, sep...)
		}
		dst, err = f.FormatFrame(dst, frms[ifrm], pkt)
		if err != nil {
			return dst, err
		}
	}
	debuglog("pcap:fmt:done")
	return dst, nil
}

// FormatFrame formats a single frame's protocol, fields, and errors into dst.
func (f *Formatter) FormatFrame(dst []byte, frm Frame, pkt []byte) (_ []byte, err error) {
	debuglog("pcap:fmtframe:start")
	sep := f.fieldSep()
	bitlen := frm.LenBits()
	dst = append(dst, frm.Protocol...)
	if bitlen%8 == 0 {
		dst = append(dst, " len="...)
		dst = strconv.AppendInt(dst, int64(bitlen/8), 10)
	} else {
		dst = append(dst, " bitlen="...)
		dst = strconv.AppendInt(dst, int64(bitlen), 10)
	}

	for ifield := range frm.Fields {
		field := frm.Fields[ifield]
		if f.filterField(field) {
			continue
		}
		dst = append(dst, sep...)
		if field.Class == FieldClassFlags && frm.Protocol == "TCP" {
			// TCP flags pretty print special case.
			dst = append(dst, "flags="...)
			v, err := f.fieldAsUint(pkt, frm.PacketBitOffset+field.FrameBitOffset, field.BitLength, field.Flags.IsRightAligned())
			if err != nil {
				return dst, err
			}
			dst = tcp.Flags(v).AppendFormat(dst)
			continue
		}
		dst, err = f.FormatField(dst, frm.PacketBitOffset, field, pkt)
		if err != nil {
			return dst, err
		}
	}
	if len(frm.Errors) > 0 {
		dst = append(dst, " errs=("...)
		for i, err := range frm.Errors {
			if i != 0 {
				dst = append(dst, ';')
			}
			dst = append(dst, err.Error()...)
		}
		dst = append(dst, ')')
	}
	debuglog("pcap:fmtframe:done")
	return dst, nil
}

func (f *Formatter) filterField(field FrameField) bool {
	return f.FilterClasses != nil && !slices.Contains(f.FilterClasses, field.Class) ||
		(field.Flags.IsLegacy() && !f.DisableLegacyFilter)
}

func (f *Formatter) FormatField(dst []byte, pktStartOff int, field FrameField, pkt []byte) (_ []byte, err error) {
	printOnlySubfields := field.Class == FieldClassOptions && len(field.SubFields) > 0
	if !printOnlySubfields {
		dst, err = f.formatField(dst, pktStartOff, field, pkt)
	} else {
		dst = append(dst, field.Name...)
	}
	if f.SubfieldLimit > 0 && len(field.SubFields) > 0 {
		sep := f.subfieldSep()
		lim := min(len(field.SubFields), f.SubfieldLimit)
		for i := 0; err == nil && i < lim && !f.filterField(field.SubFields[i]); i++ {
			dst = append(dst, sep...)
			// Notice we only format subfields one level low
			dst, err = f.formatField(dst, pktStartOff, field.SubFields[i], pkt)
		}
	}
	return dst, err
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
	if field.BitLength == 0 {
		return dst, nil
	}
	dst = append(dst, '=')
	f.mubuf.Lock()
	defer f.mubuf.Unlock()
	f.buf, err = appendField(f.buf[:0], pkt, field.FrameBitOffset+pktStartOff, field.BitLength, field.Flags.IsRightAligned())
	if err != nil {
		return dst, err
	}
	debuglog("pcap:fmtfield:append-done")
	fieldBitStart := pktStartOff + field.FrameBitOffset
	switch field.Class {
	default:
		fallthrough
	case FieldClassChecksum, FieldClassID, FieldClassFlags, FieldClassOptions:
		// Binary data to be printed as hexadecimal.
		dst = append(dst, "0x"...)
		dst = hex.AppendEncode(dst, f.buf)
	case FieldClassTimestamp:
		debuglog("pcap:fmtfield:timestamp")
		// inspired by [time.RFC3339]
		const littlerfc3339 = "2006-01-02T15:04:05.9999"
		if len(f.buf) != 8 {
			return dst, lneto.ErrUnsupported
		}
		ts := ntp.TimestampFromUint64(binary.BigEndian.Uint64(f.buf))
		dst = ts.Time().AppendFormat(dst, littlerfc3339)
		debuglog("pcap:fmtfield:timestamp-done")
	case FieldClassText:
		debuglog("pcap:fmtfield:text")
		if len(f.buf) > 0 {
			dst = strconv.AppendQuote(dst, unsafe.String(&f.buf[0], len(f.buf)))
		}
		debuglog("pcap:fmtfield:text-done")
	case FieldClassDst, FieldClassSrc, FieldClassSize, FieldClassAddress, FieldClassOperation:
		// IP, MAC addresses and ports.
		if field.BitLength <= 16 {
			v, err := f.fieldAsUint(pkt, fieldBitStart, field.BitLength, field.Flags.IsRightAligned())
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

func (f *Formatter) frameSep() string {
	sep := f.FrameSep
	if sep == "" {
		sep = " | "
	}
	return sep
}
func (f *Formatter) fieldSep() string {
	sep := f.FieldSep
	if sep == "" {
		sep = "; " // default field separator
	}
	return sep
}
func (f *Formatter) subfieldSep() string {
	sep := f.SubfieldSep
	if sep == "" {
		sep = "_" // default sub-field separator
	}
	return sep
}

// fieldAsUint evaluates a packet field as a uint64 using the Formatter's
// scratch buffer to avoid a TinyGo heap escape from a local [8]byte.
func (f *Formatter) fieldAsUint(pkt []byte, fieldBitStart, bitlen int, rightAligned bool) (uint64, error) {
	const badUint64 = math.MaxUint64
	octets := (bitlen + 7) / 8
	if octets > 8 {
		return badUint64, lneto.ErrUnsupported
	}
	f.uintBuf = [8]byte{}
	_, err := appendField(f.uintBuf[8-octets:8-octets], pkt, fieldBitStart, bitlen, rightAligned)
	if err != nil {
		return badUint64, err
	}
	return binary.BigEndian.Uint64(f.uintBuf[:]), nil
}
