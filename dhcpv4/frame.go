package dhcpv4

import (
	"encoding/binary"
	"errors"

	"github.com/soypat/lneto"
)

const (
	maxHostSize  = 16  // max size for hostname.
	sizeSName    = 64  // Server name, part of BOOTP too.
	sizeBootFile = 128 // Boot file name, Legacy.
	sizeHeader   = 44
	// Magic Cookie offset measured from the start of the UDP payload.
	magicCookieOffset = sizeHeader + sizeSName + sizeBootFile
	// Expected Magic Cookie value.
	MagicCookie uint32 = 0x63825363
	// DHCP Options offset measured from the start of the UDP payload.
	optionsOffset = magicCookieOffset + 4

	DefaultClientPort = 68
	DefaultServerPort = 67
)

// NewFrame returns a new DHCPv4 Frame with data set to buf.
// An error is returned if the buffer size is smaller than 240.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < optionsOffset {
		return Frame{}, errSmallFrame
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of a DHCP packet
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC2131].
//
// [RFC2131]: https://tools.ietf.org/html/rfc2131
type Frame struct {
	buf []byte
}

// OptionsPayload returns the options portion of the DHCP frame. May be zero lengthed.
func (frm Frame) OptionsPayload() []byte {
	return frm.buf[optionsOffset:]
}

func (frm Frame) Op() Op      { return Op(frm.buf[0]) }
func (frm Frame) SetOp(op Op) { frm.buf[0] = byte(op) }

func (frm Frame) Hardware() (Type, Len, Ops uint8) {
	return frm.buf[1], frm.buf[2], frm.buf[3]
}

func (frm Frame) SetHardware(Type, Len, Ops uint8) {
	frm.buf[1], frm.buf[2], frm.buf[3] = Type, Len, Ops
}

// XID is the transaction ID. Is unique and constant for a DHCP request/response exchange of packets.
func (frm Frame) XID() uint32       { return binary.BigEndian.Uint32(frm.buf[4:8]) }
func (frm Frame) SetXID(xid uint32) { binary.BigEndian.PutUint32(frm.buf[4:8], xid) }

// Secs is seconds elapsed.
func (frm Frame) Secs() uint16        { return binary.BigEndian.Uint16(frm.buf[8:10]) }
func (frm Frame) SetSecs(secs uint16) { binary.BigEndian.PutUint16(frm.buf[8:10], secs) }

func (frm Frame) Flags() Flags         { return Flags(binary.BigEndian.Uint16(frm.buf[10:12])) }
func (frm Frame) SetFlags(flags Flags) { binary.BigEndian.PutUint16(frm.buf[10:12], uint16(flags)) }

// CIAddr is the client IP address. If the client has not obtained an IP
// address yet, this field is set to 0.
func (frm Frame) CIAddr() *[4]byte {
	return (*[4]byte)(frm.buf[12:16])
}

// YIAddr is the IP address offered by the server to the client. Your (client) IP Address.
func (frm Frame) YIAddr() *[4]byte {
	return (*[4]byte)(frm.buf[16:20])
}

// SIAddr is the IP address of the next server to use in bootstrap. This
// field is used in DHCPOFFER and DHCPACK messages.
func (frm Frame) SIAddr() *[4]byte {
	return (*[4]byte)(frm.buf[20:24])
}

// GIAddr is the gateway IP address. Is also known as the Relay Agent IP Address.
func (frm Frame) GIAddr() *[4]byte {
	return (*[4]byte)(frm.buf[24:28])
}

// CHAddrAs6 returns [Frame.CHAddr] but limited to first 6 bytes.
func (frm Frame) CHAddrAs6() *[6]byte {
	return (*[6]byte)(frm.buf[28 : 28+6])
}

// CHAddr is the client hardware address. Can be up to 16 bytes in length but
// is usually 6 bytes for Ethernet.
func (frm Frame) CHAddr() *[16]byte {
	return (*[16]byte)(frm.buf[28:44])
}

// MagicCookie returns the magic cookie of the header. Expect this to always be [MagicCookie].
func (frm Frame) MagicCookie() uint32 { return binary.BigEndian.Uint32(frm.buf[magicCookieOffset:]) }

// SetMagicCookie sets the MagicCookie. Call this with [MagicCookie] to create a valid DHCP header.
func (frm Frame) SetMagicCookie(cookie uint32) {
	binary.BigEndian.PutUint32(frm.buf[magicCookieOffset:], cookie)
}

// ClearHeader zeros out the header contents.
func (frm Frame) ClearHeader() {
	for i := range frm.buf[:optionsOffset] {
		frm.buf[i] = 0
	}
}

// ForEachOption iterates over all DHCPv4 options returning an error on a malformed option or when user provided callback returns an error.
// If the user provided callback is nil then only option buffer validation is performed.
func (frm Frame) ForEachOption(fn func(op OptNum, data []byte) error) error {
	// Parse DHCP options.
	ptr := optionsOffset
	if ptr > len(frm.buf) {
		return errSmallFrame
	} else if len(frm.buf[ptr:]) == 0 {
		return errNoOptions
	}
	callback := fn != nil
	for ptr+1 < len(frm.buf) {
		if int(frm.buf[ptr+1]) >= len(frm.buf) {
			return errDHCPBadOption
		}
		optnum := OptNum(frm.buf[ptr])
		if optnum == 0xff {
			break
		} else if optnum == OptWordAligned {
			ptr++
			continue
		}
		optlen := frm.buf[ptr+1]
		if callback {
			optionData := frm.buf[ptr+2 : ptr+2+int(optlen)]
			if err := fn(optnum, optionData); err != nil {
				return err
			}
		}
		ptr += int(optlen) + 2
	}
	return nil
}

//
// Validation API.
//

var (
	errSmallFrame    = errors.New("DHCPv4: frame size <240")
	errDHCPBadOption = errors.New("DHCPv4: opt length exceeds payload")
	errNoOptions     = errors.New("DHCPv4: no options")
	errOptionNotFit  = errors.New("DHCPv4: options dont fit")
)

func (frm Frame) ValidateSize(vld *lneto.Validator) {
	err := frm.ForEachOption(nil) // Does all necessary validation.
	if err != nil {
		vld.AddError(errDHCPBadOption)
	}
}
