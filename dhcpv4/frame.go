package dhcpv4

import (
	"encoding/binary"
	"errors"
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
		return Frame{}, errors.New("DHCPv4 short frame")
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
	return frm.buf[:optionsOffset]
}

func (frm Frame) Op() Op      { return Op(frm.buf[0]) }
func (frm Frame) SetOp(op Op) { frm.buf[0] = byte(op) }

func (frm Frame) Hardware() (Type, Len, Ops uint8) {
	return frm.buf[1], frm.buf[2], frm.buf[3]
}

func (frm Frame) SetHardware(Type, Len, Ops uint8) {
	frm.buf[1], frm.buf[2], frm.buf[3] = Type, Len, Ops
}

func (frm Frame) XID() uint32       { return binary.BigEndian.Uint32(frm.buf[4:8]) }
func (frm Frame) SetXID(xid uint32) { binary.BigEndian.PutUint32(frm.buf[4:8], xid) }

func (frm Frame) Secs() uint16        { return binary.BigEndian.Uint16(frm.buf[8:10]) }
func (frm Frame) SetSecs(secs uint16) { binary.BigEndian.PutUint16(frm.buf[8:10], secs) }

func (frm Frame) Flags() Flags         { return Flags(binary.BigEndian.Uint16(frm.buf[10:12])) }
func (frm Frame) SetFlags(flags Flags) { binary.BigEndian.PutUint16(frm.buf[10:12], uint16(flags)) }

// CIAddr is the client IP address. If the client has not obtained an IP
// address yet, this field is set to 0.
func (frm Frame) CIAddr() *[4]byte {
	return (*[4]byte)(frm.buf[12:16])
}

// YIAddr is the IP address offered by the server to the client.
func (frm Frame) YIAddr() *[4]byte {
	return (*[4]byte)(frm.buf[16:20])
}

// SIAddr is the IP address of the next server to use in bootstrap. This
// field is used in DHCPOFFER and DHCPACK messages.
func (frm Frame) SIAddr() *[4]byte {
	return (*[4]byte)(frm.buf[20:24])
}

// GIAddr is the gateway IP address.
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

func (frm Frame) MagicCookie() uint32 { return binary.BigEndian.Uint32(frm.buf[magicCookieOffset:]) }
func (frm Frame) SetMagicCookie(cookie uint32) {
	binary.BigEndian.PutUint32(frm.buf[magicCookieOffset:], cookie)
}

// ClearHeader zeros out the header contents.
func (frm Frame) ClearHeader() {
	for i := range frm.buf[:optionsOffset] {
		frm.buf[i] = 0
	}
}

func (frm Frame) ForEachOption(fn func(op OptNum, data []byte) error) error {
	if fn == nil {
		return errors.New("nil function to parse DHCP")
	}
	// Parse DHCP options.
	ptr := optionsOffset
	if ptr >= len(frm.buf) {
		return errors.New("short payload to parse DHCP options")
	}
	for ptr+1 < len(frm.buf) {
		if int(frm.buf[ptr+1]) >= len(frm.buf) {
			return errors.New("DHCP option length exceeds payload")
		}
		optnum := OptNum(frm.buf[ptr])
		if optnum == 0xff {
			break
		} else if optnum == OptWordAligned {
			ptr++
			continue
		}
		optlen := frm.buf[ptr+1]
		optionData := frm.buf[ptr+2 : ptr+2+int(optlen)]
		if err := fn(optnum, optionData); err != nil {
			return err
		}
		ptr += int(optlen) + 2
	}
	return nil
}
