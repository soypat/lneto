package lneto

import "errors"

var (
	errShortUDP  = errors.New("UDP length exceeds frame")
	errBadUDPLen = errors.New("UDP length invalid")
	errShortIPv4 = errors.New("IPv4 total length exceeds frame")
	errBadIPv4TL = errors.New("IPv4 short total length")
	errShortIPv6 = errors.New("IPv6 payload length exceeds frame")

	errShortTCP  = errors.New("TCP offset exceeds frame")
	errBadTCPOff = errors.New("TCP offset invalid")
)

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (ufrm UDPFrame) ValidateSize() error {
	ul := ufrm.Length()
	if ul < sizeHeaderUDP {
		return errBadUDPLen
	} else if int(ul) > len(ufrm.RawData()) {
		return errShortUDP
	}
	return nil
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (ifrm IPv4Frame) ValidateSize() error {
	tl := ifrm.TotalLength()
	if tl < sizeHeaderIPv4 {
		return errBadIPv4TL
	} else if int(tl) > len(ifrm.RawData()) {
		return errShortIPv4
	}
	return nil
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (tfrm TCPFrame) ValidateSize() error {
	off := tfrm.HeaderLength()
	if off < sizeHeaderTCP {
		return errBadTCPOff
	} else if off > len(tfrm.RawData()) {
		return errShortTCP
	}
	return nil
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (i6frm IPv6Frame) ValidateSize() error {
	tl := i6frm.PayloadLength()
	if int(tl)+sizeHeaderIPv6 > len(i6frm.RawData()) {
		return errShortIPv6
	}
	return nil
}
