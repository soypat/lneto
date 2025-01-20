package lneto

import "errors"

var (
	errShortEth   = errors.New("ethernet length exceeds frame")
	errShortVLAN  = errors.New("ethernet length too short for VLAN")
	errShortUDP   = errors.New("UDP length exceeds frame")
	errBadUDPLen  = errors.New("UDP length invalid")
	errShortIPv4  = errors.New("IPv4 total length exceeds frame")
	errBadIPv4TL  = errors.New("IPv4 short total length")
	errBadIPv4IHL = errors.New("IPv4 bad IHL (<5)")
	errShortIPv6  = errors.New("IPv6 payload length exceeds frame")
	errShortARP   = errors.New("bad ARP size")
	errShortTCP   = errors.New("TCP offset exceeds frame")
	errBadTCPOff  = errors.New("TCP offset invalid")

	errBadIPVersion = errors.New("bad IP version field")
	errEvilPacket   = errors.New("evil packet")
	errZeroDstPort  = errors.New("TCP zero destination port")
	errZeroSrcPort  = errors.New("TCP zero source port")
)

type Validator struct {
	checkEvil      bool
	allowMultiErrs bool
	accum          []error
}

func (v *Validator) ResetErr() {
	v.accum = v.accum[:0]
}

func (v *Validator) Err() error {
	if len(v.accum) == 1 {
		return v.accum[0]
	} else if len(v.accum) == 0 {
		return nil
	}
	return errors.Join(v.accum...)
}

func (v *Validator) gotErr(err error) {
	if len(v.accum) != 0 && !v.allowMultiErrs {
		return
	}
	v.accum = append(v.accum, err)
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (efrm EthFrame) ValidateSize(v *Validator) {
	sz := efrm.EtherTypeOrSize()
	if sz.IsSize() && len(efrm.buf) < int(sz) {
		v.gotErr(errShortEth)
	}
	if sz == EtherTypeVLAN && len(efrm.buf) < 18 {
		v.gotErr(errShortVLAN)
	}
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (afrm ARPFrame) ValidateSize(v *Validator) {
	_, hlen := afrm.Hardware()
	_, ilen := afrm.Protocol()
	minLen := 8 + 2*(hlen+ilen)
	if len(afrm.buf) < int(minLen) {
		v.gotErr(errShortARP)
	}
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (ifrm IPv4Frame) ValidateSize(v *Validator) {
	ihl := ifrm.ihl()
	tl := ifrm.TotalLength()
	if tl < sizeHeaderIPv4 {
		v.gotErr(errBadIPv4TL)
	}
	if int(tl) > len(ifrm.RawData()) {
		v.gotErr(errShortIPv4)
	}
	if ihl < 5 {
		v.gotErr(errBadIPv4IHL)
	}
}

// ValidateExceptCRC checks for invalid frame values but does not check CRC.
func (ifrm IPv4Frame) ValidateExceptCRC(v *Validator) {
	ifrm.ValidateSize(v)
	flags := ifrm.Flags()
	if ifrm.version() != 4 {
		v.gotErr(errBadIPVersion)
	}
	if v.checkEvil && flags.IsEvil() {
		v.gotErr(errEvilPacket)
	}
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (i6frm IPv6Frame) ValidateSize(v *Validator) {
	tl := i6frm.PayloadLength()
	if int(tl)+sizeHeaderIPv6 > len(i6frm.RawData()) {
		v.gotErr(errShortIPv6)
	}
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (tfrm TCPFrame) ValidateSize(v *Validator) {
	off := tfrm.HeaderLength()
	if off < sizeHeaderTCP {
		v.gotErr(errBadTCPOff)
	}
	if off > len(tfrm.RawData()) {
		v.gotErr(errShortTCP)
	}
}

func (tfrm TCPFrame) ValidateExceptCRC(v *Validator) {
	tfrm.ValidateSize(v)
	if tfrm.DestinationPort() == 0 {
		v.gotErr(errZeroDstPort)
	}
	if tfrm.SourcePort() == 0 {
		v.gotErr(errZeroSrcPort)
	}
}

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (ufrm UDPFrame) ValidateSize(v *Validator) {
	ul := ufrm.Length()
	if ul < sizeHeaderUDP {
		v.gotErr(errBadUDPLen)
	}
	if int(ul) > len(ufrm.RawData()) {
		v.gotErr(errShortUDP)
	}
}
