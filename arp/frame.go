package arp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/lneto2"
)

// NewARPFrame returns a ARPFrame with data set to buf.
// An error is returned if the buffer size is smaller than 28 (IPv4 min size).
// Users should still call [ARPFrame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeHeaderv4 {
		return Frame{buf: nil}, errors.New("ARP packet too short")
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of an ARP packet
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [RFC826].
//
// [RFC826]: https://tools.ietf.org/html/rfc826
type Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (afrm Frame) RawData() []byte { return afrm.buf }

// HardwareType specifies the network link protocol type. Example: Ethernet is 1.
func (afrm Frame) Hardware() (Type uint16, length uint8) {
	Type = binary.BigEndian.Uint16(afrm.buf[0:2])
	return Type, afrm.hwlen()
}

func (afrm Frame) hwlen() uint8 {
	return afrm.buf[4]
}

// SetHardware sets the networl link protocol type. See [Frame.SetHardware].
func (afrm Frame) SetHardware(Type uint16, length uint8) {
	binary.BigEndian.PutUint16(afrm.buf[0:2], Type)
	afrm.buf[4] = length
}

// Protocol returns the internet protocol type and length. See [ethernet.Type].
func (afrm Frame) Protocol() (Type ethernet.Type, length uint8) {
	Type = ethernet.Type(binary.BigEndian.Uint16(afrm.buf[2:4]))
	return Type, afrm.protolen()
}

func (afrm Frame) protolen() uint8 { return afrm.buf[5] }

// SetProtocol sets the protocol type and length fields of the ARP frame. See [Frame.Protocol] and [ethernet.Type].
func (afrm Frame) SetProtocol(Type ethernet.Type, length uint8) {
	binary.BigEndian.PutUint16(afrm.buf[2:4], uint16(Type))
	afrm.buf[5] = length
}

// Operation returns the ARP header operation field. See [Operation].
func (afrm Frame) Operation() Operation { return Operation(binary.BigEndian.Uint16(afrm.buf[6:8])) }

// SetOperation sets the ARP header operation field. See [Operation].
func (afrm Frame) SetOperation(op Operation) { binary.BigEndian.PutUint16(afrm.buf[6:8], uint16(op)) }

// Sender returns the hardware (MAC) and protocol addresses of sender of ARP packet.
// In an ARP request MAC address is used to indicate
// the address of the host sending the request. In an ARP reply MAC address is
// used to indicate the address of the host that the request was looking for.
func (afrm Frame) Sender() (hardwareAddr []byte, proto []byte) {
	_, hlen := afrm.Hardware()
	_, ilen := afrm.Protocol()
	return afrm.buf[8 : 8+hlen], afrm.buf[8+hlen : 8+hlen+ilen]
}

// Target returns the hardware (MAC) and protocol addresses of target of ARP packet.
// In an ARP request MAC target is ignored. In ARP reply MAC is used to indicate the address of host that originated request.
func (afrm Frame) Target() (hardwareAddr []byte, proto []byte) {
	_, hlen := afrm.Hardware()
	_, ilen := afrm.Protocol()
	toff := 8 + hlen + ilen
	return afrm.buf[toff : toff+hlen], afrm.buf[toff+hlen : toff+hlen+ilen]
}

// Sender4 returns the IPv4 sender addresses. See [Frame.Sender].
func (afrm Frame) Sender4() (hardwareAddr *[6]byte, proto *[4]byte) {
	return (*[6]byte)(afrm.buf[8:14]), (*[4]byte)(afrm.buf[14:18])
}

// Target4 returns the IPv4 target addresses. See [Frame.Sender].
func (afrm Frame) Target4() (hardwareAddr *[6]byte, proto *[4]byte) {
	return (*[6]byte)(afrm.buf[18:24]), (*[4]byte)(afrm.buf[24:28])
}

// Sender6 returns the IPv6 sender addresses. See [Frame.Sender].
func (afrm Frame) Sender16() (hardwareAddr *[6]byte, proto *[16]byte) {
	return (*[6]byte)(afrm.buf[8:14]), (*[16]byte)(afrm.buf[14:30])
}

// Target6 returns the IPv6 target addresses. See [Frame.Sender].
func (afrm Frame) Target16() (hardwareAddr *[6]byte, proto *[16]byte) {
	return (*[6]byte)(afrm.buf[30:36]), (*[16]byte)(afrm.buf[36:52])
}

// ClearHeader zeros out the fixed(non-variable) header contents.
func (afrm Frame) ClearHeader() {
	for i := range afrm.buf[:8] {
		afrm.buf[i] = 0
	}
}

func (afrm Frame) Clip() Frame {
	return Frame{buf: afrm.buf[:sizeHeader+2*int(afrm.hwlen())+2*int(afrm.protolen())]}
}

func (afrm Frame) SwapTargetSender() {
	hwTarget, protoTarget := afrm.Target()
	hwSender, protoSender := afrm.Sender()
	for i := range hwTarget {
		hwTarget[i], hwSender[i] = hwSender[i], hwTarget[i]
	}
	for i := range protoTarget {
		protoTarget[i], protoSender[i] = protoSender[i], protoTarget[i]
	}
}

// Validation API
//
// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (afrm Frame) ValidateSize(v *lneto2.Validator) {
	_, hlen := afrm.Hardware()
	_, ilen := afrm.Protocol()
	minLen := 8 + 2*(hlen+ilen)
	if len(afrm.buf) < int(minLen) {
		v.AddError(errShortARP)
	}
}

func (afrm Frame) String() string {
	opstr := afrm.Operation().String()
	hwt, _ := afrm.Hardware()
	ptt, _ := afrm.Protocol()
	sndhw, sndpt := afrm.Sender()
	tgthw, tgtpt := afrm.Target()
	var sndstr, tgtstr string
	if ptt == ethernet.TypeIPv4 || ptt == ethernet.TypeIPv6 {
		sender, _ := netip.AddrFromSlice(sndpt)
		target, _ := netip.AddrFromSlice(tgtpt)
		sndstr = sender.String()
		tgtstr = target.String()
	} else {
		sndstr = net.HardwareAddr(sndpt).String()
		tgtstr = net.HardwareAddr(tgtpt).String()
	}
	return fmt.Sprintf("ARP %s HW=(%d,SENDER=%s,TARGET=%s) PROTO=(%s,SENDER=%s,TARGET=%s)",
		opstr, hwt, net.HardwareAddr(sndhw).String(), net.HardwareAddr(tgthw).String(),
		ptt.String(), sndstr, tgtstr)
}
