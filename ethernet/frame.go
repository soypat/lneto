package ethernet

import (
	"encoding/binary"
	"errors"

	"github.com/soypat/lneto"
)

// NewFrame returns a EthFrame with data set to buf.
// An error is returned if the buffer size is smaller than 14.
// Users should still call [EthFrame.ValidateSize] before working
// with payload/options of frames to avoid panics.
func NewFrame(buf []byte) (Frame, error) {
	if len(buf) < sizeHeaderNoVLAN {
		return Frame{buf: nil}, errShort
	}
	return Frame{buf: buf}, nil
}

// Frame encapsulates the raw data of an Ethernet frame
// without including preamble (first byte is start of destination address)
// and provides methods for manipulating, validating and
// retrieving fields and payload data. See [IEEE 802.3].
//
// [IEEE 802.3]: https://standards.ieee.org/ieee/802.3/7071/
type Frame struct {
	buf []byte
}

// RawData returns the underlying slice with which the frame was created.
func (efrm Frame) RawData() []byte { return efrm.buf }

// HeaderLength returns the length of the ethernet packet header. Nominally returns 14; or 18 for VLAN packets.
func (efrm Frame) HeaderLength() int {
	if efrm.IsVLAN() {
		return 18
	}
	return sizeHeaderNoVLAN
}

// Payload returns the data portion of the ethernet packet with correct handling of VLAN packets.
func (efrm Frame) Payload() []byte {
	hl := efrm.HeaderLength()
	et := efrm.EtherTypeOrSize()
	if et.IsSize() {
		return efrm.buf[hl : hl+int(et)]
	}
	return efrm.buf[hl:]
}

// DestinationHardwareAddr returns the target's MAC/hardware address for the ethernet packet.
func (efrm Frame) DestinationHardwareAddr() (dst *[6]byte) {
	return (*[6]byte)(efrm.buf[0:6])
}

// IsBroadcast returns true if the destination is the broadcast address ff:ff:ff:ff:ff:ff, false otherwise.
func (efrm Frame) IsBroadcast() bool {
	return efrm.buf[0] == 0xff && efrm.buf[1] == 0xff && efrm.buf[2] == 0xff &&
		efrm.buf[3] == 0xff && efrm.buf[4] == 0xff && efrm.buf[5] == 0xff
}

// SourceHardwareAddr returns the sender's MAC/hardware address of the ethernet packet.
func (efrm Frame) SourceHardwareAddr() (src *[6]byte) {
	return (*[6]byte)(efrm.buf[6:12])
}

// EtherTypeOrSize returns the EtherType/Size field of the ethernet packet.
// Caller should check if the field is actually a valid EtherType or if it represents the Ethernet payload size with [EtherType.IsSize].
func (efrm Frame) EtherTypeOrSize() Type {
	return Type(binary.BigEndian.Uint16(efrm.buf[12:14]))
}

// SetEtherType sets the EtherType field of the ethernet packet. See [EtherType] and [Frame.EtherTypeOrSize].
func (efrm Frame) SetEtherType(v Type) {
	binary.BigEndian.PutUint16(efrm.buf[12:14], uint16(v))
}

// VLANTag returns the VLAN tag field following the TPID=0x8100. See [VLANTag]. Call [Frame.ValidateSize] to ensure this function does not panic.
func (efrm Frame) VLANTag() VLANTag { return VLANTag(binary.BigEndian.Uint16(efrm.buf[14:16])) }

// SetVLAN sets following 3 fields:
//   - 12:14 ethernet frame type set to constant [TypeVLAN].
//   - 14:16 set to VLANTag argument value vt
//   - 16:18 set to the VLAN ether type vlanType.
func (efrm Frame) SetVLAN(tag VLANTag, vlanType Type) {
	efrm.SetEtherType(TypeVLAN)
	binary.BigEndian.PutUint16(efrm.buf[14:16], uint16(tag))
	binary.BigEndian.PutUint16(efrm.buf[16:18], uint16(vlanType))
}

// VLAN returns fields 14:16 and 16:18. Does not check field 12:14 for correctness.
// VLAN panics if length is insufficient.
func (efrm Frame) VLAN() (VLANTag, Type) {
	vt := binary.BigEndian.Uint16(efrm.buf[14:16])
	et := binary.BigEndian.Uint16(efrm.buf[16:18])
	return VLANTag(vt), Type(et)
}

// SetVLANTag sets the VLAN tag field of the Ethernet Header. See [VLANTag]. Call [Frame.ValidateSize] to ensure this function does not panic.
func (efrm Frame) SetVLANTag(vt VLANTag) { binary.BigEndian.PutUint16(efrm.buf[14:16], uint16(vt)) }

// VLANEtherType returns the [EtherType] for a VLAN ethernet frame (octet position 16). Call [Frame.ValidateSize] to ensure this function does not panic.
func (efrm Frame) VLANEtherType() Type {
	return Type(binary.BigEndian.Uint16(efrm.buf[16:18]))
}

// SetVLANEtherType sets the [EtherType] for a VLAN ethernet frame (octet position 16). Call [Frame.ValidateSize] to ensure this function does not panic.
func (efrm Frame) SetVLANEtherType(vt Type) {
	binary.BigEndian.PutUint16(efrm.buf[16:18], uint16(vt))
}

// IsVLAN returns true if the SizeOrEtherType is set to the VLAN tag 0x8100. This
// indicates the EthernetHeader is invalid as-is and instead of EtherType the field
// contains the first two octets of a 4 octet 802.1Q VLAN tag. In this case 4 more bytes
// must be read from the wire, of which the last 2 of these bytes contain the actual
// SizeOrEtherType field, which needs to be validated yet again in case the packet is
// a VLAN double-tap packet.
func (efrm Frame) IsVLAN() bool {
	return efrm.EtherTypeOrSize() == TypeVLAN
}

// ClearHeader zeros out the fixed(non-variable) header contents.
func (frm Frame) ClearHeader() {
	for i := range frm.buf[:sizeHeaderNoVLAN] {
		frm.buf[i] = 0
	}
}

//
// Validation API.
//

var (
	errShort     = errors.New("ethernet: too short")
	errShortVLAN = errors.New("ethernet: short VLAN")
)

// ValidateSize checks the frame's size fields and compares with the actual buffer
// the frame. It returns a non-nil error on finding an inconsistency.
func (efrm Frame) ValidateSize(v *lneto.Validator) {
	sz := efrm.EtherTypeOrSize()
	if sz.IsSize() && len(efrm.buf) < int(sz) {
		v.AddError(errShort)
	}
	if sz == TypeVLAN && len(efrm.buf) < 18 {
		v.AddError(errShortVLAN)
	}
}
