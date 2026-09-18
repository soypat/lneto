package tls

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

type HelloClientMsg struct {
	buf []byte
}

func (d *HelloClientMsg) reset() {
	d.buf = nil
}

func (d *HelloClientMsg) SIDLen() uint8 { return d.buf[2+SizeHelloRandom] }

// Random returns the 32-byte client_random.
func (ch HelloClientMsg) Random() *[SizeHelloRandom]byte {
	return (*[SizeHelloRandom]byte)(ch.buf[2 : 2+SizeHelloRandom])
}

func (d *HelloClientMsg) Decode(body []byte) (int, error) {
	const fixed = 2 + SizeHelloRandom + 1
	if len(body) < fixed {
		return 0, lneto.ErrTruncatedFrame
	}
	off := 2 + SizeHelloRandom
	sidLen := int(body[off])
	off += sidLen + 1
	suitesLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	compLen := int(body[off])
	off += compLen
	extsLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	_ = suitesLen
	_ = extsLen
	return 0, nil
}

// NextKeyShare returns parsed group and key data that is next in buffer. If caller is server then asServer=true.
func NextKeyShare(body []byte, asServer bool) (group NamedGroup, key []byte, n int, err error) {
	if len(body) < 2 {
		return 0, nil, 0, lneto.ErrTruncatedFrame
	}
	group = NamedGroup(binary.BigEndian.Uint16(body))
	if asServer && len(body) == 2 {
		return group, nil, 0, nil
	} else if len(body) < 4 {
		return 0, nil, 0, lneto.ErrTruncatedFrame
	}
	n = int(binary.BigEndian.Uint16(body[2:4]))
	if n == 0 {
		return 0, nil, 0, lneto.ErrInvalidLengthField
	} else if n > len(body)-4 {
		return 0, nil, 0, lneto.ErrTruncatedFrame
	} else if asServer && n != len(body)-4 {
		return 0, nil, 0, lneto.ErrInvalidLengthField
	}
	return group, body[4 : 4+n], 4 + n, nil
}

type ExtensionFrame struct {
	buf []byte
}

func NewExtensionFrame(buf []byte) (ExtensionFrame, error) {
	if len(buf) < 4 {
		return ExtensionFrame{}, lneto.ErrTruncatedFrame
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	if n > len(buf)-4 {
		return ExtensionFrame{}, lneto.ErrTruncatedFrame
	}
	return ExtensionFrame{buf: buf[:4+n]}, nil
}

// Type returns the extension type.
func (ef ExtensionFrame) Type() ExtensionType { return ExtensionType(binary.BigEndian.Uint16(ef.buf)) }

// Length returns the declared extension_data length.
func (ef ExtensionFrame) Length() uint16 { return binary.BigEndian.Uint16(ef.buf[2:4]) }

// Data is extension_data section of frame.
func (ef ExtensionFrame) Data() []byte { return ef.buf[4:] }

// RawData returns the extension bytes, type and length included. Its length is
// the distance to the next extension in a list.
func (ef ExtensionFrame) RawData() []byte { return ef.buf }

// ValidateType validates the overall data size and shape carried by extension without
// introspection into the actual data. If caller is server then asServer=true.
func (ef ExtensionFrame) ValidateType(vld *lneto.Validator, asServer bool) (checked bool) {
	checked = true
	data := ef.Data()
	var err error
	switch ef.Type() {
	case ExtServerName:
		if asServer {
			// A server acknowledges the name with empty extension_data.
			if len(data) != 0 {
				err = lneto.ErrInvalidLengthField
			}
		} else {
			err = validateServerNames(data)
		}
	case ExtALPN:
		err = validateALPN(data)
	case ExtSupportedGroups, ExtSignatureAlgorithms, ExtSignatureAlgorithmsCert:
		if err = checkVec16(data); err != nil {
			break
		} else if len(data) < 4 || len(data)%2 != 0 {
			err = lneto.ErrInvalidLengthField
		}
	case ExtSupportedVersions:
		if asServer {
			// A server names the one selected version.
			if len(data) != 2 {
				err = lneto.ErrInvalidLengthField
			}
		} else if err = checkVec8(data); err != nil {
			break
		} else if len(data) < 3 || (len(data)-1)%2 != 0 {
			err = lneto.ErrInvalidLengthField
		}
	case ExtKeyShare:
		err = validateKeyShare(data, asServer)
	default:
		checked = false
	}
	if err != nil {
		vld.AddError(err)
	}
	return checked
}

func validateALPN(data []byte) error {
	// Shortest valid list is a single one-byte protocol name.
	if len(data) < 2+2 {
		return lneto.ErrTruncatedFrame
	} else if err := checkVec16(data); err != nil {
		return err
	}
	data = data[2:]
	for off := 0; off < len(data); {
		n := int(data[off])
		off++
		if n == 0 {
			// A zero-length name would make a walk unable to advance.
			return lneto.ErrInvalidLengthField
		} else if n > len(data)-off {
			return lneto.ErrTruncatedFrame
		}
		off += n
	}
	return nil
}

func validateServerNames(data []byte) error {
	// Shortest valid list is a single entry with a one-byte host name.
	if len(data) < 2+4 {
		return lneto.ErrTruncatedFrame
	} else if err := checkVec16(data); err != nil {
		return err
	}
	data = data[2:]
	for off := 0; off < len(data); {
		if len(data)-off < 3 {
			return lneto.ErrTruncatedFrame
		}
		n := int(binary.BigEndian.Uint16(data[off+1 : off+3]))
		off += 3
		if n == 0 {
			return lneto.ErrInvalidLengthField
		} else if n > len(data)-off {
			return lneto.ErrTruncatedFrame
		}
		off += n
	}
	return nil
}

func validateKeyShare(data []byte, asServer bool) error {
	if asServer {
		// A ServerHello names one group and its key; a HelloRetryRequest names only the group.
		if len(data) == 2 {
			return nil
		}
		return validateKeyShareEntries(data)
	}
	if err := checkVec16(data); err != nil {
		return err
	}
	return validateKeyShareEntries(data[2:])
}

func validateKeyShareEntries(b []byte) error {
	for off := 0; off < len(b); {
		if len(b)-off < 4 {
			return lneto.ErrTruncatedFrame
		}
		n := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if n > len(b)-off {
			return lneto.ErrTruncatedFrame
		}
		off += n
	}
	return nil
}

func checkVec16(data []byte) error {
	if len(data) < 2 {
		return lneto.ErrTruncatedFrame
	}
	n := int(binary.BigEndian.Uint16(data))
	if n != len(data)-2 {
		if n > len(data)-2 {
			return lneto.ErrTruncatedFrame
		}
		return lneto.ErrInvalidLengthField
	}
	return nil
}

func checkVec8(data []byte) error {
	if len(data) < 1 {
		return lneto.ErrTruncatedFrame
	}
	n := int(data[0])
	if n != len(data)-1 {
		if n > len(data)-1 {
			return lneto.ErrTruncatedFrame
		}
		return lneto.ErrInvalidLengthField
	}
	return nil
}
