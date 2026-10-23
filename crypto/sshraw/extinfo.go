package sshraw

import "github.com/soypat/lneto"

// ExtServerSigAlgs names the extension whose value is a name-list of signature algorithms
// the server accepts for user authentication. Check value with [ValidateNameList] before use.
const ExtServerSigAlgs = "server-sig-algs"

// sizeExtInfoHeader is the message type byte plus nr-extensions count.
const sizeExtInfoHeader = 1 + 4

// ValidateExtInfo validates an SSH_MSG_EXT_INFO payload, message type byte first, returning its
// extensions to iterate with [NextExtInfo]. Only sent to a peer that advertised [ExtInfoClient]
// or [ExtInfoServer]. Unrecognized extensions must be ignored. Trailing bytes are rejected.
func ValidateExtInfo(payload []byte) (exts []byte, err error) {
	var dec decoder
	dec.Reset(payload)
	dec.msgType(MsgExtInfo)
	count := dec.Uint32()
	if dec.IsFailed() {
		return nil, dec.Err()
	}
	exts = payload[sizeExtInfoHeader:]
	rest := exts
	// count is peer controlled: each extension takes at least 8 bytes, bounding the loop by payload length.
	for ; count > 0; count-- {
		_, _, n, err := NextExtInfo(rest)
		if err != nil {
			return nil, err
		}
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, lneto.ErrInvalidLengthField
	}
	return exts, nil
}

// NextExtInfo returns name and value of the first extension of exts and the bytes it takes.
// Names are validated, values are not checked.
func NextExtInfo(exts []byte) (name, value []byte, n int, err error) {
	var dec decoder
	dec.Reset(exts)
	name = dec.String()
	value = dec.String()
	if !dec.IsFailed() {
		if err := validateName(name); err != nil {
			dec.Fail(err)
		}
	}
	if dec.IsFailed() {
		return nil, nil, 0, dec.Err()
	}
	return name, value, dec.Off(), nil
}
