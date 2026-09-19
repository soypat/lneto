package tlsraw

import (
	"encoding/binary"

	"github.com/soypat/lneto"
)

type HelloClientMsg struct {
	buf       []byte
	_extOff   int // cached, not part of message.
	extLen    uint16
	suitesLen uint16
	complen   uint8
	sidLen    uint8
}

func (d *HelloClientMsg) reset()        { *d = HelloClientMsg{} }
func (d *HelloClientMsg) extoff() int   { return d._extOff }
func (d *HelloClientMsg) SIDLen() uint8 { return d.buf[2+SizeHelloRandom] }

// Random returns the 32-byte client_random.
func (ch HelloClientMsg) Random() *[SizeHelloRandom]byte {
	return (*[SizeHelloRandom]byte)(ch.buf[2 : 2+SizeHelloRandom])
}

// Decode parses the HelloClientMsg body bytes. First byte is start of version.
// Decode fails if message is not complete.
func (d *HelloClientMsg) Decode(body []byte, vld *lneto.Validator) (int, error) {
	d.reset()
	dec := decoder{buf: body, vld: vld, off: 2 + SizeHelloRandom}
	sidLen := int(dec.Uint8())
	if sidLen > MaxSessionIDLen {
		vld.AddError(lneto.ErrInvalidLengthField)
	}
	dec.Advance(sidLen)
	suitesLen := int(dec.Uint16())
	if suitesLen < 2 || suitesLen%2 != 0 {
		vld.AddError(lneto.ErrInvalidLengthField)
	}
	dec.Advance(suitesLen)
	compLen := int(dec.Uint8())
	if compLen == 0 {
		vld.AddError(lneto.ErrInvalidLengthField)
	}
	dec.Advance(compLen)
	extsLen := dec.Uint16()
	dec.Advance(int(extsLen))
	if vld.HasError() {
		return dec.off, vld.ErrPop()
	}
	d.buf = body
	d._extOff = dec.off - int(extsLen)
	d.extLen = extsLen
	d.suitesLen = uint16(suitesLen)
	d.sidLen = uint8(sidLen)
	d.complen = uint8(compLen)
	return dec.off, nil
}

// SessionID returns legacy_session_id, which the server echoes.
func (h *HelloClientMsg) SessionID() []byte {
	const off = 2 + SizeHelloRandom + 1
	return h.buf[off : off+h.sidLen]
}

func (h *HelloClientMsg) Suites() []byte {
	off := 2 + SizeHelloRandom + 1 + int(h.sidLen) + 2
	return h.buf[off : off+int(h.suitesLen)]
}

func (h *HelloClientMsg) Compressions() []byte {
	off := 2 + SizeHelloRandom + 1 + int(h.sidLen) + 2 + int(h.suitesLen) + 1
	return h.buf[off : off+int(h.complen)]
}

func (h *HelloClientMsg) Extensions() []byte {
	off := h.extoff()
	return h.buf[off : off+int(h.extLen)]
}

type HelloServerMsg struct {
	buf     []byte
	_extOff int // cached, not part of message.
	extLen  uint16
	sidLen  uint8
}

func (d *HelloServerMsg) reset()      { *d = HelloServerMsg{} }
func (d *HelloServerMsg) extoff() int { return d._extOff }

// Random returns the 32-byte server_random.
func (h *HelloServerMsg) Random() *[SizeHelloRandom]byte {
	return (*[SizeHelloRandom]byte)(h.buf[2 : 2+SizeHelloRandom])
}

// SessionID returns legacy_session_id_echo, which must match the ClientHello's.
func (h *HelloServerMsg) SessionID() []byte {
	const off = 2 + SizeHelloRandom + 1
	return h.buf[off : off+int(h.sidLen)]
}

func (h *HelloServerMsg) CipherSuite() CipherSuite {
	off := 2 + SizeHelloRandom + 1 + int(h.sidLen)
	return CipherSuite(binary.BigEndian.Uint16(h.buf[off:]))
}

// Compression returns legacy_compression_method, which must be 0.
func (h *HelloServerMsg) Compression() uint8 {
	return h.buf[2+SizeHelloRandom+1+int(h.sidLen)+2]
}

func (h *HelloServerMsg) Extensions() []byte {
	off := h.extoff()
	return h.buf[off : off+int(h.extLen)]
}

// Decode parses the HelloServerMsg body bytes. First byte is start of version.
// Decode fails if message is not complete.
func (d *HelloServerMsg) Decode(body []byte, vld *lneto.Validator) (int, error) {
	d.reset()
	dec := decoder{buf: body, vld: vld, off: 2 + SizeHelloRandom}
	sidLen := int(dec.Uint8())
	if sidLen > MaxSessionIDLen {
		vld.AddError(lneto.ErrInvalidLengthField)
	}
	dec.Advance(sidLen)
	dec.Advance(2 + 1) // cipher_suite and legacy_compression_method.
	extsLen := dec.Uint16()
	dec.Advance(int(extsLen))
	if vld.HasError() {
		return dec.off, vld.ErrPop()
	}
	d.buf = body
	d._extOff = dec.off - int(extsLen)
	d.extLen = extsLen
	d.sidLen = uint8(sidLen)
	return dec.off, nil
}

// NextKeyShare returns the group and key of the KeyShareEntry at the start of body and its length n.
// sentByServer is true when body was sent by a server, which sends a single entry, or only the group in a HelloRetryRequest.
func NextKeyShare(body []byte, sentByServer bool) (group NamedGroup, key []byte, n int, err error) {
	if len(body) < 2 {
		return 0, nil, 0, lneto.ErrTruncatedFrame
	}
	group = NamedGroup(binary.BigEndian.Uint16(body))
	if sentByServer && len(body) == 2 {
		return group, nil, 2, nil
	} else if len(body) < 4 {
		return 0, nil, 0, lneto.ErrTruncatedFrame
	}
	n = int(binary.BigEndian.Uint16(body[2:4]))
	if n == 0 {
		return 0, nil, 0, lneto.ErrInvalidLengthField
	} else if n > len(body)-4 {
		return 0, nil, 0, lneto.ErrTruncatedFrame
	} else if sentByServer && n != len(body)-4 {
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
// introspection into the actual data. sentByServer is true when the extension was
// sent by a server (ServerHello, HelloRetryRequest) and false when sent by a client.
func (ef ExtensionFrame) ValidateType(vld *lneto.Validator, sentByServer bool) (checked bool) {
	checked = true
	data := ef.Data()
	var err error
	switch ef.Type() {
	case ExtServerName:
		if sentByServer {
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
		if sentByServer {
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
		err = validateKeyShare(data, sentByServer)
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

func validateKeyShare(data []byte, sentByServer bool) error {
	if sentByServer {
		_, _, _, err := NextKeyShare(data, true)
		return err
	} else if err := checkVec16(data); err != nil {
		return err
	}
	// Empty client_shares is legal: the client asks for a HelloRetryRequest.
	for data = data[2:]; len(data) > 0; {
		_, _, n, err := NextKeyShare(data, false)
		if err != nil {
			return err
		}
		data = data[n:]
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

// decoder provides a API to readably decode TLS packets.
// It's decoding methods are meant to be used with no error checking between them
// for maximum readability while not sacrificing panic risk; performance is secondary.
type decoder struct {
	buf []byte
	off int
	vld *lneto.Validator
}

func (dec *decoder) Uint16() (v uint16) {
	if dec.failLen(2) {
		return
	}
	v = binary.BigEndian.Uint16(dec.buf[dec.off:])
	dec.off += 2
	return v
}

func (dec *decoder) Uint8() (v uint8) {
	if dec.failLen(1) {
		return
	}
	v = dec.buf[dec.off]
	dec.off++
	return v
}

func (dec *decoder) Advance(n int) {
	if !dec.failLen(n) {
		dec.off += n
	}
}

func (dec *decoder) failLen(n int) (failed bool) {
	if dec.vld.HasError() {
		return true
	} else if len(dec.buf)-dec.off < n {
		dec.vld.AddError(lneto.ErrTruncatedFrame)
		return true
	}
	return false
}

// encoder writes TLS structures to a fixed buffer, the counterpart of [decoder].
// A write past the end of buf sets err and all later writes are dropped, so
// callers check err once after writing.
type encoder struct {
	buf []byte
	off int
	err error
}

// next reserves n bytes. It returns nil if they do not fit.
func (e *encoder) next(n int) []byte {
	if e.err == nil && len(e.buf)-e.off < n {
		e.err = lneto.ErrShortBuffer
	}
	if e.err != nil {
		return nil
	}
	e.off += n
	return e.buf[e.off-n : e.off]
}

func (e *encoder) Uint8(v uint8) {
	if b := e.next(1); b != nil {
		b[0] = v
	}
}

func (e *encoder) Uint16(v uint16) {
	if b := e.next(2); b != nil {
		binary.BigEndian.PutUint16(b, v)
	}
}

func (e *encoder) Bytes(v []byte) {
	if b := e.next(len(v)); b != nil {
		copy(b, v)
	}
}

// Rest returns the unwritten part of buf for a callee to write into. Commit with Advance.
func (e *encoder) Rest() []byte {
	if e.err != nil {
		return nil
	}
	return e.buf[e.off:]
}

func (e *encoder) Advance(n int) { e.next(n) }

// Open reserves a length prefix of width bytes and returns where its content starts.
func (e *encoder) Open(width int) (start int) {
	e.next(width)
	return e.off
}

// Close writes the length of the content written since Open returned start.
func (e *encoder) Close(start, width int) {
	if e.err != nil {
		return
	}
	n := e.off - start
	if n>>(8*width) != 0 {
		e.err = lneto.ErrInvalidLengthField
		return
	}
	for i := start - 1; i >= start-width; i-- {
		e.buf[i] = byte(n)
		n >>= 8
	}
}

// StartMessage writes a handshake message header whose length is set by EndMessage.
func (e *encoder) StartMessage(typ HandshakeType) (start int) {
	start = e.off
	e.Uint8(uint8(typ))
	e.Open(3)
	return start
}

// EndMessage sets the length of the message started at start and returns the message.
func (e *encoder) EndMessage(start int) []byte {
	e.Close(start+SizeHeaderHandshake, 3)
	if e.err != nil {
		return nil
	}
	return e.buf[start:e.off]
}

// StartRecord writes a TLSPlaintext header whose length is set by EndRecord.
func (e *encoder) StartRecord(ct ContentType) (start int) {
	start = e.off
	e.Uint8(uint8(ct))
	e.Uint16(VersionTLS12)
	e.Open(2)
	return start
}

func (e *encoder) EndRecord(start int) { e.Close(start+SizeHeaderRecord, 2) }

// SealRecord protects with hc the content written since StartRecord returned start.
func (e *encoder) SealRecord(hc *halfConn, start int, ct ContentType) {
	if e.err != nil {
		return
	}
	rec, err := hc.Seal(e.buf[start:e.off:len(e.buf)], ct)
	if err != nil {
		e.err = err
		return
	}
	e.off = start + len(rec)
}
