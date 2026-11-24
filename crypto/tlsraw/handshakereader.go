package tlsraw

import "github.com/soypat/lneto"

// HandshakeReader reassembles handshake messages from record content, RFC 8446
// 5.1: a message may span records and a record may carry several messages.
// With a buffer it returns whole messages. Discard drops messages without one,
// so a client can stop using its buffer after the handshake and still read
// NewSessionTicket. The message Next returns stays valid until the following
// Next, since bytes move only while no message is held.
type HandshakeReader struct {
	buf      []byte
	off, end int
	held     int // Length of the message returned by the last Next, 0 if none.
	// Discard state.
	hdr  [SizeHeaderHandshake]byte
	hdrN uint8
	skip int // Body bytes of the current message left to drop.
}

// Reset sets the reassembly buffer and drops all state. A nil buf leaves only Discard usable.
func (hr *HandshakeReader) Reset(buf []byte) { *hr = HandshakeReader{buf: buf} }

// Write appends handshake record content in full or not at all. It returns
// [lneto.ErrBufferFull] if content does not fit. Callers reject empty
// handshake records themselves, RFC 8446 5.1.
func (hr *HandshakeReader) Write(content []byte) error {
	if hr.held == 0 && hr.off > 0 {
		hr.compact()
	}
	if len(content) > len(hr.buf)-hr.end {
		return lneto.ErrBufferFull
	}
	hr.end += copy(hr.buf[hr.end:], content)
	return nil
}

// Next releases the held message and returns the next complete message with
// its header, or nil when none is complete. It returns [lneto.ErrBufferFull]
// when a header announces a message larger than the buffer.
func (hr *HandshakeReader) Next() (msg []byte, err error) {
	hr.off += hr.held
	hr.held = 0
	pending := hr.buf[hr.off:hr.end]
	if len(pending) >= SizeHeaderHandshake {
		n := SizeHeaderHandshake + int(uint24(pending[1:]))
		if n > len(hr.buf) {
			return nil, lneto.ErrBufferFull
		} else if n <= len(pending) {
			hr.held = n
			return pending[:n:n], nil
		}
	}
	hr.compact()
	return nil, nil
}

// Pending reports buffered bytes after the held message, which RFC 8446 5.1
// forbids across a key change.
func (hr *HandshakeReader) Pending() bool { return hr.end > hr.off+hr.held }

// Discard drops whole messages of type allow from content across calls,
// without buffering. It returns [lneto.ErrMismatch] on any other type.
func (hr *HandshakeReader) Discard(content []byte, allow HandshakeType) error {
	for len(content) > 0 {
		if hr.skip > 0 {
			n := min(hr.skip, len(content))
			hr.skip -= n
			content = content[n:]
			continue
		}
		n := copy(hr.hdr[hr.hdrN:], content)
		hr.hdrN += uint8(n)
		content = content[n:]
		if int(hr.hdrN) < len(hr.hdr) {
			return nil
		} else if HandshakeType(hr.hdr[0]) != allow {
			return lneto.ErrMismatch
		}
		hr.hdrN, hr.skip = 0, int(uint24(hr.hdr[1:]))
	}
	return nil
}

// Zeroize clears the buffer and drops all state. It keeps the buffer.
func (hr *HandshakeReader) Zeroize() {
	clear(hr.buf)
	hr.Reset(hr.buf)
}

func (hr *HandshakeReader) compact() {
	hr.end = copy(hr.buf, hr.buf[hr.off:hr.end])
	hr.off = 0
}

func uint24(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }
