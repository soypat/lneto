package tlsauto

import (
	"io"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/tlsraw"
	"github.com/soypat/lneto/internal"
)

const (
	minWriteBuf     = 512
	minHandshakeBuf = 1024
	// recordSlack is what a TLSCiphertext adds to MaxRecord plaintext: content type, padding and tag, RFC 8446 5.2.
	recordSlack = 256
)

// handler is the TLS 1.3 client engine without a transport, the role
// tcp.Handler plays for TCP. The caller moves ciphertext between the transport
// and Recv/Send, and plaintext through Read/Write. No method blocks.
// It must not be copied after Configure.
type handler struct {
	cfg   Config
	state connState
	hs    clientHandshake
	keys  recordKeys
	ring  internal.Ring // Over cfg.ReadBuf.
	rr    tlsraw.RecordReader
	// held is the wire length of the record app points into. The next process discards it from ring.
	held int
	hr   tlsraw.HandshakeReader // First half of cfg.HandshakeBuf; Discard only after the handshake.

	sent, queued int    // cfg.WriteBuf[sent:queued] is sealed output for Send.
	app          []byte // Unread plaintext, decrypted in place inside ring.
	prevCCS      bool   // The last record was a dropped ChangeCipherSpec.
	peerClosed   bool
}

func (h *handler) Configure(cfg Config) error {
	if h.state == stateHandshake || h.state == stateConnected {
		return lneto.ErrBadState
	}
	if cfg.Rand == nil || cfg.Verifier == nil || len(cfg.Suites) == 0 || len(cfg.KeyExchanges) == 0 {
		return errNoConfig
	} else if len(cfg.ALPN) > 255 || len(cfg.ServerName) > 255 {
		return errNoConfig
	} else if cfg.MaxRecord < 0 || cfg.MaxRecord > tlsraw.MaxPlaintext || (cfg.MaxRecord > 0 && cfg.MaxRecord < 512) {
		return errNoConfig
	}
	if cfg.MaxRecord == 0 {
		cfg.MaxRecord = tlsraw.MaxPlaintext
	}
	if len(cfg.ReadBuf) < tlsraw.SizeHeaderRecord+cfg.MaxRecord+recordSlack ||
		len(cfg.WriteBuf) < minWriteBuf || len(cfg.HandshakeBuf) < minHandshakeBuf {
		return errNoConfig
	}
	for _, s := range cfg.Suites {
		if s.ID == 0 || s.NewAEAD == nil || s.NewHash == nil || s.KeyLen <= 0 || s.KeyLen > maxKeyLen {
			return errNoConfig
		}
	}
	for _, g := range cfg.KeyExchanges {
		if g.ID == 0 || g.NewExchanger == nil || g.ClientShareLen <= 0 || g.ServerShareLen <= 0 ||
			g.SharedLen <= 0 || g.SharedLen > maxShared {
			return errNoConfig
		}
	}
	if len(cfg.Schemes) == 0 {
		cfg.Schemes = DefaultSchemes
	}
	h.Zeroize()
	h.cfg = cfg
	h.keys = recordKeys{}
	h.hs.configure(&h.cfg)
	return nil
}

// Open resets h for a new connection. The ClientHello is encoded by the first Send or SendTo.
func (h *handler) Open() error {
	if h.cfg.Rand == nil {
		return lneto.ErrBadState
	}
	h.Zeroize()
	h.ring = internal.Ring{Buf: h.cfg.ReadBuf}
	if err := h.rr.Reset(h.cfg.MaxRecord + recordSlack); err != nil {
		return err
	}
	half := len(h.cfg.HandshakeBuf) / 2
	h.hr.Reset(h.cfg.HandshakeBuf[:half])
	h.hs.reset(h.cfg.HandshakeBuf[half:])
	h.prevCCS, h.peerClosed = false, false
	h.state = stateHandshake
	return nil
}

// Recv consumes transport bytes and processes every complete record it can.
// It returns n < len(b) when the receive ring is full of unread plaintext; Read frees it.
func (h *handler) Recv(b []byte) (n int, err error) {
	if h.state != stateHandshake && h.state != stateConnected {
		return 0, lneto.ErrBadState
	}
	for n < len(b) && len(h.app) == 0 && !h.peerClosed {
		k := min(len(b)-n, h.ring.Free())
		if k == 0 {
			break
		}
		h.ring.Write(b[n : n+k])
		n += k
		if err = h.process(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// RecvFrom performs one r.Read straight into the receive ring and processes the records it completes.
func (h *handler) RecvFrom(r io.Reader) (int, error) {
	if h.state != stateHandshake && h.state != stateConnected {
		return 0, lneto.ErrBadState
	}
	n, err := h.ring.ReadOnceFrom(r)
	if n > 0 {
		if perr := h.process(); perr != nil {
			return n, perr
		}
	}
	return n, err
}

// Send copies queued ciphertext into dst.
func (h *handler) Send(dst []byte) (int, error) {
	if err := h.start(); err != nil {
		return 0, err
	}
	n := copy(dst, h.cfg.WriteBuf[h.sent:h.queued])
	h.sent += n
	return n, nil
}

// SendTo writes queued ciphertext to w in one call.
func (h *handler) SendTo(w io.Writer) (int, error) {
	if err := h.start(); err != nil {
		return 0, err
	} else if h.sent == h.queued {
		return 0, nil
	}
	n, err := w.Write(h.cfg.WriteBuf[h.sent:h.queued])
	h.sent += n
	return n, err
}

// start queues a flight the handshake has before any message arrives, which
// is the ClientHello after Open. It fails h on error.
func (h *handler) start() error {
	if h.state != stateHandshake {
		return nil
	} else if err := h.speak(); err != nil {
		return h.fail(err)
	}
	return nil
}

// speak queues the handshake's next flight if it has one. The encoder is only
// built then: it compacts WriteBuf, which the ClientHello view points into.
func (h *handler) speak() error {
	if !h.hs.wantFlight() {
		return nil
	}
	e := h.encoder()
	if err := h.hs.writeFlight(&h.keys, &e); err != nil {
		return err
	}
	return h.commit(&e)
}

// Read copies buffered plaintext, processing records already received when none
// is buffered. It returns 0, nil when more ciphertext is needed and io.EOF after
// the server's close_notify.
func (h *handler) Read(p []byte) (int, error) {
	if h.state != stateConnected {
		return 0, lneto.ErrBadState
	}
	if len(h.app) == 0 {
		if err := h.process(); err != nil {
			return 0, err
		} else if len(h.app) == 0 && h.peerClosed {
			return 0, io.EOF
		}
	}
	n := copy(p, h.app)
	h.app = h.app[n:]
	return n, nil
}

// Write seals p into as many application data records as the write buffer
// fits. It returns n < len(p) and a nil error when the buffer is full.
func (h *handler) Write(p []byte) (n int, err error) {
	if h.state != stateConnected {
		return 0, lneto.ErrBadState
	}
	for n < len(p) {
		e := h.encoder()
		room := len(h.cfg.WriteBuf) - h.queued - tlsraw.SizeHeaderRecord - h.keys.out.Overhead()
		if room <= 0 {
			break
		}
		chunk := min(len(p)-n, room, tlsraw.MaxPlaintext)
		rec := e.StartRecord(tlsraw.ContentTypeApplicationData)
		e.Bytes(p[n : n+chunk])
		e.SealRecord(&h.keys.out, rec, tlsraw.ContentTypeApplicationData)
		if err = h.commit(&e); err != nil {
			return n, h.fail(err)
		}
		n += chunk
	}
	return n, nil
}

// Close queues close_notify when connected and wipes secrets. Queued output stays for Send.
func (h *handler) Close() error {
	var err error
	if h.state == stateConnected {
		err = h.queueAlert(tlsraw.AlertCloseNotify)
	}
	h.wipeSecrets()
	h.state = stateClosed
	return err
}

func (h *handler) HandshakeDone() bool { return h.state == stateConnected }

// ALPN returns cfg.ALPN once the server selected it, the only protocol it may select.
func (h *handler) ALPN() string {
	if h.hs.alpnOK {
		return h.cfg.ALPN
	}
	return ""
}

func (h *handler) BufferedOutput() int { return h.queued - h.sent }
func (h *handler) BufferedInput() int  { return len(h.app) }

// Zeroize wipes secrets and every buffer, queued output included.
func (h *handler) Zeroize() {
	h.wipeSecrets()
	clear(h.cfg.WriteBuf)
	h.sent, h.queued = 0, 0
}

// wipeSecrets wipes keys, handshake state and received data. Queued output is kept for a last Send.
func (h *handler) wipeSecrets() {
	h.hs.zeroize()
	h.keys.zeroize()
	clear(h.cfg.ReadBuf)
	clear(h.cfg.HandshakeBuf)
	h.ring.Reset()
	h.hr.Zeroize()
	h.held = 0
	h.app = nil
}

// process frames and handles received records until application data is held
// or no complete record is buffered.
func (h *handler) process() error {
	for len(h.app) == 0 && !h.peerClosed {
		if h.held > 0 {
			h.ring.DiscardInput(h.held)
			h.held = 0
		}
		if h.ring.IsEmpty() {
			h.ring.Reset() // Nothing is staged past the write position, so restart at index 0 to wrap less often.
		}
		first, second := h.ring.BufferedData()
		n, needMore, err := h.rr.Next(first, second)
		if needMore {
			return nil
		} else if err != nil {
			return h.fail(alertError(tlsraw.AlertRecordOverflow))
		}
		if n > len(first) {
			h.ring.LinearizeInput() // AEADs decrypt contiguous records only.
			first, _ = h.ring.BufferedData()
		}
		h.held = n
		ct, content, drop, err := h.open(first[:n:n])
		if err != nil {
			return h.fail(err)
		} else if drop {
			continue
		}
		if err = h.dispatch(ct, content); err != nil {
			return h.fail(err)
		}
	}
	return nil
}

// open checks a record and decrypts it in place once keys are installed.
// drop reports a ChangeCipherSpec to ignore.
func (h *handler) open(rec []byte) (ct tlsraw.ContentType, content []byte, drop bool, err error) {
	ct = tlsraw.ContentType(rec[0])
	content = rec[tlsraw.SizeHeaderRecord:]
	switch {
	case ct == tlsraw.ContentTypeChangeCipherSpec:
		// RFC 8446 5: dropped during the handshake.
		if h.state != stateHandshake || len(content) != 1 || content[0] != 1 || h.prevCCS {
			return 0, nil, false, alertError(tlsraw.AlertUnexpectedMessage)
		}
		h.prevCCS = true
		return ct, nil, true, nil
	case h.keys.in.HasKeys():
		if ct != tlsraw.ContentTypeApplicationData {
			return 0, nil, false, alertError(tlsraw.AlertUnexpectedMessage)
		}
		content, ct, err = h.keys.in.Open(rec)
		if err != nil {
			return 0, nil, false, alertError(tlsraw.AlertBadRecordMAC)
		}
	case ct != tlsraw.ContentTypeHandshake && ct != tlsraw.ContentTypeAlert:
		return 0, nil, false, alertError(tlsraw.AlertUnexpectedMessage)
	}
	h.prevCCS = false
	if len(content) > h.cfg.MaxRecord {
		return 0, nil, false, alertError(tlsraw.AlertRecordOverflow)
	}
	return ct, content, false, nil
}

func (h *handler) dispatch(ct tlsraw.ContentType, content []byte) error {
	switch ct {
	case tlsraw.ContentTypeHandshake:
		if len(content) == 0 {
			return alertError(tlsraw.AlertUnexpectedMessage)
		} else if h.state == stateHandshake {
			return h.recvHandshake(content)
		}
		// PSK is not supported and KeyUpdate is not supported yet, so only tickets are expected, and dropped.
		if h.hr.Discard(content, tlsraw.HandshakeTypeNewSessionTicket) != nil {
			return alertError(tlsraw.AlertUnexpectedMessage)
		}
		return nil
	case tlsraw.ContentTypeAlert:
		if err := h.recvAlert(content); err != nil {
			return err
		} else if h.state == stateHandshake {
			return io.ErrUnexpectedEOF
		}
		return nil
	case tlsraw.ContentTypeApplicationData:
		if h.state == stateHandshake {
			return alertError(tlsraw.AlertUnexpectedMessage)
		}
		h.app = content
		return nil
	}
	return alertError(tlsraw.AlertUnexpectedMessage)
}

// recvHandshake reassembles handshake content and runs the handshake over every
// complete message, queuing each flight the handshake answers with. h is
// connected once the handshake is done.
func (h *handler) recvHandshake(content []byte) error {
	if h.hr.Write(content) != nil {
		return alertError(tlsraw.AlertRecordOverflow)
	}
	for !h.hs.done() {
		msg, err := h.hr.Next()
		if err != nil {
			return alertError(tlsraw.AlertRecordOverflow)
		} else if msg == nil {
			return nil
		}
		if err = h.hs.handle(&h.keys, msg, h.hr.Pending()); err != nil {
			return err
		} else if err = h.speak(); err != nil {
			return err
		}
	}
	h.state = stateConnected
	// Discard reads post-handshake messages without a buffer, so wipe the handshake buffer.
	h.hs.zeroize()
	clear(h.cfg.HandshakeBuf)
	h.hr.Reset(nil)
	return nil
}

func (h *handler) recvAlert(content []byte) error {
	if len(content) != 2 {
		return alertError(tlsraw.AlertDecodeError)
	}
	switch desc := tlsraw.AlertDescription(content[1]); desc {
	case tlsraw.AlertCloseNotify:
		h.peerClosed = true
		return nil
	case tlsraw.AlertUserCanceled:
		return nil
	default:
		return peerAlertError(desc)
	}
}

// encoder moves unsent output to the front of the write buffer and returns an
// encoder that appends after it.
func (h *handler) encoder() tlsraw.Encoder {
	if h.sent > 0 {
		h.queued = copy(h.cfg.WriteBuf, h.cfg.WriteBuf[h.sent:h.queued])
		h.sent = 0
	}
	var e tlsraw.Encoder
	e.Reset(h.cfg.WriteBuf, h.queued)
	return e
}

// commit queues what e encoded, or nothing if e failed.
func (h *handler) commit(e *tlsraw.Encoder) error {
	if err := e.Err(); err != nil {
		return err
	}
	h.queued = e.Len()
	return nil
}

func (h *handler) queueRecord(ct tlsraw.ContentType, content []byte) error {
	e := h.encoder()
	rec := e.StartRecord(ct)
	e.Bytes(content)
	if h.keys.out.HasKeys() {
		e.SealRecord(&h.keys.out, rec, ct)
	} else {
		e.EndRecord(rec)
	}
	return h.commit(&e)
}

func (h *handler) queueAlert(desc tlsraw.AlertDescription) error {
	level := tlsraw.AlertLevelFatal
	if desc == tlsraw.AlertCloseNotify {
		level = tlsraw.AlertLevelWarning
	}
	alert := [2]byte{byte(level), byte(desc)}
	return h.queueRecord(tlsraw.ContentTypeAlert, alert[:])
}

// fail sends the alert for err, wipes secrets and marks c unusable.
func (h *handler) fail(err error) error {
	switch a := err.(type) {
	case peerAlertError:
	case alertError:
		h.queueAlert(tlsraw.AlertDescription(a))
	case verifyError:
		h.queueAlert(tlsraw.AlertBadCertificate)
	default:
		if err == errHelloRetry {
			h.queueAlert(tlsraw.AlertHandshakeFailure)
		} else if err != io.EOF && err != io.ErrUnexpectedEOF {
			h.queueAlert(tlsraw.AlertInternalError)
		}
	}
	h.wipeSecrets()
	h.state = stateFailed
	return err
}
