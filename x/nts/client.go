package nts

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ntp"
)

// maxAuthBody is the maximum auth field body size:
// 4-byte header (NonceLen + CtLen) + maxNonceLen + 32-byte max AEAD overhead.
const maxAuthBody = 4 + maxNonceLen + 32

// minCarrierRoom is the minimum extra bytes beyond NTP header that
// carrierData must have for an NTS request. The cookie can be at most
// MaxCookieLen bytes; the auth body at most maxAuthBody bytes, each wrapped
// in a 4-byte ext-field header.
const minCarrierRoom = ntp.SizeHeader + (4 + 32) + (4 + MaxCookieLen) + (4 + maxAuthBody + 3)

// ClientConfig configures an NTS [Client].
type ClientConfig struct {
	C2S, S2C   cipher.AEAD
	ChosenAlg  AEADAlgorithmID
	Rand       io.Reader
	Now        func() time.Time
	Sysprec    int8
	Cookies    [MaxCookies][MaxCookieLen]byte
	CookieLens [MaxCookies]int
	NumCookies int
}

// Client is a stateful NTS-capable NTP client implementing [lneto.StackNode].
// It wraps an [ntp.Client] and injects/validates NTS extension fields.
//
// Client is not safe for concurrent use.
type Client struct {
	connID     uint64
	cfg        ClientConfig
	ntpState   ntp.Client
	uniqueID   [32]byte
	nonce      [maxNonceLen]byte
	cookies    [MaxCookies][MaxCookieLen]byte
	cookieLens [MaxCookies]int
	numCookies int
}

// Reset re-initialises the client with cfg.  May be called again after
// a fresh [PerformKE] to refresh cookies without losing connID.
func (c *Client) Reset(cfg ClientConfig) error {
	if cfg.C2S == nil || cfg.S2C == nil {
		return lneto.ErrInvalidConfig
	}
	if cfg.C2S.NonceSize() > maxNonceLen || cfg.S2C.NonceSize() > maxNonceLen {
		return lneto.ErrInvalidConfig
	}
	if cfg.NumCookies <= 0 {
		return lneto.ErrInvalidConfig
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ChosenAlg == 0 {
		cfg.ChosenAlg = AlgAESSIVCMAC256
	}
	*c = Client{
		connID:     c.connID + 1,
		cfg:        cfg,
		cookies:    cfg.Cookies,
		cookieLens: cfg.CookieLens,
		numCookies: cfg.NumCookies,
	}
	c.ntpState.Reset(cfg.Sysprec, cfg.Now)
	return nil
}

// ConnectionID implements [lneto.StackNode].
func (c *Client) ConnectionID() *uint64 { return &c.connID }

// Protocol implements [lneto.StackNode].
func (c *Client) Protocol() uint64 { return uint64(ntp.ServerPort) }

// LocalPort implements [lneto.StackNode].
func (c *Client) LocalPort() uint16 { return c.ntpState.LocalPort() }

// IsDone reports whether both NTP exchanges completed.
func (c *Client) IsDone() bool { return c.ntpState.IsDone() }

// Offset returns the averaged clock offset after both exchanges (zero before).
func (c *Client) Offset() time.Duration { return c.ntpState.Offset() }

// RoundTripDelay returns the averaged RTD (-1 before done).
func (c *Client) RoundTripDelay() time.Duration { return c.ntpState.RoundTripDelay() }

// Now returns the NTS-corrected current time (local time before done).
func (c *Client) Now() time.Time { return c.ntpState.Now() }

// Encapsulate implements [lneto.StackNode].
//
// carrierData must have at least [minCarrierRoom] bytes available starting at
// offsetToFrame; otherwise [lneto.ErrShortBuffer] is returned.
func (c *Client) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if c.numCookies == 0 {
		return 0, lneto.ErrExhausted
	}
	if len(carrierData)-offsetToFrame < minCarrierRoom {
		return 0, lneto.ErrShortBuffer
	}

	n, err := c.ntpState.Encapsulate(carrierData, offsetToIP, offsetToFrame)
	if err != nil || n == 0 {
		return n, err
	}

	// buf is a view into carrierData starting at offsetToFrame.
	// Appending to buf writes into carrierData's backing array because we
	// verified capacity above; no reallocation will occur.
	buf := carrierData[offsetToFrame : offsetToFrame+n]

	// UniqueID: 32 random bytes.
	if _, err = io.ReadFull(c.cfg.Rand, c.uniqueID[:]); err != nil {
		return 0, err
	}
	buf = ntp.AppendExtField(buf, ntp.ExtNTSUniqueID, c.uniqueID[:])

	// Cookie: pop one from the pool.
	ci := c.numCookies - 1
	buf = ntp.AppendExtField(buf, ntp.ExtNTSCookie, c.cookies[ci][:c.cookieLens[ci]])
	c.numCookies--

	// NTS-Authenticator-and-EEF (RFC 8915 §5.6).
	// Body = [nonceLen(2)] [ctLen(2)] [nonce(N)] [ciphertext(M)]
	// For a client request there is no EEF, so plaintext is empty and M = AEAD overhead.
	nonceLen := c.cfg.C2S.NonceSize()
	overhead := c.cfg.C2S.Overhead()
	if _, err = io.ReadFull(c.cfg.Rand, c.nonce[:nonceLen]); err != nil {
		return 0, err
	}

	// aad = all packet bytes written so far (header + UniqueID + Cookie).
	aad := buf

	// Build auth body in a stack-allocated buffer to avoid heap allocation.
	var authBody [maxAuthBody]byte
	binary.BigEndian.PutUint16(authBody[0:2], uint16(nonceLen))
	binary.BigEndian.PutUint16(authBody[2:4], uint16(overhead))
	copy(authBody[4:4+nonceLen], c.nonce[:nonceLen])

	// Seal computes the authentication tag for empty plaintext.
	// The tag is appended into authBody[4+nonceLen:].
	tag := c.cfg.C2S.Seal(authBody[4+nonceLen:4+nonceLen], c.nonce[:nonceLen], nil, aad)
	if len(tag) != overhead {
		return 0, lneto.ErrBug
	}

	buf = ntp.AppendExtField(buf, ntp.ExtNTSAuthAndEEF, authBody[:4+nonceLen+overhead])
	return len(buf), nil
}

// Demux implements [lneto.StackNode].
func (c *Client) Demux(carrierData []byte, frameOffset int) error {
	frame, err := ntp.NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	payload := frame.Payload()
	if len(payload) == 0 {
		return lneto.ErrMismatch
	}

	// RFC 8915 §5.7: verify the response carries the same UniqueID we sent.
	if err = c.verifyUniqueID(payload); err != nil {
		return err
	}

	authOffset, authField, err := findAuthField(payload)
	if err != nil {
		return err
	}
	body := authField.Value()
	if len(body) < 4 {
		return lneto.ErrTruncatedFrame
	}

	// Parse auth body header (RFC 8915 §5.6).
	nonceLen := int(binary.BigEndian.Uint16(body[0:2]))
	ctLen := int(binary.BigEndian.Uint16(body[2:4]))
	if len(body) < 4+nonceLen+ctLen {
		return lneto.ErrTruncatedFrame
	}
	nonce := body[4 : 4+nonceLen]
	ciphertext := body[4+nonceLen : 4+nonceLen+ctLen]

	// aad = everything from the NTP header start up to (not including) the auth field.
	aadEnd := frameOffset + ntp.SizeHeader + authOffset
	aad := carrierData[frameOffset:aadEnd]

	plaintext, openErr := c.cfg.S2C.Open(nil, nonce, ciphertext, aad)
	if openErr != nil {
		return lneto.ErrBadCRC
	}

	c.ingestAuthPayload(plaintext)
	return c.ntpState.Demux(carrierData, frameOffset)
}

// verifyUniqueID scans extension fields in payload for the NTS UniqueID
// field and verifies it matches the one sent in the request (RFC 8915 §5.7).
func (c *Client) verifyUniqueID(payload []byte) error {
	buf := payload
	for {
		field, rest, err := ntp.NextExtField(buf)
		if err != nil || len(field.RawData()) == 0 {
			return lneto.ErrMismatch // UniqueID not found
		}
		if field.Type() == ntp.ExtNTSUniqueID {
			v := field.Value()
			if len(v) != len(c.uniqueID) {
				return lneto.ErrMismatchLen
			}
			for i := range c.uniqueID {
				if v[i] != c.uniqueID[i] {
					return lneto.ErrMismatch
				}
			}
			return nil
		}
		buf = rest
	}
}

// findAuthField iterates extension fields in payload and returns the byte
// offset of the NTSAuthAndEEF field within payload, plus the field itself.
func findAuthField(payload []byte) (offsetInPayload int, auth ntp.ExtField, err error) {
	scanned := 0
	buf := payload
	for {
		field, rest, e := ntp.NextExtField(buf)
		if e != nil {
			return 0, ntp.ExtField{}, e
		}
		if len(field.RawData()) == 0 {
			return 0, ntp.ExtField{}, lneto.ErrMismatch
		}
		if field.Type() == ntp.ExtNTSAuthAndEEF {
			return scanned, field, nil
		}
		scanned += len(field.RawData())
		buf = rest
	}
}

// ingestAuthPayload extracts NTS-Cookie fields from the authenticated EEF
// payload and adds them to the cookie pool (up to MaxCookies).
func (c *Client) ingestAuthPayload(payload []byte) {
	buf := payload
	for {
		field, rest, err := ntp.NextExtField(buf)
		if err != nil || len(field.RawData()) == 0 {
			return
		}
		if field.Type() == ntp.ExtNTSCookie && c.numCookies < MaxCookies {
			v := field.Value()
			if len(v) <= MaxCookieLen {
				i := c.numCookies
				copy(c.cookies[i][:], v)
				c.cookieLens[i] = len(v)
				c.numCookies++
			}
		}
		buf = rest
	}
}
