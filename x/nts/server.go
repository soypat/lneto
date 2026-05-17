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

// ServerConfig configures an NTS [Server].
type ServerConfig struct {
	C2S, S2C cipher.AEAD
	Rand     io.Reader
	Now      func() time.Time
	Stratum  ntp.Stratum
	Prec     int8
	RefID    [4]byte
	// MakeCookie is called during Encapsulate to generate a fresh cookie for
	// the response's encrypted extension fields. If nil, no new cookie is sent.
	MakeCookie func() []byte
}

// Server is a stateful NTS-capable NTP server implementing [lneto.StackNode].
// It wraps an [ntp.Server] and validates/builds NTS extension fields.
//
// Server is not safe for concurrent use.
type Server struct {
	connID   uint64
	cfg      ServerConfig
	ntpState ntp.Server
	nonce    [maxNonceLen]byte
	// pending stores extension data from the last Demux needed for Encapsulate.
	pending    [1]pendingNTS
	hasPending bool
}

type pendingNTS struct {
	uniqueID [32]byte
	uidLen   int
}

// Reset re-initialises the server with cfg.
func (s *Server) Reset(cfg ServerConfig) error {
	if cfg.C2S == nil || cfg.S2C == nil {
		return lneto.ErrInvalidConfig
	}
	if cfg.C2S.NonceSize() > maxNonceLen || cfg.S2C.NonceSize() > maxNonceLen {
		return lneto.ErrInvalidConfig
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	prevConnID := s.connID
	*s = Server{
		connID: prevConnID,
		cfg:    cfg,
	}
	if err := s.ntpState.Reset(ntp.ServerConfig{
		Now:       cfg.Now,
		Stratum:   cfg.Stratum,
		Precision: cfg.Prec,
		RefID:     cfg.RefID,
	}); err != nil {
		return err
	}
	s.connID = prevConnID + 1
	return nil
}

// ConnectionID implements [lneto.StackNode].
func (s *Server) ConnectionID() *uint64 { return &s.connID }

// Protocol implements [lneto.StackNode].
func (s *Server) Protocol() uint64 { return uint64(ntp.ServerPort) }

// LocalPort implements [lneto.StackNode].
func (s *Server) LocalPort() uint16 { return ntp.ServerPort }

// Demux implements [lneto.StackNode]. It verifies the NTS authentication on
// an incoming client request and queues the underlying NTP request.
func (s *Server) Demux(carrierData []byte, frameOffset int) error {
	frame, err := ntp.NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	payload := frame.ExtensionFields()
	if len(payload) == 0 {
		return lneto.ErrMismatch
	}

	// Extract UniqueID for echoing in the response.
	var p pendingNTS
	for off := 0; off < len(payload); {
		field, n, e := ntp.NextExtField(payload[off:])
		if e != nil || len(field.RawData()) == 0 {
			break
		}
		if field.Type() == ntp.ExtNTSUniqueID {
			v := field.Value()
			vn := min(len(v), len(p.uniqueID))
			copy(p.uniqueID[:], v[:vn])
			p.uidLen = vn
		}
		off += n
	}

	// Find and verify the NTS authenticator.
	authOffset, authField, err := findAuthField(payload)
	if err != nil {
		return err
	}
	body := authField.Value()
	if len(body) < 4 {
		return lneto.ErrTruncatedFrame
	}
	nonceLen := int(binary.BigEndian.Uint16(body[0:2]))
	ctLen := int(binary.BigEndian.Uint16(body[2:4]))
	if len(body) < 4+nonceLen+ctLen {
		return lneto.ErrTruncatedFrame
	}
	nonce := body[4 : 4+nonceLen]
	ciphertext := body[4+nonceLen : 4+nonceLen+ctLen]

	aadEnd := frameOffset + ntp.SizeHeader + authOffset
	aad := carrierData[frameOffset:aadEnd]

	if _, err := s.cfg.C2S.Open(nil, nonce, ciphertext, aad); err != nil {
		return lneto.ErrBadCRC
	}

	// Authentication passed; queue the NTP request.
	if err := s.ntpState.Demux(carrierData, frameOffset); err != nil {
		return err
	}
	s.pending[0] = p
	s.hasPending = true
	return nil
}

// minServerCarrierRoom is the minimum extra bytes beyond NTP header that
// carrierData must have for an NTS server response.
const minServerCarrierRoom = ntp.SizeHeader + (4 + 32) + (4 + maxAuthBody + 3)

// Encapsulate implements [lneto.StackNode]. It builds an NTS-authenticated
// NTP server response.
func (s *Server) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if !s.hasPending {
		return 0, nil
	}
	if len(carrierData)-offsetToFrame < minServerCarrierRoom {
		return 0, lneto.ErrShortBuffer
	}

	n, err := s.ntpState.Encapsulate(carrierData, offsetToIP, offsetToFrame)
	if err != nil || n == 0 {
		return n, err
	}

	buf := carrierData[offsetToFrame : offsetToFrame+n : len(carrierData)]

	// Echo UniqueID.
	p := s.pending[0]
	if p.uidLen > 0 {
		buf = ntp.AppendExtField(buf, ntp.ExtNTSUniqueID, p.uniqueID[:p.uidLen])
	}

	// AAD is everything up to (not including) the auth field we're about to write.
	aad := buf

	// Build auth body with optional encrypted cookie.
	nonceLen := s.cfg.S2C.NonceSize()
	overhead := s.cfg.S2C.Overhead()
	if _, err = io.ReadFull(s.cfg.Rand, s.nonce[:nonceLen]); err != nil {
		return 0, err
	}

	var plaintext []byte
	if s.cfg.MakeCookie != nil {
		cookie := s.cfg.MakeCookie()
		if len(cookie) > 0 {
			plaintext = ntp.AppendExtField(nil, ntp.ExtNTSCookie, cookie)
		}
	}

	var authBody [maxAuthBody + 512]byte
	binary.BigEndian.PutUint16(authBody[0:2], uint16(nonceLen))
	binary.BigEndian.PutUint16(authBody[2:4], uint16(len(plaintext)+overhead))
	copy(authBody[4:4+nonceLen], s.nonce[:nonceLen])

	sealed := s.cfg.S2C.Seal(authBody[4+nonceLen:4+nonceLen], s.nonce[:nonceLen], plaintext, aad)
	totalAuth := 4 + nonceLen + len(sealed)

	buf = ntp.AppendExtField(buf, ntp.ExtNTSAuthAndEEF, authBody[:totalAuth])
	s.hasPending = false
	return len(buf), nil
}
