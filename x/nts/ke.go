package nts

import (
	"crypto/tls"
	"encoding/binary"
	"io"

	"github.com/soypat/lneto"
)

// KERecord provides zero-copy access to a single NTS-KE record within an
// existing buffer.  The wire format is (RFC 8915 §4.1.2):
//
//	[C(1b) | RecordType(15b) BE uint16] [BodyLen BE uint16] [Body…]
type KERecord struct {
	buf []byte
}

// NewKERecord wraps buf as a KERecord.  Returns [lneto.ErrTruncatedFrame] if
// buf is shorter than the 4-byte header plus the declared body length.
func NewKERecord(buf []byte) (KERecord, error) {
	if len(buf) < 4 {
		return KERecord{}, lneto.ErrTruncatedFrame
	}
	bodyLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if 4+bodyLen > len(buf) {
		return KERecord{}, lneto.ErrTruncatedFrame
	}
	return KERecord{buf: buf[:4+bodyLen]}, nil
}

// RecordType returns the record type (lower 15 bits of the first two bytes).
func (r KERecord) RecordType() KERecordType {
	return KERecordType(binary.BigEndian.Uint16(r.buf[0:2]) & 0x7FFF)
}

// IsCritical reports whether the Critical bit (bit 15 of the type field) is set.
func (r KERecord) IsCritical() bool {
	return r.buf[0]&0x80 != 0
}

// BodyLen returns the declared body length in bytes.
func (r KERecord) BodyLen() uint16 {
	return binary.BigEndian.Uint16(r.buf[2:4])
}

// Body returns the record body bytes (excludes the 4-byte header).
func (r KERecord) Body() []byte {
	return r.buf[4 : 4+r.BodyLen()]
}

// RawData returns the complete record bytes including the 4-byte header.
func (r KERecord) RawData() []byte { return r.buf }

// ValidateSize adds an error to v if the record is structurally invalid.
func (r KERecord) ValidateSize(v *lneto.Validator) {
	if len(r.buf) < 4 {
		v.AddError(lneto.ErrTruncatedFrame)
		return
	}
	if 4+int(r.BodyLen()) > len(r.buf) {
		v.AddError(lneto.ErrMismatchLen)
	}
}

// AppendKERecord appends a single NTS-KE record to dst and returns the result.
func AppendKERecord(dst []byte, critical bool, typ KERecordType, body []byte) []byte {
	var hdr [4]byte
	typeField := uint16(typ)
	if critical {
		typeField |= 0x8000
	}
	binary.BigEndian.PutUint16(hdr[0:2], typeField)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, body...)
	return dst
}

// KEConfig configures a [PerformKE] call.
type KEConfig struct {
	OfferedAlgorithms [4]AEADAlgorithmID
	NumAlgorithms     int
	Scratch           []byte
}

// KESecrets holds all material produced by a successful NTS-KE exchange.
// All fields are fixed-size arrays to avoid heap allocation.
type KESecrets struct {
	C2SKey     [32]byte
	S2CKey     [32]byte
	Cookies    [MaxCookies][MaxCookieLen]byte
	CookieLens [MaxCookies]int
	NumCookies int
	ChosenAlg  AEADAlgorithmID
	NTPAddr    [64]byte
	NTPAddrLen int
	NTPPort    uint16
}

// PerformKE runs the NTS Key Exchange protocol over an already-established
// TLS 1.3 connection.  The connection MUST be configured with:
//   - MinVersion: tls.VersionTLS13
//   - ALPN: "ntske/1"
//
// On success the returned [KESecrets] contains the C2S/S2C keys, cookies,
// and optional NTP server address.  The caller should close the connection
// after PerformKE returns; it is not used for NTP traffic.
func PerformKE(conn *tls.Conn, cfg KEConfig) (KESecrets, error) {
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		return KESecrets{}, lneto.ErrInvalidConfig
	}
	if err := sendKERequest(conn, cfg); err != nil {
		return KESecrets{}, err
	}
	secrets, err := readKEResponse(conn, cfg.Scratch)
	if err != nil {
		return secrets, err
	}
	if err := DeriveKeys(conn, &secrets); err != nil {
		return secrets, err
	}
	return secrets, nil
}

func sendKERequest(w io.Writer, cfg KEConfig) error {
	numAlg := cfg.NumAlgorithms
	if numAlg == 0 {
		numAlg = 1
		cfg.OfferedAlgorithms[0] = AlgAESSIVCMAC256
	}

	var proto [2]byte
	binary.BigEndian.PutUint16(proto[:], ntpv4ProtocolID)
	var buf []byte
	buf = AppendKERecord(buf, true, RecordNextProtoNeg, proto[:])

	algBody := make([]byte, numAlg*2)
	for i := 0; i < numAlg; i++ {
		binary.BigEndian.PutUint16(algBody[i*2:], uint16(cfg.OfferedAlgorithms[i]))
	}
	buf = AppendKERecord(buf, true, RecordAEADAlgNeg, algBody)
	buf = AppendKERecord(buf, true, RecordEndOfMessage, nil)
	_, err := w.Write(buf)
	return err
}

func readKEResponse(r io.Reader, scratch []byte) (KESecrets, error) {
	if cap(scratch) < 4096 {
		scratch = make([]byte, 4096)
	}
	scratch = scratch[:cap(scratch)]

	var secrets KESecrets
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return secrets, err
		}
		bodyLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		recType := KERecordType(binary.BigEndian.Uint16(hdr[0:2]) & 0x7FFF)
		critical := hdr[0]&0x80 != 0

		var body []byte
		if bodyLen > 0 {
			if bodyLen > len(scratch) {
				scratch = make([]byte, bodyLen)
			}
			body = scratch[:bodyLen]
			if _, err := io.ReadFull(r, body); err != nil {
				return secrets, err
			}
		}

		switch recType {
		case RecordEndOfMessage:
			if secrets.ChosenAlg == 0 {
				return secrets, lneto.ErrInvalidConfig
			}
			return secrets, nil

		case RecordError:
			return secrets, lneto.ErrInvalidField

		case RecordNextProtoNeg:
			// Mandatory in every response (RFC 8915 §4.1.2). Verify it
			// indicates NTPv4 (protocol ID 0).
			if len(body) >= 2 {
				proto := binary.BigEndian.Uint16(body[:2])
				if proto != ntpv4ProtocolID {
					return secrets, lneto.ErrUnsupported
				}
			}

		case RecordAEADAlgNeg:
			if len(body) >= 2 {
				secrets.ChosenAlg = AEADAlgorithmID(binary.BigEndian.Uint16(body[:2]))
			}

		case RecordNewCookie:
			if secrets.NumCookies < MaxCookies && len(body) <= MaxCookieLen {
				i := secrets.NumCookies
				copy(secrets.Cookies[i][:], body)
				secrets.CookieLens[i] = len(body)
				secrets.NumCookies++
			}

		case RecordNTPv4Server:
			n := len(body)
			if n > len(secrets.NTPAddr) {
				n = len(secrets.NTPAddr)
			}
			copy(secrets.NTPAddr[:], body[:n])
			secrets.NTPAddrLen = n

		case RecordNTPv4Port:
			if len(body) >= 2 {
				secrets.NTPPort = binary.BigEndian.Uint16(body[:2])
			}

		default:
			if critical {
				return secrets, lneto.ErrUnsupported
			}
		}
	}
}

// DeriveKeys fills secrets.C2SKey and secrets.S2CKey by exporting keying
// material from the TLS connection per RFC 8915 §4.2.  Two separate
// ExportKeyingMaterial calls are made with 5-byte contexts:
//
//	C2S context: [0x00, 0x00, algID_hi, algID_lo, 0x00]
//	S2C context: [0x00, 0x00, algID_hi, algID_lo, 0x01]
//
// This is called automatically by [PerformKE]; expose it for callers
// that manage the TLS handshake themselves.
func DeriveKeys(conn *tls.Conn, secrets *KESecrets) error {
	cs := conn.ConnectionState()
	const label = "EXPORTER-network-time-security"
	var ctx [5]byte
	binary.BigEndian.PutUint16(ctx[2:4], uint16(secrets.ChosenAlg))

	// C2S key: context byte 4 = 0x00.
	ctx[4] = 0x00
	c2s, err := cs.ExportKeyingMaterial(label, ctx[:], 32)
	if err != nil {
		return err
	}
	copy(secrets.C2SKey[:], c2s)

	// S2C key: context byte 4 = 0x01.
	ctx[4] = 0x01
	s2c, err := cs.ExportKeyingMaterial(label, ctx[:], 32)
	if err != nil {
		return err
	}
	copy(secrets.S2CKey[:], s2c)
	return nil
}
