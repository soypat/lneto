package nts

import (
	"crypto/tls"
	"encoding/binary"
	"io"

	"github.com/soypat/lneto"
)

// KEServerConfig configures [HandleKE].
type KEServerConfig struct {
	SupportedAlgorithms [4]AEADAlgorithmID
	NumAlgorithms       int
	Cookies             [][]byte
}

// HandleKE runs the server side of the NTS Key Exchange protocol over an
// already-established TLS 1.3 connection. It reads the client's request,
// negotiates algorithm and protocol, sends cookies, and derives keys.
//
// The returned [KESecrets] contains the negotiated algorithm and derived
// C2S/S2C keys matching the client's view.
func HandleKE(conn *tls.Conn, cfg KEServerConfig) (KESecrets, error) {
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		return KESecrets{}, lneto.ErrInvalidConfig
	}
	numAlg := cfg.NumAlgorithms
	if numAlg == 0 {
		numAlg = 1
		cfg.SupportedAlgorithms[0] = AlgAESSIVCMAC256
	}

	clientAlg, err := readKERequest(conn)
	if err != nil {
		return KESecrets{}, err
	}

	chosen := negotiateAlg(clientAlg, cfg.SupportedAlgorithms[:numAlg])
	if chosen == 0 {
		errBody := make([]byte, 2)
		binary.BigEndian.PutUint16(errBody, 0) // unrecognized critical record
		var resp []byte
		resp = AppendKERecord(resp, true, RecordError, errBody)
		resp = AppendKERecord(resp, true, RecordEndOfMessage, nil)
		conn.Write(resp)
		return KESecrets{}, lneto.ErrUnsupported
	}

	var secrets KESecrets
	secrets.ChosenAlg = chosen
	if err := sendKEResponse(conn, chosen, cfg.Cookies); err != nil {
		return secrets, err
	}

	for i, c := range cfg.Cookies {
		if i >= MaxCookies {
			break
		}
		n := len(c)
		if n > MaxCookieLen {
			n = MaxCookieLen
		}
		copy(secrets.Cookies[i][:], c[:n])
		secrets.CookieLens[i] = n
		secrets.NumCookies++
	}

	if err := DeriveKeys(conn, &secrets); err != nil {
		return secrets, err
	}
	return secrets, nil
}

// maxKERecordBody is the maximum body length accepted for a single NTS-KE
// record. Real records are tiny; this guards against malicious inputs.
const maxKERecordBody = 1024

// readKERequest reads the client NTS-KE request and returns the offered AEAD
// algorithms. It consumes records until EndOfMessage.
func readKERequest(r io.Reader) (offered []AEADAlgorithmID, err error) {
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		bodyLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		recType := KERecordType(binary.BigEndian.Uint16(hdr[0:2]) & 0x7FFF)

		if bodyLen > maxKERecordBody {
			return nil, lneto.ErrInvalidLengthField
		}
		var body []byte
		if bodyLen > 0 {
			body = make([]byte, bodyLen)
			if _, err := io.ReadFull(r, body); err != nil {
				return nil, err
			}
		}

		switch recType {
		case RecordEndOfMessage:
			return offered, nil
		case RecordAEADAlgNeg:
			for i := 0; i+1 < len(body); i += 2 {
				offered = append(offered, AEADAlgorithmID(binary.BigEndian.Uint16(body[i:i+2])))
			}
		case RecordNextProtoNeg:
			if len(body) >= 2 {
				proto := binary.BigEndian.Uint16(body[:2])
				if proto != ntpv4ProtocolID {
					return nil, lneto.ErrUnsupported
				}
			}
		}
	}
}

func negotiateAlg(clientOffered []AEADAlgorithmID, serverSupported []AEADAlgorithmID) AEADAlgorithmID {
	for _, c := range clientOffered {
		for _, s := range serverSupported {
			if c == s {
				return c
			}
		}
	}
	return 0
}

func sendKEResponse(w io.Writer, chosen AEADAlgorithmID, cookies [][]byte) error {
	var proto [2]byte
	binary.BigEndian.PutUint16(proto[:], ntpv4ProtocolID)
	var buf []byte
	buf = AppendKERecord(buf, true, RecordNextProtoNeg, proto[:])

	var algBody [2]byte
	binary.BigEndian.PutUint16(algBody[:], uint16(chosen))
	buf = AppendKERecord(buf, true, RecordAEADAlgNeg, algBody[:])

	for _, c := range cookies {
		buf = AppendKERecord(buf, false, RecordNewCookie, c)
	}

	buf = AppendKERecord(buf, true, RecordEndOfMessage, nil)
	_, err := w.Write(buf)
	return err
}
