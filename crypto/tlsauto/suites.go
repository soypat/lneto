package tlsauto

import (
	"hash"

	"github.com/soypat/lneto/crypto/internal/lcrypto"
	"github.com/soypat/lneto/crypto/tlsraw"
)

// Aliases so users outside lneto can name the interfaces of the internal lcrypto package.
type (
	AEADCipher = lcrypto.AEADCipher
	Exchanger  = lcrypto.Exchanger
	Credential = lcrypto.Credential
	Verifier   = lcrypto.Verifier
	CertChain  = lcrypto.CertChain
)

// Suite is a TLS 1.3 cipher suite, RFC 8446 B.4.
type Suite struct {
	ID      uint16
	KeyLen  int
	NewAEAD func() lcrypto.AEADCipher
	// NewHash must return a new instance on every call.
	NewHash func() hash.Hash
}

// KeyExchange is a key share group, RFC 8446 4.2.8.
type KeyExchange struct {
	ID             uint16
	ClientShareLen int
	ServerShareLen int
	SharedLen      int
	NewExchanger   func() lcrypto.Exchanger
}

// DefaultSchemes are the signature schemes offered when Config.Schemes is empty.
var DefaultSchemes = []uint16{
	uint16(tlsraw.SigECDSAP256SHA256),
	uint16(tlsraw.SigEd25519),
	uint16(tlsraw.SigECDSAP384SHA384),
	uint16(tlsraw.SigRSAPSSRSAESHA256),
	uint16(tlsraw.SigRSAPSSRSAESHA384),
	uint16(tlsraw.SigRSAPSSRSAESHA512),
}
