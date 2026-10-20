//go:build tinygo

package nts

import (
	"crypto/tls"

	"github.com/soypat/lneto"
)

// exportKeyingMaterial fails: TinyGo's crypto/tls has no ExportKeyingMaterial,
// so keys must be derived elsewhere and passed in [ClientConfig].
func exportKeyingMaterial(cs *tls.ConnectionState, label string, context []byte, length int) ([]byte, error) {
	return nil, lneto.ErrUnsupported
}
