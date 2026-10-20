//go:build !tinygo

package nts

import "crypto/tls"

func exportKeyingMaterial(cs *tls.ConnectionState, label string, context []byte, length int) ([]byte, error) {
	return cs.ExportKeyingMaterial(label, context, length)
}
