//go:build !tinygo

package internet

import "github.com/soypat/lneto"

func makecbnode(s lneto.StackNode) cbnode {
	return cbnode{
		_s: s,
	}
}

type cbnode struct {
	// Do not access outside of handlers/node logic.
	_s lneto.StackNode
}

func (s cbnode) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	return s._s.Encapsulate(carrierData, offsetToIP, offsetToFrame)
}

func (s cbnode) Demux(carrierData []byte, frameOffset int) error {
	return s._s.Demux(carrierData, frameOffset)
}

func (s cbnode) IsZeroed() bool {
	return s._s == nil
}
