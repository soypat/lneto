//go:build tinygo

package internet

func makecbnode(s StackNode) cbnode {
	return cbnode{
		_demux:       s.Demux,
		_encapsulate: s.Encapsulate,
	}
}

type cbnode struct {
	// Do not access outside of handlers/node logic.
	_demux func([]byte, int) error
	// Do not access outside of handlers/node logic.
	_encapsulate func([]byte, int, int) (int, error)
}

func (s *cbnode) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	return s._encapsulate(carrierData, offsetToIP, offsetToFrame)
}

func (s *cbnode) Demux(carrierData []byte, frameOffset int) error {
	return s._demux(carrierData, frameOffset)
}

func (s cbnode) IsZeroed() bool {
	return s._demux == nil || s._encapsulate == nil
}
