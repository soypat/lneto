//go:build tinygo

package internet

func makecbnode(s StackNode) cbnode {
	return cbnode{
		demux:       s.Demux,
		encapsulate: s.Encapsulate,
	}
}

type cbnode struct {
	// Do not access outside of handlers/node logic.
	demux func([]byte, int) error
	// Do not access outside of handlers/node logic.
	encapsulate func([]byte, int, int) (int, error)
}

func (s *cbnode) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	return s.encapsulate(carrierData, offsetToIP, offsetToFrame)
}

func (s *cbnode) Demux(carrierData []byte, frameOffset int) error {
	return s.demux(carrierData, frameOffset)
}

func (s cbnode) IsZeroed() bool {
	return s.demux == nil || s.encapsulate == nil
}
