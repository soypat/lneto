//go:build tinygo

package internet

import "github.com/soypat/lneto"

func makecbnode(s lneto.StackNode) cbnode {
	return cbnode{
		_demux:        s.Demux,
		_encapsulate:  s.Encapsulate,
		_nextDeadline: s.NextDeadline,
	}
}

type cbnode struct {
	// Do not access outside of handlers/node logic.
	_demux func([]byte, int) error
	// Do not access outside of handlers/node logic.
	_encapsulate func([]byte, int, int) (int, error)
	// Do not access outside of handlers/node logic.
	_nextDeadline func() int64
}

func (s *cbnode) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	return s._encapsulate(carrierData, offsetToIP, offsetToFrame)
}

func (s *cbnode) Demux(carrierData []byte, frameOffset int) error {
	debugLog("cbnode:pre-demux")
	return s._demux(carrierData, frameOffset)
}

func (s *cbnode) NextDeadline() int64 {
	return s._nextDeadline()
}

func (s cbnode) IsZeroed() bool {
	return s._demux == nil || s._encapsulate == nil
}
