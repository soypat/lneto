package main

import (
	"math/rand"
	"time"

	"github.com/soypat/lneto/ethernet"
)

func init() {
	mn := &mockNetwork{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	network = mn
}

type mockNetwork struct {
	rng *rand.Rand
}

func (m *mockNetwork) SendEth(frame []byte) error {
	return nil
}
func (m *mockNetwork) RecvEth(dst []byte) (int, error) {
	n := m.rng.Int() % ethernet.MaxFrameLength
	if n < ethernet.MinimumFrameLength {
		return 0, nil
	}
	n, _ = m.rng.Read(dst[:min(len(dst), n)])
	return n, nil
}
func (m *mockNetwork) HardwareAddress6() ([6]byte, error) {
	return [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00}, nil
}
func (m *mockNetwork) MaxFrameLength() (int, error) {
	return ethernet.MaxFrameLength, nil
}
