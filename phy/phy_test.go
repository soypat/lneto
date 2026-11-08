package phy_test

import (
	"errors"
	"testing"

	"github.com/soypat/lneto/phy"
)

var errBus = errors.New("mdio bus error")

// faultyBus is a Clause 22 register file whose failRead'th Read call (1-indexed) fails returning failValue.
type faultyBus struct {
	regs      [32]uint16
	nread     int
	failRead  int
	failValue uint16
}

func (b *faultyBus) Read(phyAddr, devAddr uint8, regAddr uint16) (uint16, error) {
	b.nread++
	if b.nread == b.failRead {
		return b.failValue, errBus
	}
	return b.regs[regAddr&31], nil
}

func (b *faultyBus) Write(phyAddr, devAddr uint8, regAddr, value uint16) error {
	b.regs[regAddr&31] = value
	return nil
}

func TestEnableAutoNegotiationVerifyReadError(t *testing.T) {
	tests := []struct {
		name      string
		enable    bool
		failValue uint16
	}{
		{name: "enable-floating-bus", enable: true, failValue: 0xffff},
		{name: "disable-zero-read", enable: false, failValue: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bus := &faultyBus{failRead: 2, failValue: tc.failValue} // Fail verify read after write.
			var dev phy.Device
			err := dev.ConfigureAs22(bus, 1)
			if err != nil {
				t.Fatal(err)
			}
			err = dev.EnableAutoNegotiation(tc.enable)
			if !errors.Is(err, errBus) {
				t.Fatalf("want bus error, got %v", err)
			}
		})
	}
}
