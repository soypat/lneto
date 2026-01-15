// Package phy provides Ethernet PHY management via MDIO.
// It supports IEEE 802.3 Clause 22 and Clause 45 register access
// for configuring and monitoring physical layer transceivers.
package phy

import (
	"errors"
	"time"
)

// FindPHYs finds all regular non-clause45 PHYs on the MDIO bus and writes them to dst.
func FindPHYs(mdio MDIOBus, dst []uint8) (n int, err error) {
	const maxAddr = 31
	const regBasicStatus = 0x01
	if len(dst) < 32 {
		return -1, errors.New("require buffer length 32 for FindPHYs")
	}
	n = 0
	for addr := uint8(0); addr <= maxAddr; addr++ {
		// Future proofing for supported clause 45.
		// Check PMA/PMD device (DEVAD 1), register 0 (control)
		const devAddr = 1
		var val uint16
		val, err = mdio.Read(addr, devAddr, BMCRAddr)
		if err != nil {
			continue
		}
		// Basic status has some bits that must be zero and one, so if this check fails then we know its a bad address.
		if val != 0xffff && val != 0x0000 {
			dst[n] = addr
			n++
		}
		time.Sleep(150 * time.Microsecond)
	}
	return n, err
}

type Device struct {
	mdio    MDIOBus
	phyaddr uint8
	// Is 1 for Clause 45 devices and 0 for clause 22 devices.
	clause45 uint8
}

func (d *Device) BasicControl() (BMCR, error) {
	ctl, err := d.rread(BMCRAddr)
	return BMCR(ctl), err
}

func (d *Device) BasicStatus(phyaddr uint8) (BMSR, error) {
	stat, err := d.rread(BMSRAddr)
	return BMSR(stat), err
}

func (d *Device) ID1() (uint16, error) {
	return d.rread(regPhyId1)
}

func (d *Device) ID2() (uint16, error) {
	return d.rread(regPhyId2)
}

func (d *Device) Reset(phyaddr uint8) error {
	err := d.rwrite(BMCRAddr, uint16(BMCRReset))
	if err != nil {
		return err
	}
	// Wait for reset to complete (bit self-clears).
	// IEEE 802.3 allows up to 500ms.
	const maxPolls = 50
	const resetTimeout = 500 * time.Millisecond // As per standard.
	for i := 0; i < maxPolls; i++ {
		time.Sleep(resetTimeout / maxPolls)
		ctl, err := d.BasicControl()
		if err != nil {
			continue
		}
		if ctl&BMCRReset == 0 {
			return nil
		}
	}
	return errors.New("PHY reset timeout")
}

// rwrite mdio register write.
func (d *Device) rwrite(addr uint16, value uint16) error {
	return d.mdio.Write(d.phyaddr, d.clause45, addr, value)
}

// rread mdio register read.
func (d *Device) rread(addr uint16) (value uint16, _ error) {
	return d.mdio.Read(d.phyaddr, d.clause45, addr)
}
