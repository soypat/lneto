// Package phy provides Ethernet PHY management via MDIO.
// It supports IEEE 802.3 Clause 22 and Clause 45 register access
// for configuring and monitoring physical layer transceivers.
package phy

// Add more stringers in linecomment mode by adding them to type flag (comma separated).
//go:generate stringer -type=LinkMode -linecomment -output=phy_stringers.go

import (
	"errors"
	"time"

	"github.com/soypat/lneto"
)

// MDIOBus is a HAL for MDIO bus access supporting both Clause 22 and Clause 45 devices.
// Implementations should use devaddr to select the framing:
//   - devaddr=0: Clause 22 framing (devaddr ignored in transaction)
//   - devaddr>=1: Clause 45 framing (PMA/PMD=1, WIS=2, PCS=3, PHY XS=4, DTE XS=5, AN=7)
//
// Register address range: Clause 22 uses 0-31, Clause 45 uses 0-65535.
// Invalid combinations of devaddr and regAddr may or may not return an error
// depending on the implementation or result in undefined behavior.
// To avoid this wrap your MDIOBus interfaces with a wrapper type that checks validity of ranges.
type MDIOBus interface {
	// Read reads a 16-bit register from the PHY.
	Read(phyAddr, devAddr uint8, regAddr uint16) (value uint16, err error)
	// Write writes a 16-bit value to a PHY register.
	Write(phyAddr, devAddr uint8, regAddr, value uint16) error
}

// FindPHYs finds all regular non-clause45 PHYs on the MDIO bus and writes them to dst.
// FindClause22PHYs returns error only if unable to find no PHYs.
func FindClause22PHYs(mdio MDIOBus, dst []uint8) (n int, err error) {
	const maxAddr = 31
	const regBasicStatus = 0x01
	if len(dst) < 32 {
		return -1, lneto.ErrShortBuffer
	}
	n = 0
	for addr := uint8(0); addr <= maxAddr; addr++ {
		// Future proofing for supported clause 45.
		// Check PMA/PMD device (DEVAD 1), register 0 (control)
		val, err := mdio.Read(addr, 0, AddrBMSR)
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
	if n <= 0 {
		err = errors.New("no phy found")
	}
	return n, err
}

var errInvalidPhyAddr error = lneto.ErrInvalidAddr

type Device struct {
	mdio    MDIOBus
	phyaddr uint8
	// isClause45 is 0 for clause 22 devices and 1 for clause45 devices.
	isClause45 uint8
}

// ConfigureAs22 resets all state of device to be used as a Clause22 device. Does not do a software reset.
func (phy *Device) ConfigureAs22(mdio MDIOBus, phyAddr uint8) error {
	if phyAddr > 31 {
		return errInvalidPhyAddr

	} else if mdio == nil {
		return lneto.ErrInvalidConfig
	}
	phy.mdio = mdio
	phy.phyaddr = phyAddr
	phy.isClause45 = 0
	return nil
}

// IsClause45 returns true if the device uses Clause 45 MDIO addressing (extended register access).
func (phy *Device) IsClause45() bool {
	return phy.isClause45 == 1
}

// PHYAddr returns the PHY address on the MDIO bus (0-31).
func (phy *Device) PHYAddr() uint8 {
	return phy.phyaddr
}

// BasicControl reads the Basic Mode Control Register (BMCR, register 0).
func (phy *Device) BasicControl() (BMCR, error) {
	ctl, err := phy.rread(AddrBMCR)
	return BMCR(ctl), err
}

// BasicStatus reads the Basic Mode Status Register (BMSR, register 1).
func (phy *Device) BasicStatus() (BMSR, error) {
	stat, err := phy.rread(AddrBMSR)
	return BMSR(stat), err
}

// EnableAutoNegotiation enables or disables PHY auto-negotiation and verifies the change took effect.
func (phy *Device) EnableAutoNegotiation(b bool) error {
	ctl, err := phy.BasicControl()
	if err != nil {
		return err
	}
	if b {
		ctl |= BMCRANEnable
	} else {
		ctl &^= BMCRANEnable
	}
	err = phy.rwrite(AddrBMCR, uint16(ctl))
	if err != nil {
		return err
	}
	ctl, err = phy.BasicControl()
	if (ctl&BMCRANEnable != 0) != b {
		return errors.New("unable to set control enable bit")
	}
	return nil
}

// ID1 reads the PHY Identifier 1 register (register 2), containing bits 3-18 of the OUI.
func (phy *Device) ID1() (uint16, error) {
	return phy.rread(regPhyId1)
}

// ID2 reads the PHY Identifier 2 register (register 3), containing bits 19-24 of the OUI and model/revision.
func (phy *Device) ID2() (uint16, error) {
	return phy.rread(regPhyId2)
}

// ResetPHY performs a software reset and waits for completion.
// Returns an error on IO error on MDIO bus or on timeout during wait for register reset.
func (phy *Device) ResetPHY() (err error) {
	err = phy.rwrite(AddrBMCR, uint16(BMCRReset))
	if err != nil {
		return err
	}
	// Wait for reset to complete (bit self-clears).
	// IEEE 802.3 allows up to 500ms.
	const maxPolls = 50
	const resetTimeout = 500 * time.Millisecond // As per standard.
	var ctl BMCR
	for i := 0; i < maxPolls; i++ {
		time.Sleep(resetTimeout / maxPolls)
		ctl, err = phy.BasicControl()
		if err != nil {
			continue
		}
		if ctl&BMCRReset == 0 {
			return nil
		}
	}
	if err != nil {
		return err
	}
	return errors.New("PHY reset timeout")
}

// SetupForced disables auto-negotiation and forces a specific link mode.
//
// Inspired by drivers/net/phy/phy_device.c
func (phy *Device) SetupForced(mode LinkMode) error {
	var ctl BMCR
	switch mode.SpeedMbps() {
	case 1000:
		ctl |= BMCRSpeed1000
	case 100:
		ctl |= BMCRSpeed100
	case 10:
		// No speed bits = 10Mbps
	default:
		return lneto.ErrUnsupported
	}
	if mode.IsFullDuplex() {
		ctl |= BMCRFullDuplex
	}
	// Note: BMCRANEnable is NOT set, disabling auto-negotiation
	return phy.rwrite(AddrBMCR, uint16(ctl))
}

// Advertisement reads the current Auto-Negotiation Advertisement Register.
func (phy *Device) Advertisement() (ANAR, error) {
	val, err := phy.rread(AddrANAR)
	return ANAR(val), err
}

// SetAdvertisement writes to the Auto-Negotiation Advertisement Register.
// Does NOT restart auto-negotiation; call RestartAutoNeg() after if needed.
func (phy *Device) SetAdvertisement(ad ANAR) error {
	return phy.rwrite(AddrANAR, uint16(ad))
}

// LinkPartnerAdvertisement reads what the link partner is advertising (ANLPAR).
func (phy *Device) LinkPartnerAdvertisement() (ANAR, error) {
	val, err := phy.rread(AddrANLPAR)
	return ANAR(val), err
}

// RestartAutoNeg enables auto-negotiation and restarts it.
func (phy *Device) RestartAutoNeg() error {
	ctl, err := phy.BasicControl()
	if err != nil {
		return err
	}
	ctl |= BMCRANEnable | BMCRANRestart
	return phy.rwrite(AddrBMCR, uint16(ctl))
}

// IsLinkUp returns true if link is established.
func (phy *Device) IsLinkUp() (bool, error) {
	status, err := phy.BasicStatus()
	if err != nil {
		return false, err
	}
	return status&BMSRLinkStatus != 0, nil
}

// WaitForLinkWithDeadline waits for link to establish until the deadline.
// If auto-negotiation is enabled (BMCR.ANEnable=1), waits for AN to complete first.
// Returns true if link is up, false if deadline exceeded.
//
// Per IEEE 802.3:
//   - BMSR.LinkStatus is latched-low, so first read clears any previous fault
//   - BMSR.ANComplete must be set before link parameters are valid (when AN enabled)
//   - link_fail_inhibit_timer (50-75ms) delays link indication after AN completes
func (phy *Device) WaitForLinkWithDeadline(deadline time.Time) (bool, error) {
	const pollInterval = 50 * time.Millisecond
	// Check current PHY configuration.
	// Early exit: link impossible if PHY isolated or powered down.
	ctl, err := phy.BasicControl()
	if err != nil {
		return false, err
	} else if ctl&BMCRIsolate != 0 {
		return false, errors.New("PHY isolated from MII")
	} else if ctl&BMCRPowerDown != 0 {
		return false, errors.New("PHY powered down")
	}

	// First read clears latched-low bits (LinkStatus, ANComplete).
	// This ensures we get fresh status on subsequent reads.
	_, _ = phy.BasicStatus()
	anEnabled := ctl&BMCRANEnable != 0
	for time.Now().Before(deadline) {
		status, err := phy.BasicStatus()
		if err != nil {
			return false, err
		}
		// If AN enabled, must wait for it to complete first.
		// No point checking link status until AN is done.
		if anEnabled && !status.AutoNegotiationComplete() {
			time.Sleep(pollInterval)
			continue
		}
		// AN complete (or disabled). Check link status.
		if status.LinkUp() {
			return true, nil
		}
		time.Sleep(pollInterval)
	}

	// Final check after deadline.
	status, err := phy.BasicStatus()
	if err != nil {
		return false, err
	}
	return status.LinkUp(), nil
}

// NegotiatedLink returns the auto-negotiated link mode using standard MII registers.
// Returns LinkMode based on ANAR (our advertisement) AND ANLPAR (link partner ability).
// Priority order per IEEE 802.3 Annex 28B.3.
func (phy *Device) NegotiatedLink() (LinkMode, error) {
	// First check if auto-negotiation is complete
	status, err := phy.BasicStatus()
	if err != nil {
		return LinkDown, err
	}
	if status&BMSRANComplete == 0 {
		return LinkDown, errors.New("auto-negotiation not complete")
	}

	// Read our advertisement
	anar, err := phy.Advertisement()
	if err != nil {
		return LinkDown, err
	}

	// Read link partner's advertisement
	anlpar, err := phy.LinkPartnerAdvertisement()
	if err != nil {
		return LinkDown, err
	}

	// Common capabilities = what both sides support
	common := anar & anlpar
	return common.LinkMode(), nil
}

// SetLoopback enables or disables PHY near-end loopback mode (BMCR bit 14).
// In loopback mode, TX data is routed back to RX internally through PCS/PMA/PMD.
func (phy *Device) SetLoopback(enable bool) error {
	ctl, err := phy.BasicControl()
	if err != nil {
		return err
	}
	if enable {
		ctl |= BMCRLoopback
	} else {
		ctl &^= BMCRLoopback
	}
	return phy.rwrite(AddrBMCR, uint16(ctl))
}

func (phy *Device) rread(regaddr uint16) (uint16, error) {
	return phy.mdio.Read(phy.phyaddr, phy.isClause45, regaddr)
}
func (phy *Device) rwrite(regaddr, value uint16) error {
	return phy.mdio.Write(phy.phyaddr, phy.isClause45, regaddr, value)
}
