package phy

// MDIOBus is a HAL for MDIO bus access supporting both Clause 22 and Clause 45 devices.
// Implementations should use devaddr to select the framing:
//   - devaddr=0: Clause 22 framing (devaddr ignored in transaction)
//   - devaddr>=1: Clause 45 framing (PMA/PMD=1, WIS=2, PCS=3, PHY XS=4, DTE XS=5, AN=7)
//
// Register address range: Clause 22 uses 0-31, Clause 45 uses 0-65535.
type MDIOBus interface {
	// Read reads a 16-bit register from the PHY.
	Read(phyAddr, devaddr uint8, regAddr uint16) (value uint16, err error)
	// Write writes a 16-bit value to a PHY register.
	Write(phyAddr, devaddr uint8, regAddr, value uint16) error
}
