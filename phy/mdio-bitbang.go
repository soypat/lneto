package phy

import (
	"errors"
)

var _ MDIOBus = (*MDIOBitBang)(nil) // compile time guarantee of interface implementation.

const (
	mdioRead  = 0b10
	mdioWrite = 0b01
	miaddrc45 = 1 << 30
	c45bit    = 1 << 15
	c45Addr   = c45bit | 0b00
	c45Read   = c45bit | 0b11
	c45Write  = c45bit | 0b01
)

// MDIOBitBang provides a software defined(bitbang) MDIO/MDC management interface for PHY register access
// as the STA (Management station, this implementation) which communicates to the PHY (Physical layer device).
// Inspired by linux/v3.13.1/source/drivers/net/phy/mdio-bitbang.c
// Below is a TinyGo oriented HAL needed to use MDIOBitBang. MDC is clock line, MDIO is data line.
//
//	const mdioDelay = 340 * time.Nanosecond // MDIO spec max turnaround time
//	pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
//	pinMDC.Configure(machine.PinConfig{Mode: machine.PinOutput})
//	pinMDC.Low()
//	var mdio2 phy.MDIOBitBang
//	mdio2.Configure(func(outBit bool) {
//		// sendBit: set data, clock high, clock low
//		if outBit {
//			pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
//		} else {
//			pinMDIO.Low()
//			pinMDIO.Configure(machine.PinConfig{Mode: machine.PinOutput})
//		}
//		time.Sleep(mdioDelay)
//		pinMDC.High()
//		time.Sleep(mdioDelay)
//		pinMDC.Low()
//	}, func() (inBit bool) {
//		// getBit: clock high, read, clock low
//		time.Sleep(mdioDelay)
//		pinMDC.High()
//		time.Sleep(mdioDelay)
//		pinMDC.Low()
//		return pinMDIO.Get()
//	}, func(setOut bool) {
//		// setDir: configure pin direction
//		if setOut {
//			pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
//		} else {
//			pinMDIO.Configure(machine.PinConfig{Mode: machine.PinInput})
//		}
//	})
type MDIOBitBang struct {
	_sendBit func(bit bool)
	_getBit  func() (inputBit bool)
	_setDir  func(output bool)
}

// Configure initializes the MDIO bit-bang interface with the given pin control callbacks.
func (m *MDIOBitBang) Configure(sendBit func(bit bool), getBit func() bool, setDir func(setOut bool)) {
	if sendBit == nil || getBit == nil || setDir == nil {
		panic("nil callback")
	}
	m._getBit = getBit
	m._sendBit = sendBit
	m._setDir = setDir
	m.reset()
}

func (m *MDIOBitBang) reset() {
	// setting direction to output releases the bus.
	m.setDir(true)
}

// Read reads a PHY register. Uses Clause 45 framing if devAddr is non-zero.
func (m *MDIOBitBang) Read(phyAddr, devAddr uint8, regAddr uint16) (uint16, error) {
	isC45 := devAddr != 0
	if isC45 {
		m.cmdAddr2(phyAddr, devAddr, regAddr)
		m.cmd(c45Read, phyAddr, devAddr)
	} else {
		m.cmd(mdioRead, phyAddr, uint8(regAddr))
	}
	m.setDir(false)
	// Check turnaround bit, PHY should drive it to zero.
	if m.getBit() {
		// PHY did not drive low, as would be expected.
		// Ensure flush:
		for range 32 {
			m.getBit()
		}
		return 0xffff, errors.New("PHY did not drive turnaround low")
	}
	ret := m.getNum(16)
	m.getBit()
	return ret, nil
}

// Write writes a value to a PHY register. Uses Clause 45 framing if devAddr is non-zero.
func (m *MDIOBitBang) Write(phyAddr, devAddr uint8, regAddr, value uint16) error {
	isC45 := devAddr != 0
	if isC45 {
		m.cmdAddr2(phyAddr, devAddr, regAddr)
		m.cmd(c45Write, phyAddr, devAddr)
	} else {
		m.cmd(mdioWrite, phyAddr, uint8(regAddr))
	}
	// send turnaround (10)
	m.sendBit(true)
	m.sendBit(false)

	m.sendNum(value, 16)
	m.setDir(false)
	m.getBit()
	return nil
}

func (m *MDIOBitBang) cmdAddr2(phy, dev uint8, reg uint16) {
	m.cmd(c45Addr, phy, dev)
	// turnaround 10.
	m.sendBit(true)
	m.sendBit(false)

	m.sendNum(reg, 16)
	m.setDir(false)
	m.getBit()
}

func (m *MDIOBitBang) cmd(op uint16, phy uint8, reg uint8) {
	const writeDir = true
	m.setDir(writeDir)
	// Preamble, 32 bits of 1.
	for range 32 {
		m.sendBit(true)
	}
	// Start of frame: 01
	// Clause 45 op uses 00=start, 11=read, 10=write
	m.sendBit(false)
	m.sendBit(op&c45bit == 0)

	m.sendBit((op>>1)&1 != 0)
	m.sendBit((op>>0)&1 != 0)
	m.sendNum(uint16(phy), 5)
	m.sendNum(uint16(reg), 5)
}

func (m *MDIOBitBang) sendNum(val uint16, bits int) {
	for i := bits - 1; i >= 0; i-- {
		m.sendBit((val>>i)&1 != 0)
	}
}

func (m *MDIOBitBang) getNum(bits int) (ret uint16) {
	for i := bits - 1; i >= 0; i-- {
		ret <<= 1
		ret |= uint16(b2u8(m.getBit()))
	}
	return ret
}

// MDIO low-level clock operations
// Reference: https://github.com/sandeepmistry/pico-rmii-ethernet/blob/main/examples/httpd/main.c
// Reference: netif_rmii_ethernet_mdio_clock_out() and netif_rmii_ethernet_mdio_clock_in()
// from rmii_ethernet.c

// setDir configures pins preparing for write/read operations.
func (m *MDIOBitBang) setDir(outWrite bool) {
	m._setDir(outWrite)
}

func (m *MDIOBitBang) sendBit(b bool) {
	m._sendBit(b)
}

func (m *MDIOBitBang) getBit() bool {
	return m._getBit()
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
