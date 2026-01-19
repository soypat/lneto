package phy

// See https://github.com/PieVo/mdio-tool/blob/master/mii.h

// Registers 0..15 as defined by 802.3.
const (
	// First two registers are BMCR and BMSR. See below.

	regPhyId1 = 0x02
	regPhyId2 = 0x03

	regAutoNegotiationAdvertisement      = 0x04
	regAutoNegotiationLinkPartnerAbility = 0x05
	regAutoNegotiationExpansion          = 0x05
	regModeControlStatus                 = 0x11
	regSpecialModes                      = 0x12
	regSymbolErorCounter                 = 0x1a
	regSpecialControlStatusIndications   = 0x1b
	regIRQSourceFlag                     = 0x1d
	regIRQMask                           = 0x1e
	regPhySpecialScontrolStatus          = 0x1f
)

// BMCR represents the Basic Mode Control Register at address 0x00.
// Reference: IEEE 802.3 Clause 22.2.4.1
type BMCR uint16

const (
	AddrBMCR = 0x00 // Address of Basic Mode Control Register.

	BMCRSpeed1000  BMCR = 0x0040 // MSB of Speed (1000Mbps)
	BMCRCollision  BMCR = 0x0080 // Collision test
	BMCRFullDuplex BMCR = 0x0100 // Full duplex mode
	BMCRANRestart  BMCR = 0x0200 // Restart auto-negotiation
	BMCRIsolate    BMCR = 0x0400 // Isolate PHY from MII
	BMCRPowerDown  BMCR = 0x0800 // Power down PHY
	BMCRANEnable   BMCR = 0x1000 // Enable auto-negotiation
	BMCRSpeed100   BMCR = 0x2000 // Select 100Mbps
	BMCRLoopback   BMCR = 0x4000 // Enable TXD loopback
	BMCRReset      BMCR = 0x8000 // Software reset (self-clearing)
)

// BMSR represents the Basic Mode Status Register at address 0x01.
// Reference: IEEE 802.3 Clause 22.2.4.2
type BMSR uint16

const (
	AddrBMSR = 0x01 // Address of Basic Mode Status Register.

	BMSRExtCap      BMSR = 0x0001 // Extended register capability
	BMSRJabber      BMSR = 0x0002 // Jabber detected
	BMSRLinkStatus  BMSR = 0x0004 // Link status (1=up)
	BMSRANCap       BMSR = 0x0008 // Auto-negotiation capable
	BMSRRemoteFault BMSR = 0x0010 // Remote fault detected
	BMSRANComplete  BMSR = 0x0020 // Auto-negotiation complete
	BMSRNoPreamble  BMSR = 0x0040 // Preamble suppression capable
	BMSRExtStatus   BMSR = 0x0100 // Extended status in register 15
	BMSR100Half2    BMSR = 0x0200 // 100BASE-T2 half-duplex capable
	BMSR100Full2    BMSR = 0x0400 // 100BASE-T2 full-duplex capable
	BMSR10Half      BMSR = 0x0800 // 10Mbps half-duplex capable
	BMSR10Full      BMSR = 0x1000 // 10Mbps full-duplex capable
	BMSR100Half     BMSR = 0x2000 // 100Mbps half-duplex capable
	BMSR100Full     BMSR = 0x4000 // 100Mbps full-duplex capable
	BMSR100Base4    BMSR = 0x8000 // 100BASE-T4 capable
)

// ANAR represents the Auto-Negotiation Advertisement Register value at address 0x04.
// ANLPAR (Link Partner Ability Register at 0x05) shares the same bit layout.
// Reference: IEEE 802.3 Clause 28.2.4.1
type ANAR uint16

const (
	AddrANAR   = 0x04 // Address of Auto-Negotiation Advertisement Register.
	AddrANLPAR = 0x05 // Address of Auto-Negotiation Link Partner Advertisement Register.
	AddrANER   = 0x06 // Address of Auto-Negotiation Error Register.

	ANARSelector     ANAR = 0x001f // Protocol selector mask
	ANARSelector8023 ANAR = 0x0001 // IEEE 802.3 selector value (required)
	ANAR10Half       ANAR = 0x0020 // 10BASE-T half-duplex
	ANAR10Full       ANAR = 0x0040 // 10BASE-T full-duplex
	ANAR100Half      ANAR = 0x0080 // 100BASE-TX half-duplex
	ANAR100Full      ANAR = 0x0100 // 100BASE-TX full-duplex
	ANAR100BaseT4    ANAR = 0x0200 // 100BASE-T4
	ANARPause        ANAR = 0x0400 // Pause capability
	ANARPauseAsym    ANAR = 0x0800 // Asymmetric pause
	ANARRemoteFault  ANAR = 0x2000 // Remote fault
	ANARAck          ANAR = 0x4000 // Acknowledge (ANLPAR only)
	ANARNextPage     ANAR = 0x8000 // Next page capable

	// Convenience masks
	ANARSpeedMask ANAR = ANAR10Half | ANAR10Full | ANAR100Half | ANAR100Full | ANAR100BaseT4
	ANARPauseMask ANAR = ANARPause | ANARPauseAsym
)

func (l LinkMode) ANAR() (a ANAR) {
	switch l {
	case Link10HDX:
		a = ANAR10Half
	case Link10FDX:
		a = ANAR10Full
	case Link100HDX:
		a = ANAR100Half
	case Link100FDX:
		a = ANAR100Full
	case Link100T4:
		a = ANAR100BaseT4
	}
	return a
}

// WithPause returns ANAR with pause bits set according to parameters.
//
// Flow control allows a receiver to signal the sender to pause transmission.
// Common combinations:
//   - (true, false):  Symmetric pause - both ends can pause each other
//   - (true, true):   Full flow control with asymmetric fallback
//   - (false, true):  Rx-only pause - we can be paused, won't pause partner
//   - (false, false): No flow control
func (a ANAR) WithPause(symmetric, asymmetric bool) ANAR {
	a &^= ANARPauseMask
	if symmetric {
		a |= ANARPause
	}
	if asymmetric {
		a |= ANARPauseAsym
	}
	return a
}

// WithMaxSpeed returns ANAR with only speeds at or below maxMbps enabled.
// Preserves non-speed bits (pause, selector, etc).
func (a ANAR) WithMaxSpeed(maxMbps int) ANAR {
	a &^= ANARSpeedMask
	switch {
	case maxMbps >= 100:
		a |= ANAR100Half | ANAR100Full
		fallthrough
	case maxMbps >= 10:
		a |= ANAR10Half | ANAR10Full
	}
	return a
}

// FullDuplexOnly returns ANAR with half-duplex modes cleared.
func (a ANAR) FullDuplexOnly() ANAR {
	return a &^ (ANAR10Half | ANAR100Half)
}

// HalfDuplexOnly returns ANAR with full-duplex modes cleared.
func (a ANAR) HalfDuplexOnly() ANAR {
	return a &^ (ANAR10Full | ANAR100Full)
}

// NewANAR returns an ANAR with the IEEE 802.3 selector set.
// Always start with this when building an advertisement value.
func NewANAR() ANAR {
	return ANARSelector8023
}

// With10M returns ANAR with 10Mbps modes (half and full) enabled.
func (a ANAR) With10M() ANAR {
	return a | ANAR10Half | ANAR10Full
}

// With100M returns ANAR with 100Mbps modes (half and full) enabled.
func (a ANAR) With100M() ANAR {
	return a | ANAR100Half | ANAR100Full
}

// Without10M returns ANAR with 10Mbps modes cleared.
func (a ANAR) Without10M() ANAR {
	return a &^ (ANAR10Half | ANAR10Full)
}

// Without100M returns ANAR with 100Mbps modes cleared.
func (a ANAR) Without100M() ANAR {
	return a &^ (ANAR100Half | ANAR100Full | ANAR100BaseT4)
}

// LinkMode returns the highest priority LinkMode from the ANAR speed bits.
// Priority order per IEEE 802.3 Annex 28B.3.
// Returns LinkDown if no speed bits are set.
func (a ANAR) LinkMode() LinkMode {
	switch {
	case a&ANAR100Full != 0:
		return Link100FDX
	case a&ANAR100BaseT4 != 0:
		return Link100T4
	case a&ANAR100Half != 0:
		return Link100HDX
	case a&ANAR10Full != 0:
		return Link10FDX
	case a&ANAR10Half != 0:
		return Link10HDX
	default:
		return LinkDown
	}
}

// LinkMode represents the negotiated/force-set Ethernet link speed and duplex mode.
//
// Naming convention:
//   - H/HDX: Half-duplex (one direction at a time)
//   - F/FDX: Full-duplex (simultaneous bidirectional)
//   - T4: 100BASE-T4 (100Mbps over 4 twisted pairs, legacy)
//   - G: Gigabit, implies number is multiplied by 1000 (1G=1000M)
type LinkMode uint8

const (
	LinkDown    LinkMode = iota // down
	Link10HDX                   // 10M-H
	Link10FDX                   // 10M-F
	Link100HDX                  // 100M-H
	Link100FDX                  // 100M-F
	Link100T4                   // 100M-T4
	Link1000HDX                 // 1000M-H
	Link1000FDX                 // 1000M-F

	// Clause 45 speeds (10Gbps+, full-duplex only):

	Link2500FDX // 2.5G-F
	Link5GFDX   // 5G-F
	Link10GFDX  // 10G-F
	Link25GFDX  // 25G-F
	Link40GFDX  // 40G-F
	Link100GFDX // 100G-F
)

// SpeedMbps returns the link speed in megabits per second.
func (lm LinkMode) SpeedMbps() int {
	switch lm {
	case Link10HDX, Link10FDX:
		return 10
	case Link100HDX, Link100FDX, Link100T4:
		return 100
	case Link1000HDX, Link1000FDX:
		return 1000
	case Link2500FDX:
		return 2500
	case Link5GFDX:
		return 5000
	case Link10GFDX:
		return 10_000
	case Link25GFDX:
		return 25_000
	case Link40GFDX:
		return 40_000
	case Link100GFDX:
		return 100_000
	default:
		return 0
	}
}

// IsFullDuplex returns true if the link mode is full duplex.
func (lm LinkMode) IsFullDuplex() bool {
	switch lm {
	case Link10FDX, Link100FDX, Link1000FDX,
		Link2500FDX, Link5GFDX, Link10GFDX, Link25GFDX, Link40GFDX, Link100GFDX:
		return true
	default:
		return false
	}
}
