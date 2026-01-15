package phy

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
	BMCRAddr = 0x00

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
	BMSRAddr = 0x01

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
