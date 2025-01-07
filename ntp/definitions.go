package ntp

// LeapIndicator represents the leap second indicator.
// It indicates whether there is no warning, an extra second (61 seconds in the last minute),
// or a missing second (59 seconds in the last minute).
type LeapIndicator uint8

const (
	LeapNoWarning    LeapIndicator = iota // no warning
	LeapLastMinute61                      // last minute 61
	LeapLastMinute59                      // last minute 59
)

// Stratum represents the stratum level of the NTP server.
type Stratum uint8

const (
	// If the Stratum field is 0, which implies unspecified or invalid, the
	// Reference Identifier field can be used to convey messages useful for
	// status reporting and access control.  These are called Kiss-o'-Death
	// (KoD) packets and the ASCII messages they convey are called kiss codes.
	StratumUnspecified Stratum = 0  // unspecified
	StratumPrimary     Stratum = 1  // primary
	StratumUnsync      Stratum = 16 // unsynchronized
)

// String returns a human readable representation of the Stratum.
func (s Stratum) String() string {
	switch s {
	case 0:
		return "unspecified"
	case 1:
		return "primary"
	case 16:
		return "unsynchronized"
	}
	if s < 16 {
		return "secondary"
	}
	return "invalid"
}

func (s Stratum) IsSecondary() bool {
	return s > 1 && s < 16
}

// Mode represents the mode of the NTP message.
// It can be undefined, symmetric active, symmetric passive, client, server, broadcast,
// NTP control message, or private use.
type Mode uint8

const (
	modeUndef             Mode = iota // undefined
	ModeSymmetricActive               // symmetric active
	ModeSymmetricPassive              // symmetric passive
	ModeClient                        // client
	ModeServer                        // server
	ModeBroadcast                     // broadcast
	ModeNTPControlMessage             // control message
	ModePrivateUse                    // private use
)
