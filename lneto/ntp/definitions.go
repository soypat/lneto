package ntp

type LeapIndicator uint8

const (
	LeapNoWarning    LeapIndicator = iota // no warning
	LeapLastMinute61                      // last minute 61
	LeapLastMinute59                      // last minute 59
)

const (
	// If the Stratum field is 0, which implies unspecified or invalid, the
	// Reference Identifier field can be used to convey messages useful for
	// status reporting and access control.  These are called Kiss-o'-Death
	// (KoD) packets and the ASCII messages they convey are called kiss codes.
	StratumUnspecified = 0
	StratumPrimary     = 1
	StratumUnsync      = 16
)

func IsStratumSecondary(stratum uint8) bool {
	return stratum > 1 && stratum < 16
}

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
