package lneto

type errGeneric uint8

// Generic errors common to internet functioning.
const (
	_                     errGeneric = iota // non-initialized err
	ErrBug                                  // lneto-bug(use build tag "debugheaplog")
	ErrPacketDrop                           // packet dropped
	ErrBadCRC                               // incorrect checksum
	ErrZeroSource                           // zero source(port/addr)
	ErrZeroDestination                      // zero destination(port/addr)
	ErrShortBuffer                          // short buffer
	ErrBufferFull                           // buffer full
	ErrInvalidAddr                          // invalid address
	ErrUnsupported                          // unsupported
	ErrMismatch                             // mismatch
	ErrMismatchLen                          // mismatched length
	ErrInvalidConfig                        // invalid configuration
	ErrInvalidField                         // invalid field
	ErrInvalidLengthField                   // invalid length field
	ErrExhausted                            // resource exhausted
	ErrAlreadyRegistered                    // protocol already registered
	ErrTruncatedFrame                       // truncated frame

	// Below are potentially good future error additions
	// based on one or two encountered use cases, example use case included.
	/*
		- ErrUnregistered/ErrAborted // connection unregistered. i.e: ICMP client aborted during active ping, ping process returns this.
		- ErrInvalidArgs // invalid func arguments i.e: different from Config since this refers to non-config arguments. usually nil values.
	*/
)

func (err errGeneric) Error() string {
	return err.String()
}
