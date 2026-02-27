package lneto

type errGeneric uint8

// Generic errors common to internet functioning.
const (
	_                  errGeneric = iota // non-initialized err
	ErrBug                               // lneto-bug(use build tag "debugheaplog")
	ErrPacketDrop                        // packet dropped
	ErrBadCRC                            // incorrect checksum
	ErrZeroSource                        // zero source(port/addr)
	ErrZeroDestination                   // zero destination(port/addr)
	ErrShortBuffer                       // short buffer
	ErrBufferFull                        // buffer full
	ErrInvalidAddr                       // invalid address
	ErrUnsupported                       // unsupported
	ErrMismatch                          // mismatch
	ErrMismatchLen                       // mismatched length
	ErrInvalidConfig                     // invalid configuration
	ErrInvalidField                      // invalid field
	ErrInvalidLengthField                // invalid length field
	ErrExhausted                         // resource exhausted
)

func (err errGeneric) Error() string {
	return err.String()
}
