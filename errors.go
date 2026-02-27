package lneto

// type ErrorPacketDrop struct {
// 	Message string
// }

// var genericErrPacketDrop = &ErrorPacketDrop{Message: ErrPacketDrop.Error()}

// // ErrGenericPacketDrop returns the generic packet drop error. It performs no allocations.
// func ErrGenericPacketDrop() error {
// 	return genericErrPacketDrop
// }

// func (err *ErrorPacketDrop) Error() string {
// 	return err.Message
// }

type errGeneric uint8

// Generic errors common to internet functioning.
const (
	_                  errGeneric = iota // non-initialized err
	ErrBug                               // lneto-bug(use build tag "debugheaplog")
	ErrPacketDrop                        // packet dropped
	ErrBadCRC                            // incorrect checksum
	ErrZeroSource                        // zero source(port/addr)
	ErrZeroDestination                   // zero destination(port/addr)
)

func (err errGeneric) Error() string {
	return err.String()
}
