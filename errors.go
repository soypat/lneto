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
	_             errGeneric = iota // non-initialized err
	ErrPacketDrop                   // packet dropped
	ErrBadCRC                       // incorrect checksum
)

func (err errGeneric) Error() string {
	return err.String()
}
