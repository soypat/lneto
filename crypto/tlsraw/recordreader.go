package tlsraw

import (
	"github.com/soypat/lneto"
)

// RecordReader receives a byte stream and outputs framed TLS records similar to httpraw.HeaderV1.
type RecordReader struct {
	maxLen int // Largest record body accepted, <= [MaxCiphertext].
}

// Reset sets the underlying buffer used to read records. buf must fit [SizeHeaderRecord]+maxLen bytes.
// maxLen must be less than or equal to [MaxCipherText].
func (rr *RecordReader) Reset(maxLen int) error {
	if maxLen == 0 {
		maxLen = MaxCiphertext
	}
	if maxLen < 0 || maxLen > MaxCiphertext {
		return lneto.ErrInvalidConfig
	}
	rr.maxLen = maxLen
	return nil
}

// Next parses next complete record with its header and drops the data returned in previous Next call.
// It returns needMoreData=true if the next record is incomplete.
func (rr *RecordReader) Next(first, second []byte) (n int, needMoreData bool, err error) {
	if len(first) == 0 {
		first, second = second, nil
	}
	if len(first)+len(second) < SizeHeaderRecord {
		return 0, true, lneto.ErrTruncatedFrame
	}
	bodyLen := int(ringByte(first, second, 3))<<8 | int(ringByte(first, second, 4))
	if bodyLen > rr.maxLen {
		return 0, false, lneto.ErrInvalidLengthField
	}
	n = SizeHeaderRecord + bodyLen
	if n > len(first)+len(second) {
		return 0, true, lneto.ErrTruncatedFrame
	}
	return n, false, nil
}

func ringByte(first, second []byte, i int) byte {
	if i < len(first) {
		return first[i]
	}
	return second[i-len(first)]
}
