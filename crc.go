package lneto

import (
	"encoding/binary"
)

// CRC791 function as defined by RFC 791. The Checksum field for TCP+IP
// is the 16-bit ones' complement of the ones' complement sum of
// all 16-bit words in the header. In case of uneven number of octet the
// last word is LSB padded with zeros.
//
// The zero value of CRC791 is ready to use.
type CRC791 struct {
	sum uint32
}

func checksum16(sum uint32) uint16 {
	sum = (sum & 0xffff) + sum>>16
	// the max value of sum at this point is 0x1fffe, so an additional round is enough
	return ^uint16(sum + sum>>16)
}

func checksumWriteEven(sum uint32, buff []byte) uint32 {
	for i := 0; i < len(buff); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buff[i:]))
	}
	return sum
}

// Write adds the bytes in p to the running checksum. The buffer size must be even or the function will panic.
func (c *CRC791) WriteEven(buff []byte) {
	c.sum = checksumWriteEven(c.sum, buff)
}

// AddUint32 adds a 32 bit value to the running checksum interpreted as BigEndian (network order).
func (c *CRC791) AddUint32(value uint32) {
	c.AddUint16(uint16(value >> 16))
	c.AddUint16(uint16(value))
}

// Add16 adds a 16 bit value to the running checksum interpreted as BigEndian (network order).
func (c *CRC791) AddUint16(value uint16) {
	c.sum += uint32(value)
}

// Sum16 calculates the checksum with the data written to c thus far.
func (c *CRC791) Sum16() uint16 {
	return checksum16(c.sum)
}

// PayloadSum16 returns the checksum resulting by adding the bytes in p to the running checksum.
func (c *CRC791) PayloadSum16(buff []byte) uint16 {
	odd := len(buff) & 1
	sum := checksumWriteEven(c.sum, buff[:len(buff)-odd])
	if odd > 0 {
		sum += uint32(buff[len(buff)-1]) << 8
	}
	return checksum16(sum)
}

// Reset zeros out the CRC791, resetting it to the initial state.
func (c *CRC791) Reset() { *c = CRC791{} }

// NonZeroChecksum ensures that the given checksum is not zero, by returning 0xffff instead.
func NeverZeroChecksum(sum16 uint16) uint16 {
	// 0x0000 and 0xffff are the same number in ones' complement math
	if sum16 == 0 {
		return 0xffff
	}
	return sum16
}
