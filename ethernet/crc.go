package ethernet

import (
	"encoding/binary"
	"hash/crc32"
)

//
// CRC API.
//

// crcTable is the IEEE CRC-32 table used for Ethernet FCS calculation.
var crcTable = crc32.MakeTable(crc32.IEEE)

// CRC32 calculates the Ethernet Frame Check Sequence (FCS) for the given data.
// The CRC is computed using the IEEE 802.3 CRC-32 polynomial.
// The input should be the frame data from destination MAC through payload,
// excluding any existing FCS.
func CRC32(data []byte) uint32 {
	return crc32.Checksum(data, crcTable)
}

// CRC32Search searches for a valid CRC32 in data starting from minOffCRC.
// It computes the CRC incrementally from minOffCRC, checking at each position
// if the CRC matches the next 4 bytes (little-endian FCS).
// Returns the offset where a valid CRC was found, or -1 if no valid CRC exists.
// This is useful when the exact frame length is unknown but bounded by minOffCRC.
func CRC32Search(data []byte, minOffCRC int) (foundOffOrNegative int) {
	if minOffCRC < 0 {
		minOffCRC = 0
	}
	if len(data) < minOffCRC+4 {
		return -1
	}
	// Calculate CRC up to minOffCRC
	crc := crc32.Checksum(data[:minOffCRC], crcTable)
	// Incrementally extend and check at each position
	for off := minOffCRC; off <= len(data)-4; off++ {
		got := binary.LittleEndian.Uint32(data[off:])
		if crc == got {
			return off
		}
		// Extend CRC by one byte for next iteration
		crc = crc32.Update(crc, crcTable, data[off:off+1])
	}
	return -1
}
