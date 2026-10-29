//go:build tinygo && baremetal

package main

import (
	"encoding/binary"
	"machine"
)

// readRNG uses tinygo's machine package HAL GetRNG to read into byte slice.
func readRNG(b []byte) (int, error) {
	for len(b) >= 4 {
		v, err := machine.GetRNG()
		if err != nil {
			return 0, err
		}
		binary.LittleEndian.PutUint32(b, v)
		b = b[4:]
	}
	for i := range b {
		v, err := machine.GetRNG()
		if err != nil {
			return 0, err
		}
		b[i] = uint8(v)
	}
	return len(b), nil
}
