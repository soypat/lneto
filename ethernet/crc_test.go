package ethernet

import (
	"encoding/binary"
	"testing"
)

func TestCRC32Search(t *testing.T) {
	// Helper to create test data with CRC appended at a specific position.
	makeDataWithCRC := func(payloadLen int) []byte {
		data := make([]byte, payloadLen+4)
		for i := range data[:payloadLen] {
			data[i] = byte(i)
		}
		crc := CRC32(data[:payloadLen])
		binary.LittleEndian.PutUint32(data[payloadLen:], crc)
		return data
	}

	t.Run("finds CRC at end", func(t *testing.T) {
		data := makeDataWithCRC(100)
		off := CRC32Search(data, 0)
		if off != 100 {
			t.Errorf("expected offset 100, got %d", off)
		}
	})

	t.Run("finds CRC with minOff before CRC", func(t *testing.T) {
		data := makeDataWithCRC(100)
		off := CRC32Search(data, 50)
		if off != 100 {
			t.Errorf("expected offset 100, got %d", off)
		}
	})

	t.Run("finds CRC with minOff exactly at CRC", func(t *testing.T) {
		data := makeDataWithCRC(100)
		off := CRC32Search(data, 100)
		if off != 100 {
			t.Errorf("expected offset 100, got %d", off)
		}
	})

	t.Run("returns -1 when minOff past CRC", func(t *testing.T) {
		data := makeDataWithCRC(100)
		off := CRC32Search(data, 101)
		if off != -1 {
			t.Errorf("expected -1, got %d", off)
		}
	})

	t.Run("returns -1 when no valid CRC", func(t *testing.T) {
		data := make([]byte, 100)
		for i := range data {
			data[i] = byte(i)
		}
		off := CRC32Search(data, 0)
		if off != -1 {
			t.Errorf("expected -1, got %d", off)
		}
	})

	t.Run("returns -1 when data too short", func(t *testing.T) {
		data := []byte{1, 2, 3}
		off := CRC32Search(data, 0)
		if off != -1 {
			t.Errorf("expected -1, got %d", off)
		}
	})

	t.Run("handles negative minOff", func(t *testing.T) {
		data := makeDataWithCRC(20)
		off := CRC32Search(data, -5)
		if off != 20 {
			t.Errorf("expected offset 20, got %d", off)
		}
	})

	t.Run("finds CRC at position 0", func(t *testing.T) {
		// Empty payload, just CRC
		data := make([]byte, 4)
		crc := CRC32(nil)
		binary.LittleEndian.PutUint32(data, crc)
		off := CRC32Search(data, 0)
		if off != 0 {
			t.Errorf("expected offset 0, got %d", off)
		}
	})

	t.Run("finds first valid CRC when multiple could match", func(t *testing.T) {
		// Create data where CRC is at position 50
		data := makeDataWithCRC(50)
		// Extend with more bytes (the search should still find first match)
		data = append(data, make([]byte, 50)...)
		off := CRC32Search(data, 0)
		if off != 50 {
			t.Errorf("expected offset 50 (first match), got %d", off)
		}
	})
}
