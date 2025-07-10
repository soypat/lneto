package arp

import (
	"bytes"
	"log"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
)

func TestHandler(t *testing.T) {
	var c1, c2 Handler
	err := c1.Reset(HandlerConfig{
		HardwareAddr: []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00},
		ProtocolAddr: []byte{192, 168, 1, 1},
		MaxQueries:   1,
		MaxPending:   1,
		HardwareType: 1,
		ProtocolType: ethernet.TypeIPv4,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c2.Reset(HandlerConfig{
		HardwareAddr: []byte{0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee},
		ProtocolAddr: []byte{192, 168, 1, 2},
		MaxQueries:   1,
		MaxPending:   1,
		HardwareType: 1,
		ProtocolType: ethernet.TypeIPv4,
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf, discard [64]byte
	n, err := c1.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal("error on should be nop send:", err)
	} else if n > 0 {
		t.Fatal("should not send if no query")
	}
	n, err = c2.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal("error on should be nop send:", err)
	} else if n > 0 {
		t.Fatal("should not send if no query")
	}

	// Perform ARP exchange.
	expectHWAddr := c2.ourHWAddr
	queryAddr := c2.ourProtoAddr
	err = c1.StartQuery(queryAddr)
	if err != nil {
		t.Fatal(err)
	}
	n, err = c1.Encapsulate(buf[:], 0) // Send Request.
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("expected send of data after first query")
	}
	validateARP(t, buf[:])
	err = c2.Demux(buf[:n], 0) // Receive request.
	if err != nil {
		t.Fatal(err)
	}

	n, err = c2.Encapsulate(buf[:], 0) //  Send response.
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("got no response to request")
	}
	validateARP(t, buf[:])
	n, err = c2.Encapsulate(discard[:], 0) // Double tap check, should send nothing.
	if err != nil {
		t.Fatal("double tap send error:", err)
	} else if n > 0 {
		t.Fatal("wanted no data sent after response sent")
	}

	err = c1.Demux(buf[:], 0) // Receive response.
	if err != nil {
		t.Fatal(err)
	}
	hwaddr, err := c1.QueryResult(queryAddr)
	if err != nil {
		log.Fatal("expected query result:", err)
	} else if !bytes.Equal(hwaddr, expectHWAddr) {
		log.Fatalf("expected to get hwaddr %x!=%x", hwaddr, expectHWAddr)
	}
	n, err = c1.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data")
	}
	n, err = c2.Encapsulate(buf[:], 0)
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data")
	}
}

func validateARP(t *testing.T, buf []byte) {
	t.Helper()
	afrm, err := NewFrame(buf)
	if err != nil {
		t.Error(err)
		return
	}
	var vld lneto.Validator
	afrm.ValidateSize(&vld)
	if vld.HasError() {
		t.Errorf("invalid arp: %s", vld.ErrPop())
	} else if err := vld.ErrPop(); err != nil {
		panic("unreachable: " + err.Error())
	}
}
