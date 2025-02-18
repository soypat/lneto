package arp

import (
	"bytes"
	"log"
	"testing"

	"github.com/soypat/lneto/lneto2"
)

func TestHandler(t *testing.T) {
	c1, err := NewHandler(HandlerConfig{
		HardwareAddr: []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00},
		ProtocolAddr: []byte{192, 168, 1, 1},
		MaxQueries:   1,
		MaxPending:   1,
		HardwareType: 1,
		ProtocolType: lneto2.EtherTypeIPv4,
	})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewHandler(HandlerConfig{
		HardwareAddr: []byte{0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee},
		ProtocolAddr: []byte{192, 168, 1, 2},
		MaxQueries:   1,
		MaxPending:   1,
		HardwareType: 1,
		ProtocolType: lneto2.EtherTypeIPv4,
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf, discard [64]byte
	n, err := c1.Send(buf[:])
	if err != nil {
		t.Fatal("error on should be nop send:", err)
	} else if n > 0 {
		t.Fatal("should not send if no query")
	}
	n, err = c2.Send(buf[:])
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
	n, err = c1.Send(buf[:]) // Send Request.
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("expected send of data after first query")
	}
	err = c2.Recv(buf[:n]) // Receive request.
	if err != nil {
		t.Fatal(err)
	}

	n, err = c2.Send(buf[:]) //  Send response.
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("got no response to request")
	}
	n, err = c2.Send(discard[:]) // Double tap check, should send nothing.
	if err != nil {
		t.Fatal("double tap send error:", err)
	} else if n > 0 {
		t.Fatal("wanted no data sent after response sent")
	}

	err = c1.Recv(buf[:]) // Receive response.
	if err != nil {
		t.Fatal(err)
	}
	hwaddr, err := c1.QueryResult(queryAddr)
	if err != nil {
		log.Fatal("expected query result:", err)
	} else if !bytes.Equal(hwaddr, expectHWAddr) {
		log.Fatalf("expected to get hwaddr %x!=%x", hwaddr, expectHWAddr)
	}
	n, err = c1.Send(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data")
	}
	n, err = c2.Send(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data")
	}
}
