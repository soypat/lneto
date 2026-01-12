package arp

import (
	"bytes"
	"log"
	"slices"
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
	n, err := c1.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("error on should be nop send:", err)
	} else if n > 0 {
		t.Fatal("should not send if no query")
	}
	n, err = c2.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal("error on should be nop send:", err)
	} else if n > 0 {
		t.Fatal("should not send if no query")
	}

	// Perform ARP exchange.
	expectHWAddr := c2.ourHWAddr
	queryAddr := c2.ourProtoAddr
	err = c1.StartQuery(nil, queryAddr)
	if err != nil {
		t.Fatal(err)
	}
	n, err = c1.Encapsulate(buf[:], -1, 0) // Send Request.
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

	n, err = c2.Encapsulate(buf[:], -1, 0) //  Send response.
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		t.Fatal("got no response to request")
	}
	validateARP(t, buf[:])
	n, err = c2.Encapsulate(discard[:], -1, 0) // Double tap check, should send nothing.
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
	n, err = c1.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data")
	}
	n, err = c2.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data")
	}
}

func TestQueryCompaction(t *testing.T) {
	var h Handler

	startQuery := func(addr []byte) {
		err := h.StartQuery(nil, addr)
		if err != nil {
			t.Fatal(err)
		}
	}

	err := h.Reset(HandlerConfig{
		HardwareAddr: []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00},
		ProtocolAddr: []byte{192, 168, 1, 1},
		MaxQueries:   5,
		MaxPending:   1,
		HardwareType: 1,
		ProtocolType: ethernet.TypeIPv4,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create multiple queries
	addr1 := []byte{192, 168, 1, 10}
	addr2 := []byte{192, 168, 1, 20}
	addr3 := []byte{192, 168, 1, 30}

	// Start 3 queries
	startQuery(addr1)
	startQuery(addr2)
	startQuery(addr3)

	if len(h.queries) != 3 {
		t.Fatalf("expected 3 queries, got %d", len(h.queries))
	}

	// Discard the middle query (addr2)
	if err := h.DiscardQuery(addr2); err != nil {
		t.Fatal(err)
	}

	// Verify addr2 is marked as invalid
	hasAddr2 := slices.ContainsFunc(h.queries, func(q queryResult) bool {
		return bytes.Equal(q.protoaddr, addr2)
	})
	if hasAddr2 {
		t.Fatal("addr2 query found after discard")
	}

	// Start new queries to trigger compaction
	addr4 := []byte{192, 168, 1, 40}
	addr5 := []byte{192, 168, 1, 50}
	addr6 := []byte{192, 168, 1, 60}

	startQuery(addr4)
	startQuery(addr5)
	startQuery(addr6)

	// After compaction we should be left with 5 queries
	expectedAddrs := [][]byte{addr1, addr3, addr4, addr5, addr6}

	if len(h.queries) != len(expectedAddrs) {
		t.Fatalf("after compaction: expected %d queries, got %d", len(expectedAddrs), len(h.queries))
	}

	gotAddrs := [][]byte{}
	for _, q := range h.queries {
		if !q.isInvalid() {
			gotAddrs = append(gotAddrs, q.protoaddr)
		} else {
			t.Fatalf("invalid query %v should have been removed during compaction", q.protoaddr)
		}
	}

	if !slices.EqualFunc(gotAddrs, expectedAddrs, bytes.Equal) {
		t.Fatalf("expected %v, got %v", expectedAddrs, gotAddrs)
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
