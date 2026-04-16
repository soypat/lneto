package tcp

import "testing"

// setIPv4Version sets the IP version nibble to 4 at the given offset,
// as required by Drain's call to internal.SetIPAddrs.
func setIPv4Version(carrier []byte, offsetToIP int) {
	carrier[offsetToIP] = 0x45 // version=4, IHL=5 (20 bytes)
}

func TestRSTQueue_QueueAndDrain(t *testing.T) {
	var q RSTQueue
	if q.Pending() != 0 {
		t.Fatal("new queue should be empty")
	}

	srcAddr := [4]byte{10, 0, 0, 1}
	q.Queue(srcAddr[:], 8080, 1234, 100, 200, FlagRST|FlagACK)
	if q.Pending() != 1 {
		t.Fatalf("expected 1 pending, got %d", q.Pending())
	}

	carrier := make([]byte, 256)
	const offsetToIP = 14
	const offsetToTCP = 34
	setIPv4Version(carrier, offsetToIP)

	n, err := q.Drain(carrier, offsetToIP, offsetToTCP)
	if err != nil {
		t.Fatal(err)
	}
	if n != sizeHeaderTCP {
		t.Fatalf("expected %d bytes written, got %d", sizeHeaderTCP, n)
	}
	if q.Pending() != 0 {
		t.Fatal("queue should be empty after drain")
	}

	tfrm, err := NewFrame(carrier[offsetToTCP:])
	if err != nil {
		t.Fatal(err)
	}
	if tfrm.SourcePort() != 1234 {
		t.Errorf("source port = %d; want 1234", tfrm.SourcePort())
	}
	if tfrm.DestinationPort() != 8080 {
		t.Errorf("dest port = %d; want 8080", tfrm.DestinationPort())
	}
	seg := tfrm.Segment(0)
	if seg.SEQ != 100 {
		t.Errorf("SEQ = %d; want 100", seg.SEQ)
	}
	if seg.ACK != 200 {
		t.Errorf("ACK = %d; want 200", seg.ACK)
	}
	if !seg.Flags.HasAll(FlagRST | FlagACK) {
		t.Errorf("flags = %s; want RST|ACK", seg.Flags)
	}
}

func TestRSTQueue_DrainEmpty(t *testing.T) {
	var q RSTQueue
	carrier := make([]byte, 256)
	n, err := q.Drain(carrier, 14, 34)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("drain of empty queue should return 0, got %d", n)
	}
}

func TestRSTQueue_DrainNegativeOffset(t *testing.T) {
	var q RSTQueue
	q.Queue([]byte{10, 0, 0, 1}, 80, 1234, 0, 0, FlagRST)
	carrier := make([]byte, 256)
	n, err := q.Drain(carrier, -1, 34)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("drain with negative offsetToIP should return 0, got %d", n)
	}
}

func TestRSTQueue_Full(t *testing.T) {
	var q RSTQueue
	addr := []byte{10, 0, 0, 1}
	for i := range 4 {
		q.Queue(addr, uint16(i), 1234, Value(i), 0, FlagRST)
	}
	if q.Pending() != 4 {
		t.Fatalf("expected 4 pending, got %d", q.Pending())
	}

	// Overflow should be silently dropped.
	q.Queue(addr, 9999, 1234, 0, 0, FlagRST)
	if q.Pending() != 4 {
		t.Fatalf("expected 4 pending after overflow, got %d", q.Pending())
	}
}

func TestRSTQueue_NonIPv4Dropped(t *testing.T) {
	var q RSTQueue
	addr6 := make([]byte, 16)
	q.Queue(addr6, 80, 1234, 0, 0, FlagRST)
	if q.Pending() != 0 {
		t.Fatalf("non-IPv4 should be dropped, got %d pending", q.Pending())
	}
}

func TestRSTQueue_LIFO(t *testing.T) {
	var q RSTQueue
	addr := []byte{10, 0, 0, 1}
	q.Queue(addr, 1000, 1234, 0, 0, FlagRST)
	q.Queue(addr, 2000, 1234, 0, 0, FlagRST)

	carrier := make([]byte, 256)
	const offsetToIP = 14
	const offsetToTCP = 34
	setIPv4Version(carrier, offsetToIP)

	// Drain returns last-in first (LIFO).
	n, err := q.Drain(carrier, offsetToIP, offsetToTCP)
	if err != nil || n == 0 {
		t.Fatal("drain failed")
	}
	tfrm, _ := NewFrame(carrier[offsetToTCP:])
	if tfrm.DestinationPort() != 2000 {
		t.Errorf("expected LIFO order: first drain dest port = %d; want 2000", tfrm.DestinationPort())
	}
}

func TestRSTQueue_MultipleDrains(t *testing.T) {
	var q RSTQueue
	addr := []byte{10, 0, 0, 1}
	q.Queue(addr, 1000, 100, 0, 0, FlagRST)
	q.Queue(addr, 2000, 200, 0, 0, FlagRST)
	q.Queue(addr, 3000, 300, 0, 0, FlagRST)

	carrier := make([]byte, 256)
	const offsetToIP = 14
	const offsetToTCP = 34

	// Drain all 3 entries.
	for i := range 3 {
		setIPv4Version(carrier, offsetToIP)
		n, err := q.Drain(carrier, offsetToIP, offsetToTCP)
		if err != nil {
			t.Fatal(err)
		}
		if n != sizeHeaderTCP {
			t.Fatalf("drain %d: expected %d bytes, got %d", i, sizeHeaderTCP, n)
		}
	}
	if q.Pending() != 0 {
		t.Fatal("queue should be empty")
	}

	// Fourth drain should return 0.
	n, _ := q.Drain(carrier, offsetToIP, offsetToTCP)
	if n != 0 {
		t.Fatal("expected 0 from empty queue")
	}
}
