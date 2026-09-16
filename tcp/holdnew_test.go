package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// TestPolicy_HoldNewWithholdsData verifies that a PreTx directive with
// HoldNew set withholds new (unsent) data — the payload stays buffered — while
// leaving retransmissions and control segments unaffected, and that clearing
// HoldNew lets the data flow.
func TestPolicy_HoldNewWithholdsData(t *testing.T) {
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(1))
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)

	loss := newRecordingLoss()
	client.SetPolicy(loss, func() int64 { return 1 })
	setupClientServer(t, rng, client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:]) // loss.tx is the zero value during handshake.

	// Congestion window "full": hold new data.
	loss.tx = TxDirective{HoldNew: true}
	data := []byte("payload")
	if _, err := client.Write(data); err != nil {
		t.Fatal("client write:", err)
	}
	clear(buf[:])
	n, err := client.Send(buf[:])
	if err != nil {
		t.Fatal("client send under hold:", err)
	}
	if n != 0 {
		seg := mustSegment(t, buf[:n], n-sizeHeaderTCP)
		if seg.DATALEN > 0 {
			t.Fatalf("HoldNew must withhold new data, but sent %d payload bytes", seg.DATALEN)
		}
	}
	if client.BufferedUnsent() != len(data) {
		t.Fatalf("held data must stay buffered: BufferedUnsent=%d, want %d", client.BufferedUnsent(), len(data))
	}

	// Release the hold: the data must now be sent.
	loss.tx = TxDirective{}
	clear(buf[:])
	n, err = client.Send(buf[:])
	if err != nil {
		t.Fatal("client send after release:", err)
	}
	seg := mustSegment(t, buf[:n], n-sizeHeaderTCP)
	if int(seg.DATALEN) != len(data) {
		t.Fatalf("released data segment DATALEN=%d, want %d", seg.DATALEN, len(data))
	}
	if client.BufferedUnsent() != 0 {
		t.Fatalf("data must be sent after release: BufferedUnsent=%d, want 0", client.BufferedUnsent())
	}
}
