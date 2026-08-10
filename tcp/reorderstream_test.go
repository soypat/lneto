package tcp

import (
	"math/rand"
	"strconv"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// TestHandlerStreamIntegrityUnderReorder asserts byte identity of a reassembled
// stream whose segments arrive out of order: arrival order is randomised within
// each block of shuffleWindow segments, and nothing is lost or retransmitted, so
// several segments sit staged in the receive ring at once. Reordering may cost
// throughput; it may not change the bytes.
func TestHandlerStreamIntegrityUnderReorder(t *testing.T) {
	const (
		mtu           = ethernet.MaxMTU
		maxpackets    = 8
		segSize       = 100
		nsegs         = 8  // per round; 800 bytes through a 1500-byte ring
		rounds        = 40 // enough for the ring to wrap many times
		shuffleWindow = 4  // segments that may arrive in any order among themselves
	)
	rng := rand.New(rand.NewSource(3))
	client, server := newHandler(t, mtu, maxpackets), newHandler(t, mtu, maxpackets)
	setupClientServer(t, rng, client, server)
	var rawbuf [mtu]byte
	establish(t, client, server, rawbuf[:])

	var want, got []byte
	rb := make([]byte, mtu)
	letter := byte('A')
	for round := 0; round < rounds; round++ {
		// Capture this round's segments on the wire, one segment per write.
		segs := make([][]byte, 0, nsegs)
		for i := 0; i < nsegs; i++ {
			payload := make([]byte, segSize)
			for j := range payload {
				payload[j] = letter
			}
			letter++
			if letter > 'Z' {
				letter = 'A'
			}
			if n, err := client.Write(payload); err != nil || n != segSize {
				t.Fatalf("round %d: client write: %d %v", round, n, err)
			}
			clear(rawbuf[:])
			n, err := client.Send(rawbuf[:])
			if err != nil {
				t.Fatalf("round %d: client send: %v", round, err)
			}
			segs = append(segs, append([]byte(nil), rawbuf[:n]...))
			want = append(want, payload...)
		}

		order := make([]int, 0, nsegs)
		for i := 0; i < nsegs; i += shuffleWindow {
			block := make([]int, 0, shuffleWindow)
			for j := i; j < min(i+shuffleWindow, nsegs); j++ {
				block = append(block, j)
			}
			rng.Shuffle(len(block), func(a, b int) { block[a], block[b] = block[b], block[a] })
			order = append(order, block...)
		}

		for _, idx := range order {
			if err := server.Recv(append([]byte(nil), segs[idx]...)); err != nil {
				t.Logf("round %d segment %d refused: %v", round, idx, err)
			}
			// Drain as an application would, keeping the ring from filling.
			for {
				n, err := server.Read(rb)
				if n > 0 {
					got = append(got, rb[:n]...)
				}
				if n == 0 || err != nil {
					break
				}
			}
			// Feed ACKs back so the sender's window keeps opening; without this
			// the test stalls on flow control instead of exercising reassembly.
			clear(rawbuf[:])
			if n, err := server.Send(rawbuf[:]); err == nil && n > 0 {
				client.Recv(rawbuf[:n])
			}
		}

		if string(got) != string(want) {
			// Report the first divergence; later rounds only add noise.
			i := 0
			for i < len(got) && i < len(want) && got[i] == want[i] {
				i++
			}
			t.Errorf("stream diverges in round %d at byte %d of %d; arrival order %v",
				round, i, len(want), order)
			lo := max(0, i-200)
			t.Errorf("got  %s", summarizeRuns(got[lo:min(len(got), i+200)]))
			t.Errorf("want %s", summarizeRuns(want[lo:min(len(want), i+200)]))
			t.FailNow()
		}
	}
	t.Logf("%d bytes intact across %d rounds of reordering (window %d)", len(got), rounds, shuffleWindow)
}

// summarizeRuns renders a byte stream as run-length pairs ("A*100 B*100") so a
// duplicated or missing segment is visible at a glance.
func summarizeRuns(b []byte) string {
	out := make([]byte, 0, 64)
	for i := 0; i < len(b); {
		j := i
		for j < len(b) && b[j] == b[i] {
			j++
		}
		out = append(out, b[i], '*')
		out = append(out, strconv.Itoa(j-i)...)
		out = append(out, ' ')
		i = j
	}
	return string(out)
}
