package congestion

import (
	"reflect"
	"testing"
	"time"

	"github.com/soypat/lneto/tcp"
)

// This file holds the shared behavioural contract exercised against every
// tcp.CongestionControl implementation in this package (requested in the PR #115
// review). Each controller is driven only through the tcp.CongestionControl
// interface (Control/Reset); the resulting congestion window is read back via
// CongestionWindow, which both controllers expose. The subtests assert
// algorithm-independent invariants and run for every controller in
// contractControllers, so a new controller is covered automatically once added:
//
//   - reset-reusable:   Reset restores the configured initial window and yields
//                       deterministic behaviour, so a connection can be reused
//                       without reconfiguration.
//   - no-congest-on-ok: sustained loss-free delivery opens the window and never
//                       collapses it to zero.
//   - congest-on-drop:  a loss/RTO signal never makes the controller more
//                       aggressive. The loss-based CUBIC reduces its window; the
//                       model-based BBR holds it steady. Neither may grow it.

const (
	contractMSS           tcp.Size  = 1000
	contractInitialCwnd   tcp.Size  = 10                                // segments.
	contractISS           tcp.Value = 1000                              // our initial send sequence.
	contractPeerSeq       tcp.Value = 0x5000_0000                       // peer sequence carried on our ACKs.
	contractBytesPerRound tcp.Size  = contractInitialCwnd * contractMSS // one initial window per round.
	contractRTT                     = 50 * time.Millisecond
	contractWarmupRounds            = 6
	contractHealthyRounds           = 8
)

// ccMake builds a freshly configured controller bound to the now clock.
type ccMake func(t *testing.T, now func() time.Time) tcp.CongestionControl

// contractControllers lists a constructor for every controller the package
// ships. Add new controllers here to bring them under the shared contract.
var contractControllers = []ccMake{
	func(t *testing.T, now func() time.Time) tcp.CongestionControl {
		t.Helper()
		c := new(CUBIC)
		if err := c.Configure(CUBICConfig{MSS: contractMSS, InitialCwnd: contractInitialCwnd, Now: now}); err != nil {
			t.Fatalf("configure CUBIC: %v", err)
		}
		return c
	},
	func(t *testing.T, now func() time.Time) tcp.CongestionControl {
		t.Helper()
		b := new(BBR)
		if err := b.Configure(BBRConfig{MSS: contractMSS, InitialCwnd: contractInitialCwnd, Now: now}); err != nil {
			t.Fatalf("configure BBR: %v", err)
		}
		return b
	},
}

// windowReporter is the read-only window accessor both controllers expose. The
// contract drives behaviour purely through tcp.CongestionControl and only reads
// the window through this accessor.
type windowReporter interface{ CongestionWindow() tcp.Size }

func window(t *testing.T, cc tcp.CongestionControl) tcp.Size {
	t.Helper()
	wr, ok := cc.(windowReporter)
	if !ok {
		t.Fatalf("%s does not expose CongestionWindow", ccName(cc))
	}
	return wr.CongestionWindow()
}

// ccName returns the controller's bare type name with no package qualifier, dot
// or pointer star, e.g. "CUBIC" or "BBR".
func ccName(cc tcp.CongestionControl) string {
	tp := reflect.TypeOf(cc)
	for tp.Kind() == reflect.Pointer {
		tp = tp.Elem()
	}
	return tp.Name()
}

// ccDriver couples a controller with the simulated clock and send-sequence
// cursor needed to feed it ordered tcp.CongestionEvents.
type ccDriver struct {
	cc    tcp.CongestionControl
	clock time.Time
	snd   tcp.Value
}

func newDriver(t *testing.T, newCC ccMake) *ccDriver {
	d := &ccDriver{clock: time.Unix(0, 0), snd: contractISS}
	d.cc = newCC(t, func() time.Time { return d.clock })
	return d
}

// healthyRound transmits one window of new data and acknowledges all of it one
// RTT later, modelling loss-free delivery. It returns the window reported by the
// acknowledging Control call.
func (d *ccDriver) healthyRound() tcp.Size {
	start := d.snd
	d.cc.Control(tcp.CongestionEvent{
		Segment: tcp.Segment{SEQ: start, ACK: contractPeerSeq, DATALEN: contractBytesPerRound, Flags: tcp.FlagPSH | tcp.FlagACK},
		SndUNA:  start, SndNXT: start, MSS: contractMSS, Tx: true,
	})
	d.clock = d.clock.Add(contractRTT)
	end := start + tcp.Value(contractBytesPerRound)
	wnd := d.cc.Control(tcp.CongestionEvent{
		Segment: tcp.Segment{SEQ: contractPeerSeq, ACK: end, Flags: tcp.FlagACK},
		SndUNA:  end, SndNXT: end, MSS: contractMSS,
	})
	d.snd = end
	return wnd
}

func TestCongestionControlContract(t *testing.T) {
	for _, newCC := range contractControllers {
		name := ccName(newDriver(t, newCC).cc)
		t.Run(name, func(t *testing.T) {
			t.Run("reset-reusable", func(t *testing.T) {
				d := newDriver(t, newCC)
				initial := window(t, d.cc)
				if initial == 0 {
					t.Fatal("initial congestion window must be positive")
				}
				for range contractWarmupRounds {
					d.healthyRound()
				}
				d.cc.Reset()
				if got := window(t, d.cc); got != initial {
					t.Errorf("Reset did not restore the initial window: got %d, want %d", got, initial)
				}
				// After Reset the controller must behave like a fresh sibling fed
				// the same events: per-connection state is fully cleared and the
				// controller is deterministic given the injected clock.
				d.clock, d.snd = time.Unix(0, 0), contractISS
				for range contractWarmupRounds {
					d.healthyRound()
				}
				sib := newDriver(t, newCC)
				for range contractWarmupRounds {
					sib.healthyRound()
				}
				if got, want := window(t, d.cc), window(t, sib.cc); got != want {
					t.Errorf("reused controller diverged from a fresh one: got %d, want %d", got, want)
				}
			})

			t.Run("no-congest-on-ok", func(t *testing.T) {
				d := newDriver(t, newCC)
				initial := window(t, d.cc)
				for round := range contractHealthyRounds {
					if w := d.healthyRound(); w == 0 {
						t.Fatalf("round %d: window collapsed to zero under loss-free delivery", round)
					}
				}
				if got := window(t, d.cc); got <= initial {
					t.Errorf("window did not open under sustained loss-free delivery: %d -> %d", initial, got)
				}
			})

			t.Run("congest-on-drop", func(t *testing.T) {
				warm := func() *ccDriver {
					d := newDriver(t, newCC)
					for range contractWarmupRounds {
						d.healthyRound()
					}
					return d
				}
				// An RTO must never increase the window: CUBIC collapses to the
				// loss window, the model-based BBR holds steady.
				d := warm()
				before := window(t, d.cc)
				d.clock = d.clock.Add(contractRTT)
				if after := d.cc.Control(tcp.CongestionEvent{RTO: true}); after > before {
					t.Errorf("RTO increased the congestion window: %d -> %d", before, after)
				}
				// A duplicate-ACK loss signal likewise must not increase it.
				dup := warm()
				beforeDup := window(t, dup.cc)
				afterDup := dup.cc.Control(tcp.CongestionEvent{
					Segment: tcp.Segment{SEQ: contractPeerSeq, ACK: dup.snd, Flags: tcp.FlagACK},
					SndUNA:  dup.snd, SndNXT: dup.snd + tcp.Value(contractBytesPerRound), Dupacks: dupackLossThresh,
				})
				if afterDup > beforeDup {
					t.Errorf("duplicate-ACK loss increased the congestion window: %d -> %d", beforeDup, afterDup)
				}
				// A drop must never leave a larger window than continuing cleanly
				// from the same warmed-up state would have.
				ok, drop := warm(), warm()
				wOK := ok.healthyRound()
				drop.clock = drop.clock.Add(contractRTT)
				wDrop := drop.cc.Control(tcp.CongestionEvent{RTO: true})
				if wDrop > wOK {
					t.Errorf("a drop yielded a larger window (%d) than a clean round (%d)", wDrop, wOK)
				}
			})
		})
	}
}
