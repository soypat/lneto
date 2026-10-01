package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

type deadlinePolicy struct {
	*recordingPolicy
	deadline int64
}

func (p deadlinePolicy) NextDeadline() int64 { return p.deadline }

func TestComposite_Add(t *testing.T) {
	var c Composite
	if err := c.Add(nil); err == nil {
		t.Error("nil policy added")
	}
	for range MaxComposedPolicies {
		if err := c.Add(newRecordingPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Add(newRecordingPolicy()); err == nil {
		t.Error("added more than MaxComposedPolicies")
	}
}

// TestComposite_Merge verifies the merge rules: the smallest new-data limit,
// the lowest requested retransmission and a segment kept only if every member
// keeps it, with every member asked regardless of the others' answers.
func TestComposite_Merge(t *testing.T) {
	const una = Value(1000)
	type member struct {
		limit Size
		rtx   bool
		from  Value
		keep  bool
	}
	for _, tc := range []struct {
		name      string
		members   []member
		wantLimit Size
		wantRtx   bool
		wantFrom  Value
		wantKeep  bool
	}{
		{name: "empty", wantLimit: TransmitUnlimited, wantKeep: true},
		{
			name:      "smallest-limit",
			members:   []member{{limit: TransmitUnlimited, keep: true}, {limit: 10, keep: true}, {limit: 20, keep: true}},
			wantLimit: 10, wantKeep: true,
		},
		{
			name:      "lowest-retransmit",
			members:   []member{{limit: TransmitUnlimited, rtx: true, from: una + 500, keep: true}, {limit: TransmitUnlimited, keep: true}, {limit: TransmitUnlimited, rtx: true, from: una, keep: true}},
			wantLimit: TransmitUnlimited, wantRtx: true, wantFrom: una, wantKeep: true,
		},
		{
			name:      "one-drops",
			members:   []member{{limit: TransmitUnlimited, keep: false}, {limit: TransmitUnlimited, keep: true}},
			wantLimit: TransmitUnlimited, wantKeep: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Composite
			var recs []*recordingPolicy
			for _, m := range tc.members {
				p := newRecordingPolicy()
				p.txLimit, p.retransmit, p.rtxFrom, p.keep = m.limit, m.rtx, m.from, m.keep
				recs = append(recs, p)
				if err := c.Add(p); err != nil {
					t.Fatal(err)
				}
			}
			frm, _ := NewFrame(make([]byte, sizeHeaderTCP))
			frm.SetOffsetAndFlags(5, FlagACK)
			limit, from, rtx := c.PreTx(nil, frm)
			if limit != tc.wantLimit || rtx != tc.wantRtx || (rtx && from != tc.wantFrom) {
				t.Errorf("PreTx = (%d, %d, %v), want (%d, %d, %v)", limit, from, rtx, tc.wantLimit, tc.wantFrom, tc.wantRtx)
			}
			if keep := c.PreRx(nil, frm); keep != tc.wantKeep {
				t.Errorf("PreRx = %v, want %v", keep, tc.wantKeep)
			}
			for i, p := range recs {
				if p.preTx != 1 || len(p.preRx) != 1 {
					t.Errorf("member %d asked PreTx %d, PreRx %d times; want 1 each", i, p.preTx, len(p.preRx))
				}
			}
		})
	}
}

func TestComposite_NextDeadline(t *testing.T) {
	var c Composite
	for _, p := range []Policy{deadlinePolicy{newRecordingPolicy(), 0}, newRecordingPolicy(), deadlinePolicy{newRecordingPolicy(), 30}, deadlinePolicy{newRecordingPolicy(), 20}} {
		if err := c.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	if got := c.NextDeadline(); got != 20 {
		t.Errorf("NextDeadline = %d, want 20", got)
	}
}

// TestComposite_Handler verifies a Composite installed on a Handler relays every
// hook to each member through a handshake.
func TestComposite_Handler(t *testing.T) {
	const mtu = ethernet.MaxMTU
	client, server := newHandler(t, mtu, 3), newHandler(t, mtu, 3)
	a, b := newRecordingPolicy(), newRecordingPolicy()
	var c Composite
	if err := c.Add(a); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(b); err != nil {
		t.Fatal(err)
	}
	client.SetPolicy(&c)
	setupClientServer(t, rand.New(rand.NewSource(2)), client, server)
	var buf [mtu]byte
	establish(t, client, server, buf[:])
	for i, p := range []*recordingPolicy{a, b} {
		if p.resets == 0 || p.preTx == 0 || len(p.postTx) == 0 || len(p.preRx) == 0 || len(p.postRx) == 0 {
			t.Errorf("member %d missed hooks: resets=%d preTx=%d postTx=%d preRx=%d postRx=%d", i, p.resets, p.preTx, len(p.postTx), len(p.preRx), len(p.postRx))
		}
	}
}
