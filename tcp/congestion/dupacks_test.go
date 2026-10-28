package congestion

import (
	"cmp"
	"testing"

	"github.com/soypat/lneto/tcp"
)

// TestIsDupACK verifies only an ACK of SND.UNA without data, SYN or FIN, with
// data in flight and the peer's window not grown, is a duplicate ACK.
func TestIsDupACK(t *testing.T) {
	const una, nxt = 1000, 2000
	for _, tc := range []struct {
		name    string
		seg     tcp.Segment
		unaNow  tcp.Value
		nxt     tcp.Value
		roomNow tcp.Size
		want    bool
	}{
		{name: "duplicate", seg: tcp.Segment{ACK: una, Flags: tcp.FlagACK}, want: true},
		{name: "window-grown", seg: tcp.Segment{ACK: una, Flags: tcp.FlagACK}, roomNow: 600},
		{name: "data", seg: tcp.Segment{ACK: una, Flags: tcp.FlagACK, DATALEN: 1}},
		{name: "fin", seg: tcp.Segment{ACK: una, Flags: tcp.FlagACK | tcp.FlagFIN}},
		{name: "new-data-acked", seg: tcp.Segment{ACK: una + 100, Flags: tcp.FlagACK}, unaNow: una + 100},
		{name: "nothing-in-flight", seg: tcp.Segment{ACK: una, Flags: tcp.FlagACK}, nxt: una},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unaNow, n, roomNow := cmp.Or(tc.unaNow, una), cmp.Or(tc.nxt, nxt), cmp.Or(tc.roomNow, 500)
			if got := isDupACK(tc.seg, una, unaNow, n, 500, roomNow); got != tc.want {
				t.Errorf("isDupACK = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDupACKs verifies three duplicate ACKs make a loss, an owed resend
// otherwise is a copy, a duplicate ACK at the next SND.UNA answers each copy
// instead of counting, and answers lapse once SND.UNA passes the data sent
// before the last copy.
func TestDupACKs(t *testing.T) {
	var d dupACKs
	for range 3 {
		d.dup(true)
	}
	if !d.owed(true) || d.owed(false) {
		t.Fatal("owed after three duplicate ACKs: want a loss if allowed, else none")
	}
	if !d.resent(1000, 1000, 2000) || d.resent(1100, 1000, 2000) {
		t.Fatal("resend of SND.UNA not a copy, or of other data a copy")
	}
	d.acked(1100)
	d.dup(true)
	if d.n != 0 {
		t.Fatalf("%d duplicate ACKs counted while one answers a copy, want 0", d.n)
	}
	d.dup(true)
	d.owed(false)
	d.resent(1100, 1100, 2000)
	d.acked(2001)
	if d.dup(true); d.n != 1 {
		t.Errorf("%d duplicate ACKs counted after SND.UNA passed the copies, want 1", d.n)
	}
}
