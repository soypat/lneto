package internet

import (
	"encoding/binary"
	"sync/atomic"
	"testing"

	"github.com/soypat/lneto"
)

// portRecorder is a UDP StackNode that records the destination port of each frame demuxed to it.
type portRecorder struct {
	connID atomic.Uint32
	lport  uint16
	got    []uint16
}

func (r *portRecorder) LocalPort() uint16            { return r.lport }
func (r *portRecorder) Protocol() uint64             { return uint64(lneto.IPProtoUDP) }
func (r *portRecorder) ConnectionID() *atomic.Uint32 { return &r.connID }
func (r *portRecorder) Encapsulate([]byte, int, int) (int, error) {
	return 0, nil
}
func (r *portRecorder) Demux(b []byte, off int) error {
	r.got = append(r.got, binary.BigEndian.Uint16(b[off+2:]))
	return nil
}

func udpHeaderTo(dst uint16) []byte {
	var b [8]byte
	binary.BigEndian.PutUint16(b[2:], dst)
	binary.BigEndian.PutUint16(b[4:], 8)
	return b[:]
}

func TestStackPortsRegisterPortRange(t *testing.T) {
	type reg struct {
		start, n uint16
		exact    bool // Register with LocalPort()=start instead of RegisterPortRange.
		wantErr  error
	}
	tests := []struct {
		name string
		regs []reg
	}{
		{name: "zero start", regs: []reg{{start: 0, n: 4, wantErr: lneto.ErrZeroSource}}},
		{name: "zero ports", regs: []reg{{start: 100, n: 0, wantErr: lneto.ErrInvalidConfig}}},
		{name: "past 65535", regs: []reg{{start: 65535, n: 2, wantErr: lneto.ErrInvalidConfig}}},
		{name: "all ports", regs: []reg{{start: 1, n: 65535}}},
		{name: "exact inside range", regs: []reg{{start: 100, n: 10}, {start: 105, exact: true, wantErr: lneto.ErrAlreadyRegistered}}},
		{name: "range over exact", regs: []reg{{start: 105, exact: true}, {start: 100, n: 10, wantErr: lneto.ErrAlreadyRegistered}}},
		{name: "overlap tail", regs: []reg{{start: 100, n: 10}, {start: 109, n: 5, wantErr: lneto.ErrAlreadyRegistered}}},
		{name: "overlap head", regs: []reg{{start: 100, n: 10}, {start: 95, n: 6, wantErr: lneto.ErrAlreadyRegistered}}},
		{name: "range inside range", regs: []reg{{start: 100, n: 10}, {start: 102, n: 2, wantErr: lneto.ErrAlreadyRegistered}}},
		{name: "adjacent", regs: []reg{{start: 100, n: 10}, {start: 110, n: 5}, {start: 95, n: 5}, {start: 115, exact: true}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ps StackPorts
			ps.ResetUDP(uint16(len(tc.regs)))
			for i, r := range tc.regs {
				node := &portRecorder{lport: r.start}
				var err error
				if r.exact {
					err = ps.Register(node)
				} else {
					err = ps.RegisterPortRange(node, r.start, r.n)
				}
				if err != r.wantErr {
					t.Fatalf("reg[%d] start=%d n=%d: got err %v, want %v", i, r.start, r.n, err, r.wantErr)
				}
			}
		})
	}
}

func TestStackPortsPortRangeDemux(t *testing.T) {
	var ps StackPorts
	ps.ResetUDP(3)
	var low, exact, high portRecorder
	if err := ps.RegisterPortRange(&low, 100, 10); err != nil {
		t.Fatal(err)
	}
	exact.lport = 110
	if err := ps.Register(&exact); err != nil {
		t.Fatal(err)
	}
	if err := ps.RegisterPortRange(&high, 65000, 536); err != nil { // Up to and including 65535.
		t.Fatal(err)
	}
	tests := []struct {
		port uint16
		want *portRecorder // nil means dropped.
	}{
		{port: 99},
		{port: 100, want: &low},
		{port: 109, want: &low},
		{port: 110, want: &exact},
		{port: 111},
		{port: 64999},
		{port: 65000, want: &high},
		{port: 65535, want: &high},
	}
	for _, tc := range tests {
		for _, r := range []*portRecorder{&low, &exact, &high} {
			r.got = r.got[:0]
		}
		err := ps.Demux(udpHeaderTo(tc.port), 0)
		if tc.want == nil {
			if err != lneto.ErrPacketDrop {
				t.Errorf("port %d: got err %v, want %v", tc.port, err, lneto.ErrPacketDrop)
			}
			continue
		}
		if err != nil {
			t.Errorf("port %d: %v", tc.port, err)
		} else if len(tc.want.got) != 1 || tc.want.got[0] != tc.port {
			t.Errorf("port %d: receiving node got %v", tc.port, tc.want.got)
		}
	}
}

func TestStackPortsPortRangeReuseAfterClose(t *testing.T) {
	var ps StackPorts
	ps.ResetUDP(1)
	var old, cur portRecorder
	if err := ps.RegisterPortRange(&old, 100, 10); err != nil {
		t.Fatal(err)
	}
	// Rejected as overlap or, when capacity is exactly one node, as exhausted.
	if err := ps.RegisterPortRange(&cur, 105, 10); err == nil {
		t.Fatal("registered over a live range")
	}
	old.ConnectionID().Add(1) // Closes old's registration.
	if err := ps.RegisterPortRange(&cur, 105, 10); err != nil {
		t.Fatal("register after close:", err)
	}
	if err := ps.Demux(udpHeaderTo(100), 0); err != lneto.ErrPacketDrop {
		t.Errorf("port of closed range: got err %v, want %v", err, lneto.ErrPacketDrop)
	}
	if err := ps.Demux(udpHeaderTo(114), 0); err != nil || len(cur.got) != 1 {
		t.Errorf("port of new range: err=%v got=%v", err, cur.got)
	}
}

func TestStackPortsNextFreePortSkipsRanges(t *testing.T) {
	tests := []struct {
		name          string
		ranges        [][2]uint16 // start, numPorts.
		start, inc, n uint16
		want          uint16
	}{
		{name: "inside range", ranges: [][2]uint16{{100, 100}}, start: 150, inc: 4, n: 16, want: 200},
		{name: "range start", ranges: [][2]uint16{{100, 100}}, start: 100, inc: 1, n: 2, want: 200},
		{name: "back to back ranges", ranges: [][2]uint16{{100, 100}, {200, 50}}, start: 150, inc: 4, n: 16, want: 250},
		{name: "wraps past 65535", ranges: [][2]uint16{{65000, 536}}, start: 65100, inc: 1, n: 16, want: 1},
		{name: "all ports taken", ranges: [][2]uint16{{1, 65535}}, start: 500, inc: 1, n: 16, want: 0},
		{name: "too few checks", ranges: [][2]uint16{{100, 100}}, start: 150, inc: 4, n: 1, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ps StackPorts
			ps.ResetUDP(uint16(len(tc.ranges)))
			for _, r := range tc.ranges {
				if err := ps.RegisterPortRange(&portRecorder{}, r[0], r[1]); err != nil {
					t.Fatal(err)
				}
			}
			got := ps.NextFreePort(tc.start, tc.inc, tc.n)
			if got != tc.want {
				t.Errorf("NextFreePort(%d,%d,%d) = %d, want %d", tc.start, tc.inc, tc.n, got, tc.want)
			}
		})
	}
}
