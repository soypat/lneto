package udp

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

func newTestPacketConn(t *testing.T) *PacketConn {
	t.Helper()
	var pc PacketConn
	err := pc.Configure(PacketConnConfig{
		RxBuf:       make([]byte, 256),
		TxBuf:       make([]byte, 256),
		RxQueueSize: 4,
		TxQueueSize: 4,
		RWBackoff:   backoffYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &pc
}

func TestPacketConnOpenPortRange(t *testing.T) {
	addr := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	tests := []struct {
		name      string
		port, n   uint16
		wantErr   error
		wantStart uint16
		wantN     uint16
	}{
		{name: "zero port", port: 0, n: 4, wantErr: lneto.ErrZeroSource},
		{name: "zero ports", port: 9000, n: 0, wantErr: lneto.ErrInvalidConfig},
		{name: "past 65535", port: 65535, n: 2, wantErr: lneto.ErrInvalidConfig},
		{name: "single", port: 9000, n: 1, wantStart: 9000, wantN: 1},
		{name: "up to 65535", port: 65530, n: 6, wantStart: 65530, wantN: 6},
		{name: "all ports", port: 1, n: 65535, wantStart: 1, wantN: 65535},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pc := newTestPacketConn(t)
			err := pc.OpenPortRange(netip.AddrPortFrom(addr, tc.port), tc.n)
			if err != tc.wantErr {
				t.Fatalf("got err %v, want %v", err, tc.wantErr)
			}
			start, n := pc.LocalPortRange()
			if start != tc.wantStart || n != tc.wantN {
				t.Errorf("LocalPortRange() = (%d,%d), want (%d,%d)", start, n, tc.wantStart, tc.wantN)
			}
		})
	}
}

func TestPacketConnOpenIsSinglePortRange(t *testing.T) {
	pc := newTestPacketConn(t)
	if err := pc.Open(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 9000)); err != nil {
		t.Fatal(err)
	}
	if start, n := pc.LocalPortRange(); start != 9000 || n != 1 {
		t.Errorf("LocalPortRange() = (%d,%d), want (9000,1)", start, n)
	}
}

func TestPacketConnPortRangeDemuxRead(t *testing.T) {
	const remotePort = 5353
	tests := []struct {
		name       string
		start, n   uint16
		dst        uint16
		wantFilter bool // Datagram rejected by port filter.
	}{
		{name: "below", start: 9000, n: 4, dst: 8999, wantFilter: true},
		{name: "first", start: 9000, n: 4, dst: 9000},
		{name: "last", start: 9000, n: 4, dst: 9003},
		{name: "above", start: 9000, n: 4, dst: 9004, wantFilter: true},
		{name: "port 65535", start: 65530, n: 6, dst: 65535},
		{name: "all ports", start: 1, n: 65535, dst: 65535},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pc := newTestPacketConn(t)
			if err := pc.OpenPortRange(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), tc.start), tc.n); err != nil {
				t.Fatal(err)
			}
			payload := []byte("dgram")
			err := pc.Demux(makeUDPFrame(remotePort, tc.dst, payload), 0)
			if tc.wantFilter {
				if err != lneto.ErrMismatch {
					t.Fatalf("got err %v, want %v", err, lneto.ErrMismatch)
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			var buf [64]byte
			n, lport, raddr, err := pc.ReadFromLocal(buf[:])
			if err != nil {
				t.Fatal(err)
			}
			if !internal.BytesEqual(buf[:n], payload) {
				t.Errorf("payload %q, want %q", buf[:n], payload)
			}
			if lport != tc.dst {
				t.Errorf("lport %d, want %d", lport, tc.dst)
			}
			if raddr.Port() != remotePort {
				t.Errorf("remote port %d, want %d", raddr.Port(), remotePort)
			}
		})
	}
}

func TestPacketConnWriteToLocal(t *testing.T) {
	raddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 5353)
	tests := []struct {
		name    string
		lport   uint16 // Zero means WriteTo.
		wantErr error
		wantSrc uint16
	}{
		{name: "WriteTo uses start", wantSrc: 9000},
		{name: "first", lport: 9000, wantSrc: 9000},
		{name: "last", lport: 9003, wantSrc: 9003},
		{name: "below", lport: 8999, wantErr: lneto.ErrInvalidAddr},
		{name: "above", lport: 9004, wantErr: lneto.ErrInvalidAddr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pc := newTestPacketConn(t)
			if err := pc.OpenPortRange(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 9000), 4); err != nil {
				t.Fatal(err)
			}
			payload := []byte("reply")
			var err error
			if tc.lport == 0 {
				_, err = pc.WriteTo(payload, raddr)
			} else {
				_, err = pc.WriteToLocal(payload, tc.lport, raddr)
			}
			if err != tc.wantErr {
				t.Fatalf("got err %v, want %v", err, tc.wantErr)
			}
			var buf [64]byte
			n, err := pc.Encapsulate(buf[:], -1, 0)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != nil {
				if n != 0 {
					t.Fatalf("rejected write sent %d bytes", n)
				}
				return
			}
			ufrm, err := NewFrame(buf[:n])
			if err != nil {
				t.Fatal(err)
			}
			if ufrm.SourcePort() != tc.wantSrc {
				t.Errorf("src port %d, want %d", ufrm.SourcePort(), tc.wantSrc)
			}
			if ufrm.DestinationPort() != raddr.Port() {
				t.Errorf("dst port %d, want %d", ufrm.DestinationPort(), raddr.Port())
			}
		})
	}
}
