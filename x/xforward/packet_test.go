package xforward_test

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/xforward"
)

func TestValidatePacket(t *testing.T) {
	v4a, v4b := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("192.0.2.1")
	v6a, v6b := netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::1")
	syn := tcpSeg(40000, 443, 1000, 0, tcp.FlagSYN, nil)
	dgram := udpDgram(5353, 53, []byte("query"))
	tcp4 := buildIP(v4a, v4b, lneto.IPProtoTCP, syn)
	udp4 := buildIP(v4a, v4b, lneto.IPProtoUDP, dgram)
	udp6 := buildIP(v6a, v6b, lneto.IPProtoUDP, dgram)
	// mod returns a copy of pkt changed by fn, refreshing the IPv4 header checksum.
	mod := func(pkt []byte, fn func(b []byte)) []byte {
		b := append([]byte(nil), pkt...)
		fn(b)
		if b[0]>>4 == 4 {
			binary.BigEndian.PutUint16(b[10:], 0)
			var crc lneto.CRC791
			crc.WriteEven(b[:20])
			binary.BigEndian.PutUint16(b[10:], crc.Sum16())
		}
		return b
	}
	idTCP4 := xforward.FlowID{Local: netip.AddrPortFrom(v4b, 443), Remote: netip.AddrPortFrom(v4a, 40000)}
	idTCP6 := xforward.FlowID{Local: netip.AddrPortFrom(v6b, 443), Remote: netip.AddrPortFrom(v6a, 40000)}
	idUDP4 := xforward.FlowID{Local: netip.AddrPortFrom(v4b, 53), Remote: netip.AddrPortFrom(v4a, 5353)}
	idUDP6 := xforward.FlowID{Local: netip.AddrPortFrom(v6b, 53), Remote: netip.AddrPortFrom(v6a, 5353)}
	exts := []lneto.IPProto{lneto.IPProtoHopByHop, lneto.IPProtoIPv6Route, lneto.IPProtoIPv6Opts}
	tooMany := []lneto.IPProto{lneto.IPProtoHopByHop, lneto.IPProtoIPv6Opts, lneto.IPProtoIPv6Opts, lneto.IPProtoIPv6Opts, lneto.IPProtoIPv6Opts}
	for _, tc := range []struct {
		name      string
		pkt       []byte
		wantErr   error
		wantProto lneto.IPProto
		wantID    xforward.FlowID
		wantLen   int // 0 means len(pkt).
	}{
		{name: "ipv4 tcp", pkt: tcp4, wantProto: lneto.IPProtoTCP, wantID: idTCP4},
		{name: "ipv4 udp", pkt: udp4, wantProto: lneto.IPProtoUDP, wantID: idUDP4},
		{name: "ipv6 tcp", pkt: buildIP(v6a, v6b, lneto.IPProtoTCP, syn), wantProto: lneto.IPProtoTCP, wantID: idTCP6},
		{name: "ipv6 udp", pkt: udp6, wantProto: lneto.IPProtoUDP, wantID: idUDP6},
		{name: "ipv6 extension headers", pkt: buildIP(v6a, v6b, lneto.IPProtoTCP, syn, exts...), wantProto: lneto.IPProtoTCP, wantID: idTCP6},
		{name: "ipv4 link padding trimmed", pkt: append(append([]byte(nil), udp4...), 0, 0, 0, 0), wantProto: lneto.IPProtoUDP, wantID: idUDP4, wantLen: len(udp4)},
		{name: "ipv4 udp zero checksum", pkt: mod(udp4, func(b []byte) { b[26], b[27] = 0, 0 }), wantProto: lneto.IPProtoUDP, wantID: idUDP4},
		{name: "icmp", pkt: buildIP(v4a, v4b, lneto.IPProtoICMP, make([]byte, 8)), wantProto: lneto.IPProtoICMP,
			wantID: xforward.FlowID{Local: netip.AddrPortFrom(v4b, 0), Remote: netip.AddrPortFrom(v4a, 0)}},
		{name: "empty", pkt: nil, wantErr: lneto.ErrTruncatedFrame},
		{name: "ip version 5", pkt: mod(tcp4, func(b []byte) { b[0] = 5<<4 | 5 }), wantErr: lneto.ErrUnsupported},
		{name: "ipv4 truncated", pkt: tcp4[:30], wantErr: lneto.ErrTruncatedFrame},
		{name: "ipv4 ihl too small", pkt: mod(tcp4, func(b []byte) { b[0] = 4<<4 | 4 }), wantErr: lneto.ErrInvalidLengthField},
		{name: "ipv4 bad header checksum", pkt: append(append([]byte(nil), tcp4[:10]...), append([]byte{tcp4[10] ^ 1}, tcp4[11:]...)...), wantErr: lneto.ErrBadCRC},
		{name: "ipv4 more fragments", pkt: mod(tcp4, func(b []byte) { b[6] |= 0x20 }), wantErr: lneto.ErrUnsupported},
		{name: "ipv4 fragment offset", pkt: mod(tcp4, func(b []byte) { b[7] = 1 }), wantErr: lneto.ErrUnsupported},
		{name: "ipv4 bad tcp checksum", pkt: mod(tcp4, func(b []byte) { b[len(b)-1] ^= 1 }), wantErr: lneto.ErrBadCRC},
		{name: "ipv6 bad udp checksum", pkt: mod(udp6, func(b []byte) { b[len(b)-1] ^= 1 }), wantErr: lneto.ErrBadCRC},
		{name: "ipv6 udp zero checksum", pkt: mod(udp6, func(b []byte) { b[46], b[47] = 0, 0 }), wantErr: lneto.ErrBadCRC},
		{name: "ipv6 fragment", pkt: buildIP(v6a, v6b, lneto.IPProtoTCP, syn, lneto.IPProtoIPv6Frag), wantErr: lneto.ErrUnsupported},
		{name: "ipv6 extension chain too long", pkt: buildIP(v6a, v6b, lneto.IPProtoTCP, syn, tooMany...), wantErr: lneto.ErrUnsupported},
		{name: "ipv6 v4-mapped source", pkt: buildIP(netip.MustParseAddr("::ffff:10.0.0.2"), v6b, lneto.IPProtoTCP, syn), wantErr: lneto.ErrInvalidAddr},
		{name: "tcp zero destination port", pkt: buildIP(v4a, v4b, lneto.IPProtoTCP, tcpSeg(40000, 0, 1, 0, tcp.FlagSYN, nil)), wantErr: lneto.ErrZeroDestination},
		{name: "udp zero source port", pkt: buildIP(v4a, v4b, lneto.IPProtoUDP, udpDgram(0, 53, nil)), wantErr: lneto.ErrZeroSource},
		{name: "unsupported protocol", pkt: buildIP(v4a, v4b, lneto.IPProtoGRE, make([]byte, 8)), wantErr: lneto.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var vld lneto.Validator
			p, err := xforward.ValidatePacket(tc.pkt, &vld)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err %v, want %v", err, tc.wantErr)
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			wantLen := tc.wantLen
			if wantLen == 0 {
				wantLen = len(tc.pkt)
			}
			if p.Proto() != tc.wantProto {
				t.Errorf("proto %s, want %s", p.Proto(), tc.wantProto)
			}
			if p.ID() != tc.wantID {
				t.Errorf("ID %v, want %v", p.ID(), tc.wantID)
			}
			if len(p.RawData()) != wantLen {
				t.Errorf("RawData length %d, want %d", len(p.RawData()), wantLen)
			}
		})
	}
}

func FuzzValidatePacket(f *testing.F) {
	v4a, v4b := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("192.0.2.1")
	v6a, v6b := netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::1")
	syn := tcpSeg(40000, 443, 1000, 0, tcp.FlagSYN, []byte("data"))
	dgram := udpDgram(5353, 53, []byte("query"))
	f.Add(buildIP(v4a, v4b, lneto.IPProtoTCP, syn))
	f.Add(buildIP(v4a, v4b, lneto.IPProtoUDP, dgram))
	f.Add(buildIP(v6a, v6b, lneto.IPProtoTCP, syn, lneto.IPProtoHopByHop, lneto.IPProtoIPv6Opts))
	f.Add(buildIP(v6a, v6b, lneto.IPProtoUDP, dgram))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		var vld lneto.Validator
		p, err := xforward.ValidatePacket(pkt, &vld)
		if err != nil {
			return
		}
		raw := p.RawData()
		if len(raw) > len(pkt) || p.TransportOffset() > len(raw) {
			t.Fatalf("view out of bounds: raw=%d toff=%d in=%d", len(raw), p.TransportOffset(), len(pkt))
		}
		p2, err := xforward.ValidatePacket(raw, &vld)
		if err != nil || p2.ID() != p.ID() || len(p2.RawData()) != len(raw) {
			t.Fatalf("revalidating view: err=%v", err)
		}
	})
}
