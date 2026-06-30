package pcap

import (
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/udp"
)

const benchSubfieldLimit = 32

// buildDHCPPacket builds an Ethernet+IPv4+UDP+DHCPv4 Discover packet, exercising
// the option-heavy DHCP path (hostname, client id, requested address, param list).
func buildDHCPPacket(b testing.TB) []byte {
	const (
		ethSize  = 14
		ipv4Size = 20
		udpSize  = 8
	)
	pkt := make([]byte, 600)

	efrm, _ := ethernet.NewFrame(pkt)
	*efrm.DestinationHardwareAddr() = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	*efrm.SourceHardwareAddr() = [6]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	efrm.SetEtherType(ethernet.TypeIPv4)

	ifrm, _ := ipv4.NewFrame(pkt[ethSize:])
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetID(0x1234)
	ifrm.SetFlags(0x4000)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)

	ufrm, _ := udp.NewFrame(pkt[ethSize+ipv4Size:])
	ufrm.SetSourcePort(dhcpv4.DefaultClientPort)
	ufrm.SetDestinationPort(dhcpv4.DefaultServerPort)

	var cl dhcpv4.Client
	err := cl.BeginRequest(0xdeadbeef, dhcpv4.RequestConfig{
		RequestedAddr:      [4]byte{192, 168, 1, 100},
		ClientHardwareAddr: [6]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
		Hostname:           "myhost",
		ClientID:           "lneto-test",
	})
	if err != nil {
		b.Fatal("begin request:", err)
	}
	dhcpLen, err := cl.Encapsulate(pkt, ethSize, ethSize+ipv4Size+udpSize)
	if err != nil {
		b.Fatal("encapsulate:", err)
	}
	totalLen := ipv4Size + udpSize + dhcpLen
	ifrm.SetTotalLength(uint16(totalLen))
	ufrm.SetLength(uint16(udpSize + dhcpLen))
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())
	return pkt[:ethSize+totalLen]
}

// buildDNSPacket builds an Ethernet+IPv4+UDP+DNS message with multiple questions
// and answers, exercising name encoding and resource record rendering.
func buildDNSPacket(b testing.TB) []byte {
	const (
		ethSize  = 14
		ipv4Size = 20
		udpSize  = 8
	)
	var msg dns.Message
	msg.Questions = []dns.Question{
		{Name: dns.MustNewName("example.com"), Type: dns.TypeA, Class: dns.ClassINET},
		{Name: dns.MustNewName("temu.com"), Type: dns.TypeAAAA, Class: dns.ClassANY},
	}
	msg.Answers = []dns.Resource{
		dns.NewResource(dns.MustNewName("abc.com"), dns.TypeALL, dns.ClassANY, 64, []byte{10, 0, 11, 1}),
		dns.NewResource(dns.MustNewName("123.com"), dns.TypeA, dns.ClassINET, 64, []byte{20, 0, 22, 2}),
	}
	dnsPayload, err := msg.AppendTo(nil, 0x1234, dns.NewClientHeaderFlags(dns.OpCodeQuery, true))
	if err != nil {
		b.Fatal("dns encode:", err)
	}

	pkt := make([]byte, ethSize+ipv4Size+udpSize+len(dnsPayload))

	efrm, _ := ethernet.NewFrame(pkt)
	*efrm.DestinationHardwareAddr() = [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	*efrm.SourceHardwareAddr() = [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	efrm.SetEtherType(ethernet.TypeIPv4)

	ifrm, _ := ipv4.NewFrame(pkt[ethSize:])
	ifrm.SetVersionAndIHL(4, 5)
	ifrm.SetTTL(64)
	ifrm.SetProtocol(lneto.IPProtoUDP)
	ifrm.SetTotalLength(uint16(ipv4Size + udpSize + len(dnsPayload)))
	ifrm.SetCRC(ifrm.CalculateHeaderCRC())

	ufrm, _ := udp.NewFrame(pkt[ethSize+ipv4Size:])
	ufrm.SetSourcePort(58200)
	ufrm.SetDestinationPort(dns.ServerPort)
	ufrm.SetLength(uint16(udpSize + len(dnsPayload)))

	copy(pkt[ethSize+ipv4Size+udpSize:], dnsPayload)
	return pkt
}

func configureBenchFormatter(f *Formatter) {
	f.SubfieldLimit = benchSubfieldLimit
	f.FrameSep = "\n"
	f.FieldSep = "; "
	f.SubfieldSep = "\n\t"
}

// BenchmarkPcap measures the decode, format, and decode+format (roundtrip) phases
// separately for the string-heavy DHCP and DNS frames. Run with -benchmem for
// per-phase allocs/op.
func BenchmarkPcap(b *testing.B) {
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"DHCP", buildDHCPPacket(b)},
		{"DNS", buildDNSPacket(b)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.Run("decode", func(b *testing.B) {
				var pb PacketBreakdown
				pb.SubfieldLimit = benchSubfieldLimit
				var frames []Frame
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					frames, _ = pb.CaptureEthernet(frames[:0], tc.pkt, 0)
				}
			})
			b.Run("format", func(b *testing.B) {
				var pb PacketBreakdown
				pb.SubfieldLimit = benchSubfieldLimit
				frames, err := pb.CaptureEthernet(nil, tc.pkt, 0)
				if err != nil {
					b.Fatal(err)
				}
				var f Formatter
				configureBenchFormatter(&f)
				var buf []byte
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					buf, _ = f.FormatFrames(buf[:0], frames, tc.pkt)
				}
			})
			b.Run("roundtrip", func(b *testing.B) {
				var pb PacketBreakdown
				pb.SubfieldLimit = benchSubfieldLimit
				var f Formatter
				configureBenchFormatter(&f)
				var frames []Frame
				var buf []byte
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					frames, _ = pb.CaptureEthernet(frames[:0], tc.pkt, 0)
					buf, _ = f.FormatFrames(buf[:0], frames, tc.pkt)
				}
			})
		})
	}
}

// BenchmarkPcapPhases runs decode+format in a single benchmark loop while
// reporting per-phase wall time via custom metrics (decode-ns/op, format-ns/op).
// decode-ns/op + format-ns/op approximates ns/op minus time.Now overhead.
// Per-phase allocs are not split here (ReadMemStats is STW and skews timing);
// use BenchmarkPcap's decode/format sub-benchmarks with -benchmem for that.
func BenchmarkPcapPhases(b *testing.B) {
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"DHCP", buildDHCPPacket(b)},
		{"DNS", buildDNSPacket(b)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var pb PacketBreakdown
			pb.SubfieldLimit = benchSubfieldLimit
			var f Formatter
			configureBenchFormatter(&f)
			var frames []Frame
			var buf []byte
			var decNs, fmtNs int64
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t0 := time.Now()
				frames, _ = pb.CaptureEthernet(frames[:0], tc.pkt, 0)
				t1 := time.Now()
				buf, _ = f.FormatFrames(buf[:0], frames, tc.pkt)
				t2 := time.Now()
				decNs += t1.Sub(t0).Nanoseconds()
				fmtNs += t2.Sub(t1).Nanoseconds()
			}
			b.ReportMetric(float64(decNs)/float64(b.N), "decode-ns/op")
			b.ReportMetric(float64(fmtNs)/float64(b.N), "format-ns/op")
		})
	}
}
