package xnet

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

func FuzzStackPacketHTTP(f *testing.F) {
	const MTU = ethernet.MaxMTU
	const seed = 1
	var buf [ethernet.MaxFrameLength]byte
	s1, s2, c1, c2 := newTCPStacks(f, seed, MTU)
	var hdr httpraw.Header
	err := s1.ListenTCP(c1, 80)
	if err != nil {
		f.Fatal(err)
	}
	err = s2.DialTCP(c2, 1337, netip.AddrPortFrom(s1.Addr(), c1.LocalPort()))
	if err != nil {
		f.Fatal(err)
	}
	hdr.SetMethod("GET")
	hdr.SetProtocol("HTTP/1.1")
	hdr.SetRequestURI("/")
	data := hdr.AppendHeaders(nil)

	pktnum := 0
	written := false
	closed := false
	for {
		n1, err := s1.EgressEthernet(buf[:])
		if err != nil {
			f.Fatal(err)
		}
		if n1 > 0 {
			err = s2.IngressEthernet(buf[:n1])
			if err != nil {
				f.Fatal(err)
			}
			f.Add(pktnum, buf[:n1])
			pktnum++
			if !written && c2.State() >= tcp.StateEstablished {
				_, err = c2.Write(data)
				if err != nil {
					f.Fatal(err)
				}
				written = true
			}
		}
		n2, err := s2.EgressEthernet(buf[:])
		if n2 > 0 {
			pktnum++
			err = s1.IngressEthernet(buf[:n2])
			if err != nil {
				f.Fatal(err)
			}
			f.Add(pktnum, buf[:n2])
		}
		if n1 == 0 && n2 == 0 {
			if !closed {
				c2.Close()
				closed = true
				continue
			}
			break // No more data to send
		}
	}

	f.Fuzz(func(t *testing.T, pktnum int, a []byte) {
		var buf [ethernet.MaxFrameLength]byte
		s1, s2, c1, c2 := newTCPStacks(t, seed, MTU)
		err = s1.EnableICMP(true)
		if err != nil {
			t.Fatal(err)
		}
		err = s2.EnableICMP(true)
		if err != nil {
			t.Fatal(err)
		}
		err := s1.ListenTCP(c1, 80)
		if err != nil {
			t.Fatal(err)
		}
		err = s2.DialTCP(c2, 1337, netip.AddrPortFrom(s1.Addr(), c1.LocalPort()))
		if err != nil {
			t.Fatal(err)
		}
		pkt := 0
		written := false
		closed := false
		const maxpkts = 100
		for {
			n1, err := s1.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal(err)
			}
			if n1 > 0 {
				if pkt == pktnum {
					n1 = copy(buf[:], a)
					fixIPTCPCRCs(buf[:n1])
				}
				s2.IngressEthernet(buf[:n1])
				pkt++
				if !written && c2.State() >= tcp.StateEstablished {
					c2.Write(data)
					written = true
				}
			}
			n2, err := s2.EgressEthernet(buf[:])
			if n2 > 0 {
				if pkt == pktnum {
					n2 = copy(buf[:], a)
					fixIPTCPCRCs(buf[:n2])
				}
				pkt++
				s1.IngressEthernet(buf[:n2])
			}
			if n1 == 0 && n2 == 0 {
				if !closed {
					if c1.BufferedInput() > 0 {
						var hdr httpraw.Header
						n, _ := c1.Read(buf[:])
						hdr.ReadFromBytes(buf[:n])
						hdr.TryParse(false)
					}
					c2.Close()
					closed = true
					continue
				}
				break // No more data to send
			}
			if pkt > maxpkts {
				panic("infinite retransmission loop")
			}
		}
	})
}

// fixIPTCPCRCs corrects CRCs of IP and TCP headers so that
// fuzzed packets are not discarded 99.9999% of the time.
func fixIPTCPCRCs(pkt []byte) (fixable bool) {
	efrm, err := ethernet.NewFrame(pkt)
	if err != nil || efrm.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return false
	}
	ifrm, err := ipv4.NewFrame(efrm.Payload())
	if err != nil {
		return false
	}
	v, ihl := ifrm.VersionAndIHL()
	tl := ifrm.TotalLength()
	if v != 4 || ihl < 5 || tl < uint16(ihl)*4 || int(tl) > len(pkt) {
		return false // Invalid frame
	}
	var crc lneto.CRC791
	ifrm.SetCRC(0)
	ifrm.CRCWriteHeader(&crc)
	ifrm.SetCRC(crc.Sum16())
	if ifrm.Protocol() != lneto.IPProtoTCP {
		return false
	}
	IPpayload := ifrm.Payload()
	tfrm, err := tcp.NewFrame(IPpayload)
	if err != nil {
		return false
	}
	crc.Reset()
	ifrm.CRCWriteTCPPseudo(&crc)
	// Zero the CRC field so its value does not add to the final result.
	tfrm.SetCRC(0)
	crcValue := crc.PayloadSum16(IPpayload)
	tfrm.SetCRC(crcValue)
	return true
}

func FuzzStackSeeded(f *testing.F) {
	f.Add(int64(1), int64(2))
	// Numbers below taken from ANU QRNG https://qrng.anu.edu.au/random-hex/
	f.Add(int64(0x5b38810084b73b78), int64(0xfbc7243ac2c4a84))
	f.Add(int64(0x78b75e43c6fb1336), int64(0x09f9c425438dd42a))
	f.Add(int64(0xf63789e3a0750ed), int64(0xd4d3df265f09358))
	f.Add(int64(0x9649343892132dc), int64(0xfd5be085171f904))

	// Set to the values of the fuzz case that is crashing to enable verbose debugging logs.
	f.Fuzz(testStackSeeded)
}

// fuzz test printing facilities.
var (
	fzppr    CapturePrinter
	fzpmut   ltesto.PacketMut
	fzoutput = os.Stdout
)

func init() {
	fzppr.Configure(fzoutput, CapturePrinterConfig{
		NamespaceWidth: 3,
	})
}

const (
	printFuzz  = false
	printSeed1 = 676827762285163398
	printSeed2 = 1141027023543727980
)

// Debugging facility.
func TestStackSeeded(t *testing.T) {
	testStackSeeded(t, printSeed1, printSeed2)
}

func testStackSeeded(t *testing.T, seed1, seed2 int64) {
	if seed1 == 0 {
		seed1++
	}
	if seed2 == 0 {
		seed2++
	}
	verbose := printFuzz && printSeed1 == seed1 && printSeed2 == seed2
	const (
		actionUDP = iota
		actionTCP
		actionICMP
		actionARP
		actionLim
	)
	const maxActions = 32
	const maxConsecutivePackets = 6
	var actions [maxActions]struct {
		Action   int64
		Rand     int64
		Mutation [maxConsecutivePackets]struct {
			Seed1, Seed2       int64
			MutBits1, MutBits2 int64
			IsMut              int64
		}
	}
	// Fuzz tests are supposed to be predictable and repeatable.
	// We only generate the randomness in one place and in same order of
	// rng.Int64 calls. We cannot add new calls into the for loop but we
	// can add a new for loops when we need more fields filled in.
	// Be wary of invalidating the entire fuzz corpus we have.
	{
		rng := rand.New(rand.NewPCG(uint64(seed1), uint64(seed2)))
		for i := range actions {
			// DO NOT ADD CALLS TO rng API IN HERE! Read comment above.
			actions[i].Action = rng.Int64() % actionLim
			actions[i].Rand = rng.Int64()
			for k := range maxConsecutivePackets {
				mut := &actions[i].Mutation[k]
				mut.IsMut = rng.Int64()
				mut.Seed1 = rng.Int64()
				mut.Seed2 = rng.Int64()
				mut.MutBits1 = rng.Int64()
				mut.MutBits2 = rng.Int64()
			}
		}
	}

	const mtu = ethernet.MaxMTU
	const mfl = mtu + ethernet.MaxOverheadSize // frame length includes ethernet header
	var buf [mfl]byte
	var s1, s2 StackAsync
	v1, v2 := byte(seed1), byte(seed2)
	cfg1 := StackConfig{
		Hostname:          "s1",
		StaticAddress:     netip.AddrFrom4([4]byte{1, 0, 0, v1}),
		RandSeed:          seed1,
		MaxActiveTCPPorts: 1,
		MaxActiveUDPPorts: 1,
		ICMPQueueLimit:    1 + int(v1%4),
		MTU:               mtu,
		HardwareAddress:   [6]byte{0x1, 0, 0, 0, 0, v1},
		AcceptMulticast:   v1%2 == 0,
		PassivePeers:      int(v1 >> 6),
	}
	err := s1.Reset(cfg1)
	if err != nil {
		t.Fatal(err, cfg1)
	}
	cfg2 := StackConfig{
		Hostname:          "s2",
		StaticAddress:     netip.AddrFrom4([4]byte{1, 0, 0, v2}),
		RandSeed:          seed2,
		MaxActiveTCPPorts: 1,
		MaxActiveUDPPorts: 1,
		ICMPQueueLimit:    1 + int(v2%4),
		MTU:               mtu,
		HardwareAddress:   [6]byte{0x2, 0, 0, 0, 0, v2},
		AcceptMulticast:   v2%2 == 0,
		PassivePeers:      int(v2 >> 6),
	}
	err = s2.Reset(cfg2)
	if err != nil {
		t.Fatal(err, cfg2)
	}

	const (
		pingMinPayload = 8
		port1          = 8080
		port2          = 80
		bufsize        = 64
	)
	var udp1, udp2 udp.Conn
	var tcp1, tcp2 tcp.Conn
	err = tcp1.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 1 + int(uint16(seed1)%10),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tcp2.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufsize),
		TxBuf:             make([]byte, bufsize),
		TxPacketQueueSize: 1 + int(uint16(seed2)%10),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = udp1.Configure(udp.ConnConfig{
		RxBuf:       make([]byte, bufsize),
		TxBuf:       make([]byte, bufsize),
		RxQueueSize: int(1 + uint16(seed1>>32)%10),
		TxQueueSize: int(1 + uint16(seed1>>32)%10),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = udp2.Configure(udp.ConnConfig{
		RxBuf:       make([]byte, bufsize),
		TxBuf:       make([]byte, bufsize),
		RxQueueSize: int(1 + uint16(seed2>>32)%10),
		TxQueueSize: int(1 + uint16(seed2>>32)%10),
	})
	if err != nil {
		t.Fatal(err)
	}
	icmpEnabled := false
	udpOrder := 0
	betsAreOff := false // When a packet is mutated all bets on which error can be returned are off.
	for i, action := range actions {
		switch action.Action {
		case actionTCP:
			state1 := tcp1.State()
			state2 := tcp2.State()
			if state1 == 0 && state2 == 0 {
				if verbose {
					fmt.Fprintln(fzoutput, "TCP dial")
				}
				err = s1.DialTCP(&tcp1, port1, netip.AddrPortFrom(s2.Addr(), port2))
				if err != nil {
					t.Fatal(i, err)
				}
				err = s2.ListenTCP(&tcp2, port2)
				if err != nil {
					t.Fatal(i, err)
				}
			} else if state1 == tcp.StateEstablished && state2 == tcp.StateEstablished {
				// For now just close after established.
				closeNum := 1 + action.Rand%2
				if verbose {
					fmt.Fprintln(fzoutput, "TCP close", closeNum)
				}
				switch closeNum {
				case 1:
					tcp1.Close()
				case 2:
					tcp2.Close()
				}
			}
		case actionUDP:
			// Ensure connections open.
			if !udp1.IsOpen() {
				if verbose {
					fmt.Fprintln(fzoutput, "UDP dial 1")
				}
				err = s1.DialUDP(&udp1, port1, netip.AddrPortFrom(s2.Addr(), port2))
				if err != nil {
					t.Fatal(i, err)
				}
			}
			if !udp2.IsOpen() {
				if verbose {
					fmt.Fprintln(fzoutput, "UDP dial 2")
				}
				err = s2.DialUDP(&udp2, port2, netip.AddrPortFrom(s1.Addr(), port1))
				if err != nil {
					t.Fatal(i, err)
				}
			}
			udpOrder++
			action := action.Rand % 8
			if verbose {
				fmt.Fprintln(fzoutput, "UDP action", action)
			}
			switch action {
			case 0:
				if udp1.FreeOutput() > 0 {
					udp1.Write([]byte{byte(udpOrder)})
				}
			case 1:
				if udp1.BufferedInput() > 0 {
					udp1.Read(buf[:])
				}
			case 2:
				if udp2.FreeOutput() > 0 {
					udp2.Write([]byte{byte(udpOrder)})
				}
			case 3:
				if udp2.BufferedInput() > 0 {
					udp2.Read(buf[:])
				}
			case 4:
				udp1.Close()
			case 5:
				udp2.Close()
			}
		case actionICMP:
			icmpaction := action.Rand % 2
			if verbose {
				fmt.Fprintln(fzoutput, "ICMP action", icmpaction, "enabled", icmpEnabled)
			}
			if !icmpEnabled {
				err = s1.EnableICMP(true)
				if err != nil {
					t.Fatal(i, err)
				}
				err = s2.EnableICMP(true)
				if err != nil {
					t.Fatal(i, err)
				}
				icmpEnabled = true
			}
			switch icmpaction {
			case 0:
				s1.icmp.Reset()
				_, err = s1.icmp.PingStart(s2.Addr().As4(), buf[:pingMinPayload], pingMinPayload+uint16(action.Rand)%pingMinPayload)
				if err != nil {
					t.Fatal(i, err)
				}
			case 1:
				s2.icmp.Reset()
				_, err = s2.icmp.PingStart(s1.Addr().As4(), buf[:pingMinPayload], pingMinPayload+uint16(action.Rand)%pingMinPayload)
				if err != nil {
					t.Fatal(i, err)
				}
			}

		case actionARP:
			action := action.Rand % 6
			if verbose {
				fmt.Fprintln(fzoutput, "ARP action", action)
			}
			switch action {
			case 0: // s1 queries s2 address.
				s1.StartResolveHardwareAddress6(s2.Addr())
			case 1: // s2 queries s1 address.
				s2.StartResolveHardwareAddress6(s1.Addr())
			case 2: // s1 checks query result for s2.
				s1.ResultResolveHardwareAddress6(s2.Addr())
			case 3: // s2 checks query result for s1.
				s2.ResultResolveHardwareAddress6(s1.Addr())
			case 4: // s1 discards pending query.
				s1.DiscardResolveHardwareAddress6(s2.Addr())
			case 5: // s2 discards pending query.
				s2.DiscardResolveHardwareAddress6(s1.Addr())
			}
		}
		// Exchange data while checking stack does not enter runaway infinite frame send loop.
		first, second := &s1, &s2
		if (action.Rand>>32)%2 == 0 {
			first, second = second, first
		}
		// TODO(soypat): add specialized packet mutation by detecting protocol and modifying specific packet fields.

		for k, mut := range action.Mutation {
			n, err := first.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal(i, k, err)
			} else if n > 0 {
				if mut.IsMut&1 != 0 {
					if verbose {
						fmt.Fprintln(fzoutput, "mutate tx", first.Hostname())
					}
					fzpmut.MutateEthernet(buf[:n], mut.Seed1, mut.MutBits1)
					betsAreOff = true
				}
				if verbose {
					fzppr.PrintPacket(first.Hostname(), buf[:n])
				}
				err = second.IngressEthernet(buf[:n])
				if err != nil && !betsAreOff && err != lneto.ErrPacketDrop && err != lneto.ErrExhausted {
					t.Fatal(i, k, err)
				} else if verbose && err != nil {
					fmt.Fprintln(fzoutput, "err rx", second.Hostname(), err.Error())
				}
			}
			n, err = second.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal(i, k, err)
			} else if n > 0 {
				if mut.IsMut&1 != 0 {
					if verbose {
						fmt.Fprintln(fzoutput, "mutate tx", second.Hostname())
					}
					fzpmut.MutateEthernet(buf[:n], mut.Seed2, mut.MutBits2)
					betsAreOff = true
				}
				if verbose {
					fzppr.PrintPacket(second.Hostname(), buf[:n])
				}
				err = first.IngressEthernet(buf[:n])
				if err != nil && !betsAreOff && err != lneto.ErrPacketDrop && err != lneto.ErrExhausted {
					t.Fatal(i, k, err)
				} else if verbose && err != nil {
					fmt.Fprintln(fzoutput, "err rx", first.Hostname(), err.Error())
				}
			}
		}
		// Drain any remaining packets (retransmits from mutation).
		// Hard ceiling prevents infinite send loops from passing silently.
		// Also send drained packet to other stack to also catch infinite feedback loops.
		const drainLimit = 8
		for d := range drainLimit {
			limit := d == drainLimit-1
			n, err := first.EgressEthernet(buf[:])
			if (err != nil || n > 0) && limit {
				fzppr.PrintPacket(first.Hostname(), buf[:n])
				t.Fatal(i, "stuck in data/error loop:", err)
			} else if n > 0 {
				if verbose {
					fzppr.PrintPacket(first.Hostname(), buf[:n])
				}
				second.IngressEthernet(buf[:n])
			}
			n, err = second.EgressEthernet(buf[:])
			if (err != nil || n > 0) && limit {
				fzppr.PrintPacket("(2) ", buf[:n])
				t.Fatal(i, "stuck in data/error loop:", err)
			} else if n > 0 {
				if verbose {
					fzppr.PrintPacket(second.Hostname(), buf[:n])
				}
				first.IngressEthernet(buf[:n])
			}
		}
	}
}
