package xnet

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

func FuzzStackAsyncHTTP(f *testing.F) {
	const MTU = 1500
	const seed = 1
	var buf [MTU + ethernet.MaxOverheadSize]byte
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
		var buf [MTU + ethernet.MaxOverheadSize]byte
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

func FuzzTwoStack(f *testing.F) {
	f.Add(int64(1), int64(2), int64(3))
	f.Fuzz(func(t *testing.T, seed1, seed2, seedAction int64) {
		const mtu = 1500
		const mfl = mtu + 14 // frame length includes ethernet header
		var buf [mfl]byte
		var s1, s2 StackAsync
		v1, v2 := byte(seed1), byte(seed2)
		err := s1.Reset(StackConfig{
			Hostname:          "s1",
			StaticAddress:     netip.AddrFrom4([4]byte{1, 0, 0, v1}),
			RandSeed:          seed1,
			MaxActiveTCPPorts: 1,
			MaxActiveUDPPorts: 1,
			ICMPQueueLimit:    int(v1 % 4),
			MTU:               mtu,
			HardwareAddress:   [6]byte{0x1, 0, 0, 0, 0, v1},
			AcceptMulticast:   v1%2 == 0,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = s2.Reset(StackConfig{
			Hostname:          "s2",
			StaticAddress:     netip.AddrFrom4([4]byte{1, 0, 0, v2}),
			RandSeed:          seed2,
			MaxActiveTCPPorts: 1,
			MaxActiveUDPPorts: 1,
			ICMPQueueLimit:    int(v2 % 4),
			MTU:               mtu,
			HardwareAddress:   [6]byte{0x2, 0, 0, 0, 0, v2},
			AcceptMulticast:   v2%2 == 0,
		})
		if err != nil {
			t.Fatal(err)
		}
		const maxActions = 100
		const (
			actionUDP = iota
			actionTCP
			actionICMP
			actionNone
			actionLim
		)
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
			TxPacketQueueSize: 1 + int(s1.Prand32())%10,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = tcp2.Configure(tcp.ConnConfig{
			RxBuf:             make([]byte, bufsize),
			TxBuf:             make([]byte, bufsize),
			TxPacketQueueSize: 1 + int(s2.Prand32())%10,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = udp1.Configure(udp.ConnConfig{
			RxBuf:       make([]byte, bufsize),
			TxBuf:       make([]byte, bufsize),
			RxQueueSize: int(1 + s1.Prand32()%10),
			TxQueueSize: int(1 + s1.Prand32()%10),
		})
		if err != nil {
			t.Fatal(err)
		}
		err = udp2.Configure(udp.ConnConfig{
			RxBuf:       make([]byte, bufsize),
			TxBuf:       make([]byte, bufsize),
			RxQueueSize: int(1 + s2.Prand32()%10),
			TxQueueSize: int(1 + s2.Prand32()%10),
		})
		if err != nil {
			t.Fatal(err)
		}
		icmpEnabled := false
		udpOrder := 0
		for i := 0; i < maxActions; i++ {
			action1 := s1.Prand32()
			switch action1 % actionLim {
			case actionTCP:
				state1 := tcp1.State()
				state2 := tcp2.State()
				if state1 == 0 && state2 == 0 {
					err = s1.DialTCP(&tcp1, port1, netip.AddrPortFrom(s2.Addr(), port2))
					if err != nil {
						t.Fatal(err)
					}
					err = s2.ListenTCP(&tcp2, port2)
					if err != nil {
						t.Fatal(err)
					}
				} else if state1 == tcp.StateEstablished && state2 == tcp.StateEstablished {
					// For now just close after established.
					if s1.Prand32()%2 == 0 {
						tcp1.Close()
					} else {
						tcp2.Close()
					}
				}
			case actionUDP:
				// Ensure connections open.
				if !udp1.IsOpen() {
					err = s1.DialUDP(&udp1, port1, netip.AddrPortFrom(s2.Addr(), port2))
					if err != nil {
						t.Fatal(err)
					}
				}
				if !udp2.IsOpen() {
					err = s2.DialUDP(&udp2, port2, netip.AddrPortFrom(s1.Addr(), port1))
					if err != nil {
						t.Fatal(err)
					}
				}
				udpOrder++
				action := s1.Prand32() % 8
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
				if !icmpEnabled {
					err = s1.EnableICMP(true)
					if err != nil {
						t.Fatal(err)
					}
					err = s2.EnableICMP(true)
					if err != nil {
						t.Fatal(err)
					}
					icmpEnabled = true
				}
				if s1.Prand32()%2 == 0 {
					s1.icmp.Reset()
					_, err = s1.icmp.PingStart(s2.Addr().As4(), buf[:pingMinPayload], pingMinPayload+uint16(s1.Prand32())%pingMinPayload)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					s2.icmp.Reset()
					_, err = s2.icmp.PingStart(s1.Addr().As4(), buf[:pingMinPayload], pingMinPayload+uint16(s2.Prand32())%pingMinPayload)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			// Exchange data while checking stack does not enter runaway infinite frame send loop.
			first, second := &s1, &s2
			if s1.Prand32()%2 == 0 {
				first, second = second, first
			}
			const maxConsecutivePackets = 6
			for k := 0; k < maxConsecutivePackets; k++ {
				n, err := first.EgressEthernet(buf[:])
				if err != nil {
					t.Fatal(err)
				} else if n > 0 {
					err = second.IngressEthernet(buf[:n])
					if err != nil {
						t.Fatal(err)
					}
				}
				n, err = second.EgressEthernet(buf[:])
				if err != nil {
					t.Fatal(err)
				} else if n > 0 {
					err = first.IngressEthernet(buf[:n])
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			n, err := first.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal("expected no errors after maxconsecutive", err)
			} else if n > 0 {
				t.Fatal("expected no more data after max consecutive")
			}
			n, err = second.EgressEthernet(buf[:])
			if err != nil {
				t.Fatal("expected no errors after maxconsecutive", err)
			} else if n > 0 {
				t.Fatal("expected no more data after max consecutive")
			}
		}
	})
}
