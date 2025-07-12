package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/internet/pcap"
)

var softRand = time.Now().Unix()

func main() {
	err := run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("success")
}

func run() (err error) {
	var (
		flagInterface     = "tap0"
		flagUseHTTP       = false
		flagHostToResolve = ""
		flagRequestedIP   = ""
	)
	flag.StringVar(&flagInterface, "i", flagInterface, "Interface to use. Either tap* or the name of an existing interface to bridge to.")
	flag.BoolVar(&flagUseHTTP, "http", flagUseHTTP, "Use HTTP tap interface.")
	flag.StringVar(&flagHostToResolve, "host", flagHostToResolve, "Hostname to resolve via DNS.")
	flag.StringVar(&flagRequestedIP, "addr", flagRequestedIP, "IP address to request via DHCP.")
	flag.Parse()
	fmt.Println("softrand", softRand)
	_, err = dns.NewName(flagHostToResolve)
	if err != nil {
		flag.Usage()
		return err
	}
	var iface ltesto.Interface
	if flagUseHTTP {
		iface = ltesto.NewHTTPTapClient("http://127.0.0.1:7070")
	} else {
		if strings.HasPrefix(flagInterface, "tap") {
			tap, err := internal.NewTap(flagInterface, netip.MustParsePrefix("192.168.1.1/24"))
			if err != nil {
				return err
			}
			iface = tap
		} else {
			bridge, err := internal.NewBridge(flagInterface)
			if err != nil {
				return err
			}
			iface = bridge
		}
	}
	defer iface.Close()

	nicHW, err := iface.HardwareAddress6()
	if err != nil {
		return err
	}
	brHW := nicHW
	brHW[5] += byte(softRand)%128 + 1 // We'll be using a similar HW address but with NIC specific identifier modified.
	mtu, err := iface.MTU()
	if err != nil {
		return err
	}
	nicAddr, err := iface.IPMask()
	if err != nil {
		return err
	}
	fmt.Println("NIC hardware address:", net.HardwareAddr(nicHW[:]).String(), "bridgeHW:", net.HardwareAddr(brHW[:]).String(), "mtu:", mtu, "addr:", nicAddr.String())
	var stack Stack
	err = stack.Reset(brHW, netip.AddrFrom4([4]byte{}), uint16(mtu))
	if err != nil {
		return err
	}
	err = stack.BeginDHCPRequest([4]byte{192, 168, 1, 199})
	if err != nil {
		return err
	}
	buf := make([]byte, mtu)
	lastAction := time.Now()
	const (
		stateDHCP = iota
		stateInitARP
		stateDNS
		stateDone
	)
	state := stateDHCP
	for {
		switch state {
		case stateDHCP:
			dhcpIsDone := stack.dhcp.State() == dhcpv4.StateBound
			if dhcpIsDone {
				state = stateInitARP
				err = stack.ip.SetAddr(netip.AddrFrom4(stack.dhcp.AssignedAddr()))
				if err != nil {
					return err
				}
				err = stack.StartResolveHardwareAddress6(netip.AddrFrom4(stack.dhcp.RouterAddr()))
				if err != nil {
					return err
				}
			}

		case stateInitARP:
			router := stack.dhcp.RouterAddr()
			hw, err := stack.ResultResolveHardwareAddress6(netip.AddrFrom4(router))
			if err == nil {
				state = stateDNS
				stack.link.SetGateway6(hw)
				err = stack.StartLookupIP(flagHostToResolve)
				if err != nil {
					return err
				}
			}

		case stateDNS:
			addrs, done, err := stack.ResultLookupIP()
			if err == nil {
				fmt.Println(flagHostToResolve, "resolved to", addrs)
				return nil
			} else if done {
				return err
			}
		}

		clear(buf)
		nwrite, err := stack.Encapsulate(buf[:], 0)
		if err != nil {
			fmt.Println("ERR:ENCAPSULATE", err)
		} else if nwrite > 0 {
			n, err := iface.Write(buf[:nwrite])
			if err != nil {
				return err
			} else if n != nwrite {
				return fmt.Errorf("mismatch written bytes %d!=%d", nwrite, n)
			}
		}

		clear(buf)
		nread, err := iface.Read(buf)
		if err != nil {
			return err
		} else if nread > 0 {
			err = stack.Demux(buf[:nread], 0)
			if err != nil {
				fmt.Println("ERR:DEMUX", err)
			}
		}

		if nread == 0 && nwrite == 0 && time.Since(lastAction) > 4*time.Second {
			time.Sleep(5 * time.Millisecond)
		} else {
			lastAction = time.Now()
			runtime.Gosched()
		}
	}
	return nil
}

type Stack struct {
	link    internet.StackEthernet
	ip      internet.StackIP
	arp     internet.NodeARP
	udps    internet.StackPorts
	dhcp    dhcpv4.Client
	dns     dns.Client
	ednsopt dns.Resource
	lookup  dns.Message

	// Packet capture and top level filtering.
	shark pcap.PacketBreakdown
	aux   []pcap.Frame
}

func (s *Stack) Demux(b []byte, _ int) (err error) {
	s.aux, err = s.shark.CaptureEthernet(s.aux[:0], b, 0)
	topFrame := s.aux[len(s.aux)-1]
	isOK := topFrame.Protocol == "DHCPv4" || // Allow DHCP responses.
		topFrame.Protocol == "DNS" ||
		topFrame.Protocol == ethernet.TypeARP // Allow ARP responses.
	if !isOK {
		return nil
	}
	if err != nil {
		fmt.Println("IN", s.aux, err.Error())
	} else {
		fmt.Println("IN", s.aux)
	}
	return s.link.Demux(b, 0)
}

func (s *Stack) Encapsulate(b []byte, _ int) (int, error) {
	n, err := s.link.Encapsulate(b, 0)
	if n > 0 {
		iframes, errpcap := s.shark.CaptureEthernet(s.aux[:0], b[:n], 0)
		if errpcap != nil {
			fmt.Println("OU", iframes, errpcap.Error())
		} else {
			fmt.Println("OU", iframes)
		}
	}
	return n, err
}

func (s *Stack) Reset(mac [6]byte, addr netip.Addr, mtu uint16) error {
	err := s.link.Reset6(mac, ethernet.BroadcastAddr(), int(mtu))
	if err != nil {
		return err
	}
	err = s.ip.Reset(addr)
	if err != nil {
		return err
	}
	ipaddr := addr.AsSlice()
	proto := ethernet.TypeIPv4
	if addr.Is6() {
		proto = ethernet.TypeIPv6
	}
	err = s.arp.Reset(arp.HandlerConfig{
		HardwareAddr: mac[:],
		ProtocolAddr: ipaddr,
		MaxQueries:   3,
		MaxPending:   3,
		HardwareType: 1,
		ProtocolType: proto,
	})
	if err != nil {
		return err
	}
	err = s.udps.Reset(uint64(lneto.IPProtoUDP), 2)
	if err != nil {
		return err
	}

	// Now setup stacks.
	err = s.link.Register(&s.arp) // ARP.
	if err != nil {
		return err
	}
	err = s.link.Register(&s.ip) // IPv4 | IPv6
	if err != nil {
		return err
	}
	err = s.ip.Register(&s.udps)
	if err != nil {
		return err
	}
	s.ip.SetLogger(slog.Default())
	return nil
}

func (s *Stack) StartLookupIP(host string) error {
	dnsSrvs := s.dhcp.DNSServerFirst()
	if !dnsSrvs.IsValid() {
		return errors.New("no valid DNS server")
	}
	name, err := dns.NewName(host)
	if err != nil {
		return err
	}
	s.link.SetHardwareAddr6([6]byte{0xd8, 0x5e, 0xd3, 0x43, 0x03, 0xeb})
	s.ip.SetAddr(netip.AddrFrom4([4]byte{192, 168, 1, 53}))
	s.ednsopt.SetEDNS0(uint16(s.link.MTU())-100, 0, 0, nil)
	err = s.dns.StartResolve(uint16(softRand>>1)+1024, uint16(softRand), dns.ResolveConfig{
		Questions: []dns.Question{
			{
				Name:  name,
				Type:  dns.TypeA,
				Class: dns.ClassINET,
			},
		},
		Additional: []dns.Resource{
			s.ednsopt,
		},
		EnableRecursion: true,
	})
	if err != nil {
		return err
	}
	var u internet.StackUDPPort
	dns4 := dnsSrvs.As4()
	u.SetStackNode(&s.dns, dns4[:], dns.ServerPort)
	err = s.udps.Register(&u)
	if err != nil {
		return err
	}
	return nil
}

func (s *Stack) ResultLookupIP() ([]netip.Addr, bool, error) {
	done, err := s.dns.MessageCopyTo(&s.lookup)
	if err != nil {
		return nil, done, err
	} else if !done {
		return nil, done, errors.New("DNS not done")
	}
	var addrs []netip.Addr
	ans := s.lookup.Answers
	for i := range ans {
		data := ans[i].RawData()
		if len(data) == 4 {
			addrs = append(addrs, netip.AddrFrom4([4]byte(data)))
		} else if len(data) == 16 {
			addrs = append(addrs, netip.AddrFrom16([16]byte(data)))
		}
	}
	return addrs, done, nil
}

func (s *Stack) BeginDHCPRequest(request [4]byte) error {
	var buf [4]byte
	rand.Read(buf[:])
	xid := binary.LittleEndian.Uint32(buf[:])
	err := s.dhcp.BeginRequest(xid, dhcpv4.RequestConfig{
		RequestedAddr:      request,
		ClientHardwareAddr: s.link.HardwareAddr6(),
		Hostname:           "lneto" + strconv.FormatInt(softRand%100, 16),
	})
	if err != nil {
		return err
	}
	var u internet.StackUDPPort
	u.SetStackNode(&s.dhcp, nil, dhcpv4.DefaultServerPort)
	err = s.udps.Register(&u)
	if err != nil {
		return err
	}
	return err
}

func (s *Stack) StartResolveHardwareAddress6(ip netip.Addr) error {
	if !ip.Is4() {
		return errors.New("unsupported or invalid IP address")
	}
	addr := ip.As4()
	return s.arp.StartQuery(addr[:])
}

func (s *Stack) ResultResolveHardwareAddress6(ip netip.Addr) (hw [6]byte, err error) {
	if !ip.Is4() {
		return hw, errors.New("unsupported or invalid IP address")
	}
	addr := ip.As4()
	hwslice, err := s.arp.QueryResult(addr[:])
	if err != nil {
		return hw, err
	} else if len(hwslice) != 6 {
		panic("unreachable slice hw leng")
	}
	return [6]byte(hwslice), nil
}

func clear(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func getField(frame pcap.Frame, pkt []byte, class pcap.FieldClass) uint64 {
	idx, err := frame.FieldByClass(class)
	if err != nil {
		return 0
	}
	v, _ := frame.FieldAsUint(idx, pkt)
	return v
}
