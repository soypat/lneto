package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/internet/pcap"
)

func main() {
	err := run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("success")
}

func run() (err error) {
	br := ltesto.NewHTTPTapClient("http://127.0.0.1:7070")
	defer br.Close()

	nicHW := br.HardwareAddr6()

	brHW := nicHW
	brHW[5]++ // We'll be using a similar HW address but with NIC specific identifier modified.
	mtu := br.MTU()
	nicAddr := br.IPPrefix()

	fmt.Println("NIC hardware address:", net.HardwareAddr(nicHW[:]).String(), "bridgeHW:", net.HardwareAddr(brHW[:]).String(), "mtu:", mtu, "addr:", nicAddr.String())
	var stack Stack
	err = stack.Reset(brHW, nicAddr.Addr().Next(), uint16(mtu))
	if err != nil {
		return err
	}
	err = stack.BeginDHCPRequest()
	if err != nil {
		return err
	}
	var shark pcap.PacketBreakdown
	buf := make([]byte, mtu)
	var iframes []pcap.Frame
	lastAction := time.Now()
	for {
		clear(buf)
		nwrite, err := stack.Encapsulate(buf[:], 0)
		if err != nil {
			fmt.Println("ERR:ENCAPSULATE", err)
		} else if nwrite > 0 {
			iframes, err = shark.CaptureEthernet(iframes[:0], buf[:nwrite], 0)
			if err != nil {
				fmt.Println("OU", iframes, err.Error())
			} else {
				fmt.Println("OU", iframes)
			}
			n, err := br.Write(buf[:nwrite])
			if err != nil {
				return err
			} else if n != nwrite {
				return fmt.Errorf("mismatch written bytes %d!=%d", nwrite, n)
			}
		}

		clear(buf)
		nread, err := br.Read(buf)
		if err != nil {
			return err
		} else if nread > 0 {
			iframes, err = shark.CaptureEthernet(iframes[:0], buf[:nread], 0)
			if err != nil {
				fmt.Println("IN", iframes, err.Error())
			} else {
				fmt.Println("IN", iframes)
			}
			err = stack.Demux(buf[:nread], 0)
			if err != nil {
				fmt.Println("ERR:DEMUX", err)
			}
		}

		if nread == 0 && nwrite == 0 && time.Since(lastAction) > 4*time.Second {
			time.Sleep(5 * time.Millisecond)
		} else {
			lastAction = time.Now()
		}
	}
	return nil
}

type Stack struct {
	link internet.StackEthernet
	ip   internet.StackIP
	arp  internet.NodeARP
	udps internet.StackPorts
	dhcp dhcpv4.Client
}

func (s *Stack) Demux(b []byte, _ int) error {
	return s.link.Demux(b, 0)
}

func (s *Stack) Encapsulate(b []byte, _ int) (int, error) {
	return s.link.Encapsulate(b, 0)
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
	return nil
}

func (s *Stack) BeginDHCPRequest() error {
	addr4 := s.ip.Addr().As4()
	var buf [4]byte
	rand.Read(buf[:])
	xid := binary.LittleEndian.Uint32(buf[:])
	err := s.dhcp.BeginRequest(xid, dhcpv4.RequestConfig{
		RequestedAddr:      addr4,
		ClientHardwareAddr: s.link.HardwareAddr6(),
		Hostname:           "lneto",
	})
	if err != nil {
		return err
	}
	var u internet.StackUDPPort
	u.SetStackNode(&s.dhcp, dhcpv4.DefaultServerPort)
	err = s.udps.Register(&u)
	if err != nil {
		return err
	}
	return err
}

func clear(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
