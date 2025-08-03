package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internal"
	"github.com/soypat/lneto/internal/ltesto"
	"github.com/soypat/lneto/x/xnet"
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
		flagDoNTP         = false
	)
	flag.StringVar(&flagInterface, "i", flagInterface, "Interface to use. Either tap* or the name of an existing interface to bridge to.")
	flag.BoolVar(&flagUseHTTP, "http", flagUseHTTP, "Use HTTP tap interface.")
	flag.StringVar(&flagHostToResolve, "host", flagHostToResolve, "Hostname to resolve via DNS.")
	flag.StringVar(&flagRequestedIP, "addr", flagRequestedIP, "IP address to request via DHCP.")
	flag.BoolVar(&flagDoNTP, "ntp", flagDoNTP, "Do NTP round and print result time")
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
	mtu, err := iface.MTU()
	if err != nil {
		return err
	}

	nicAddr, err := iface.IPMask()
	if err != nil {
		return err
	}
	fmt.Println("NIC hardware address:", net.HardwareAddr(nicHW[:]).String(), "bridgeHW:", net.HardwareAddr(brHW[:]).String(), "mtu:", mtu, "addr:", nicAddr.String())
	var stack xnet.StackAsync
	err = stack.Reset(xnet.StackConfig{
		Hostname:        "xnet-test",
		RandSeed:        softRand,
		HardwareAddress: brHW,
		MTU:             uint16(mtu),
	})
	if err != nil {
		return err
	}
	// Loop goroutine.
	go func() {
		lastAction := time.Now()
		buf := make([]byte, mtu)
		for {
			clear(buf)
			nwrite, err := stack.Encapsulate(buf[:], 0)
			if err != nil {
				fmt.Println("ERR:ENCAPSULATE", err)
			} else if nwrite > 0 {
				n, err := iface.Write(buf[:nwrite])
				if err != nil {
					log.Fatal("groutine encapsulate:", err)
				} else if n != nwrite {
					log.Fatalf("mismatch written bytes %d!=%d", nwrite, n)
				}
			}

			clear(buf)
			nread, err := iface.Read(buf)
			if err != nil {
				log.Fatal("groutine read:", err)
			} else if nread > 0 {
				err = stack.Demux(buf[:nread], 0)
				if err != nil {
					log.Println("groutine demux:", err)
				}
			}

			if nread == 0 && nwrite == 0 && time.Since(lastAction) > 4*time.Second {
				time.Sleep(5 * time.Millisecond)
			} else {
				lastAction = time.Now()
				runtime.Gosched()
			}
		}
	}()

	rstack := stack.StackRetrying()

	const (
		dhcpTimeout = 6 * time.Second
		dhcpRetries = 2
	)
	results, err := rstack.DoDHCPv4([4]byte{192, 168, 1, 96}, dhcpTimeout, dhcpRetries)
	if err != nil {
		return fmt.Errorf("DHCP failed: %w", err)
	}
	err = stack.AssimilateDHCPResults(results)
	if err != nil {
		return fmt.Errorf("assimilating DHCP results: %w", err)
	}
	const (
		arpTimeout = 2 * time.Second
		arpRetries = 2
	)
	const (
		internetTimeout = 3 * time.Second
		internetRetries = 2
	)
	routerHw, err := rstack.DoResolveHardwareAddress6(results.Router, arpTimeout, arpRetries)
	if err != nil {
		return fmt.Errorf("ARP resolution of router failed: %w", err)
	}
	stack.SetGateway6(routerHw)
	if flagDoNTP {
		const ntpHost = "pool.ntp.org"
		addrs, err := rstack.DoLookupIP(ntpHost, internetTimeout, internetRetries)
		if err != nil {
			return fmt.Errorf("NTP address lookup of %q failed: %w", ntpHost, err)
		}
		offset, err := rstack.DoNTP(addrs[0], internetTimeout, internetRetries)
		if err != nil {
			return fmt.Errorf("NTP address lookup of %q failed: %w", ntpHost, err)
		}
		relative := "behind"
		if offset < 0 {
			relative = "ahead"
		}
		fmt.Println("NTP completed. You are", offset.Abs().String(), relative, "of the NTP server")
	}
	addrs, err := rstack.DoLookupIP(flagHostToResolve, internetTimeout, internetRetries)
	if err != nil {
		return fmt.Errorf("DNS of host %q failed: %w", flagHostToResolve, err)
	}
	fmt.Printf("DNS resolution of %q complete and resolved to %v\n", flagHostToResolve, addrs)
	return nil
}

func clear(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
