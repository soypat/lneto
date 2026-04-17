// Command ntp-server is a minimal NTP server that listens for client requests
// on a UDP socket and responds with the current system time. It serves as an
// integration test target for the ntp-client example.
//
// Usage:
//
//	go run ./examples/ntp-server/ -addr :10123
//
// The listen address defaults to :123 (requires root).
//
// This tool uses the standard library net package for UDP transport instead of
// lneto's own networking stack. These examples exercise one protocol layer at a
// time in isolation, keeping the transport concern separate so failures are
// clearly attributable to the NTP codec and state machine rather than the
// full-stack IP/UDP path.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/soypat/lneto/ntp"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	listenAddr := flag.String("addr", ":123", "UDP listen address (host:port)")
	flag.Parse()

	pc, err := net.ListenPacket("udp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer pc.Close()
	fmt.Printf("NTP server listening on %s\n", pc.LocalAddr())

	var handler ntp.Handler
	err = handler.Reset(ntp.HandlerConfig{
		Now:        time.Now,
		Stratum:    ntp.StratumPrimary,
		Precision:  -20,
		RefID:      [4]byte{'G', 'O', 'L', 'N'},
		MaxPending: 16,
	})
	if err != nil {
		return fmt.Errorf("server reset: %w", err)
	}

	buf := make([]byte, 1500)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Printf("read error: %v\n", err)
			continue
		}

		if err = handler.Demux(buf[:n], 0); err != nil {
			fmt.Printf("demux error from %s: %v\n", raddr, err)
			continue
		}

		respBuf := make([]byte, ntp.SizeHeader)
		rn, err := handler.Encapsulate(respBuf, 0, 0)
		if err != nil {
			fmt.Printf("encapsulate error: %v\n", err)
			continue
		}
		if rn > 0 {
			if _, err = pc.WriteTo(respBuf[:rn], raddr); err != nil {
				fmt.Printf("write error: %v\n", err)
			}
		}
	}
}
