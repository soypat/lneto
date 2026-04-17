package main

import (
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
	listenAddr := ":123"
	if len(os.Args) > 1 {
		listenAddr = os.Args[1]
	}

	pc, err := net.ListenPacket("udp", listenAddr)
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
		return fmt.Errorf("handler reset: %w", err)
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
