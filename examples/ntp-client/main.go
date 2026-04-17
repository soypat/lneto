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
	addr := "pool.ntp.org:123"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	var client ntp.Client
	client.Reset(-18, time.Now)

	for !client.IsDone() {
		reqBuf := make([]byte, ntp.SizeHeader)
		n, err := client.Encapsulate(reqBuf, 0, 0)
		if err != nil {
			return fmt.Errorf("encapsulate: %w", err)
		}
		if n == 0 {
			continue
		}

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = conn.Write(reqBuf[:n]); err != nil {
			return fmt.Errorf("write: %w", err)
		}

		respBuf := make([]byte, 1500)
		rn, err := conn.Read(respBuf)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		if err = client.Demux(respBuf[:rn], 0); err != nil {
			return fmt.Errorf("demux: %w", err)
		}
	}

	fmt.Printf("NTP time: %s\n", client.Now().Format(time.RFC3339Nano))
	fmt.Printf("Offset:   %s\n", client.Offset())
	fmt.Printf("RTD:      %s\n", client.RoundTripDelay())
	fmt.Printf("Stratum:  %s\n", client.ServerStratum())
	return nil
}
