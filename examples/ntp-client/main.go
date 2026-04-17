// Command ntp-client performs a two-exchange NTP clock synchronization against
// a remote server and prints the corrected time, clock offset, and round-trip
// delay.
//
// Usage:
//
//	go run ./examples/ntp-client/ -server pool.ntp.org:123
//	go run ./examples/ntp-client/ -server 127.0.0.1:10123 -debug
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
	"log/slog"
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
	addr := flag.String("server", "pool.ntp.org:123", "NTP server address (host:port)")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	conn, err := net.DialTimeout("udp", *addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	var client ntp.Client
	client.Reset(-18, time.Now)
	if *debug {
		client.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

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
