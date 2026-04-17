package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/x/nts"
	"github.com/soypat/lneto/x/siv"
)

// keHostPort interprets s as either a bare hostname or a host:port string.
// Returns the dial target (host:port) and the SNI server name (host only).
// If s has no port, the default NTS-KE port is used.
func keHostPort(s string) (target, serverName string) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// No port specified — use the default KE port.
		return fmt.Sprintf("%s:%d", s, nts.KEPort), s
	}
	return net.JoinHostPort(host, port), host
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	keHost := flag.String("server", "ptbtime1.ptb.de", "NTS-KE server hostname")
	debug := flag.Bool("debug", false, "enable debug logging")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (for self-signed certs)")
	flag.Parse()

	var logger *slog.Logger
	if *debug {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// Phase 1: NTS-KE over TLS 1.3.
	// Accept -server as either a bare hostname or host:port. Default KE port
	// is nts.KEPort (4460) when no port is given.
	keTarget, serverName := keHostPort(*keHost)
	fmt.Printf("Performing NTS-KE with %s...\n", keTarget)
	tc, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		keTarget,
		&tls.Config{
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"ntske/1"},
			ServerName:         serverName,
			InsecureSkipVerify: *insecure, //nolint:gosec // intentional: user-requested flag
		},
	)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	// Use the KE server's resolved IP for NTP so both phases hit the same
	// backend (important when the server uses per-machine cookie keys).
	// Fall back to the hostname if the remote address can't be parsed.
	keRemoteIP := *keHost
	if host, _, e := net.SplitHostPort(tc.RemoteAddr().String()); e == nil {
		keRemoteIP = host
	}
	secrets, err := nts.PerformKE(tc, nts.KEConfig{})
	tc.Close()
	if err != nil {
		return fmt.Errorf("NTS-KE: %w", err)
	}
	fmt.Printf("  Algorithm: %s\n", secrets.ChosenAlg)
	fmt.Printf("  Cookies:   %d\n", secrets.NumCookies)
	if *debug {
		fmt.Fprintf(os.Stderr, "  KE server IP: %s\n", keRemoteIP)
	}

	// Derive AEAD ciphers from exported keys.
	c2s, err := siv.NewAESSIVCMAC256(secrets.C2SKey[:])
	if err != nil {
		return fmt.Errorf("c2s cipher: %w", err)
	}
	s2c, err := siv.NewAESSIVCMAC256(secrets.S2CKey[:])
	if err != nil {
		return fmt.Errorf("s2c cipher: %w", err)
	}

	// Determine NTP server address from KE response or fall back to KE server IP.
	ntpHost := keRemoteIP
	if secrets.NTPAddrLen > 0 {
		ntpHost = string(secrets.NTPAddr[:secrets.NTPAddrLen])
	}
	ntpPort := uint16(ntp.ServerPort)
	if secrets.NTPPort != 0 {
		ntpPort = secrets.NTPPort
	}

	// Phase 2: Authenticated NTP.
	var client nts.Client
	err = client.Reset(nts.ClientConfig{
		C2S:        c2s,
		S2C:        s2c,
		ChosenAlg:  secrets.ChosenAlg,
		Log:        logger,
		Now:        time.Now,
		Sysprec:    -18,
		Cookies:    secrets.Cookies,
		CookieLens: secrets.CookieLens,
		NumCookies: secrets.NumCookies,
	})
	if err != nil {
		return fmt.Errorf("client reset: %w", err)
	}

	ntpAddr := net.JoinHostPort(ntpHost, fmt.Sprintf("%d", ntpPort))
	fmt.Printf("Querying NTP at %s...\n", ntpAddr)
	conn, err := net.DialTimeout("udp", ntpAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("udp dial: %w", err)
	}
	defer conn.Close()

	for !client.IsDone() {
		carrier := make([]byte, 1500)
		n, err := client.Encapsulate(carrier, 0, 0)
		if err != nil {
			return fmt.Errorf("encapsulate: %w", err)
		}
		if n == 0 {
			continue
		}

		if *debug {
			fmt.Fprintf(os.Stderr, "TX (%d bytes):\n%s\n", n, hex.Dump(carrier[:n]))
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = conn.Write(carrier[:n]); err != nil {
			return fmt.Errorf("write: %w", err)
		}

		resp := make([]byte, 1500)
		rn, err := conn.Read(resp)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if *debug {
			fmt.Fprintf(os.Stderr, "RX (%d bytes):\n%s\n", rn, hex.Dump(resp[:rn]))
		}

		if err = client.Demux(resp[:rn], 0); err != nil {
			return fmt.Errorf("demux: %w", err)
		}
	}

	fmt.Printf("NTS time: %s\n", client.Now().Format(time.RFC3339Nano))
	fmt.Printf("Offset:   %s\n", client.Offset())
	fmt.Printf("RTD:      %s\n", client.RoundTripDelay())
	return nil
}
