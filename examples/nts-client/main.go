package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/soypat/lneto/ntp"
	"github.com/soypat/lneto/x/nts"
	"github.com/soypat/lneto/x/siv"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	keHost := "time.cloudflare.com"
	if len(os.Args) > 1 {
		keHost = os.Args[1]
	}

	// Phase 1: NTS-KE over TLS 1.3.
	fmt.Printf("Performing NTS-KE with %s:%d...\n", keHost, nts.KEPort)
	tc, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", keHost, nts.KEPort),
		&tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"ntske/1"},
			ServerName: keHost,
		},
	)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	secrets, err := nts.PerformKE(tc, nts.KEConfig{})
	tc.Close()
	if err != nil {
		return fmt.Errorf("NTS-KE: %w", err)
	}
	fmt.Printf("  Algorithm: %s\n", secrets.ChosenAlg)
	fmt.Printf("  Cookies:   %d\n", secrets.NumCookies)

	// Derive AEAD ciphers from exported keys.
	c2s, err := siv.NewAESSIVCMAC256(secrets.C2SKey[:])
	if err != nil {
		return fmt.Errorf("c2s cipher: %w", err)
	}
	s2c, err := siv.NewAESSIVCMAC256(secrets.S2CKey[:])
	if err != nil {
		return fmt.Errorf("s2c cipher: %w", err)
	}

	// Determine NTP server address.
	ntpHost := keHost
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
		Now:        time.Now,
		Sysprec:    -18,
		Cookies:    secrets.Cookies,
		CookieLens: secrets.CookieLens,
		NumCookies: secrets.NumCookies,
	})
	if err != nil {
		return fmt.Errorf("client reset: %w", err)
	}

	ntpAddr := fmt.Sprintf("%s:%d", ntpHost, ntpPort)
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

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = conn.Write(carrier[:n]); err != nil {
			return fmt.Errorf("write: %w", err)
		}

		resp := make([]byte, 1500)
		rn, err := conn.Read(resp)
		if err != nil {
			return fmt.Errorf("read: %w", err)
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
