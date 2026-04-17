package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
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

type keState struct {
	mu          sync.Mutex
	c2sKey      [32]byte
	s2cKey      [32]byte
	initialized bool
}

func run() error {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("cert: %w", err)
	}

	cookie := make([]byte, 64)
	rand.Read(cookie)

	var state keState

	// Phase 1: NTS-KE listener.
	keAddr := fmt.Sprintf(":%d", nts.KEPort)
	keLn, err := tls.Listen("tcp", keAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"ntske/1"},
	})
	if err != nil {
		return fmt.Errorf("ke listen: %w", err)
	}
	defer keLn.Close()
	fmt.Printf("NTS-KE listening on %s\n", keLn.Addr())

	// Phase 2: NTP UDP listener.
	ntpAddr := fmt.Sprintf(":%d", ntp.ServerPort)
	pc, err := net.ListenPacket("udp", ntpAddr)
	if err != nil {
		return fmt.Errorf("ntp listen: %w", err)
	}
	defer pc.Close()
	fmt.Printf("NTS-NTP server listening on %s\n", pc.LocalAddr())

	// Accept KE connections in the background.
	go func() {
		for {
			conn, err := keLn.Accept()
			if err != nil {
				fmt.Printf("ke accept: %v\n", err)
				return
			}
			go handleKE(conn.(*tls.Conn), cookie, &state)
		}
	}()

	// Serve NTP.
	buf := make([]byte, 1500)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Printf("read error: %v\n", err)
			continue
		}

		state.mu.Lock()
		if !state.initialized {
			state.mu.Unlock()
			fmt.Printf("no KE completed yet, dropping packet from %s\n", raddr)
			continue
		}
		c2sKey := state.c2sKey
		s2cKey := state.s2cKey
		state.mu.Unlock()

		c2s, err := siv.NewAESSIVCMAC256(c2sKey[:])
		if err != nil {
			fmt.Printf("c2s cipher: %v\n", err)
			continue
		}
		s2c, err := siv.NewAESSIVCMAC256(s2cKey[:])
		if err != nil {
			fmt.Printf("s2c cipher: %v\n", err)
			continue
		}

		var server nts.Server
		err = server.Reset(nts.ServerConfig{
			C2S:     c2s,
			S2C:     s2c,
			Now:     time.Now,
			Stratum: ntp.StratumPrimary,
			Prec:    -20,
			RefID:   [4]byte{'G', 'O', 'L', 'N'},
		})
		if err != nil {
			fmt.Printf("server reset: %v\n", err)
			continue
		}

		if err = server.Demux(buf[:n], 0); err != nil {
			fmt.Printf("demux from %s: %v\n", raddr, err)
			continue
		}

		resp := make([]byte, 1500)
		rn, err := server.Encapsulate(resp, 0, 0)
		if err != nil {
			fmt.Printf("encapsulate: %v\n", err)
			continue
		}
		if rn > 0 {
			if _, err = pc.WriteTo(resp[:rn], raddr); err != nil {
				fmt.Printf("write: %v\n", err)
			}
		}
	}
}

func handleKE(conn *tls.Conn, cookie []byte, state *keState) {
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		fmt.Printf("ke handshake: %v\n", err)
		return
	}
	secrets, err := nts.HandleKE(conn, nts.KEServerConfig{
		Cookies: [][]byte{cookie},
	})
	if err != nil {
		fmt.Printf("ke handle: %v\n", err)
		return
	}
	state.mu.Lock()
	state.c2sKey = secrets.C2SKey
	state.s2cKey = secrets.S2CKey
	state.initialized = true
	state.mu.Unlock()
	fmt.Printf("KE complete: alg=%s cookies=%d\n", secrets.ChosenAlg, secrets.NumCookies)
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
