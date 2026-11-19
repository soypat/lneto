package tlsauto_test

import (
	"crypto/rand"
	"net"

	"github.com/soypat/lneto/crypto/tlsauto"
)

func Example() {
	var conn tlsauto.Conn
	err := conn.Configure(tlsauto.Config{
		Rand:         rand.Reader,
		ServerName:   "example.com",
		Verifier:     verifier,
		Suites:       []tlsauto.Suite{suite},
		KeyExchanges: []tlsauto.KeyExchange{group},
		MaxRecord:    4096,
	})
	if err != nil {
		panic(err)
	}
	tcp, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		panic(err)
	}
	if err = conn.Open(tcp); err != nil {
		panic(err)
	}
	if err = conn.Handshake(); err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
}

// Supplied by a crypto library such as github.com/soypat/lcrypto.
var (
	verifier tlsauto.Verifier
	suite    tlsauto.Suite
	group    tlsauto.KeyExchange
)
