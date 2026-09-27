// ssh-transport runs lneto's SSH server transport, crypto/sshauto, against a
// real SSH client. The server completes key exchange and exchanges encrypted
// packets, then refuses every login: user authentication is not implemented
// yet, so a client failing with "unable to authenticate" is the success case.
//
// The server's cryptography is github.com/soypat/lcrypto, heapless ports of
// the Go standard library meant for microcontrollers. The in-process client
// is golang.org/x/crypto/ssh, an independent implementation to check against.
//
// By default an in-process golang.org/x/crypto/ssh client connects over
// loopback. With -listen the server waits for OpenSSH instead:
//
//	go run . -listen 127.0.0.1:2222
//	ssh -vvv -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 127.0.0.1
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/soypat/lcrypto/aesgcm"
	"github.com/soypat/lcrypto/ed25519"
	"github.com/soypat/lcrypto/sha256"
	"github.com/soypat/lcrypto/x25519"
	"github.com/soypat/lneto/crypto/sshauto"
	"github.com/soypat/lneto/crypto/sshraw"
	"golang.org/x/crypto/ssh"
)

func main() {
	listen := flag.String("listen", "", "serve OpenSSH clients on this address instead of running the in-process client")
	flag.Parse()
	if err := run(*listen); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(listen string) error {
	hostKey := new(ed25519HostKey)
	if err := hostKey.signer.SetSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize)); err != nil {
		return err
	}
	newGCM := func() sshauto.LAEADCipher { return new(aesgcm.Cipher) }
	var tr sshauto.Transport
	err := tr.Configure(sshauto.Config{
		Rand:     rand.Reader,
		Software: "lneto_0.1",
		KeyExchanges: []sshauto.KeyExchange{{
			Name:           sshraw.KexCurve25519SHA256,
			ClientShareLen: 32, ServerShareLen: 32, SharedLen: 32,
			NewExchanger: func() sshauto.LExchanger { return new(x25519.Exchanger) },
			NewHash:      func() hash.Hash { return sha256.New() },
		}},
		Ciphers: []sshauto.Cipher{
			{Name: sshraw.CipherAES256GCM, KeyLen: 32, NewAEAD: newGCM},
			{Name: sshraw.CipherAES128GCM, KeyLen: 16, NewAEAD: newGCM},
		},
		HostKeys: []sshauto.HostKey{hostKey},
	})
	if err != nil {
		return fmt.Errorf("configure: %w", err)
	}
	addr := listen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if listen != "" {
		fmt.Println("listening on", ln.Addr())
		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			err = serve(&tr, conn) // One connection at a time: the Transport is reused.
			fmt.Println("connection ended:", err)
		}
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		serverErr <- serve(&tr, conn)
	}()
	// The client checks the host key blob the server sends, parsed by x/crypto.
	blob := make([]byte, 64)
	n, err := hostKey.PublicKey(blob)
	if err != nil {
		return err
	}
	pub, err := ssh.ParsePublicKey(blob[:n])
	if err != nil {
		return err
	}
	_, err = ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "lneto",
		Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
		HostKeyCallback: ssh.FixedHostKey(pub), // Fails the dial on a bad host key signature.
		Timeout:         5 * time.Second,
	})
	if err == nil {
		return errors.New("client logged in, but the server refuses every login")
	} else if !strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("client: %w", err)
	}
	fmt.Println("client:", err)
	fmt.Println("server:", <-serverErr)
	fmt.Println("transport OK (auth refused as expected)")
	return nil
}

// serve runs the transport over conn, answering the user authentication
// service with a refusal of every request.
func serve(tr *sshauto.Transport, conn net.Conn) error {
	defer tr.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tr.Open(conn, false); err != nil {
		return err
	} else if err = tr.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	kex, hostKey, cin, cout := tr.Algorithms()
	fmt.Printf("server: negotiated kex=%s hostkey=%s cipher c2s=%s s2c=%s\n", kex, hostKey, cin, cout)
	var e sshraw.Encoder
	buf := make([]byte, 256)
	for {
		payload, err := tr.ReadPacket()
		if err != nil {
			return err
		}
		e.Reset(buf, 0)
		switch typ := sshraw.MsgType(payload[0]); typ {
		case sshraw.MsgServiceRequest:
			name, err := sshraw.ParseServiceName(payload)
			if err != nil || string(name) != sshraw.ServiceUserauth {
				return tr.Disconnect(sshraw.DisconnectServiceNotAvailable, "")
			}
			e.Uint8(uint8(sshraw.MsgServiceAccept))
			e.Str(sshraw.ServiceUserauth)
		case sshraw.MsgUserauthRequest:
			fmt.Println("server: refusing", typ.StringConst())
			e.Uint8(uint8(sshraw.MsgUserauthFailure))
			e.NameList("publickey", "password") // Methods that could continue.
			e.Bool(false)                         // No partial success.
		default:
			if err = tr.WriteUnimplemented(); err != nil {
				return err
			}
			continue
		}
		if err = tr.WritePacket(buf[:e.Len()]); err != nil {
			return err
		}
	}
}

// ed25519HostKey implements sshauto.HostKey for an ssh-ed25519 key. The
// lcrypto Signer is not safe for concurrent use and HostKey must be, since
// Config shares it between connections, so a mutex guards it.
type ed25519HostKey struct {
	mu     sync.Mutex
	signer ed25519.Signer
}

func (k *ed25519HostKey) Algorithm() string { return sshraw.HostKeyEd25519 }

// PublicKey writes the ssh-ed25519 public key blob, RFC 8709 4.
func (k *ed25519HostKey) PublicKey(dst []byte) (int, error) {
	const n = 4 + len(sshraw.HostKeyEd25519) + 4 + ed25519.PublicKeySize
	if len(dst) < n {
		return n, io.ErrShortBuffer
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	pub, err := k.signer.PublicKey()
	if err != nil {
		return 0, err
	}
	var e sshraw.Encoder
	e.Reset(dst, 0)
	e.Str(sshraw.HostKeyEd25519)
	e.String(pub)
	return e.Len(), e.Err()
}

// Sign writes the 64 byte Ed25519 signature of the exchange hash, RFC 8709 6.
func (k *ed25519HostKey) Sign(sig, msg []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.signer.Sign(sig, msg); err != nil {
		return 0, err
	}
	return ed25519.SignatureSize, nil
}
