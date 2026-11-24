// Package tlsauto is a TLS 1.3 client with mutual authentication built on tlsraw.
// It supports neither PSK nor HelloRetryRequest.
package tlsauto

import (
	"errors"
	"io"
	"strconv"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/tlsraw"
)

// Config configures a client Conn.
type Config struct {
	Rand io.Reader
	// Suites in preference order.
	Suites []Suite
	// KeyExchanges get one key share each in the ClientHello, so the server never needs a HelloRetryRequest.
	KeyExchanges []KeyExchange
	// Schemes offered in signature_algorithms. DefaultSchemes if empty.
	Schemes []uint16
	// Credential answers a CertificateRequest. Without it the client sends an empty Certificate.
	Credential Credential
	// Verifier checks the server chain and CertificateVerify.
	Verifier Verifier
	// ServerName is sent as SNI when set and is passed to Verifier.
	ServerName string
	// ALPN is the one protocol offered. The server must select it.
	ALPN string
	// MaxRecord bounds received record plaintext, tlsraw.MaxPlaintext if zero.
	MaxRecord int
	// ReadBuf is the ring received records are framed and decrypted in.
	// Required [>= tlsraw.SizeHeaderRecord+MaxRecord+256], the largest record a server may send.
	ReadBuf []byte
	// WriteBuf holds sealed records until they are written. It must fit the
	// ClientHello and the client Certificate flight. Required [>= 512].
	WriteBuf []byte
	// HandshakeBuf is split in two halves: one reassembles handshake messages,
	// the other keeps the server Certificate until CertificateVerify. It is
	// wiped after the handshake. Required [>= 1024]; 8192 fits P-256 device
	// chains of a few certificates.
	HandshakeBuf []byte
}

var (
	errHelloRetry = errors.New("tlsauto: HelloRetryRequest not supported")
	errNoConfig   = errors.New("tlsauto: invalid config")
)

type connState uint8

const (
	stateIdle connState = iota
	stateHandshake
	stateConnected
	stateFailed
	stateClosed
)

// Conn is a TLS 1.3 client connection. It is not safe for concurrent use.
type Conn struct {
	h  handler
	rw io.ReadWriter
}

// Configure checks cfg and keeps a copy of it for the next Open.
func (c *Conn) Configure(cfg Config) error { return c.h.Configure(cfg) }

// Open starts a new connection over rw, which must be a fresh reliable stream.
func (c *Conn) Open(rw io.ReadWriter) error {
	if rw == nil {
		return errNoConfig
	} else if err := c.h.Open(); err != nil {
		return err
	}
	c.rw = rw
	return nil
}

// Handshake runs the handshake if it has not run yet. Read and Write call it.
func (c *Conn) Handshake() error {
	switch c.h.state {
	case stateConnected:
		return nil
	case stateHandshake:
	default:
		return lneto.ErrBadState
	}
	for {
		if err := c.flush(); err != nil {
			return c.failed(err)
		} else if c.h.HandshakeDone() {
			return nil
		} else if err = c.fill(); err != nil {
			return err
		}
	}
}

// ALPN returns the negotiated protocol.
func (c *Conn) ALPN() string { return c.h.ALPN() }

// Read reads application data. It returns io.EOF after the server's close_notify.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	for {
		n, err := c.h.Read(p)
		if err == io.EOF {
			return 0, err
		} else if err != nil {
			return 0, c.failed(err)
		} else if n > 0 || len(p) == 0 {
			return n, nil
		} else if err = c.fill(); err != nil {
			return 0, err
		}
	}
}

// Write sends p as application data records.
func (c *Conn) Write(p []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return 0, err
	}
	for n < len(p) {
		k, err := c.h.Write(p[n:])
		if err != nil {
			return n, c.failed(err)
		} else if err = c.flush(); err != nil {
			return n, c.failed(err)
		}
		n += k
	}
	return n, nil
}

// Close sends close_notify, wipes secrets and closes rw if it is an io.Closer.
func (c *Conn) Close() error {
	connected := c.h.state == stateConnected
	err := c.h.Close()
	if connected && err == nil {
		err = c.flush()
	}
	c.h.Zeroize()
	if cl, ok := c.rw.(io.Closer); ok {
		if cerr := cl.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// Zeroize wipes secrets and buffered data. Open must be called before reuse.
func (c *Conn) Zeroize() { c.h.Zeroize() }

// flush writes all queued records to rw. The first call after Open queues the ClientHello.
func (c *Conn) flush() error {
	for {
		_, err := c.h.SendTo(c.rw)
		if err != nil || c.h.BufferedOutput() == 0 {
			return err
		}
	}
}

// fill reads once from rw and processes the records it completes.
func (c *Conn) fill() error {
	_, err := c.h.RecvFrom(c.rw)
	if err == nil {
		return nil
	} else if err == io.EOF {
		err = io.ErrUnexpectedEOF // Only close_notify ends a connection cleanly, RFC 8446 6.1.
	}
	return c.failed(err)
}

// failed fails the handler with err unless it already failed, then tries to send the queued alert.
func (c *Conn) failed(err error) error {
	if c.h.state != stateFailed {
		err = c.h.fail(err)
	}
	c.h.SendTo(c.rw)
	return err
}

type alertError tlsraw.AlertDescription

func (a alertError) Error() string { return "tlsauto: sent alert " + strconv.Itoa(int(a)) }

type peerAlertError tlsraw.AlertDescription

func (a peerAlertError) Error() string { return "tlsauto: received alert " + strconv.Itoa(int(a)) }

type verifyError struct{ err error }

func (v verifyError) Error() string { return "tlsauto: peer verification failed: " + v.err.Error() }
func (v verifyError) Unwrap() error { return v.err }
