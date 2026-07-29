//go:build !tinygo && linux

package main

import (
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/soypat/lneto/http/httphi"
)

const (
	kB          = 1 << 10
	listenPort  = 8080
	bufferSizes = 2 * kB
	// A browser sends around twenty header fields; a request carrying more
	// than this is answered 431 rather than parsed into memory it was not
	// given. Each field costs 8 bytes of table.
	numHeaderFields = 32
	numGoroutines   = 4
	readTimeout     = 2 * time.Second
)

func main() {
	if err := run(); err != nil {
		println("Error:", err.Error())
		os.Exit(1)
	}
	println("DONE")
}

func run() error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(listenPort))
	if err != nil {
		return err
	}
	defer ln.Close()
	print("listening on http://localhost:", listenPort, "\n")

	var mux httphi.MuxSlice
	mux.Handle("GET /", homepage)

	var router httphi.Router
	err = router.Configure(httphi.RouterConfig{
		FixedNumGoroutines:          numGoroutines,
		RequestHeaderBufferSize:     bufferSizes,
		RequestNumHeaderKVCap:       numHeaderFields,
		ResponseHeaderMinBufferSize: bufferSizes,
		MaxAwaitingConns:            256,
		Mux:                         &mux,
		Logger:                      slog.Default(),
	})
	if err != nil {
		return err
	}
	defer router.TeardownGoroutines()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// The connection owns the idle policy: a peer that opens a socket and
		// then stalls fails its read instead of holding a router goroutine.
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		err = router.Handle(conn)
		if err != nil {
			// Every goroutine is busy and the queue is full. Dropping the
			// connection is the backpressure: memory stays bounded.
			slog.Warn("dropped connection", slog.String("remote", conn.RemoteAddr().String()), slog.String("err", err.Error()))
			conn.Close()
		}
	}
}

const (
	htmlHead = `<html><body bgcolor="#000080" text="#00FF00"><center>` +
		`<marquee><font face="Comic Sans MS" size="5" color="#FFFF00">` +
		`*** WELCOME TO MY HOMEPAGE ***</font></marquee>` +
		`<h1><blink>YOU ARE VISITOR #`
	htmlTail = `!</blink></h1>` +
		`<font color="#FF00FF">Sign my guestbook!</font>` +
		`<br><hr>Best viewed in Netscape Navigator</center></body></html>`
	// maxPage bounds the rendered page: both halves plus the visitor number.
	maxPage = len(htmlHead) + 20 + len(htmlTail)
)

// visits counts served requests. Handlers run on the router's goroutines, so
// every visitor gets their own number.
var visits atomic.Uint64

func homepage(exch *httphi.Exchange) {
	var page [maxPage]byte
	n := copy(page[:], htmlHead)
	n += len(strconv.AppendUint(page[n:n], visits.Add(1), 10))
	n += copy(page[n:], htmlTail)

	exch.StageHeader("Content-Type", "text/html")
	exch.StageHeaderInt("Content-Length", int64(n), 10)
	exch.WriteHeader(int(httphi.StatusOK))
	exch.WriteBody(page[:n])
}
