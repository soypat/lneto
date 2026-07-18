package main

import (
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/soypat/lneto/http/httpraw"
)

const listenPort = 8080

func main() {
	if err := run(); err != nil {
		println("Error: ", err)
		os.Exit(1)
	}
	println("DONE")
}

func run() error {
	ln, err := Listen(listenPort)
	if err != nil {
		return err
	}
	defer ln.Close()
	println("listening on port", listenPort)
	conn := new(Conn)
	for {
		err := ln.Accept(conn)
		if err != nil {
			return err
		}
		visits.Add(1)
		if err := handle(conn); err != nil {
			println("handle:", conn.RemoteAddr().String(), err.Error())
		}
		conn.Close()
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
)

const maxHTTPHeader = 1024

var (
	hdr     httpraw.Header
	httpbuf [maxHTTPHeader]byte
	htmlbuf [512]byte
	visits  atomic.Uint64
)

func handle(conn *Conn) error {
	hdr.Reset(httpbuf[:0])
	hdr.EnableBufferGrowth(false)    // Limit memory to buffer capacity.
	const incomingIsResponse = false // We get HTTP requests from clients.
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Until(deadline) > 0 {
		if _, err := hdr.ReadFromLimited(conn, maxHTTPHeader); err != nil {
			return err
		}
		needmoredata, err := hdr.TryParse(incomingIsResponse)
		if err != nil {
			return err
		}
		if needmoredata {
			continue
		}
		break
	}
	println("\n\n================\n\n", hdr.String())
	if time.Since(deadline) > 0 {
		print("DEADLINE EXCEED: ", hdr.BufferParsed(), "/", hdr.BufferReceived(), " bytes parsed/read\n")
		return nil
	}
	// Prepare tacky HTML response.
	n := copy(htmlbuf[:], htmlHead)
	n += len(strconv.AppendUint(htmlbuf[n:n], visits.Load(), 10))
	n += copy(htmlbuf[n:], htmlTail)
	contentLen := n
	hdr.Reset(httpbuf[:0])
	hdr.SetProtocol("HTTP/1.1")
	hdr.SetStatus("200", "OK")
	hdr.Set("Content-Type", "text/html")
	hdr.SetInt("Content-Length", int64(contentLen), 10)
	// Here we do some buffer juggling. We use remaining space
	// of HTTP Header buffer to write the response that will be written over the wire.
	respbuf := httpbuf[hdr.BufferUsed():]
	header, err := hdr.AppendResponse(respbuf[:0])
	if err != nil {
		return err
	}
	conn.Write(header)
	_, err = conn.Write(htmlbuf[:contentLen])
	return err
}
