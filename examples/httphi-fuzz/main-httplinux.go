//go:build !tinygo && linux

package main

import (
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/http/httphi"
	"github.com/soypat/lneto/http/httpraw"
)

const (
	kB          = 1 << 10
	listenPort  = 8080
	bufferSizes = 2 * kB
	// A browser sends around twenty header fields; a request carrying more
	// than this is answered 431 rather than parsed into memory it was not
	// given. Each field costs 8 bytes of table.
	numHeaderFields = 32
	readTimeout     = 2 * time.Second
)

// Credentials the endpoints check. They are in the source on purpose: this is a
// target to point a fuzzer at, and a scan is only interesting when something is
// there to be found.
const (
	adminUser    = "admin"
	adminPass    = "hunter2"
	sessionToken = "s3cr3t-session-token"
)

// Fixed corpora the handlers answer from, so a path scan separates hits from
// misses instead of finding one status code everywhere.
var (
	users = [...]string{"alice", "bob", "carol"}
	files = [...]string{"readme.txt", "logo.png", "notes.md"}
)

var (
	flagPort    = flag.Int("port", listenPort, "TCP port to listen on")
	flagVerbose = flag.Bool("v", false, "log every request to stderr; a fuzzer at full rate makes this expensive")
	flagThreads = flag.Int("threads", 8, "Number of goroutines to spawn.")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		println("Error:", err.Error())
		os.Exit(1)
	}
	println("DONE")
}

func run() error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(*flagPort))
	if err != nil {
		return err
	}
	defer ln.Close()
	print("listening on http://localhost:", *flagPort, "\n")

	var server Server
	// One scratch per router goroutine: the router serves that many requests at
	// once, so a handler always finds one waiting for it.
	server.initScratch(*flagThreads)
	// "{$}" matches the empty path and nothing else, so an unregistered path
	// gets a 404 instead of the homepage. A bare "/" is a catch-all.
	server.Handle("GET /{$}", server.homepage)
	server.Handle("GET /health", server.health)
	server.Handle("GET /search", server.search)
	server.Handle("POST /login", server.login)
	server.Handle("GET /admin", server.admin)
	server.Handle("GET /users/{id}", server.user)
	server.Handle("GET /files/{path...}", server.file)
	server.Handle("POST /upload", server.upload)
	server.Handle("/echo", server.echo) // No method: any method matches.

	var router httphi.Router
	err = router.Configure(httphi.RouterConfig{
		FixedNumGoroutines:          *flagThreads,
		RequestHeaderBufferSize:     bufferSizes,
		RequestNumHeaderKVCap:       numHeaderFields,
		ResponseHeaderMinBufferSize: bufferSizes,
		Mux:                         &server.mux,
		Logger:                      slog.Default(),
	})
	if err != nil {
		return err
	}
	defer router.Shutdown()

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
		`<font color="#FF00FF">Sign my guestbook!</font><br><hr>` +
		`<a href="/search?q=go">/search</a> | ` +
		`<a href="/users/alice">/users/{id}</a> | ` +
		`<a href="/files/">/files/</a> | ` +
		`<a href="/admin">/admin</a> | ` +
		`<a href="/echo">/echo</a> | ` +
		`<a href="/health">/health</a>` +
		`<br><hr>Best viewed in Netscape Navigator</center></body></html>`
	// maxPage bounds the rendered page: both halves plus the visitor number.
	maxPage = len(htmlHead) + 20 + len(htmlTail)
)

// Compile-time check that a scratch's render buffer holds the largest page a
// handler builds. A page outgrowing it would grow the buffer on the heap,
// which is the one thing this server is written not to do.
const _ = uint(outBufferSize - maxPage)

type Server struct {
	// Visits counts served requests.
	Visits atomic.Uint64
	mux    httphi.MuxSlice
	// scratch is a fixed pool of per-request working memory, see [scratch].
	scratch chan *scratch
}

// Sizes of a [scratch]. Every one of these is memory spent once per pooled
// scratch, so the pool's size times the sum below is what the handlers cost.
const (
	formBufferSize      = kB
	formNumPairs        = 16
	cookieBufferSize    = 512
	cookieNumPairs      = 8
	multipartBufferSize = kB
	maxMultipartParts   = 8
	outBufferSize       = 2 * kB
	tmpBufferSize       = 256
)

// scratch is the memory a handler works in for the length of one request: the
// [Exchange] buffer holds the request header and the response header, and
// everything a handler parses or renders on top of that lives here.
//
// Parsers are handed their buffer once and forbidden to grow, so a request that
// sends more than the buffer holds is answered an error rather than served from
// memory the server never budgeted for.
type scratch struct {
	form   httpraw.Form
	cookie httpraw.Cookie
	// parts is reused across requests: its [httpraw.MultipartHeader] values keep
	// the buffers their Name and Filename were copied into.
	parts   []httphi.MultipartSink
	uploads countingSink

	formBuf   [formBufferSize]byte
	cookieBuf [cookieBufferSize]byte
	mpBuf     [multipartBufferSize]byte
	// out renders the response body, tmp holds a decoded value being read out of
	// the request. They are separate because a decode reads into one while the
	// body is being built in the other.
	out [outBufferSize]byte
	tmp [tmpBufferSize]byte
}

// initScratch fills the pool with n scratches and fixes each parser to its
// buffer. Sizing n to the router's goroutine count bounds handler memory the
// same way the router bounds its own.
func (sv *Server) initScratch(n int) {
	sv.scratch = make(chan *scratch, n)
	for range n {
		s := new(scratch)
		s.form.Reset(s.formBuf[:0], formNumPairs)
		s.form.EnableBufferGrowth(false)
		s.cookie.Reset(s.cookieBuf[:0], cookieNumPairs)
		s.cookie.EnableBufferGrowth(false)
		s.parts = make([]httphi.MultipartSink, 0, maxMultipartParts)
		sv.scratch <- s
	}
}

// acquireScratch takes a scratch out of the pool, blocking while none is free.
// With the pool sized to the router's fixed goroutine count it never blocks:
// a handler running is a goroutine that has not returned its scratch yet.
func (sv *Server) acquireScratch() *scratch { return <-sv.scratch }

func (sv *Server) releaseScratch(s *scratch) { sv.scratch <- s }

// Handle registers a handler and wraps it in the middleware every request runs
// through: the visit counter and, when asked for, the request log.
func (sv *Server) Handle(pattern string, handler httphi.HandlerFunc) {
	sv.mux.Handle(pattern, func(exch *httphi.Exchange) {
		sv.Visits.Add(1)
		if *flagVerbose {
			println(exch.RequestMethod().String(), exch.MuxPattern())
		}
		handler(exch)
	})
}

func (sv *Server) homepage(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	page := append(s.out[:0], htmlHead...)
	page = strconv.AppendUint(page, sv.Visits.Load(), 10)
	page = append(page, htmlTail...)
	exch.Respond(httphi.StatusOK, "text/html", page)
}

func (sv *Server) health(exch *httphi.Exchange) {
	exch.RespondString(httphi.StatusOK, "text/plain", "ok\n")
}

// search reads the query string, i.e: "/search?q=go+lang&limit=2". Values are
// percent and '+' encoded on the wire, so this is the decoder's surface: a
// malformed escape is answered 400 and never half decoded into the response.
func (sv *Server) search(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	const decode = true
	query, present := exch.RequestQueryAppend(s.tmp[:0], "q", decode)
	if !present {
		exch.RespondString(httphi.StatusBadRequest, "text/plain", "missing or malformed q parameter\n")
		return
	}
	limit := len(users)
	if raw, present := exch.RequestQueryValue("limit"); present {
		n, ok := atoiBounded(raw, len(users))
		if !ok {
			exch.RespondString(httphi.StatusBadRequest, "text/plain", "limit must be a non-negative integer\n")
			return
		}
		limit = n
	}
	body := append(s.out[:0], "query: "...)
	body = append(body, query...)
	body = append(body, '\n')
	for _, user := range users[:limit] {
		body = append(body, user...)
		body = append(body, '\n')
	}
	exch.Respond(httphi.StatusOK, "text/plain", body)
}

// login reads "application/x-www-form-urlencoded" pairs out of the request body
// and the query string alike, the body winning a key both carry. It is where a
// credential scan lands:
//
//	ffuf -X POST -u http://localhost:8080/login -d 'user=admin&pass=FUZZ' \
//	     -H 'Content-Type: application/x-www-form-urlencoded' -w passwords.txt -fc 401
func (sv *Server) login(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	// Checked ahead of the parse so a body in some other encoding is told what
	// is wrong with it, the parser reporting only that it would not parse.
	contentType := exch.RequestContentType()
	if contentType != nil && !httpraw.MediaTypeIs(contentType, "application/x-www-form-urlencoded") {
		exch.RespondString(httphi.StatusUnsupportedMediaType, "text/plain", "expected application/x-www-form-urlencoded\n")
		return
	}
	const parseQuery, queryWins = true, false
	err := exch.RequestParseForm(&s.form, parseQuery, queryWins)
	if err != nil {
		// A body larger than formBufferSize or more pairs than formNumPairs land
		// here too: the form was told not to grow, so it refuses instead.
		exch.RespondString(httphi.StatusBadRequest, "text/plain", "malformed or oversized form\n")
		return
	}
	if err = s.form.Decode(); err != nil {
		exch.RespondString(httphi.StatusBadRequest, "text/plain", "malformed percent escape in form\n")
		return
	}
	user, pass := s.form.Get("user"), s.form.Get("pass")
	if string(user) != adminUser || string(pass) != adminPass {
		exch.RespondString(httphi.StatusUnauthorized, "text/plain", "bad credentials\n")
		return
	}
	exch.StageHeader("Set-Cookie", "session="+sessionToken+"; Path=/; HttpOnly")
	exch.RespondString(httphi.StatusOK, "text/plain", "welcome "+adminUser+"\n")
}

// admin is gated on the cookie [Server.login] hands out, so a scan of it fuzzes
// the cookie parser:
//
//	ffuf -u http://localhost:8080/admin -b 'session=FUZZ' -w tokens.txt -fc 403
func (sv *Server) admin(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	err := exch.RequestParseCookie(&s.cookie, "Cookie")
	if err != nil {
		exch.RespondString(httphi.StatusUnauthorized, "text/plain", "no cookie\n")
		return
	}
	if string(s.cookie.Get("session")) != sessionToken {
		exch.RespondString(httphi.StatusForbidden, "text/plain", "forbidden\n")
		return
	}
	body := append(s.out[:0], "admin panel\n"...)
	// A valueless attribute, i.e: "session=...; debug", is stored with an empty
	// key, so a plain Get would never find it.
	if s.cookie.HasKeyOrSingleValue("debug") {
		body = append(body, "requests served: "...)
		body = strconv.AppendUint(body, sv.Visits.Load(), 10)
		body = append(body, '\n')
	}
	exch.Respond(httphi.StatusOK, "text/plain", body)
}

// user serves the "{id}" wildcard, a single path segment. Segments are bound
// raw, so the value is decoded here and "/users/al%69ce" reaches alice.
func (sv *Server) user(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	const decode = true
	id, err := exch.PathValueAppend(s.tmp[:0], "id", decode)
	if err != nil {
		exch.RespondString(httphi.StatusBadRequest, "text/plain", "malformed percent escape in path\n")
		return
	}
	for _, user := range users {
		if string(id) == user {
			body := append(s.out[:0], `{"user":"`...)
			body = append(body, id...)
			body = append(body, "\"}\n"...)
			exch.Respond(httphi.StatusOK, "application/json", body)
			return
		}
	}
	exch.RespondString(httphi.StatusNotFound, "text/plain", "no such user\n")
}

// file serves the "{path...}" wildcard, which takes the rest of the path
// including its slashes, so "/files/" and "/files/a/b" both reach here. That
// makes it what a recursive scan walks: ffuf -u http://localhost:8080/files/FUZZ -recursion.
func (sv *Server) file(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	path := exch.PathValue("path")
	if len(path) == 0 {
		body := append(s.out[:0], "index of /files/\n"...)
		for _, file := range files {
			body = append(body, file...)
			body = append(body, '\n')
		}
		exch.Respond(httphi.StatusOK, "text/plain", body)
		return
	}
	for _, file := range files {
		if string(path) == file {
			body := append(s.out[:0], "contents of "...)
			body = append(body, path...)
			body = append(body, '\n')
			exch.Respond(httphi.StatusOK, "text/plain", body)
			return
		}
	}
	exch.RespondString(httphi.StatusNotFound, "text/plain", "no such file\n")
}

// upload streams a "multipart/form-data" body, counting each file part instead
// of storing it. Parts declare no length, so the body is read a bufferful at a
// time and the header of a part that outgrows the buffer is refused 413.
//
//	ffuf -X POST -u http://localhost:8080/upload -w names.txt \
//	     -H 'Content-Type: multipart/form-data; boundary=X' \
//	     -d $'--X\r\nContent-Disposition: form-data; name="f"; filename="FUZZ"\r\n\r\ndata\r\n--X--\r\n'
func (sv *Server) upload(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	if !httpraw.MediaTypeIs(exch.RequestContentType(), "multipart/form-data") {
		exch.RespondString(httphi.StatusUnsupportedMediaType, "text/plain", "expected multipart/form-data\n")
		return
	}
	s.uploads.n = 0
	// The sink is a field of the scratch, so handing it over as an io.WriteCloser
	// boxes a pointer that is already on the heap and allocates nothing.
	parts, err := exch.ReadMultiparts(s.parts[:0], s.mpBuf[:], func(hdr *httpraw.MultipartHeader) io.WriteCloser {
		if len(hdr.Filename) == 0 {
			return nil // A plain field, not a file: keep the header, drop the content.
		}
		return &s.uploads
	})
	// Kept even on failure: the headers parsed so far own buffers worth reusing.
	// The slice grows with the number of parts, which only the connection's read
	// deadline bounds, so a real server would cap it.
	s.parts = parts
	if err != nil {
		if err == lneto.ErrShortBuffer {
			exch.RespondString(httphi.StatusRequestEntityTooLarge, "text/plain", "part header too large\n")
		} else {
			exch.RespondString(httphi.StatusBadRequest, "text/plain", "malformed multipart body\n")
		}
		return
	}
	body := append(s.out[:0], "parts: "...)
	body = strconv.AppendInt(body, int64(len(parts)), 10)
	body = append(body, '\n')
	for i := range parts {
		body = append(body, parts[i].Header.Name...)
		if len(parts[i].Header.Filename) > 0 {
			body = append(body, " -> "...)
			body = append(body, parts[i].Header.Filename...)
		}
		body = append(body, '\n')
	}
	body = append(body, "bytes stored: "...)
	body = strconv.AppendInt(body, s.uploads.n, 10)
	body = append(body, '\n')
	exch.Respond(httphi.StatusOK, "text/plain", body)
}

// echo hands back the request line and the header block as the parser stored
// it, which is what tells a header fuzzer what its input turned into.
func (sv *Server) echo(exch *httphi.Exchange) {
	s := sv.acquireScratch()
	defer sv.releaseScratch(s)
	body := append(s.out[:0], exch.RequestMethodRaw()...)
	body = append(body, ' ')
	body = append(body, exch.RequestTarget()...)
	body = append(body, '\n')
	if value := exch.RequestHeader("X-Fuzz"); value != nil {
		body = append(body, "x-fuzz: "...)
		body = append(body, value...)
		body = append(body, '\n')
	}
	body = append(body, "-- parsed header --\n"...)
	body = exch.RequestHeaderV1Raw().AppendHeaders(body)
	exch.Respond(httphi.StatusOK, "text/plain", body)
}

// countingSink discards a multipart part and counts what it discarded, standing
// in for the file a real upload would write.
type countingSink struct{ n int64 }

func (c *countingSink) Write(b []byte) (int, error) { c.n += int64(len(b)); return len(b), nil }
func (c *countingSink) Close() error                { return nil }

// atoiBounded parses a decimal number and clamps it to max, reporting false for
// anything that is not one. It works off the bytes rather than converting to a
// string, which would allocate on a path every request takes.
func atoiBounded(b []byte, max int) (int, bool) {
	const maxDigits = 9 // Bounded so the accumulator below cannot overflow.
	if len(b) == 0 || len(b) > maxDigits {
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return min(n, max), true
}
