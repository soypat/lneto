package httphi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/soypat/lneto"
)

func nopBackoff(consecutiveBackoffs uint) time.Duration { return lneto.BackoffFlagNop }

// newExchange returns an Exchange acquired on conn, ready to serve a request.
func newExchange(t *testing.T, conn conn, bufferSize int, normalizeKeys bool) *Exchange {
	t.Helper()
	exch := new(Exchange)
	exch.Configure(make([]byte, 2*bufferSize), bufferSize, normalizeKeys)
	if !exch.Acquire(conn) {
		t.Fatal("fresh exchange failed to acquire connection")
	}
	return exch
}

// serve runs a single exchange to completion on the calling goroutine.
func serve(t *testing.T, request string, mux Mux) *rwconn {
	t.Helper()
	const bufferSize = 1024
	conn := newConn(request)
	conn.Hangup() // Whole request already pending, nothing more will arrive.
	exch := newExchange(t, conn, bufferSize, false)
	err := Handle(exch, mux, nopBackoff)
	if err != nil {
		t.Fatalf("Handle(%q): %s", request, err)
	}
	return conn
}

// WriteHeader must emit a complete status line terminated in CRLF followed by
// the end-of-headers CRLF, for every status code including the longest text.
func TestExchangeWriteHeader(t *testing.T) {
	for _, test := range []struct {
		code int
		want string
	}{
		{code: 200, want: "HTTP/1.1 200 OK\r\n\r\n"},
		{code: 404, want: "HTTP/1.1 404 Not Found\r\n\r\n"},
		{code: 500, want: "HTTP/1.1 500 Internal Server Error\r\n\r\n"},
		// Longest status text in status.go: worst case for the status line buffer.
		{code: 511, want: "HTTP/1.1 511 Network Authentication Required\r\n\r\n"},
	} {
		conn := newConn("")
		exch := newExchange(t, conn, 128, false)
		exch.WriteHeader(test.code)
		if got := conn.ViewWritten(); got != test.want {
			t.Errorf("code %d: want %q, got %q", test.code, test.want, got)
		}
	}
}

// Status line is written once: a second WriteHeader must not reach the wire.
func TestExchangeWriteHeaderOnce(t *testing.T) {
	conn := newConn("")
	exch := newExchange(t, conn, 128, false)
	exch.WriteHeader(404)
	exch.WriteHeader(500)
	const want = "HTTP/1.1 404 Not Found\r\n\r\n"
	if got := conn.ViewWritten(); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// Write with no prior WriteHeader must flush a 200 header ahead of the body.
func TestExchangeWriteFlushesHeader(t *testing.T) {
	const body = "hello"
	conn := newConn("")
	exch := newExchange(t, conn, 128, false)
	n, err := exch.Write([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(body) {
		t.Errorf("want %d bytes written, got %d", len(body), n)
	}
	const want = "HTTP/1.1 200 OK\r\n\r\n" + body
	if got := conn.ViewWritten(); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

func TestExchangeSetHeader(t *testing.T) {
	for _, test := range []struct {
		name      string
		normalize bool
		set       [][2]string
		want      string // Header block emitted after the status line.
	}{
		{name: "none", want: "\r\n"},
		{name: "single", set: [][2]string{{"Content-Type", "text/plain"}}, want: "Content-Type:text/plain\r\n\r\n"},
		{
			name: "multiple",
			set:  [][2]string{{"Content-Type", "text/plain"}, {"Content-Length", "5"}},
			want: "Content-Type:text/plain\r\nContent-Length:5\r\n\r\n",
		},
		{
			name:      "normalized key",
			normalize: true,
			set:       [][2]string{{"content-TYPE", "text/plain"}},
			want:      "Content-Type:text/plain\r\n\r\n",
		},
		{
			name: "key kept verbatim when not normalizing",
			set:  [][2]string{{"content-TYPE", "text/plain"}},
			want: "content-TYPE:text/plain\r\n\r\n",
		},
		{name: "empty value", set: [][2]string{{"X-Empty", ""}}, want: "X-Empty:\r\n\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := newConn("")
			exch := newExchange(t, conn, 128, test.normalize)
			for _, kv := range test.set {
				if !exch.SetHeader(kv[0], kv[1]) {
					t.Fatalf("SetHeader(%q,%q) reported insufficient memory", kv[0], kv[1])
				}
			}
			exch.WriteHeader(200)
			got, found := strings.CutPrefix(conn.ViewWritten(), "HTTP/1.1 200 OK\r\n")
			if !found {
				t.Fatalf("want 200 status line, got %q", conn.ViewWritten())
			}
			if got != test.want {
				t.Errorf("want header block %q, got %q", test.want, got)
			}
		})
	}
}

// SetHeader must refuse to write past the buffer and say so, never panic nor
// emit a truncated field.
func TestExchangeSetHeaderOOM(t *testing.T) {
	const bufferSize = 32
	conn := newConn("")
	exch := newExchange(t, conn, bufferSize, false)
	if exch.SetHeader("X-Big", strings.Repeat("v", 4*bufferSize)) {
		t.Fatal("want insufficient memory reported for oversized header value")
	}
	exch.WriteHeader(200)
	if got := conn.ViewWritten(); strings.Contains(got, "X-Big") {
		t.Errorf("dropped header must not appear in response, got %q", got)
	}
}

// Request line and fields the handler observes, over a spread of well formed
// and awkward but legal request headers.
func TestHandleRequestFields(t *testing.T) {
	for _, test := range []struct {
		name       string
		request    string
		wantMethod string
		wantURI    string
		wantHost   string
	}{
		{
			name:       "minimal",
			request:    "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
			wantMethod: "GET", wantURI: "/", wantHost: "h",
		},
		{
			name:       "query string",
			request:    "GET /search?q=go&n=1 HTTP/1.1\r\nHost: h\r\n\r\n",
			wantMethod: "GET", wantURI: "/search?q=go&n=1", wantHost: "h",
		},
		{
			name:       "no fields",
			request:    "GET /x HTTP/1.1\r\n\r\n",
			wantMethod: "GET", wantURI: "/x", wantHost: "",
		},
		{
			name:       "post",
			request:    "POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
			wantMethod: "POST", wantURI: "/submit", wantHost: "h",
		},
		{
			name:       "extension method",
			request:    "FROBNICATE / HTTP/1.1\r\nHost: h\r\n\r\n",
			wantMethod: "FROBNICATE", wantURI: "/", wantHost: "h",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var gotMethod, gotURI, gotHost string
			var sm MuxSlice
			sm.Handle(test.wantURI, func(ex *Exchange) {
				gotMethod = string(ex.RequestMethod())
				gotURI = string(ex.RequestURI())
				gotHost = string(ex.RequestHeader("Host"))
				ex.WriteHeader(200)
			})
			serve(t, test.request, &sm)

			if gotMethod != test.wantMethod {
				t.Errorf("want method %q, got %q", test.wantMethod, gotMethod)
			}
			if gotURI != test.wantURI {
				t.Errorf("want URI %q, got %q", test.wantURI, gotURI)
			}
			if gotHost != test.wantHost {
				t.Errorf("want Host %q, got %q", test.wantHost, gotHost)
			}
		})
	}
}

// Malformed request headers must fail the exchange, never reach a handler.
func TestHandleMalformedRequest(t *testing.T) {
	for _, test := range []struct {
		name    string
		request string
	}{
		{name: "no colon in field", request: "GET / HTTP/1.1\r\nBadFieldNoColon\r\n\r\n"},
		{name: "no protocol", request: "GET /\r\nHost: h\r\n\r\n"},
		{name: "empty request line", request: "\r\n\r\n"},
		{name: "truncated header", request: "GET / HTTP/1.1\r\nHost: h\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var handled bool
			var sm MuxSlice
			sm.Handle("/", func(ex *Exchange) { handled = true })
			conn := newConn(test.request)
			conn.Hangup()
			exch := newExchange(t, conn, 1024, false)
			if err := Handle(exch, &sm, nopBackoff); err == nil {
				t.Error("want error on malformed request, got nil")
			}
			if handled {
				t.Error("handler must not run on malformed request")
			}
		})
	}
}

// No registered handler must yield 404, not an empty response.
func TestHandleNoHandler(t *testing.T) {
	var sm MuxSlice
	sm.Handle("GET /", func(ex *Exchange) { t.Error("handler must not run") })
	conn := serve(t, "GET /nowhere HTTP/1.1\r\nHost: h\r\n\r\n", &sm)
	const want = "HTTP/1.1 404 Not Found\r\n\r\n"
	if got := conn.ViewWritten(); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// A handler that writes nothing must still produce a valid response.
func TestHandleSilentHandler(t *testing.T) {
	var sm MuxSlice
	sm.Handle("/", func(ex *Exchange) {})
	conn := serve(t, "GET / HTTP/1.1\r\nHost: h\r\n\r\n", &sm)
	const want = "HTTP/1.1 200 OK\r\n\r\n"
	if got := conn.ViewWritten(); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// Body bytes arriving in the same segment as the header must be readable.
func TestExchangeReadBody(t *testing.T) {
	const body = "message body"
	var got string
	var readErr error
	var sm MuxSlice
	sm.Handle("POST /", func(ex *Exchange) {
		dst := make([]byte, len(body))
		n, err := ex.ReadBody(dst)
		got, readErr = string(dst[:n]), err
		ex.WriteHeader(200)
	})
	serve(t, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\n"+body, &sm)

	if readErr != nil {
		t.Fatal(readErr)
	}
	if got != body {
		t.Errorf("want body %q, got %q", body, got)
	}
}

// SetHeader must budget every byte it writes: colon, CRLF, and the CRLF that
// FlushHeader appends after the last field. Buffers that fit all but the last
// byte must be refused, never overrun.
func TestExchangeSetHeaderExactFit(t *testing.T) {
	const key, value = "K", "V"
	const field = len(key) + len(value) + len(":\r\n")
	for _, bufLen := range []int{field + 2, field + 1, field} {
		conn := newConn("")
		exch := new(Exchange)
		exch.Configure(make([]byte, bufLen), bufLen, false)
		if !exch.Acquire(conn) {
			t.Fatal("fresh exchange failed to acquire connection")
		}
		set := exch.SetHeader(key, value)
		exch.WriteHeader(200)

		want := "HTTP/1.1 200 OK\r\n"
		if set {
			want += key + ":" + value + "\r\n"
		}
		want += "\r\n"
		if got := conn.ViewWritten(); got != want {
			t.Errorf("buffer %d: want %q, got %q", bufLen, want, got)
		}
		if wantSet := bufLen >= field+2; set != wantSet {
			t.Errorf("buffer %d: want SetHeader=%v, got %v", bufLen, wantSet, set)
		}
	}
}

// Handle never closes the connection, on any outcome: the caller owns it so
// that error policy and connection reuse stay the caller's decision.
func TestHandleLeavesConnOpen(t *testing.T) {
	var sm MuxSlice
	sm.Handle("GET /", staticPage(t, "ok"))
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: h\r\n\r\n",         // Served.
		"GET /nowhere HTTP/1.1\r\nHost: h\r\n\r\n",  // 404.
		"GET /\r\nHost: h\r\n\r\n",                  // Rejected: no HTTP version.
		"GET / HTTP/1.1\r\nBadFieldNoColon\r\n\r\n", // Rejected: parse error.
	} {
		conn := newConn(request)
		conn.Hangup()
		exch := newExchange(t, conn, 1024, false)
		Handle(exch, &sm, nopBackoff)
		if conn.IsClosed() {
			t.Errorf("Handle closed the connection for %q", request)
		}
	}
}

// Hijacking hands the connection to the handler, so Release must not close it.
// Ownership must not carry over: the next connection the exchange serves is
// the router's again and must be closed on Release.
func TestExchangeHijackOwnership(t *testing.T) {
	var sm MuxSlice
	var hijackErr error
	sm.Handle("GET /", func(ex *Exchange) {
		_, _, hijackErr = ex.HijackRaw(nil)
	})
	first := newConn("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	first.Hangup()
	exch := newExchange(t, first, 1024, false)
	if err := Handle(exch, &sm, nopBackoff); err != nil {
		t.Fatal(err)
	}
	if hijackErr != nil {
		t.Fatal(hijackErr)
	}
	exch.Release()
	if first.IsClosed() {
		t.Error("hijacked connection must stay open after Release")
	}

	second := newConn("")
	if !exch.Acquire(second) {
		t.Fatal("released exchange must be acquirable")
	}
	exch.Release()
	if !second.IsClosed() {
		t.Error("connection must be closed on Release: hijack of a previous request must not carry over")
	}
}

// Idle peer policy belongs to the connection: Handle keeps retrying an empty
// read until the conn itself reports failure, so a stalled peer ends the
// exchange through the conn's deadline instead of pinning the exchange.
func TestHandleIdlePeerEndsOnConnDeadline(t *testing.T) {
	var sm MuxSlice
	sm.Handle("/", func(ex *Exchange) { t.Error("handler must not run on partial request") })
	conn := newConn("GET / HTTP") // Peer stalls mid request line, never hangs up.
	conn.SetDeadline(time.Now().Add(10 * time.Millisecond))
	exch := newExchange(t, conn, 1024, false)

	done := make(chan error, 1)
	go func() { done <- Handle(exch, &sm, nopBackoff) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("want connection deadline error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Handle ignored the connection deadline")
	}
}

// A body must never reach the wire without its header: if flushing the header
// fails, Write must report the failure and send nothing.
func TestExchangeWriteHeaderFlushFails(t *testing.T) {
	const body = "body"
	conn := newConn("")
	exch := newExchange(t, conn, 128, false)
	conn.FailWrites(1) // Status line write fails, body write would succeed.

	n, err := exch.Write([]byte(body))
	if err == nil {
		t.Error("want error when header flush fails, got nil")
	}
	if n != 0 {
		t.Errorf("want 0 bytes written, got %d", n)
	}
	if got := conn.ViewWritten(); got != "" {
		t.Errorf("want nothing on the wire, got %q", got)
	}
	// Writes after a failed header stay failed: the response is unrecoverable,
	// a body without its header would corrupt the stream.
	if _, err = exch.Write([]byte(body)); err == nil {
		t.Error("want error on write after failed header flush, got nil")
	}
	if got := conn.ViewWritten(); got != "" {
		t.Errorf("want nothing on the wire, got %q", got)
	}
}

func TestExchangeSetHeaderInt(t *testing.T) {
	for _, test := range []struct {
		value int64
		base  int
		want  string // Header block emitted after the status line.
	}{
		{value: 1234, base: 10, want: "N:1234\r\n\r\n"},
		{value: 0, base: 10, want: "N:0\r\n\r\n"},
		{value: -42, base: 10, want: "N:-42\r\n\r\n"},
		{value: 255, base: 16, want: "N:ff\r\n\r\n"},
		{value: 9223372036854775807, base: 10, want: "N:9223372036854775807\r\n\r\n"},
		{value: -9223372036854775808, base: 10, want: "N:-9223372036854775808\r\n\r\n"},
		{value: 1, base: 2, want: "\r\n"},  // Below base 10, dropped.
		{value: 1, base: 37, want: "\r\n"}, // Above base 36, dropped.
	} {
		conn := newConn("")
		exch := newExchange(t, conn, 256, false)
		exch.SetHeaderInt("N", test.value, test.base)
		exch.WriteHeader(200)
		got, _ := strings.CutPrefix(conn.ViewWritten(), "HTTP/1.1 200 OK\r\n")
		if got != test.want {
			t.Errorf("value %d base %d: want %q, got %q", test.value, test.base, test.want, got)
		}
	}
}

// SetHeaderInt must format into the response buffer without allocating.
func TestExchangeSetHeaderIntNoAlloc(t *testing.T) {
	exch := newExchange(t, newConn(""), 256, false)
	allocs := testing.AllocsPerRun(100, func() {
		exch.SetHeaderInt("Content-Length", 1234567890, 10)
	})
	if allocs != 0 {
		t.Errorf("SetHeaderInt allocated %v times, want 0", allocs)
	}
}
