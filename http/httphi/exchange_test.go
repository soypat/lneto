package httphi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unsafe"

	"testing"
	"time"

	"github.com/soypat/lneto/http/httpraw"

	"github.com/soypat/lneto"
)

func nopBackoff(consecutiveBackoffs uint) time.Duration { return lneto.BackoffFlagNop }

// newExchange returns an Exchange acquired on conn, ready to serve a request.
func newExchange(t *testing.T, conn conn, cfg ExchangeConfig) *Exchange {
	t.Helper()
	exch := new(Exchange)
	const numHeaderCap = 1
	exch.Configure(cfg)
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
	var buf [128]byte
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
		exch := newExchange(t, conn, ExchangeConfig{RawBuf: buf[:], RequestBufferLim: 64})
		exch.WriteHeader(test.code)
		if got := conn.ViewWritten(); got != test.want {
			t.Errorf("code %d: want %q, got %q", test.code, test.want, got)
		}
	}
}

// Status line is written once: a second WriteHeader must not reach the wire.
func TestExchangeWriteHeaderOnce(t *testing.T) {
	var buf [128]byte
	conn := newConn("")
	exch := newExchange(t, conn, ExchangeConfig{RawBuf: buf[:], RequestBufferLim: 64})
	exch.WriteHeader(404)
	exch.WriteHeader(500)
	const want = "HTTP/1.1 404 Not Found\r\n\r\n"
	if got := conn.ViewWritten(); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// Write with no prior WriteHeader must flush a 200 header ahead of the body.
func TestExchangeWriteFlushesHeader(t *testing.T) {
	var buf [128]byte
	const body = "hello"
	conn := newConn("")
	exch := newExchange(t, conn, ExchangeConfig{RawBuf: buf[:], RequestBufferLim: 64})
	n, err := exch.WriteBody([]byte(body))
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
			exch := newExchange(t, conn, ExchangeConfig{RawBuf: make([]byte, 128), RequestBufferLim: 64, NormalizeOutgoingKeys: test.normalize})
			for _, kv := range test.set {
				if !exch.StageHeader(kv[0], kv[1]) {
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
	exch := newExchange(t, conn, ExchangeConfig{RawBuf: make([]byte, bufferSize), RequestBufferLim: 64})
	if exch.StageHeader("X-Big", strings.Repeat("v", 4*bufferSize)) {
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
			route, _, _ := strings.Cut(test.wantURI, "?") // Mux matches on path.
			sm.Handle(route, func(ex *Exchange) {
				gotMethod = string(ex.RequestMethod())
				gotURI = string(ex.RequestTarget())
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
var _ io.ReadWriteCloser = (*ExchangeRW)(nil)

// ExchangeRW writes the response body and reads the request body, so it may be
// handed to code that wants an io.ReadWriter.
func TestExchangeRW(t *testing.T) {
	const body = "hello"
	conn := newConn("")
	exch := newExchange(t, conn, 128, false)
	var rw ExchangeRW
	exch.ReadWriter(&rw)

	n, err := io.WriteString(&rw, body)
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

// The exchange is pooled and reused: a handle kept past the request it was
// taken from must fail instead of reaching the next request's connection.
func TestExchangeRWOutlivesExchange(t *testing.T) {
	conn := newConn("")
	exch := newExchange(t, conn, 128, false)
	var rw ExchangeRW
	exch.ReadWriter(&rw)
	if !rw.IsValid() {
		t.Fatal("want a fresh handle to be valid")
	}
	exch.Release()

	if rw.IsValid() {
		t.Error("want handle invalidated by release")
	}
	if _, err := rw.Write([]byte("late")); err == nil {
		t.Error("want error writing through a released exchange, got nil")
	}
	if _, err := rw.Read(make([]byte, 4)); err == nil {
		t.Error("want error reading through a released exchange, got nil")
	}
	if got := conn.ViewWritten(); strings.Contains(got, "late") {
		t.Errorf("late write reached the connection: %q", got)
	}
}

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
func TestExchangeStageOKAndFail(t *testing.T) {
	const key, value = "K", "V"
	const field = len(key) + len(value) + len(":\r\n")
	const numHeaderCap = 4
	for _, bufLen := range []int{field + 2, field + 1, field} {
		conn := newConn("")
		exch := new(Exchange)
		exch.Configure(make([]byte, bufLen), bufLen, numHeaderCap, false)
		if !exch.Acquire(conn) {
			t.Fatal("fresh exchange failed to acquire connection")
		}
		set := exch.StageHeader(key, value)
		n, err := exch.FlushHeader()

		want := "HTTP/1.1 200 OK\r\n"
		if set {
			want += key + ":" + value + "\r\n"
			want += "\r\n"
		} else {
			if err != lneto.ErrBufferFull || n != 0 {
				t.Fatal("expected buffer full and no data written:", err, n)
			}
			want = ""
		}
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

	n, err := exch.WriteBody([]byte(body))
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
	if _, err = exch.WriteBody([]byte(body)); err == nil {
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
		exch.StageHeaderInt("N", test.value, test.base)
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
		exch.StageHeaderInt("Content-Length", 1234567890, 10)
	})
	if allocs != 0 {
		t.Errorf("SetHeaderInt allocated %v times, want 0", allocs)
	}
}

// The Mux matches on the request path: a query string must not defeat routing.
func TestHandleMuxOnPath(t *testing.T) {
	var sm MuxSlice
	var gotPath, gotQuery string
	sm.Handle("GET /search", func(ex *Exchange) {
		gotPath = string(ex.RequestPath())
		rawkey, rawval, rest := httpraw.NextQueryPair(ex.RequestQuery())
		for rawkey != nil {
			gotQuery += string(rawkey) + "=" + string(rawval) + ";"
			rawkey, rawval, rest = httpraw.NextQueryPair(rest)
		}
		ex.WriteHeader(200)
	})
	conn := serve(t, "GET /search?q=go&n=1 HTTP/1.1\r\nHost: h\r\n\r\n", &sm)

	if gotPath != "/search" {
		t.Errorf("want path %q, got %q", "/search", gotPath)
	}
	if gotQuery != "q=go;n=1;" {
		t.Errorf("want query %q, got %q", "q=go;n=1;", gotQuery)
	}
	if got := conn.ViewWritten(); !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("want the handler to have run, got %q", got)
	}
}

func TestExchangeAppendQuery(t *testing.T) {
	for _, test := range []struct {
		uri         string
		key         string
		decoded     bool
		want        string
		wantPresent bool
	}{
		{uri: "/x?q=go", key: "q", want: "go", wantPresent: true},
		{uri: "/x?q=go&n=1", key: "n", want: "1", wantPresent: true},
		{uri: "/x?a=1&a=2", key: "a", want: "1", wantPresent: true},       // First match wins.
		{uri: "/x?q=go", key: "nope", want: "", wantPresent: false},       // Absent.
		{uri: "/x", key: "q", want: "", wantPresent: false},               // No query at all.
		{uri: "/x?debug&q=go", key: "debug", want: "", wantPresent: true}, // Flag: present, no value.
		{uri: "/x?q=", key: "q", want: "", wantPresent: true},             // Present, empty.
		// Decoding is opt-in and applies to the value only.
		{uri: "/x?q=hello%20world", key: "q", want: "hello%20world", wantPresent: true},
		{uri: "/x?q=hello%20world", key: "q", decoded: true, want: "hello world", wantPresent: true},
		{uri: "/x?q=a+b", key: "q", want: "a+b", wantPresent: true},
		{uri: "/x?q=a+b", key: "q", decoded: true, want: "a b", wantPresent: true},
		// Keys are matched decoded: "a b" cannot appear raw.
		{uri: "/x?a%20b=c", key: "a b", want: "c", wantPresent: true},
		{uri: "/x?a+b=c", key: "a b", want: "c", wantPresent: true},
		// Malformed escapes: a bad key is skipped, a bad value is not returned.
		{uri: "/x?%zz=1&q=go", key: "q", want: "go", wantPresent: true},
		{uri: "/x?q=%zz", key: "q", decoded: true, want: "", wantPresent: false},
		{uri: "/x?q=%zz", key: "q", want: "%zz", wantPresent: true}, // Undecoded, passed through.
	} {
		var sm MuxSlice
		var got string
		var present bool
		sm.Handle("/x", func(ex *Exchange) {
			var value []byte
			value, present = ex.AppendQuery(nil, test.key, test.decoded)
			got = string(value)
		})
		serve(t, "GET "+test.uri+" HTTP/1.1\r\nHost: h\r\n\r\n", &sm)

		if present != test.wantPresent {
			t.Errorf("%s key %q decoded=%v: want present=%v, got %v", test.uri, test.key, test.decoded, test.wantPresent, present)
		}
		if got != test.want {
			t.Errorf("%s key %q decoded=%v: want %q, got %q", test.uri, test.key, test.decoded, test.want, got)
		}
	}
}

// AppendQuery appends to dst, leaving what was already there untouched, and
// does not allocate when dst has the capacity.
func TestExchangeAppendQueryReusesBuffer(t *testing.T) {
	var sm MuxSlice
	var got string
	var allocs float64
	dst := make([]byte, 0, 64)
	sm.Handle("/x", func(ex *Exchange) {
		var value []byte
		allocs = testing.AllocsPerRun(50, func() {
			value, _ = ex.AppendQuery(dst[:len("prefix:")], "q", true)
		})
		got = string(value) // Conversion allocates, keep it out of the measurement.
	})
	copy(dst[:cap(dst)], "prefix:")
	serve(t, "GET /x?q=hello%20world HTTP/1.1\r\nHost: h\r\n\r\n", &sm)

	if got != "prefix:hello world" {
		t.Errorf("want %q, got %q", "prefix:hello world", got)
	}
	if allocs != 0 {
		t.Errorf("AppendQuery allocated %v times into a buffer with capacity, want 0", allocs)
	}
}

// formString renders a form as "key=value" pairs joined by '|', a pair with no
// value shown as the bare key.
func formString(f *httpraw.Form) string {
	var sb strings.Builder
	for i := 0; i < f.Len(); i++ {
		if i > 0 {
			sb.WriteByte('|')
		}
		key, value := f.Pair(i)
		sb.Write(key)
		if value != nil {
			sb.WriteByte('=')
			sb.Write(value)
		}
	}
	return sb.String()
}

const formType = "Content-Type: application/x-www-form-urlencoded\r\n"

func TestExchangeRequestParseForm(t *testing.T) {
	for _, test := range []struct {
		name    string
		request string
		bufSize int // Defaults to 64.
		want    string
		wantErr error
	}{
		{
			name:    "pairs",
			request: "POST /f HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 11\r\n\r\na=1&b=2&c=3",
			want:    "a=1|b=2|c=3",
		}, {
			// A flag and an empty value stay distinguishable, unlike http.FormValue.
			name:    "flag and empty",
			request: "POST /f HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 4\r\n\r\na&b=",
			want:    "a|b=",
		}, {
			name:    "left encoded",
			request: "POST /f HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 7\r\n\r\nn=a%20b",
			want:    "n=a%20b",
		}, {
			name:    "media type parameters",
			request: "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nContent-Length: 3\r\n\r\na=1",
			want:    "a=1",
		}, {
			// Only the body is parsed: the query string is not folded in.
			name:    "query not folded",
			request: "POST /f?q=go HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 3\r\n\r\na=1",
			want:    "a=1",
		}, {
			// No Content-Length means no body at all, RFC 9112 6.3.
			name:    "no content length",
			request: "POST /f HTTP/1.1\r\nHost: h\r\n" + formType + "\r\n",
			want:    "",
		}, {
			name:    "wrong media type",
			request: "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\na=1",
			wantErr: errNotFormEncoded,
		}, {
			name:    "no media type",
			request: "POST /f HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na=1",
			wantErr: errNotFormEncoded,
		}, {
			name:    "chunked",
			request: "POST /f HTTP/1.1\r\nHost: h\r\n" + formType + "Transfer-Encoding: chunked\r\n\r\n3\r\na=1\r\n0\r\n\r\n",
			wantErr: errUnsupportedTransferCoding,
		}, {
			name:    "body larger than buffer",
			request: "POST /f HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 11\r\n\r\na=1&b=2&c=3",
			bufSize: 4,
			wantErr: lneto.ErrBufferFull,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bufSize := test.bufSize
			if bufSize == 0 {
				bufSize = 64
			}
			var form httpraw.Form
			var gotErr error
			var sm MuxSlice
			sm.Reset(1)
			sm.Handle("/f", func(exch *Exchange) {
				gotErr = exch.RequestParseForm(&form, make([]byte, bufSize), nopBackoff)
			})
			serve(t, test.request, &sm)
			if gotErr != test.wantErr {
				t.Fatalf("want error %v, got %v", test.wantErr, gotErr)
			}
			if got := formString(&form); test.wantErr == nil && got != test.want {
				t.Errorf("want %q, got %q", test.want, got)
			}
		})
	}
}

// A body arriving after the header, in its own segment, must still be parsed whole.
func TestExchangeRequestParseFormSplit(t *testing.T) {
	conn := newConn("POST /f HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 11\r\n\r\na=1&")
	conn.AddSegment("b=2&c=3")
	conn.Hangup()
	var form httpraw.Form
	var gotErr error
	var sm MuxSlice
	sm.Reset(1)
	sm.Handle("/f", func(exch *Exchange) {
		gotErr = exch.RequestParseForm(&form, make([]byte, 64), nopBackoff)
	})
	exch := newExchange(t, conn, 1024, false)
	if err := Handle(exch, &sm, nopBackoff); err != nil {
		t.Fatal(err)
	}
	if gotErr != nil {
		t.Fatal(gotErr)
	}
	if got := formString(&form); got != "a=1|b=2|c=3" {
		t.Errorf("want %q, got %q", "a=1|b=2|c=3", got)
	}
}

// Decode is the caller's call, and it must reach both keys and values.
func TestExchangeRequestParseFormDecode(t *testing.T) {
	var form httpraw.Form
	var sm MuxSlice
	sm.Reset(1)
	sm.Handle("/f", func(exch *Exchange) {
		if err := exch.RequestParseForm(&form, make([]byte, 64), nopBackoff); err != nil {
			t.Error(err)
		} else if err = form.Decode(); err != nil {
			t.Error(err)
		}
	})
	serve(t, "POST /f HTTP/1.1\r\nHost: h\r\n"+formType+"Content-Length: 16\r\n\r\na+b=c%20d&e=f%2B", &sm)
	if got := formString(&form); got != "a b=c d|e=f+" {
		t.Errorf("want %q, got %q", "a b=c d|e=f+", got)
	}
}

// partBuffer is a sink that keeps a part's content in memory and records that
// [Exchange.ReadMultiparts] closed it.
type partBuffer struct {
	content []byte
	closed  bool
}

func (p *partBuffer) Write(b []byte) (int, error) {
	if p.closed {
		return 0, errors.New("write to closed part sink")
	}
	p.content = append(p.content, b...)
	return len(b), nil
}

func (p *partBuffer) Close() error { p.closed = true; return nil }

// serveMultipart serves request to a handler that streams its multipart body
// with [Exchange.ReadMultiparts] over a buffer of bufSize bytes. segments are
// delivered on later reads, so the parser must compact and read more to see
// them. skip names the parts whose sink is refused, exercising discarding.
func serveMultipart(t *testing.T, request string, bufSize int, skip string, segments ...string) ([]MultipartSink, error) {
	t.Helper()
	conn := newConn(request)
	for _, segment := range segments {
		conn.AddSegment(segment)
	}
	conn.Hangup()
	var parts []MultipartSink
	var gotErr error
	var sm MuxSlice
	sm.Reset(1)
	sm.Handle("/f", func(exch *Exchange) {
		newSink := func(hdr *httpraw.MultipartHeader) io.WriteCloser {
			if skip != "" && string(hdr.Name) == skip {
				return nil // Discard this part's content.
			}
			return new(partBuffer)
		}
		parts, gotErr = exch.ReadMultiparts(parts, make([]byte, bufSize), newSink)
	})
	const x = unsafe.Sizeof(http.Request{})
	exch := newExchange(t, conn, 1024, false)
	if err := Handle(exch, &sm, nopBackoff); err != nil {
		t.Fatal(err)
	}
	return parts, gotErr
}

// partsString renders parts as "name=content" joined by '|', a file part shown
// as "name(filename)=content" and a discarded one as "name=<nil>". Fails the
// test if a sink was left open, which would hide a part that never ended.
func partsString(t *testing.T, parts []MultipartSink) string {
	t.Helper()
	var sb strings.Builder
	for i := range parts {
		if i > 0 {
			sb.WriteByte('|')
		}
		part := &parts[i]
		sb.Write(part.Header.Name)
		if len(part.Header.Filename) > 0 {
			sb.WriteByte('(')
			sb.Write(part.Header.Filename)
			sb.WriteByte(')')
		}
		sb.WriteByte('=')
		if part.Sink == nil {
			sb.WriteString("<nil>")
			continue
		}
		sink := part.Sink.(*partBuffer)
		if !sink.closed {
			t.Errorf("part %q: sink left open", part.Header.Name)
		}
		sb.Write(sink.content)
	}
	return sb.String()
}

// Names, filenames and content of every part, over a body split so that a part
// straddles two reads and the parser must compact and read more.
func TestExchangeReadMultiparts(t *testing.T) {
	const (
		head  = "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=--xyz\r\n\r\n"
		part1 = "----xyz\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\nhi there\r\n"
		part2 = "----xyz\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"beach.png\"\r\n\r\n\x89PNG\r\n\x00\r\n"
		tail  = "----xyz--\r\n"
	)
	parts, err := serveMultipart(t, head+part1+part2[:20], 128, "", part2[20:]+tail)
	if err != nil {
		t.Fatal(err)
	}
	const want = "caption=hi there|photo(beach.png)=\x89PNG\r\n\x00"
	if got := partsString(t, parts); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// A part longer than the buffer must come out whole: every compaction has to
// keep the tail NextBody held back, or content that looks like the start of a
// delimiter is dropped. The header's Name must survive those reads too.
func TestExchangeReadMultipartsPartLargerThanBuffer(t *testing.T) {
	// Content teases the parser with delimiter prefixes that never complete.
	content := strings.Repeat("\r\n--xy", 16) + strings.Repeat("A", 100) + "\r\n--xyy"
	body := "--xyz\r\nContent-Disposition: form-data; name=\"blob\"\r\n\r\n" + content + "\r\n--xyz--\r\n"
	head := "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=xyz\r\n\r\n"
	parts, err := serveMultipart(t, head, 64, "", body[:30], body[30:])
	if err != nil {
		t.Fatal(err)
	}
	want := "blob=" + content
	if got := partsString(t, parts); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// A nil sink discards a part's content without losing its place in the body:
// the parts around it must still arrive whole.
func TestExchangeReadMultipartsDiscardsPart(t *testing.T) {
	const (
		head  = "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=xyz\r\n\r\n"
		part1 = "--xyz\r\nContent-Disposition: form-data; name=\"keep\"\r\n\r\nkept\r\n"
		part2 = "--xyz\r\nContent-Disposition: form-data; name=\"huge\"; filename=\"big.bin\"\r\n\r\n"
		part3 = "--xyz\r\nContent-Disposition: form-data; name=\"also\"\r\n\r\nkept too\r\n"
		tail  = "--xyz--\r\n"
	)
	discarded := strings.Repeat("Z", 200) + "\r\n"
	parts, err := serveMultipart(t, head+part1+part2+discarded+part3+tail, 96, "huge")
	if err != nil {
		t.Fatal(err)
	}
	const want = "keep=kept|huge(big.bin)=<nil>|also=kept too"
	if got := partsString(t, parts); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// A part header that does not fit the buffer cannot be completed by reading
// more, so the caller is told instead of spinning.
func TestExchangeReadMultipartsHeaderLargerThanBuffer(t *testing.T) {
	head := "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=xyz\r\n\r\n"
	body := "--xyz\r\nContent-Disposition: form-data; name=\"" + strings.Repeat("n", 64) + "\"\r\n\r\nv\r\n--xyz--\r\n"
	parts, err := serveMultipart(t, head+body, 32, "")
	if err != lneto.ErrShortBuffer {
		t.Errorf("want %v, got %v", lneto.ErrShortBuffer, err)
	}
	if len(parts) != 0 {
		t.Errorf("want no parts reported for a header that never parsed, got %d", len(parts))
	}
}

// A buffer too small to ever outgrow a delimiter is a caller error, refused
// before any of the body is read.
func TestExchangeReadMultipartsBufferUnusable(t *testing.T) {
	head := "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=xyz\r\n\r\n"
	body := "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--xyz--\r\n"
	if _, err := serveMultipart(t, head+body, len("\r\n--xyz"), ""); err != lneto.ErrInvalidConfig {
		t.Errorf("want %v, got %v", lneto.ErrInvalidConfig, err)
	}
}

// A request that is not multipart, or whose boundary is missing, must be refused.
func TestExchangeRequestParseMultipartRejects(t *testing.T) {
	for _, test := range []struct {
		contentType string
		wantErr     bool
	}{
		{contentType: "multipart/form-data; boundary=xyz"},
		{contentType: "application/x-www-form-urlencoded", wantErr: true},
		{contentType: "multipart/form-data", wantErr: true}, // Boundary is required.
		{contentType: "", wantErr: true},
	} {
		var gotErr error
		var sm MuxSlice
		sm.Reset(1)
		sm.Handle("/f", func(exch *Exchange) {
			_, gotErr = exch.RequestMultipart()
		})
		request := "POST /f HTTP/1.1\r\nHost: h\r\n"
		if test.contentType != "" {
			request += "Content-Type: " + test.contentType + "\r\n"
		}
		serve(t, request+"\r\n", &sm)
		if (gotErr != nil) != test.wantErr {
			t.Errorf("%q: want error %v, got %v", test.contentType, test.wantErr, gotErr)
		}
	}
}

// A request from a browser carries around twenty header fields. Serving one
// must not depend on how many fields the parser happens to have room for: the
// exchange's buffer is the memory the caller granted, and the field table comes
// out of it.
func TestHandleBrowserSizedRequest(t *testing.T) {
	const wantMode = "navigate"
	request := "GET /echo HTTP/1.1\r\nHost: lneto.test\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
		"Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n" +
		"Upgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Site: none\r\n" +
		"Sec-Ch-Ua: \"Chromium\";v=\"120\"\r\nCache-Control: max-age=0\r\nDnt: 1\r\n" +
		"Referer: https://lneto.test/index.html\r\nCookie: session=abcdef0123456789; theme=dark\r\n" +
		"X-Trace: 0123456789abcdef\r\nX-Client: bench\r\nX-Seq: 42\r\nX-Tag: alpha\r\n" +
		"X-Nonce: cafebabe\r\nX-Mode: " + wantMode + "\r\n\r\n"

	var gotMode string
	var fields int
	var sm MuxSlice
	sm.Reset(1)
	sm.Handle("GET /echo", func(exch *Exchange) {
		gotMode = string(exch.RequestHeader("X-Mode"))
		exch.RequestHeaderRaw().ForEach(func(key, value []byte) error {
			fields++
			return nil
		})
	})
	conn := newConn(request)
	conn.Hangup()
	exch := newExchange(t, conn, 8192, false)
	if err := Handle(exch, &sm, nopBackoff); err != nil {
		t.Fatalf("serving a browser sized request: %s", err)
	}
	if gotMode != wantMode {
		t.Errorf("last header field read back as %q, want %q", gotMode, wantMode)
	}
	const sent = 19
	if fields < sent {
		t.Errorf("handler saw %d header fields, request carried %d", fields, sent)
	}
}

// A request with more header fields than the exchange has room for must be
// answered, not dropped: the peer learns its request was too large instead of
// seeing the connection go away.
func TestHandleTooManyHeaderFields(t *testing.T) {
	request := "GET /echo HTTP/1.1\r\nHost: lneto.test\r\n"
	for i := 0; i < 512; i++ {
		request += "H" + strconv.Itoa(i) + ":v\r\n"
	}
	request += "\r\n"

	var served bool
	var sm MuxSlice
	sm.Reset(1)
	sm.Handle("GET /echo", func(exch *Exchange) { served = true })
	conn := newConn(request)
	conn.Hangup()
	exch := newExchange(t, conn, 1024, false)
	err := Handle(exch, &sm, nopBackoff)
	if err != nil {
		t.Fatal(err)
	}
	if served {
		t.Fatal("handler ran on a request the parser could not hold")
	}
	got := conn.ViewWritten()
	if !strings.HasPrefix(got, "HTTP/1.1 431 ") {
		t.Errorf("want a 431 answer, got %q", firstLine(got))
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// A body that already arrived alongside the request header must be handed over
// without touching the connection again. A peer that sent a whole request and
// is waiting for its answer sends nothing more, so a read for bytes already in
// hand blocks until the connection's deadline, or forever without one.
func TestExchangeReadBodyDoesNotReadPastWhatArrived(t *testing.T) {
	const body = "message body"
	dst := make([]byte, 64) // Deliberately larger than the body.
	var got string
	var readErr error
	var sm MuxSlice
	sm.Reset(1)
	sm.Handle("POST /", func(ex *Exchange) {
		n, err := ex.ReadBody(dst)
		got, readErr = string(dst[:n]), err
		ex.WriteHeader(200)
	})
	// The peer is still there, waiting to be answered: a read for bytes it is
	// not going to send blocks, exactly as it does on a socket.
	conn := &blockingConn{request: "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\n" + body}
	exch := newExchange(t, conn, 1024, false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Handle(exch, &sm, nopBackoff)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadBody blocked waiting for a body that had already arrived")
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got != body {
		t.Errorf("want body %q, got %q", body, got)
	}
}

// blockingConn delivers a request and then blocks on reads, the way a peer
// awaiting its answer does. Writes are discarded.
type blockingConn struct {
	request string
	read    int
	blocked chan struct{}
}

func (c *blockingConn) Read(b []byte) (int, error) {
	if c.read >= len(c.request) {
		if c.blocked == nil {
			c.blocked = make(chan struct{})
		}
		<-c.blocked // Nothing more is coming, and nothing unblocks this.
		return 0, io.EOF
	}
	n := copy(b, c.request[c.read:])
	c.read += n
	return n, nil
}

func (c *blockingConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *blockingConn) Close() error                { return nil }
