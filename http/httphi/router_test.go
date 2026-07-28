package httphi

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto"
)

// rwconn is a in-memory conn. The router handles connections on another
// goroutine so every field is guarded; onClose lets tests await the handler.
//
// A drained rwconn reads (0,nil) as a live socket with no data pending would,
// so a partial request can be completed with AddReadable mid-handling. Tests
// that need the peer to hang up call Hangup.
type rwconn struct {
	mu       sync.Mutex
	readable bytes.Buffer
	segments []string
	written  bytes.Buffer
	closed   bool
	hangup   bool
	failWr   int
	onClose  chan struct{}
	deadline time.Time
}

// newConn returns a conn preloaded with request and whose Close is observable
// with [rwconn.AwaitClose].
func newConn(request string) *rwconn {
	r := &rwconn{onClose: make(chan struct{})}
	r.AddReadable([]byte(request))
	return r
}

// AddSegment queues data delivered on a later read, once everything already
// pending has been read. Models a request split over several TCP segments
// without depending on goroutine scheduling.
func (r *rwconn) AddSegment(b string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.segments = append(r.segments, b)
}

// FailWrites makes the next n writes fail, as a conn refusing further data
// would. Later writes succeed.
func (r *rwconn) FailWrites(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failWr = n
}

// Hangup makes reads past the pending data return [io.EOF], as a peer that
// closed its side of the connection would.
func (r *rwconn) Hangup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hangup = true
}

func (r *rwconn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		if r.onClose != nil {
			close(r.onClose)
		}
	}
	return nil
}

// AwaitClose blocks until the connection is closed by its handler or timeout elapses.
func (r *rwconn) AwaitClose(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-r.onClose:
	case <-time.After(timeout):
		t.Fatal("timed out awaiting connection close by handler")
	}
}

func (r *rwconn) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, net.ErrClosed
	} else if r.deadlineExceeded() {
		return 0, context.DeadlineExceeded
	} else if r.readable.Len() == 0 {
		if len(r.segments) > 0 {
			r.readable.WriteString(r.segments[0])
			r.segments = r.segments[1:]
			return r.readable.Read(b)
		}
		if r.hangup {
			return 0, io.EOF
		}
		return 0, nil // No data pending, handler backs off and retries.
	}
	return r.readable.Read(b)
}
func (r *rwconn) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, net.ErrClosed
	} else if r.deadlineExceeded() {
		return 0, context.DeadlineExceeded
	} else if r.failWr > 0 {
		r.failWr--
		return 0, io.ErrShortWrite
	}
	return r.written.Write(b)
}
func (r *rwconn) deadlineExceeded() bool {
	return !r.deadline.IsZero() && time.Since(r.deadline) > 0
}
func (r *rwconn) AddReadable(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readable.Write(b)
}

// SetDeadline makes reads and writes past t fail, as a conn with a read
// deadline set would.
func (r *rwconn) SetDeadline(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deadline = t
}

// IsClosed reports whether the connection was closed by its handler.
func (r *rwconn) IsClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *rwconn) ViewWritten() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.written.String()
}

var _ Mux = (*MuxSlice)(nil)

func configSynchronousRouter(t *testing.T, router *Router, bufferSize int, mux Mux) {
	err := router.Configure(RouterConfig{
		FixedNumGoroutines:          -1,
		Mux:                         mux,
		RequestHeaderBufferSize:     bufferSize,
		RequestNumHeaderKVCap:       16,
		ResponseHeaderMinBufferSize: bufferSize,
		Backoff: func(consecutiveBackoffs uint) (sleepOrFlag time.Duration) {
			return lneto.BackoffFlagNop
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRouterGet(t *testing.T) {
	const bufferSize = 1024
	const expectResponse = "its time"
	var (
		sm     MuxSlice
		router Router
	)
	sm.Handle("GET /", staticPage(t, expectResponse))
	configSynchronousRouter(t, &router, bufferSize, &sm)

	conn := newConn("GET / HTTP/1.1\r\nHost: tinygo.org\r\n\r\n")
	err := router.Handle(conn)
	if err != nil {
		t.Fatal(err)
	}
	conn.AwaitClose(t, time.Second)

	got := conn.ViewWritten()
	if !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("want 200 status line, got %q", got)
	}
	if !strings.HasSuffix(got, expectResponse) {
		t.Errorf("want body %q at end of response, got %q", expectResponse, got)
	}
}

// The handler observes the request line and header fields the router parsed.
func TestRouterRequestVisibleToHandler(t *testing.T) {
	const bufferSize = 1024
	var (
		sm     MuxSlice
		router Router
	)
	var gotMethod, gotURI, gotHost string
	sm.Handle("GET /index.html", func(ex *Exchange) {
		gotMethod = string(ex.RequestMethod())
		gotURI = string(ex.RequestTarget())
		gotHost = string(ex.RequestHeader("Host"))
		ex.WriteHeader(200)
	})
	configSynchronousRouter(t, &router, bufferSize, &sm)

	conn := newConn("GET /index.html HTTP/1.1\r\nHost: tinygo.org\r\n\r\n")
	if err := router.Handle(conn); err != nil {
		t.Fatal(err)
	}
	conn.AwaitClose(t, time.Second)

	if gotMethod != "GET" {
		t.Errorf("want method %q, got %q", "GET", gotMethod)
	}
	if gotURI != "/index.html" {
		t.Errorf("want URI %q, got %q", "/index.html", gotURI)
	}
	if gotHost != "tinygo.org" {
		t.Errorf("want Host %q, got %q", "tinygo.org", gotHost)
	}
}

// Router must route on method and URI, and must not invoke a handler for
// requests it has no registration for.
func TestRouterMux(t *testing.T) {
	const bufferSize = 1024
	for _, test := range []struct {
		name    string
		request string
		want    string // Response body, empty means no handler must run.
	}{
		{name: "get root", request: "GET / HTTP/1.1\r\nHost: h\r\n\r\n", want: "root"},
		{name: "get page", request: "GET /page HTTP/1.1\r\nHost: h\r\n\r\n", want: "page"},
		{name: "any method", request: "DELETE /any HTTP/1.1\r\nHost: h\r\n\r\n", want: "any"},
		{name: "method mismatch", request: "POST / HTTP/1.1\r\nHost: h\r\n\r\n", want: ""},
		{name: "unknown uri", request: "GET /nowhere HTTP/1.1\r\nHost: h\r\n\r\n", want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var (
				sm     MuxSlice
				router Router
			)
			sm.Handle("GET /", staticPage(t, "root"))
			sm.Handle("GET /page", staticPage(t, "page"))
			sm.Handle("/any", staticPage(t, "any")) // No method: matches any.
			configSynchronousRouter(t, &router, bufferSize, &sm)

			conn := newConn(test.request)
			if err := router.Handle(conn); err != nil {
				t.Fatal(err)
			}
			conn.AwaitClose(t, time.Second)

			got := conn.ViewWritten()
			if test.want == "" {
				if strings.Contains(got, "root") || strings.Contains(got, "page") || strings.Contains(got, "any") {
					t.Errorf("no handler must run, got response %q", got)
				}
				return
			}
			if !strings.HasSuffix(got, test.want) {
				t.Errorf("want body %q, got response %q", test.want, got)
			}
		})
	}
}

// A request arriving in pieces (TCP segmentation) must still be handled.
func TestRouterSplitRequest(t *testing.T) {
	const bufferSize = 1024
	const expectResponse = "split ok"
	var (
		sm     MuxSlice
		router Router
	)
	sm.Handle("GET /", staticPage(t, expectResponse))
	configSynchronousRouter(t, &router, bufferSize, &sm)

	conn := newConn("GET / HTTP/1.1\r\nHo")
	conn.AddSegment("st: tinygo.org\r\n\r")
	conn.AddSegment("\n") // Final CRLF lands in its own segment.
	if err := router.Handle(conn); err != nil {
		t.Fatal(err)
	}
	conn.AwaitClose(t, time.Second)

	if got := conn.ViewWritten(); !strings.HasSuffix(got, expectResponse) {
		t.Errorf("want body %q, got response %q", expectResponse, got)
	}
}

func staticPage(t *testing.T, page string) HandlerFunc {
	return func(ex *Exchange) {
		var rw ExchangeRW // Streaming APIs take the ReadWriter view.
		ex.ReadWriter(&rw)
		n, err := io.WriteString(&rw, page)
		// Handler runs on the router goroutine: Error, never Fatal.
		if err != nil {
			t.Error(err)
		} else if n != len(page) {
			t.Error("expected written ", len(page), "got", n)
		}
	}
}

// An exchange freed by the outgoing generation carries that generation's
// buffers. Recycling it under a new configuration serves the request with
// buffer limits the new [RouterConfig] never asked for.
func TestRouterReconfigureDropsStaleExchanges(t *testing.T) {
	const smallBuf, largeBuf = 256, 1024
	var (
		sm     MuxSlice
		router Router
	)
	bufsize := make(chan int, 2)
	sm.Handle("GET /", func(ex *Exchange) { bufsize <- len(ex.UnsafeRawBuffer()) })
	serve := func(want int) {
		t.Helper()
		conn := newConn("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
		conn.Hangup()
		if err := router.Handle(conn); err != nil {
			t.Fatal(err)
		}
		if got := <-bufsize; got != want {
			t.Errorf("want exchange buffer %d, got %d", want, got)
		}
		conn.AwaitClose(t, time.Second) // Exchange hits the freelist on close.
	}

	configSynchronousRouter(t, &router, smallBuf, &sm)
	serve(2 * smallBuf)
	configSynchronousRouter(t, &router, largeBuf, &sm)
	serve(2 * largeBuf)
}

// Configure writes the fields Handle reads; concurrent use must not race.
func TestRouterConfigureHandleRace(t *testing.T) {
	const bufferSize = 1024
	var (
		sm     MuxSlice
		router Router
	)
	sm.Handle("GET /", staticPage(t, "ok"))
	configSynchronousRouter(t, &router, bufferSize, &sm)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		configSynchronousRouter(t, &router, bufferSize, &sm)
	}()
	go func() {
		defer wg.Done()
		conn := newConn("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
		if err := router.Handle(conn); err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
}

// Reconfiguring a running router tears down the job queue that Handle may be
// sending a connection on. Connections may be dropped, but never panic.
// A torn down router has nothing left to serve with: it must say so instead of
// dropping the connection as if it were merely busy.
func TestRouterHandleAfterTeardown(t *testing.T) {
	var (
		sm     MuxSlice
		router Router
	)
	sm.Handle("GET /", staticPage(t, "ok"))
	err := router.Configure(RouterConfig{
		FixedNumGoroutines:          2,
		MaxAwaitingConns:            4,
		Mux:                         &sm,
		RequestHeaderBufferSize:     512,
		RequestNumHeaderKVCap:       16,
		ResponseHeaderMinBufferSize: 512,
		Backoff:                     nopBackoff,
	})
	if err != nil {
		t.Fatal(err)
	}
	router.TeardownGoroutines()

	conn := newConn("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	if err = router.Handle(conn); err != errRouterTornDown {
		t.Errorf("want errRouterTornDown, got %v", err)
	}
	if conn.IsClosed() {
		t.Error("refused connection must be left for the caller to dispose of")
	}
}

// Tearing down a generation abandons the connections queued for it. They were
// taken ownership of by Handle, so they must be closed and their exchanges
// released: an exchange left claimed by a torn down generation is a buffer the
// router can never reconfigure again.
func TestRouterTeardownReleasesQueuedConns(t *testing.T) {
	var (
		sm     MuxSlice
		router Router
	)
	const numGoro = 2
	sm.Handle("GET /", staticPage(t, "ok"))
	cfg := RouterConfig{
		FixedNumGoroutines:          numGoro,
		MaxAwaitingConns:            4,
		Mux:                         &sm,
		RequestHeaderBufferSize:     512,
		RequestNumHeaderKVCap:       16,
		ResponseHeaderMinBufferSize: 512,
		Backoff:                     nopBackoff,
	}
	// Handing connections over and tearing down immediately leaves them queued
	// for workers that will never serve them. Rounds bound the scheduling luck
	// needed; a single leaked exchange also fails every later Configure.
	var conns [numGoro]*rwconn
	for range 30 {
		// errBusyExchanges is legitimate backpressure while the previous
		// generation drops its connections, but it must not outlive it.
		var err error
		for range 100 {
			if err = router.Configure(cfg); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if err != nil {
			t.Fatal("reconfigure after teardown:", err)
		}
		for i := range conns {
			conns[i] = newConn("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
			conns[i].Hangup()
			if err := router.Handle(conns[i]); err != nil {
				t.Fatal(err)
			}
		}
		router.TeardownGoroutines()
		for i := range conns {
			// Handle took ownership of the connection: served or dropped, the
			// router closes it.
			conns[i].AwaitClose(t, time.Second)
		}
	}
}

func TestRouterConfigureDuringWorkerHandle(t *testing.T) {
	var (
		sm     MuxSlice
		router Router
	)
	sm.Handle("GET /", staticPage(t, "ok"))
	cfg := RouterConfig{
		FixedNumGoroutines:          2,
		MaxAwaitingConns:            4,
		Mux:                         &sm,
		RequestHeaderBufferSize:     512,
		RequestNumHeaderKVCap:       16,
		ResponseHeaderMinBufferSize: 512,
		Backoff:                     nopBackoff,
	}
	if err := router.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	defer router.TeardownGoroutines()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 300 {
			conn := newConn("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
			conn.Hangup()
			router.Handle(conn) // Drops are fine, panics are not.
		}
	}()
	go func() {
		defer wg.Done()
		// Each Configure sleeps 5ms tearing down the previous generation, keep
		// the count low and let the Handle loop supply the concurrency.
		for range 20 {
			// errBusyExchanges is legitimate backpressure: the previous
			// generation was still serving when the buffers were needed.
			if err := router.Configure(cfg); err != nil && err != errBusyExchanges {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
}
