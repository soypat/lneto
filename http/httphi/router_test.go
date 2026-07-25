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
	"github.com/soypat/lneto/internal"
)

// rwconn is a in-memory conn. The router handles connections on another
// goroutine so every field is guarded; onClose lets tests await the handler.
type rwconn struct {
	mu       sync.Mutex
	readable bytes.Buffer
	written  bytes.Buffer
	closed   bool
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
		return 0, io.EOF
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
func (r *rwconn) ViewWritten() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.written.String()
}

var _ Mux = (*sliceMux)(nil)

type sliceMux struct {
	_handlers []struct {
		method  Method
		uri     string
		handler HandlerFunc
	}
}

func (sm *sliceMux) LookupHandler(method Method, uri []byte) HandlerFunc {
	for _, endpoint := range sm._handlers {
		if endpoint.method != MethUndefined && endpoint.method != method {
			continue
		}
		// Method matches.
		if b2s(uri) == endpoint.uri {
			return endpoint.handler
		}
	}
	return nil
}
func (sm *sliceMux) Handle(reg string, handler HandlerFunc) {
	v := internal.SliceReclaim(&sm._handlers)
	method := MethUndefined
	methodOrURL, url, methodFound := strings.Cut(reg, " ")
	if methodFound {
		method = MethodFromBytes([]byte(methodOrURL))
	} else {
		url = methodOrURL
	}
	v.method = method
	v.uri = url
	v.handler = handler
}

func configSynchronousRouter(t *testing.T, router *Router, bufferSize int, mux Mux) {
	err := router.Configure(RouterConfig{
		FixedNumGoroutines:    -1,
		Mux:                   mux,
		RequestBufferSize:     bufferSize,
		ResponseMinBufferSize: bufferSize,
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
		sm     sliceMux
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
		sm     sliceMux
		router Router
	)
	var gotMethod, gotURI, gotHost string
	sm.Handle("GET /index.html", func(ex *Exchange) {
		gotMethod = string(ex.RequestMethod())
		gotURI = string(ex.RequestURI())
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
				sm     sliceMux
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
		sm     sliceMux
		router Router
	)
	sm.Handle("GET /", staticPage(t, expectResponse))
	configSynchronousRouter(t, &router, bufferSize, &sm)

	conn := newConn("GET / HTTP/1.1\r\nHo")
	if err := router.Handle(conn); err != nil {
		t.Fatal(err)
	}
	conn.AddReadable([]byte("st: tinygo.org\r\n\r\n"))
	conn.AwaitClose(t, time.Second)

	if got := conn.ViewWritten(); !strings.HasSuffix(got, expectResponse) {
		t.Errorf("want body %q, got response %q", expectResponse, got)
	}
}

func staticPage(t *testing.T, page string) HandlerFunc {
	return func(ex *Exchange) {
		n, err := io.WriteString(ex, page)
		// Handler runs on the router goroutine: Error, never Fatal.
		if err != nil {
			t.Error(err)
		} else if n != len(page) {
			t.Error("expected written ", len(page), "got", n)
		}
	}
}
