package httphi

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/internal"
)

type rwconn struct {
	readable bytes.Buffer
	written  bytes.Buffer
	closed   bool
	deadline time.Time
}

func (r *rwconn) Close() error {
	r.closed = true
	return nil
}
func (r *rwconn) Read(b []byte) (int, error) {
	if r.closed {
		return 0, net.ErrClosed
	} else if r.deadlineExceeded() {
		return 0, context.DeadlineExceeded
	}
	return r.readable.Read(b)
}
func (r *rwconn) Write(b []byte) (int, error) {
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
func (r *rwconn) AddReadable(b []byte) { r.readable.Write(b) }
func (r *rwconn) ViewWritten() []byte  { return r.written.Bytes() }

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
		conn   rwconn
	)
	conn.deadline = time.Now().Add(10 * time.Millisecond) // TODO: remove after tests run without blocking forever.
	sm.Handle("GET /", staticPage(t, expectResponse))
	configSynchronousRouter(t, &router, bufferSize, &sm)
	err := router.Handle(&conn)
	if err != nil {
		t.Fatal(err)
	}
}

func staticPage(t *testing.T, page string) HandlerFunc {
	return func(ex *Exchange) {
		n, err := io.WriteString(ex, page)
		if err != nil {
			t.Fatal(err)
		} else if n != len(page) {
			t.Fatal("expected written ", len(page), "got", n)
		}
	}
}
