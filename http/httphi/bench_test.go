package httphi

import (
	"io"
	"testing"

	"github.com/soypat/lneto/internal"
)

// benchConn replays a fixed request and discards the response. It allocates
// nothing itself so benchmark alloc counts belong to the package under test.
type benchConn struct {
	request string
	read    int
	written int
}

func (c *benchConn) rewind() { c.read, c.written = 0, 0 }

func (c *benchConn) Read(b []byte) (int, error) {
	if c.read >= len(c.request) {
		return 0, io.EOF
	}
	n := copy(b, c.request[c.read:])
	c.read += n
	return n, nil
}

func (c *benchConn) Write(b []byte) (int, error) {
	c.written += len(b)
	return len(b), nil
}

func (c *benchConn) Close() error { return nil }

// benchBody is package level: converting a string literal to []byte inside the
// handler would allocate on every request and hide the router's own cost.
var benchBody = []byte("hello world")

func benchExchange(b *testing.B, conn conn) *Exchange {
	b.Helper()
	const bufferSize = 1024
	exch := new(Exchange)
	exch.Configure(make([]byte, 2*bufferSize), bufferSize, false)
	if !exch.Acquire(conn) {
		b.Fatal("fresh exchange failed to acquire connection")
	}
	return exch
}

// BenchmarkHandle measures a whole exchange: read, parse, mux and respond.
func BenchmarkHandle(b *testing.B) {
	expect := []byte("123")
	buf := make([]byte, 64)
	for _, bb := range []struct {
		name    string
		request string
		handler HandlerFunc
	}{
		{
			name:    "GETWithHeadersAndQuery",
			request: "GET /?abc=123 HTTP/1.1\r\nHost: tinygo.org\r\nUser-Agent: bench\r\nAccept: */*\r\nConnection: close\r\n\r\n",
			handler: func(ex *Exchange) {
				ex.SetHeader("Content-Type", "text/plain")
				ex.SetHeaderInt("Content-Length", int64(len(benchBody)), 10)
				data, present := ex.AppendQuery(buf[:0], "abc", true)
				if !present || !internal.BytesEqual(data, expect) {
					panic("invalid result")
				}
				ex.Write(benchBody)
			},
		},
		{
			name:    "NotFound",
			request: "GET /nowhere HTTP/1.1\r\nHost: tinygo.org\r\n\r\n",
			handler: nil, // Unregistered: exercises the 404 path.
		},
	} {
		b.Run(bb.name, func(b *testing.B) {
			var mux MuxSlice
			if bb.handler != nil {
				mux.Handle("GET /", bb.handler)
			}
			conn := &benchConn{request: bb.request}
			exch := benchExchange(b, conn)
			b.ReportAllocs()
			b.SetBytes(int64(len(bb.request)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				conn.rewind()
				exch.Release()
				exch.Acquire(conn)
				Handle(exch, &mux, nopBackoff)
			}
		})
	}
}
