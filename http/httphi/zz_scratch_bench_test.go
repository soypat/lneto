package httphi

import "testing"

// Scratch benchmarks isolating query handling. Delete after diagnosis.

const scratchRequest = "GET /?abc=123 HTTP/1.1\r\nHost: tinygo.org\r\nUser-Agent: bench\r\nAccept: */*\r\nConnection: close\r\n\r\n"

func scratchExchange(b *testing.B) (*Exchange, *benchConn, *MuxSlice) {
	b.Helper()
	conn := &benchConn{request: scratchRequest}
	exch := benchExchange(b, conn)
	mux := new(MuxSlice)
	return exch, conn, mux
}

// A: whole exchange, handler writes body only. No query touched.
func BenchmarkScratchBodyOnly(b *testing.B) {
	exch, conn, mux := scratchExchange(b)
	mux.Handle("GET /", func(ex *Exchange) { ex.Write(benchBody) })
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.rewind()
		exch.Release()
		exch.Acquire(conn)
		Handle(exch, mux, nopBackoff)
	}
}

// B: same plus header writes. Isolates SetHeader/SetHeaderInt.
func BenchmarkScratchHeaders(b *testing.B) {
	exch, conn, mux := scratchExchange(b)
	mux.Handle("GET /", func(ex *Exchange) {
		ex.SetHeader("Content-Type", "text/plain")
		ex.SetHeaderInt("Content-Length", int64(len(benchBody)), 10)
		ex.Write(benchBody)
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.rewind()
		exch.Release()
		exch.Acquire(conn)
		Handle(exch, mux, nopBackoff)
	}
}

// C: iteration only, closure captures one counter.
func BenchmarkScratchForEachQuery(b *testing.B) {
	exch, conn, mux := scratchExchange(b)
	var seen int
	mux.Handle("GET /", func(ex *Exchange) {
		ex.ForEachQueryRaw(func(rawkey, rawval []byte) bool {
			seen += len(rawkey)
			return true
		})
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.rewind()
		exch.Release()
		exch.Acquire(conn)
		Handle(exch, mux, nopBackoff)
	}
	_ = seen
}

// C2: closure that reassigns a captured slice, exactly AppendQuery's shape.
func BenchmarkScratchClosureSlice(b *testing.B) {
	exch, conn, mux := scratchExchange(b)
	buf := make([]byte, 64)
	mux.Handle("GET /", func(ex *Exchange) {
		out := buf[:0]
		found := false
		ex.ForEachQueryRaw(func(rawkey, rawval []byte) bool {
			if b2s(rawkey) != "abc" {
				return true
			}
			out = append(out, rawval...)
			found = true
			return false
		})
		_ = found
		_ = out
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.rewind()
		exch.Release()
		exch.Acquire(conn)
		Handle(exch, mux, nopBackoff)
	}
}

// C3: same but the captured slice is only read, never reassigned.
func BenchmarkScratchClosureNoReassign(b *testing.B) {
	exch, conn, mux := scratchExchange(b)
	buf := make([]byte, 64)
	mux.Handle("GET /", func(ex *Exchange) {
		n := 0
		ex.ForEachQueryRaw(func(rawkey, rawval []byte) bool {
			n += copy(buf, rawval)
			return false
		})
		_ = n
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.rewind()
		exch.Release()
		exch.Acquire(conn)
		Handle(exch, mux, nopBackoff)
	}
}

// D: AppendQuery raw, into a buffer with capacity.
func BenchmarkScratchAppendQueryRaw(b *testing.B) {
	exch, conn, mux := scratchExchange(b)
	buf := make([]byte, 64)
	mux.Handle("GET /", func(ex *Exchange) {
		ex.AppendQuery(buf[:0], "abc", false)
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.rewind()
		exch.Release()
		exch.Acquire(conn)
		Handle(exch, mux, nopBackoff)
	}
}

// E: AppendQuery decoded.
func BenchmarkScratchAppendQueryDecoded(b *testing.B) {
	exch, conn, mux := scratchExchange(b)
	buf := make([]byte, 64)
	mux.Handle("GET /", func(ex *Exchange) {
		ex.AppendQuery(buf[:0], "abc", true)
	})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.rewind()
		exch.Release()
		exch.Acquire(conn)
		Handle(exch, mux, nopBackoff)
	}
}
