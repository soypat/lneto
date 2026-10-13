package httphi

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/internal"
)

// SetPathValues must agree with net/http.ServeMux on which patterns match which
// paths and what each wildcard binds to. Every case below was taken from a run
// against a real ServeMux, so this table is an oracle, not a guess.
//
// The one documented deviation is percent-decoding: ServeMux unescapes segments
// before matching and binding, this does not. See TestSetPathValuesEscaping.
func TestSetPathValues(t *testing.T) {
	for _, test := range []struct {
		pattern string
		path    string
		match   bool
		want    string // "name=value" pairs joined by "|", in bind order.
	}{
		// Single segment wildcard binds exactly one non-empty segment.
		{pattern: "/users/{id}", path: "/users/42", match: true, want: "id=42"},
		{pattern: "/users/{id}", path: "/users/42/x", match: false},
		{pattern: "/users/{id}", path: "/users/", match: false},
		{pattern: "/users/{id}", path: "/users", match: false},
		{pattern: "/users/{id}/edit", path: "/users/42/edit", match: true, want: "id=42"},
		{pattern: "/{a}/{b}", path: "/x/y", match: true, want: "a=x|b=y"},

		// "..." swallows the remainder, slashes included, and may bind empty.
		{pattern: "/b/{bucket}/o/{obj...}", path: "/b/bk/o/a/b/c", match: true, want: "bucket=bk|obj=a/b/c"},
		{pattern: "/b/{bucket}/o/{obj...}", path: "/b/bk/o/", match: true, want: "bucket=bk|obj="},
		{pattern: "/b/{bucket}/o/{obj...}", path: "/b/bk/o", match: false},
		{pattern: "/files/{p...}", path: "/files/", match: true, want: "p="},
		{pattern: "/files/{p...}", path: "/files", match: false},

		// {$} matches only the end of the path.
		{pattern: "/{$}", path: "/", match: true},
		{pattern: "/{$}", path: "/x", match: false},
		{pattern: "/a/{$}", path: "/a/", match: true},
		{pattern: "/a/{$}", path: "/a", match: false},
		{pattern: "/a/{$}", path: "/a/b", match: false},

		// A trailing slash is an anonymous "..." wildcard, binding nothing.
		{pattern: "/files/", path: "/files/a/b", match: true},
		{pattern: "/files/", path: "/files/", match: true},
		{pattern: "/files/", path: "/files", match: false},
		{pattern: "/", path: "/anything/at/all", match: true},

		// Literal patterns match exactly, trailing slash included.
		{pattern: "/health", path: "/health", match: true},
		{pattern: "/health", path: "/health/", match: false},

		// An empty segment never satisfies a single wildcard.
		{pattern: "/a/{x}/b", path: "/a//b", match: false},
	} {
		t.Run(test.pattern+"__"+test.path, func(t *testing.T) {
			vals := make([]PathValue, 8)
			match, tooShort := SetPathValues(vals, test.pattern, []byte(test.path))
			if tooShort {
				t.Fatal("8 slots must be enough for these patterns")
			}
			if match != test.match {
				t.Fatalf("want match=%v, got %v", test.match, match)
			}
			if !match {
				return
			}
			if got := renderPathValues(vals); got != test.want {
				t.Errorf("want %q, got %q", test.want, got)
			}
		})
	}
}

// Bound values must alias the request path buffer rather than copy it: the
// exchange owns that memory and a copy would allocate per request.
func TestSetPathValuesAliasesRequestBuffer(t *testing.T) {
	path := []byte("/users/42/edit")
	vals := make([]PathValue, 4)
	match, _ := SetPathValues(vals, "/users/{id}/edit", path)
	if !match {
		t.Fatal("want match")
	}
	if string(vals[0].Value) != "42" {
		t.Fatalf("want id=42, got %q", vals[0].Value)
	}
	// Mutating the request buffer must show through the bound value.
	path[7] = '9'
	if string(vals[0].Value) != "92" {
		t.Errorf("value must alias the request buffer, got %q", vals[0].Value)
	}
}

// A destination too small to hold every wildcard must say so rather than bind a
// partial set or write out of range.
func TestSetPathValuesSliceTooShort(t *testing.T) {
	match, tooShort := SetPathValues(make([]PathValue, 1), "/{a}/{b}", []byte("/x/y"))
	if !tooShort {
		t.Error("want pathValSliceTooShort for 2 wildcards in 1 slot")
	}
	if match {
		t.Error("want match=false when values could not be bound")
	}
	// A pattern that binds nothing needs no slots at all.
	match, tooShort = SetPathValues(nil, "/health", []byte("/health"))
	if !match || tooShort {
		t.Errorf("want match with no slots needed, got match=%v tooShort=%v", match, tooShort)
	}
}

// Percent escapes are compared and bound raw. ServeMux unescapes segment by
// segment, so "/users/x%2Fy" binds id="x/y" there and id="x%2Fy" here. Matching
// agrees either way; only the bound bytes differ.
func TestSetPathValuesEscaping(t *testing.T) {
	vals := make([]PathValue, 4)
	if match, _ := SetPathValues(vals, "/a%2Fb/{x}", []byte("/a%2Fb/v")); !match {
		t.Error("want literal escape in pattern to match the same bytes in path")
	}
	vals = make([]PathValue, 4)
	match, _ := SetPathValues(vals, "/users/{id}", []byte("/users/x%2Fy"))
	if !match {
		t.Fatal("want match")
	}
	if got := string(vals[0].Value); got != "x%2Fy" {
		t.Errorf("want raw %q, got %q", "x%2Fy", got)
	}
}

// renderPathValues joins the bound pairs for comparison, stopping at the first
// unused slot.
func renderPathValues(vals []PathValue) string {
	var sb strings.Builder
	for _, v := range vals {
		if v.Key == "" {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString(v.Key)
		sb.WriteByte('=')
		sb.Write(v.Value)
	}
	return sb.String()
}

// Matching a request must not allocate: keys alias the mux's pattern and values
// alias the request buffer, so nothing is copied per request.
func TestSetPathValuesNoAlloc(t *testing.T) {
	vals := make([]PathValue, 8)
	path := []byte("/b/bk/o/a/b/c")
	allocs := testing.AllocsPerRun(100, func() {
		SetPathValues(vals, "/b/{bucket}/o/{obj...}", path)
	})
	if allocs != 0 {
		t.Fatalf("SetPathValues allocated %v times, want 0", allocs)
	}
}

// pathValueMux binds one wildcard pattern, standing in for a [Mux] that
// supports them until MuxSlice sets setPathVal.
type pathValueMux struct {
	pattern string
	handler HandlerFunc
}

func (m *pathValueMux) MaxPathValues() int {
	return -1
}

func (m *pathValueMux) LookupHandler(method Method, path []byte, dst []PathValue) (string, HandlerFunc) {
	if ok, _ := SetPathValues(dst, m.pattern, path); ok {
		return m.pattern, m.handler
	}
	return "", nil
}

// A wildcard bound by one request must not be readable by the next request the
// same pooled exchange serves. A literal pattern binds nothing, so it never
// overwrites the previous request's slots, and the values it would leak alias a
// buffer the new request has already overwritten.
func TestExchangePathValueClearedBetweenRequests(t *testing.T) {
	exch := new(Exchange)
	exch.Configure(ExchangeConfig{
		RawBuf: make([]byte, 2048), RequestBufferLim: 1024,
		NumHeaderKVCap: defaultNumHeaderKVCap, PathValuesBuf: make([]PathValue, 4),
	})

	// First request binds id=42 off a wildcard pattern.
	var gotFirst string
	wildcard := &pathValueMux{pattern: "/users/{id}", handler: func(e *Exchange) {
		gotFirst = string(e.PathValue("id"))
		e.WriteHeader(200)
	}}
	conn := newConn("GET /users/42 HTTP/1.1\r\nHost: h\r\n\r\n")
	conn.Hangup()
	if !exch.Acquire(conn) {
		t.Fatal("fresh exchange failed to acquire")
	}
	if err := Handle(exch, wildcard, nopBackoff); err != nil {
		t.Fatalf("first request: %s", err)
	}
	exch.Release()
	if gotFirst != "42" {
		t.Fatalf("want id=42 bound on the first request, got %q", gotFirst)
	}

	// Second request matches a literal pattern, which binds nothing at all.
	var leaked []byte
	var sm MuxSlice
	sm.Handle("/health", func(e *Exchange) {
		leaked = e.PathValue("id")
		e.WriteHeader(200)
	})
	conn2 := newConn("GET /health HTTP/1.1\r\nHost: h\r\n\r\n")
	conn2.Hangup()
	if !exch.Acquire(conn2) {
		t.Fatal("released exchange failed to re-acquire")
	}
	if err := Handle(exch, &sm, nopBackoff); err != nil {
		t.Fatalf("second request: %s", err)
	}
	if leaked != nil {
		t.Errorf("want no path value on a literal route, got id=%q from the previous request", leaked)
	}
}

// A lookup tries each endpoint in turn and [SetPathValues] binds as it walks, so
// a pattern that binds values and then fails must not leave them behind for the
// pattern that does match: a handler would read a wildcard no matched pattern has.
func TestMuxSliceNoStaleBindingsAcrossCandidates(t *testing.T) {
	var sm MuxSlice
	sm.Reset(2)
	sm.Handle("/a/{x}/{y}/z", func(ex *Exchange) { t.Error("non-matching handler ran") })
	var gotP, gotX, gotY string
	sm.Handle("/a/{p}/b", func(ex *Exchange) {
		gotP = string(ex.PathValue("p"))
		gotX = string(ex.PathValue("x"))
		gotY = string(ex.PathValue("y"))
		ex.WriteHeader(200)
	})

	exch := new(Exchange)
	exch.Configure(ExchangeConfig{
		RawBuf: make([]byte, 2048), RequestBufferLim: 1024,
		NumHeaderKVCap: defaultNumHeaderKVCap, PathValuesBuf: make([]PathValue, sm.MaxPathValues()),
	})
	conn := newConn("GET /a/1/b HTTP/1.1\r\nHost: h\r\n\r\n")
	conn.Hangup()
	if !exch.Acquire(conn) {
		t.Fatal("fresh exchange failed to acquire")
	}
	if err := Handle(exch, &sm, nopBackoff); err != nil {
		t.Fatal(err)
	}
	if gotP != "1" {
		t.Errorf("want p=1 from the matched pattern, got %q", gotP)
	}
	if gotX != "" || gotY != "" {
		t.Errorf("want no x/y from the failed candidate, got x=%q y=%q", gotX, gotY)
	}
}

// A pattern ending in '/' carries no brace but is still a wildcard: the trailing
// slash is an anonymous "{...}", see [SetPathValues]. MuxSlice must route it
// through the same matcher rather than comparing the path literally.
func TestMuxSliceTrailingSlashPattern(t *testing.T) {
	for _, test := range []struct {
		pattern string
		path    string
		want    bool
	}{
		{pattern: "/files/", path: "/files/a/b", want: true},
		{pattern: "/files/", path: "/files/", want: true},
		{pattern: "/files/", path: "/files", want: false},
		{pattern: "/files/", path: "/other/a", want: false},
		{pattern: "/", path: "/anything/at/all", want: true},
		{pattern: "/", path: "/", want: true},
		// Without the trailing slash a pattern stays literal.
		{pattern: "/files", path: "/files/a", want: false},
		{pattern: "/files", path: "/files", want: true},
	} {
		t.Run(test.pattern+"__"+test.path, func(t *testing.T) {
			var sm MuxSlice
			sm.Reset(1)
			var served bool
			sm.Handle(test.pattern, func(ex *Exchange) { served = true; ex.WriteHeader(200) })
			// MuxSlice must agree with the matcher it delegates to.
			if ok, _ := SetPathValues(nil, test.pattern, []byte(test.path)); ok != test.want {
				t.Fatalf("SetPathValues disagrees with the table: got %v", ok)
			}
			exch := new(Exchange)
			exch.Configure(ExchangeConfig{
				RawBuf: make([]byte, 2048), RequestBufferLim: 1024,
				NumHeaderKVCap: defaultNumHeaderKVCap, PathValuesBuf: make([]PathValue, sm.MaxPathValues()),
			})
			conn := newConn("GET " + test.path + " HTTP/1.1\r\nHost: h\r\n\r\n")
			conn.Hangup()
			if !exch.Acquire(conn) {
				t.Fatal("fresh exchange failed to acquire")
			}
			if err := Handle(exch, &sm, nopBackoff); err != nil {
				t.Fatal(err)
			}
			if served != test.want {
				t.Errorf("want served=%v, got %v", test.want, served)
			}
		})
	}
}

// A malformed registration is a programming error, and one that otherwise costs
// a permanent silent 404 at runtime: "Get /x" parses to MethUnknown, which no
// GET request ever matches but every extension-method request does. Fail at
// registration, where the stack points at the offending line.
func TestMuxSliceHandlePanicsOnBadRegistration(t *testing.T) {
	for _, test := range []struct {
		name string
		reg  string
	}{
		{name: "lowercase method", reg: "Get /x"},
		{name: "all lower method", reg: "get /x"},
		{name: "mixed case method", reg: "pOsT /x"},
		{name: "no leading slash", reg: "GET x"},
		{name: "bare path no slash", reg: "x"},
		{name: "empty path after method", reg: "GET "},
	} {
		t.Run(test.name, func(t *testing.T) {
			var sm MuxSlice
			sm.Reset(1)
			defer func() {
				if recover() == nil {
					t.Errorf("want panic registering %q", test.reg)
				}
			}()
			sm.Handle(test.reg, func(ex *Exchange) {})
		})
	}
}

// An exact duplicate is unreachable code: the first registration always wins.
func TestMuxSliceHandlePanicsOnDuplicate(t *testing.T) {
	var sm MuxSlice
	sm.Reset(2)
	sm.Handle("GET /x", func(ex *Exchange) {})
	defer func() {
		if recover() == nil {
			t.Error("want panic registering the same method and path twice")
		}
	}()
	sm.Handle("GET /x", func(ex *Exchange) {})
}

// Extension methods are legal and uppercase, so they must still register: only
// the case-mangled forms are rejected.
func TestMuxSliceHandleAllowsExtensionMethod(t *testing.T) {
	var sm MuxSlice
	sm.Reset(2)
	sm.Handle("PROPFIND /dav", func(ex *Exchange) {})
	sm.Handle("/any-method", func(ex *Exchange) {}) // Bare path matches any method.
	if sm.MaxPathValues() != 0 {
		t.Errorf("want 0 path values, got %d", sm.MaxPathValues())
	}
}

// A catch-all registered before the endpoints it sits above must not swallow
// them. "/" is a wildcard pattern: its trailing slash is an anonymous "{...}",
// so a purely first-match-wins scan hands every request to it and the specific
// registrations below become dead code, answered with the root page instead of
// their own body. Registering the site root first is the ordinary way to write
// a mux, so the more specific pattern has to win regardless of order, as in
// http.ServeMux.
func TestMuxSliceSpecificPatternBeatsEarlierCatchAll(t *testing.T) {
	for _, test := range []struct {
		name     string
		register []string
		path     string
		want     string
	}{
		{
			name:     "root registered first",
			register: []string{"/", "/hello", "/cnt", "/6"},
			path:     "/cnt",
			want:     "/cnt",
		}, {
			name:     "root registered last",
			register: []string{"/hello", "/cnt", "/6", "/"},
			path:     "/cnt",
			want:     "/cnt",
		}, {
			name:     "root still serves the root path",
			register: []string{"/", "/cnt"},
			path:     "/",
			want:     "/",
		}, {
			name:     "root still catches the unregistered",
			register: []string{"/", "/cnt"},
			path:     "/nowhere",
			want:     "/",
		}, {
			name:     "subtree wildcard loses to its own literal",
			register: []string{"/files/", "/files/index"},
			path:     "/files/index",
			want:     "/files/index",
		}, {
			name:     "subtree wildcard keeps the rest",
			register: []string{"/files/", "/files/index"},
			path:     "/files/a/b",
			want:     "/files/",
		}, {
			name:     "longer literal prefix wins over shorter subtree",
			register: []string{"/", "/files/", "/files/a/b"},
			path:     "/files/a/b",
			want:     "/files/a/b",
		}, {
			name:     "named wildcard loses to the literal it covers",
			register: []string{"/users/{id}", "/users/me"},
			path:     "/users/me",
			want:     "/users/me",
		}, {
			name:     "named wildcard keeps everything else",
			register: []string{"/users/{id}", "/users/me"},
			path:     "/users/42",
			want:     "/users/{id}",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var sm MuxSlice
			sm.Reset(len(test.register))
			for _, pattern := range test.register {
				sm.Handle(pattern, func(ex *Exchange) { ex.WriteHeader(200) })
			}
			pathVals := make([]PathValue, max(sm.MaxPathValues(), 0))
			got, handler := sm.LookupHandler(MethGet, []byte(test.path), pathVals)
			if handler == nil {
				t.Fatalf("%s matched no handler, want %q", test.path, test.want)
			}
			if got != test.want {
				t.Errorf("%s matched pattern %q, want %q", test.path, got, test.want)
			}
		})
	}
}

// pathVals sizes the slice SetPathValues writes into, so it must count exactly
// the wildcards that bind. Counting braces over-reports: "{$}" marks the path's
// end, an anonymous "{...}" has no name, and a brace inside a literal segment is
// not a wildcard at all. Each of those binds nothing.
func TestMuxSliceMaxPathValuesCountsOnlyBindingWildcards(t *testing.T) {
	for _, test := range []struct {
		pattern string
		want    int
	}{
		{pattern: "/health", want: 0},
		{pattern: "/", want: 0},
		{pattern: "/files/", want: 0},       // Anonymous trailing wildcard.
		{pattern: "/{$}", want: 0},          // End-of-path marker.
		{pattern: "/a/{$}", want: 0},        //
		{pattern: "/b_{bucket}", want: 0},   // Literal: brace not a whole segment.
		{pattern: "/{...}", want: 0},        // Multi wildcard with no name.
		{pattern: "/users/{id}", want: 1},   //
		{pattern: "/files/{p...}", want: 1}, //
		{pattern: "/{a}/{b}", want: 2},      //
		{pattern: "/b/{bucket}/o/{obj...}", want: 2},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			var sm MuxSlice
			sm.Reset(1)
			sm.Handle(test.pattern, func(ex *Exchange) {})
			if got := sm.MaxPathValues(); got != test.want {
				t.Errorf("want %d path values, got %d", test.want, got)
			}
		})
	}
}

// Sizing and routing are different questions: "{$}" binds no values yet still
// needs the matcher, so an exact pathVals count must not send it to the literal
// comparison instead.
func TestMuxSliceZeroValueWildcardStillMatches(t *testing.T) {
	for _, test := range []struct {
		pattern string
		path    string
		want    bool
	}{
		{pattern: "/{$}", path: "/", want: true},
		{pattern: "/{$}", path: "/x", want: false},
		{pattern: "/a/{$}", path: "/a/", want: true},
		{pattern: "/a/{$}", path: "/a/b", want: false},
		{pattern: "/{...}", path: "/any/thing", want: true},
	} {
		t.Run(test.pattern+"__"+test.path, func(t *testing.T) {
			var sm MuxSlice
			sm.Reset(1)
			var served bool
			sm.Handle(test.pattern, func(ex *Exchange) { served = true; ex.WriteHeader(200) })
			exch := new(Exchange)
			exch.Configure(ExchangeConfig{
				RawBuf: make([]byte, 2048), RequestBufferLim: 1024,
				NumHeaderKVCap: defaultNumHeaderKVCap, PathValuesBuf: make([]PathValue, sm.MaxPathValues()),
			})
			conn := newConn("GET " + test.path + " HTTP/1.1\r\nHost: h\r\n\r\n")
			conn.Hangup()
			if !exch.Acquire(conn) {
				t.Fatal("acquire")
			}
			if err := Handle(exch, &sm, nopBackoff); err != nil {
				t.Fatal(err)
			}
			if served != test.want {
				t.Errorf("want served=%v, got %v", test.want, served)
			}
		})
	}
}

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
	const numHeaderCap = 2
	exch := new(Exchange)
	exch.Configure(ExchangeConfig{
		RawBuf:           make([]byte, 2*bufferSize),
		RequestBufferLim: bufferSize,
		NumHeaderKVCap:   numHeaderCap,
	})
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
				ex.StageHeader("Content-Type", "text/plain")
				ex.StageHeaderIntBase("Content-Length", int64(len(benchBody)), 10)
				data, present := ex.RequestQueryAppend(buf[:0], "abc", true)
				if !present || !internal.BytesEqual(data, expect) {
					panic("invalid result")
				}
				ex.WriteBody(benchBody)
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

// Fuzz targets in this file are written so that a stored corpus keeps its
// meaning as the tests grow. Go's corpus files are positional and typed, so an
// input is only reproducible while the code that decodes it stays fixed. Five
// rules keep that true, and edits to this file must obey them:
//
//  1. A target's signature is frozen: func(t *testing.T, ctrl uint64, data []byte).
//     Adding, removing or reordering a parameter invalidates every stored entry.
//  2. Control decisions come from ctrl only, wire bytes from data only. Never
//     branch on data, never put payload in ctrl: the two axes mutate apart.
//  3. ctrl is a bit field read through absolute shifts and masks named below.
//     New knobs claim unused high bits and are only ever appended, never
//     renumbered, and the zero value of a knob must decode to the behaviour that
//     existed before it was added, so old entries keep replaying as they did.
//  4. No PRNG, no cursor. No rand, no internal.Prand64, and no helper that
//     "reads the next N bits" while advancing a position: inserting one draw
//     ahead of another shifts every later decision, which is the same corpus
//     invalidation a PRNG causes.
//  5. Nothing ambient: no wall clock, no goroutines, no map iteration order.
//     Targets drive [Handle] on the calling goroutine; [Router] is not fuzzed
//     here precisely because it serves on goroutines of its own.
const (
	// Bits 0..3 index segSizes: how the request is split across reads.
	ctlSegShift, ctlSegMask = 0, 0xf
	// Bits 4..7 and 8..11 size the request and response halves of the buffer.
	ctlReqBufShift, ctlRespBufShift, ctlBufMask = 4, 8, 0xf
	// Bits 12..13 size the request header field table.
	ctlKVCapShift, ctlKVCapMask = 12, 0x3
	// Bit 14 normalizes outgoing header keys.
	ctlNormalizeShift, ctlNormalizeMask = 14, 0x1
	// Bits 15..16 make that many leading writes to the connection fail.
	ctlFailWriteShift, ctlFailWriteMask = 15, 0x3
	// Bits 17..20 select what the handler does, see the op constants.
	ctlHandlerOpsShift, ctlHandlerOpsMask = 17, 0xf
	// Bits 21..23 count the header fields the handler stages.
	ctlStageCountShift, ctlStageCountMask = 21, 0x7
	// Bit 24 asks AppendQuery for decoded values.
	ctlDecodeShift, ctlDecodeMask = 24, 0x1
	// Bits 25..28 size the scratch buffer handed to form and multipart parsing.
	ctlScratchShift, ctlScratchMask = 25, 0xf
	// Bit 29 makes the multipart sink discard part content.
	ctlDiscardShift, ctlDiscardMask = 29, 0x1
	// Next knob starts at bit 30.
)

// Handler operations, selected by the ctlHandlerOps field. Values are frozen:
// a new operation takes the next free bit within the field.
const (
	opStageHeaders = 1 << iota
	opReadBody
	opWriteBody
	opHijack
)

// segSizes are the chunk sizes a request may be delivered in, index 0 meaning
// "all at once". Splitting a request mid-CRLF or before a colon is what drives
// [httpraw.HeaderV1.TryParse]'s resumption path. Entries may be appended, never
// changed: an existing index must keep splitting exactly as it does today.
var segSizes = [16]int{0, 1, 2, 3, 5, 7, 11, 16, 23, 37, 64, 101, 173, 256, 509, 1024}

// ctlField reads a knob out of ctrl. Absolute shift, no cursor, so knobs are
// independent of one another and of the order they are read in.
func ctlField(ctrl uint64, shift, mask uint64) uint64 {
	return (ctrl >> shift) & mask
}

// maxFuzzInput bounds the wire data a target accepts. The filter depends only
// on the input, so it classifies an entry the same way on every run.
const maxFuzzInput = 16 << 10

// fuzzExchange returns an exchange acquired on a connection preloaded with data,
// both sized and segmented by ctrl.
func fuzzExchange(t *testing.T, ctrl uint64, data []byte) (*Exchange, *rwconn) {
	t.Helper()
	reqBuf := minRequestHeaderBuffer + int(ctlField(ctrl, ctlReqBufShift, ctlBufMask))*8
	respBuf := minResponseHeaderBuffer + int(ctlField(ctrl, ctlRespBufShift, ctlBufMask))*8
	kvCap := 1 + int(ctlField(ctrl, ctlKVCapShift, ctlKVCapMask))*8

	conn := newConn("")
	seg := segSizes[ctlField(ctrl, ctlSegShift, ctlSegMask)]
	if seg <= 0 || seg >= len(data) {
		conn.AddReadable(data)
	} else {
		for off := 0; off < len(data); off += seg {
			conn.AddSegment(string(data[off:min(off+seg, len(data))]))
		}
	}
	// Always hang up: a drained connection that never reports EOF reads (0,nil)
	// forever and [Handle] would back off in an unbounded loop.
	conn.Hangup()
	if n := ctlField(ctrl, ctlFailWriteShift, ctlFailWriteMask); n > 0 {
		conn.FailWrites(int(n))
	}
	exch := newExchange(t, conn, ExchangeConfig{
		RawBuf:                make([]byte, reqBuf+respBuf),
		RequestBufferLim:      reqBuf,
		NumHeaderKVCap:        kvCap,
		NormalizeOutgoingKeys: ctlField(ctrl, ctlNormalizeShift, ctlNormalizeMask) != 0,
		NoRequestBufferGrowth: true,
	})
	return exch, conn
}

// checkRequestView asserts the request-target views agree with one another.
func checkRequestView(t *testing.T, exch *Exchange) {
	t.Helper()
	target, path, query := exch.RequestTarget(), exch.RequestPath(), exch.RequestQuery()
	if !bytes.HasPrefix(target, path) {
		t.Fatalf("path %q is not a prefix of target %q", path, target)
	}
	if len(query) > 0 && !bytes.HasSuffix(target, query) {
		t.Fatalf("query %q is not a suffix of target %q", query, target)
	}
	if len(path)+len(query) > len(target) {
		t.Fatalf("path %q and query %q exceed target %q", path, query, target)
	}
}

// checkResponse asserts that whatever reached the wire is a response a peer
// could parse: a status line this package produced, followed by a header block
// that terminates, and that [httpraw] reads back what it wrote.
func checkResponse(t *testing.T, written string) {
	t.Helper()
	if written == "" {
		return // Hijacked, or a request refused before anything was staged.
	}
	const proto = "HTTP/1.1 "
	if !strings.HasPrefix(written, proto) {
		t.Fatalf("response does not open with a status line: %q", written)
	}
	if len(written) < len(proto)+4 {
		t.Fatalf("status line truncated: %q", written)
	}
	for _, c := range []byte(written[len(proto) : len(proto)+3]) {
		if c < '0' || c > '9' {
			t.Fatalf("status code is not three digits: %q", written)
		}
	}
	if written[len(proto)+3] != ' ' {
		t.Fatalf("status code not followed by a space: %q", written)
	}
	if !strings.Contains(written, "\r\n\r\n") {
		t.Fatalf("header block never terminated: %q", written)
	}
	var resp httpraw.HeaderV1
	const asResponse = true
	if err := resp.ParseBytes(asResponse, []byte(written)); err != nil {
		t.Fatalf("response does not parse back: %s in %q", err, written)
	}
}

// handler2Path is a second registration so lookup does not always match on the
// first entry of the mux.
const handler2Path = "/fuzz"

// fuzzMux returns a mux serving handler on the paths the seed corpus requests.
func fuzzMux(handler HandlerFunc) *MuxSlice {
	var mux MuxSlice
	mux.Handle("/", handler)
	mux.Handle(handler2Path, handler)
	return &mux
}

// FuzzHandleRequest drives a whole exchange: a request off the wire through
// [Handle], a handler staging and writing a response, and back out to the peer.
func FuzzHandleRequest(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, ctrl uint64, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		exch, conn := fuzzExchange(t, ctrl, data)
		ops := ctlField(ctrl, ctlHandlerOpsShift, ctlHandlerOpsMask)
		stage := ctlField(ctrl, ctlStageCountShift, ctlStageCountMask)

		Handle(exch, fuzzMux(func(exch *Exchange) {
			checkRequestView(t, exch)
			if ops&opStageHeaders != 0 {
				// Literal fields: staging request bytes would test the caller's
				// escaping, not this package's framing.
				for i := range stage {
					exch.StageHeader("X-Fuzz", "value")
					exch.StageHeaderIntBase("X-Fuzz-Int", int64(i), 10)
				}
			}
			if ops&opReadBody != 0 {
				var body [64]byte
				for range 64 {
					n, err := exch.ReadBody(body[:])
					if n == 0 && err != nil {
						break
					}
				}
			}
			if ops&opWriteBody != 0 {
				exch.WriteBody([]byte("fuzz body"))
			}
			if ops&opHijack != 0 {
				exch.HijackRaw(nil)
			}
		}), nopBackoff)

		if ctlField(ctrl, ctlFailWriteShift, ctlFailWriteMask) == 0 {
			// A refused write leaves a partial response on purpose, so the
			// wire is only well formed when every write got through.
			checkResponse(t, conn.ViewWritten())
		}
	})
}

// FuzzQueryAndForm drives the request-target query and the form-encoded body,
// both of which decode percent escapes in place over caller memory.
func FuzzQueryAndForm(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, ctrl uint64, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		exch, _ := fuzzExchange(t, ctrl, data)
		decoded := ctlField(ctrl, ctlDecodeShift, ctlDecodeMask) != 0
		scratchLen := 8 + int(ctlField(ctrl, ctlScratchShift, ctlScratchMask))*16

		Handle(exch, fuzzMux(func(exch *Exchange) {
			// Every pair the iterator yields must be reachable by name, or the
			// two views of the query string disagree.
			const maxPairs = 64
			key, _, rest := httpraw.NextQueryPair(exch.RequestQuery())
			for pairs := 0; key != nil && pairs < maxPairs; pairs++ {
				dec := make([]byte, len(key))
				n, err := httpraw.CopyDecodedPercentURL(dec, key, true)
				if err == nil {
					if n > len(key) {
						t.Fatalf("decoding key %q grew it to %d bytes", key, n)
					}
					if _, present := exch.RequestQueryAppend(nil, string(dec[:n]), decoded); !present {
						t.Fatalf("query pair %q absent from AppendQuery", key)
					}
				}
				key, _, rest = httpraw.NextQueryPair(rest)
			}

			var form httpraw.Form
			buf := make([]byte, scratchLen)
			if err := exch.RequestParseForm(&form, false, false); err != nil {
				return
			}
			total := 0
			lens := make([]int, form.Len())
			for i := range form.Len() {
				k, v := form.Pair(i)
				lens[i] = len(k) + len(v)
				total += lens[i]
			}
			if total > len(buf) {
				t.Fatalf("form pairs span %d bytes of a %d byte buffer", total, len(buf))
			}
			if err := form.Decode(); err != nil {
				return
			}
			// Decoding replaces escapes in place, so no pair may grow.
			for i := range form.Len() {
				k, v := form.Pair(i)
				if len(k)+len(v) > lens[i] {
					t.Fatalf("pair %d grew from %d to %d bytes on decode", i, lens[i], len(k)+len(v))
				}
			}
		}), nopBackoff)
	})
}

// countSink counts what a multipart part streamed into it and whether the part
// was closed off.
type countSink struct {
	written int
	closed  bool
}

func (c *countSink) Write(b []byte) (int, error) {
	c.written += len(b)
	return len(b), nil
}

func (c *countSink) Close() error {
	c.closed = true
	return nil
}

// FuzzMultipart drives [Exchange.ReadMultiparts], which streams a body of
// unknown length through a buffer the caller sized.
func FuzzMultipart(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, ctrl uint64, data []byte) {
		if len(data) > maxFuzzInput {
			return
		}
		exch, _ := fuzzExchange(t, ctrl, data)
		discard := ctlField(ctrl, ctlDiscardShift, ctlDiscardMask) != 0
		bufLen := 16 + int(ctlField(ctrl, ctlScratchShift, ctlScratchMask))*16

		Handle(exch, fuzzMux(func(exch *Exchange) {
			var sinks []*countSink
			_, err := exch.ReadMultiparts(nil, make([]byte, bufLen), func(hdr *httpraw.MultipartHeader) io.WriteCloser {
				if discard {
					return nil
				}
				sink := new(countSink)
				sinks = append(sinks, sink)
				return sink
			})
			if err != nil {
				return // Sinks are left for the caller to deal with on error.
			}
			total := 0
			for _, sink := range sinks {
				if !sink.closed {
					t.Fatal("ReadMultiparts returned with a part left open")
				}
				total += sink.written
			}
			if total > len(data) {
				t.Fatalf("parts streamed %d bytes out of a %d byte request", total, len(data))
			}
		}), nopBackoff)
	})
}

// addSeeds adds the shared seed corpus. Every seed pins ctrl to zero so its
// meaning never moves: knobs added later decode their zero value to the
// behaviour the seed was recorded under.
func addSeeds(f *testing.F) {
	f.Helper()
	const (
		formType = "Content-Type: application/x-www-form-urlencoded\r\n"
		mpType   = "Content-Type: multipart/form-data; boundary=b0undary\r\n"
	)
	seeds := []string{
		// Well formed traffic, so the fuzzer has somewhere to mutate from.
		"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /fuzz?q=go&n=1 HTTP/1.1\r\nHost: h\r\n\r\n",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + formType + "Content-Length: 11\r\n\r\na=1&b=2&c=3",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + mpType + "Content-Length: 76\r\n\r\n--b0undary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nbody\r\n--b0undary--\r\n",

		// Framing the RFC leaves room to disagree over, which is where request
		// smuggling lives: two lengths, a length plus a coding, and a coding
		// this package does not decode.
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",

		// Field names are case insensitive, RFC 9110 5.1, so a lookup that
		// misses one of these reads the request differently than the peer wrote it.
		"POST / HTTP/1.1\r\nHost: h\r\ncontent-length: 4\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nCONTENT-LENGTH: 4\r\n\r\nbody",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 3\r\n\r\na=1",

		// Content-Length values that are not a bare digit string, RFC 9112 6.2.
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\nbody!",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1 2\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length:\r\n\r\nbody",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 9223372036854775808\r\n\r\nbody",

		// Line ending and field syntax edges.
		"GET / HTTP/1.1\nHost: h\n\n",
		"GET / HTTP/1.1\r\nHost: h\rX: y\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n Continued: fold\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nX: va\x00lue\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nNoColon\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n: novalue\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nX:\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n\r\n\r\n",

		// Request lines this package tolerates or must refuse.
		"GET http://h/abs HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /\r\n\r\n", // HTTP/0.9 simple request, no version.
		" GET / HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET  / HTTP/1.1\r\nHost: h\r\n\r\n",
		"/ HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET / HTTP/9.9\r\nHost: h\r\n\r\n",

		// Percent escapes, including the truncated and the malformed.
		"GET /a%20b?a%20b=c%20d HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?q=%2 HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?q=%zz HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /%00?a=%00 HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?a=b=c&&=v&debug HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET /?a%3db=1&a+b=2 HTTP/1.1\r\nHost: h\r\n\r\n",

		// Multipart bodies that end early or never open a part.
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + mpType + "Content-Length: 12\r\n\r\n--b0undary\r\n",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\n" + mpType + "Content-Length: 14\r\n\r\n--b0undary--\r\n",
		"POST /fuzz HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data\r\nContent-Length: 4\r\n\r\nbody",

		// Sizes that crowd the buffers: a long target, many fields, and a body
		// arriving in the same read as the header it follows.
		"GET /" + strings.Repeat("a", 512) + " HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET / HTTP/1.1\r\n" + strings.Repeat("X: y\r\n", 200) + "\r\n",
		"GET / HTTP/1.1\r\n" + strings.Repeat("k", 512) + ": v\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbodyTRAILING",

		// Nothing, and nothing that resembles a request at all.
		"",
		"\r\n\r\n",
		"\x00\x00\x00\x00",
	}
	for _, seed := range seeds {
		f.Add(uint64(0), []byte(seed))
	}
}
