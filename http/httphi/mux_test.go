package httphi

import (
	"strings"
	"testing"
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
		NumHeaderKVCap: defaultNumHeaderKVCap, MaxPathValues: 4,
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
		NumHeaderKVCap: defaultNumHeaderKVCap, MaxPathValues: sm.MaxPathValues(),
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
				NumHeaderKVCap: defaultNumHeaderKVCap, MaxPathValues: sm.MaxPathValues(),
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
				NumHeaderKVCap: defaultNumHeaderKVCap, MaxPathValues: sm.MaxPathValues(),
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
