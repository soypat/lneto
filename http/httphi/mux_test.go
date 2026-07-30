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
