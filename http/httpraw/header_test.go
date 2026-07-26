package httpraw

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHeaderParseRequest(t *testing.T) {
	const (
		wantMethod  = "GET"
		wantURI     = "/data/set"
		wantMessage = "hello world!"
		asRequest   = false
		asResponse  = true
	)
	req, err := http.NewRequest(wantMethod, wantURI, strings.NewReader(wantMessage))
	if err != nil {
		t.Fatal(err)
	}
	var wantCookie http.Cookie
	wantCookie.SameSite = http.SameSiteLaxMode
	wantCookie.MaxAge = 360000
	wantCookie.Name = "key"
	wantCookie.Value = "value"
	wantCookie.Expires = time.Now().Add(time.Hour)
	wantCookie.Domain = "DOM"
	wantCookie.HttpOnly = true
	wantCookie.Secure = true
	wantCookie.Path = "/abc"
	req.Header.Set("Cookie", wantCookie.String())
	t.Log("valid cookie:", wantCookie.Valid() == nil, wantCookie.String())

	var buf bytes.Buffer
	req.Write(&buf)
	var hdr Header
	msg := buf.Bytes()

	start := time.Now()
	err = hdr.ParseBytes(asRequest, msg)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\nparsed in %s\n\n", msg, elapsed.String())
	if string(hdr.Method()) != wantMethod {
		t.Errorf("want method %s, got %q", wantMethod, hdr.Method())
	}
	if !bytes.Equal(hdr.RequestURI(), []byte(wantURI)) {
		t.Errorf("want request URI %q, got %q", wantURI, hdr.RequestURI())
	}
	contentLength, _ := strconv.Atoi(string(hdr.Get("Content-Length")))
	if contentLength != len(wantMessage) {
		t.Errorf("want Content-Length %d, got %d", len(wantMessage), contentLength)
	}
	var c Cookie
	cookie := hdr.Get("Cookie")
	c.Reset(cookie)
	err = c.Parse()
	if err != nil {
		t.Error(err)
	}
	key := string(c.Name())
	if key != wantCookie.Name {
		t.Errorf("want cookie key %q, got %q", wantCookie.Name, key)
	}
	value := string(c.Value())
	if value != wantCookie.Value {
		t.Errorf("want cookie key %q, got %q", wantCookie.Value, value)
	}
	domain := string(c.Get("Domain"))
	if domain != wantCookie.Domain {
		t.Errorf("want domain %q, got %q", wantCookie.Domain, domain)
	}
	httpOnly := c.HasKeyOrSingleValue("HttpOnly")
	if httpOnly != wantCookie.HttpOnly {
		t.Errorf("want cookie HttpOnly %v, got %v", wantCookie.HttpOnly, httpOnly)
	}
	secure := c.HasKeyOrSingleValue("Secure")
	if secure != wantCookie.Secure {
		t.Errorf("want cookie HttpOnly %v, got %v", wantCookie.Secure, secure)
	}
	samesite := string(c.Get("SameSite"))
	if samesite != strSameSite(wantCookie.SameSite) {
		t.Errorf("want cookie SameSite %v, got %v", strSameSite(wantCookie.SameSite), samesite)
	}
	body, err := hdr.Body()
	if err != nil {
		t.Error(err)
	}
	if string(body) != wantMessage {
		t.Errorf("want body message %q, got %q", wantMessage, body)
	}
	cookieStr := string(c.AppendKeyValues(nil))
	if wantCookie.String() != cookieStr {
		t.Errorf("want full cookie representation\n%qgot:\n%q", wantCookie.String(), cookieStr)
	}
	data, _ := hdr.AppendRequest(nil)
	fmt.Printf("%s", data)
}

func BenchmarkParseBytes(b *testing.B) {
	b.StopTimer()
	const (
		wantMethod  = "GET"
		wantURI     = "/data/set"
		wantMessage = "hello world!"
		asRequest   = false
	)
	req, _ := http.NewRequest(wantMethod, wantURI, strings.NewReader(wantMessage))
	var rawBuf bytes.Buffer
	req.Write(&rawBuf)
	data := rawBuf.Bytes()

	// hdr is declared outside the loop so that ParseBytes can reuse the
	// backing arrays on Reset (headers slice and data buffer) without
	// allocating on every iteration. Declaring it inside the loop causes
	// two allocs per iteration: one for the headers slice (make in reset)
	// and one for the data buffer (append in readFromBytes).
	var hdr Header
	b.StartTimer()

	for b.Loop() {
		err := hdr.ParseBytes(asRequest, data)
		if err != nil {
			b.Fatal(err)
		}
		_, err = hdr.Body()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func strSameSite(mode http.SameSite) string {
	switch mode {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteDefaultMode:
		return ""
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		panic("invalid same site")
	}
}

func TestHeaderRequestPath(t *testing.T) {
	for _, test := range []struct {
		uri  string
		want string
	}{
		{uri: "/", want: "/"},
		{uri: "/search?q=go", want: "/search"},
		{uri: "/search?", want: "/search"},
		{uri: "/a/b/c?x=1&y=2", want: "/a/b/c"},
		{uri: "/?q=go", want: "/"},
	} {
		var h Header
		err := h.ParseBytes(false, []byte("GET "+test.uri+" HTTP/1.1\r\nHost: h\r\n\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		if got := string(h.RequestPath()); got != test.want {
			t.Errorf("uri %q: want path %q, got %q", test.uri, test.want, got)
		}
	}
}

func TestNextQueryPair(t *testing.T) {
	for _, test := range []struct {
		uri  string
		want string // "key=value" pairs joined by '|'; nil value shown as "key".
	}{
		{uri: "/", want: ""},
		{uri: "/x?", want: ""},
		{uri: "/x?q=go", want: "q=go"},
		{uri: "/x?q=go&n=1", want: "q=go|n=1"},
		{uri: "/x?debug&q=go", want: "debug|q=go"},   // No '=' yields a nil value.
		{uri: "/x?q=", want: "q="},                   // Empty but present value.
		{uri: "/x?&&q=go&", want: "q=go"},            // Empty sequences skipped.
		{uri: "/x?=v", want: "=v"},                   // Empty name is kept.
		{uri: "/x?a=1&a=2", want: "a=1|a=2"},         // Duplicates all yielded.
		{uri: "/x?a%20b=c%20d", want: "a%20b=c%20d"}, // Raw, undecoded.
		{uri: "/x?a=b=c", want: "a=b=c"},             // Only first '=' splits.
	} {
		var h Header
		err := h.ParseBytes(false, []byte("GET "+test.uri+" HTTP/1.1\r\nHost: h\r\n\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		rawkey, rawval, rest := NextQueryPair(h.RequestQuery())
		for rawkey != nil {
			if len(got) > 0 {
				got = append(got, '|')
			}
			got = append(got, rawkey...)
			if rawval != nil {
				got = append(got, '=')
				got = append(got, rawval...)
			}
			rawkey, rawval, rest = NextQueryPair(rest)
		}
		if string(got) != test.want {
			t.Errorf("uri %q: want %q, got %q", test.uri, test.want, got)
		}
	}
}

// A nil key ends iteration, and stopping early is just not looping again.
func TestNextQueryPairEnd(t *testing.T) {
	rawkey, rawval, rest := NextQueryPair([]byte("a=1&b=2"))
	if string(rawkey) != "a" || string(rawval) != "1" || string(rest) != "b=2" {
		t.Fatalf("want a=1 with rest b=2, got %q=%q rest %q", rawkey, rawval, rest)
	}
	rawkey, _, rest = NextQueryPair(rest)
	if string(rawkey) != "b" || len(rest) != 0 {
		t.Fatalf("want b with empty rest, got %q rest %q", rawkey, rest)
	}
	if rawkey, _, _ = NextQueryPair(rest); rawkey != nil {
		t.Fatalf("want nil key at end of query, got %q", rawkey)
	}
	// Trailing separators yield no pair rather than an empty one.
	if rawkey, _, _ = NextQueryPair([]byte("&&")); rawkey != nil {
		t.Fatalf("want nil key for empty sequences, got %q", rawkey)
	}
}

func TestHeaderNormalizeKey(t *testing.T) {
	var tests = []struct {
		key      string
		wantnorm string
	}{
		{key: "", wantnorm: ""},
		{key: "a-a-a", wantnorm: "A-A-A"},
		{key: "a-a-a-", wantnorm: "A-A-A-"},
		{key: "-", wantnorm: "-"},
		{key: "CONTENT", wantnorm: "Content"},
		{key: "cONTENT", wantnorm: "Content"},
		{key: "Content-Length", wantnorm: "Content-Length"},
		{key: "Content-length", wantnorm: "Content-Length"},
		{key: "content-length", wantnorm: "Content-Length"},
		{key: "conTent-lENgth", wantnorm: "Content-Length"},
		{key: "conTent-lENgth-", wantnorm: "Content-Length-"},
	}
	for _, test := range tests {
		gotKey := []byte(test.key)
		modified := NormalizeHeaderKey(gotKey)
		if string(gotKey) != test.wantnorm {
			t.Errorf("mismatch want %q got %q", test.wantnorm, gotKey)
		}
		wantMod := string(gotKey) != test.key
		if wantMod != modified {
			t.Errorf("mismatch want mod=%v, got mod=%v", wantMod, modified)
		}
	}
}

func TestCopyNormalizedHeaderValue(t *testing.T) {
	var tests = []struct {
		value    string
		wantnorm string
	}{
		{value: "abc\r\n\tdef\r\n\tghi", wantnorm: "abc def ghi"},
		{value: "abc\r\n\tabc", wantnorm: "abc abc"},
		{value: "abc\n\tdef\n\tghi", wantnorm: "abc def ghi"},
		{value: "abc\n\tdef\n\tghi\n\t", wantnorm: "abc def ghi "},
		{value: "abc\n\tdef\n\tghi\r\n\t", wantnorm: "abc def ghi "},
		{value: "", wantnorm: ""},
		{value: "abc", wantnorm: "abc"},
	}
	dst := make([]byte, 256)
	for _, test := range tests {
		value := []byte(test.value)
		n, modified := CopyNormalizedHeaderValue(dst[:len(value)], value)
		got := dst[:n]
		if string(got) != test.wantnorm {
			t.Errorf("mismatch want %q got %q", test.wantnorm, got)
		}
		wantMod := string(got) != test.value
		if wantMod != modified {
			t.Errorf("mismatch want mod=%v, got mod=%v", wantMod, modified)
		}
	}
}

func TestCopyDecodedPercentURL(t *testing.T) {
	var tests = []struct {
		value       string
		plusAsSpace bool
		want        string
		wantErr     bool
	}{
		{value: "", want: ""},
		{value: "/plain/path", want: "/plain/path"},
		{value: "/a%20b", want: "/a b"},
		{value: "%41%42%43", want: "ABC"},
		{value: "%2f%2F", want: "//"}, // lower and upper case hex digits.
		{value: "%25", want: "%"},     // escaped percent must not re-trigger decoding.
		{value: "%2525", want: "%25"}, // decoded output is not re-scanned.
		{value: "a+b", want: "a+b"},   // plus is literal in path segments.
		{value: "a+b", plusAsSpace: true, want: "a b"},
		{value: "%20+%20", plusAsSpace: true, want: "   "},
		{value: "/x?q=%E2%82%AC", want: "/x?q=\xe2\x82\xac"}, // multi-byte UTF-8 sequence.
		// Malformed escapes must error, never pass through silently.
		{value: "%zz", want: "", wantErr: true},
		{value: "ok%4", want: "ok", wantErr: true}, // truncated escape at end.
		{value: "ok%", want: "ok", wantErr: true},  // bare percent at end.
		{value: "a%2gb", want: "a", wantErr: true}, // second digit not hex.
		{value: "a%g2b", want: "a", wantErr: true}, // first digit not hex.
	}
	dst := make([]byte, 256)
	for _, test := range tests {
		value := []byte(test.value)
		n, err := CopyDecodedPercentURL(dst[:len(value)], value, test.plusAsSpace)
		if test.wantErr && err == nil {
			t.Errorf("%q: want error, got nil", test.value)
		} else if !test.wantErr && err != nil {
			t.Errorf("%q: unexpected error %s", test.value, err)
		}
		if got := string(dst[:n]); got != test.want {
			t.Errorf("%q: want %q got %q", test.value, test.want, got)
		}
		// n<len(value) implies percent-escapes were decoded. The converse does not
		// hold: '+'->' ' substitution preserves length.
		if !test.wantErr && n < len(test.value) && test.want == test.value {
			t.Errorf("%q: n=%d signals decoding but value unchanged", test.value, n)
		}
		if !test.wantErr && !test.plusAsSpace && test.want != test.value && n >= len(test.value) {
			t.Errorf("%q: n=%d does not signal decoding of %q", test.value, n, test.want)
		}
	}
}

// In-place decoding (dst aliasing value at offset 0) must yield the same result.
func TestCopyDecodedPercentURLInPlace(t *testing.T) {
	const value, want = "/a%20b%2Fc%25", "/a b/c%"
	buf := []byte(value)
	n, err := CopyDecodedPercentURL(buf, buf, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("want %q got %q", want, got)
	}
}

func TestHeaderSetOverwrite(t *testing.T) {
	var h Header
	h.Reset(nil)
	h.SetMethod("GET")
	h.SetRequestURI("/")
	h.SetProtocol("HTTP/1.1")

	h.Set("Host", "first.example.com")
	h.Set("Host", "second.example.com")

	got := string(h.Get("Host"))
	if got != "second.example.com" {
		t.Errorf("want Host %q, got %q", "second.example.com", got)
	}
	req, err := h.AppendRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(req), "Host:"); n != 1 {
		t.Errorf("want 1 Host field in request, got %d:\n%s", n, req)
	}
}

func TestHeaderSetBytesEmptyValue(t *testing.T) {
	var h Header
	h.Reset(nil)
	h.SetBytes("X-Empty", nil)
	if got := h.Get("X-Empty"); len(got) != 0 {
		t.Errorf("want empty value, got %q", got)
	}
}

// buffer/offset past uint16 range silently corrupts or panics.
// A header block > 64KiB pushes a field's offset past 65535. tokint truncation
// makes Get return the wrong window (silent corruption) or panic on slice bounds.
func TestHeader_LargeBufferOverflow(t *testing.T) {
	const wantVal = "the-canary-value"
	// Pad with a big header so the canary field lands past offset 65535.
	pad := strings.Repeat("x", 70000)
	raw := "GET / HTTP/1.1\r\n" +
		"X-Pad: " + pad + "\r\n" +
		"X-Canary: " + wantVal + "\r\n" +
		"\r\n"

	var h Header
	err := h.ParseBytes(false, []byte(raw))
	if err != nil {
		// Clean rejection of the oversized header is the intended behavior:
		// no panic, no silent corruption.
		return
	}
	// If it did parse, the value must be correct (never a truncated-offset window).
	got := string(h.Get("X-Canary"))
	if got != wantVal {
		t.Fatalf("overflow corruption: want X-Canary %q, got %q", wantVal, got)
	}
}

// a complete but malformed header line with no colon must be a hard error,
// not errNeedMore (which makes a streaming parser wait forever).
func TestHeader_ColonlessLineIsHardError(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n"
	var h Header
	err := h.ParseBytes(false, []byte(raw))
	if err == nil {
		t.Fatal("want error on colonless header line, got nil")
	}
	if err == errNeedMore {
		t.Fatalf("colonless line reported as errNeedMore (parser would hang); want a hard error like errInvalidName")
	}
}

// Regression for a TCP split landing BEFORE the colon (no newline yet) must
// stay "need more data" and parse once the rest arrives. This is the case the
// Colonless fix must NOT turn into a hard error.
func TestHeader_SplitBeforeColonStillParses(t *testing.T) {
	const part1 = "GET / HTTP/1.1\r\nHost" // split mid-key, before colon+newline
	const part2 = ": example.com\r\n\r\n"

	var h Header
	h.Reset(nil)
	if _, err := h.ReadFromBytes([]byte(part1)); err != nil {
		t.Fatal(err)
	}
	needMore, err := h.TryParse(false)
	if err != nil && err != errNeedMore {
		t.Fatalf("split before colon: want errNeedMore/nil, got %v", err)
	}
	if !needMore {
		t.Fatal("want needMoreData=true after partial input")
	}

	if _, err := h.ReadFromBytes([]byte(part2)); err != nil {
		t.Fatal(err)
	}
	needMore, err = h.TryParse(false)
	if err != nil {
		t.Fatalf("after full input: %v", err)
	}
	if needMore {
		t.Fatal("want needMoreData=false after full input")
	}
	if got := string(h.Get("Host")); got != "example.com" {
		t.Fatalf("want Host %q, got %q", "example.com", got)
	}
}

// appendHeader must reserve the +1 byte that mustAppendSlice consumes on an
// empty buffer. Force cap == len(key)+len(value) to defeat allocator rounding.
func TestHeader_AppendHeaderExactCapNoPanic(t *testing.T) {
	const key, value = "K", "V"
	buf := make([]byte, 0, len(key)+len(value)) // exact cap, no slack.
	var h Header
	h.Reset(buf)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("appendHeader panicked on exact-cap buffer: %v", r)
		}
	}()
	h.Add(key, value)
	if got := string(h.Get(key)); got != value {
		t.Fatalf("want %q, got %q", value, got)
	}
}

// Add/Set on a full buffer with growth disabled must drop gracefully (flag OOM),
// never panic. Panicking is unacceptable for this package.
func TestHeader_AddFullBufferNoPanic(t *testing.T) {
	buf := make([]byte, 0, 40) // Small cap; enough for Reset (len 0) but not the field below.
	var h Header
	h.Reset(buf)
	h.EnableBufferGrowth(false)
	h.SetMethod("GET")
	h.SetRequestURI("/")
	h.SetProtocol("HTTP/1.1")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Add on full no-grow buffer panicked: %v", r)
		}
	}()
	h.Add("X-Very-Long-Header-Key", "a-value-that-cannot-possibly-fit-in-the-buffer")

	// Graceful drop: request marshalling reports OOM instead of emitting bad data.
	if _, err := h.AppendRequest(nil); err == nil {
		t.Fatal("want OOM error after dropped Add, got nil")
	}
}

func TestHeader_SetInt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value int64
		base  int
		want  string
	}{
		{"decimal", 1234, 10, "1234"},
		{"zero", 0, 10, "0"},
		{"negative", -42, 10, "-42"},
		{"maxint64", 9223372036854775807, 10, "9223372036854775807"},
		{"minint64", -9223372036854775808, 10, "-9223372036854775808"},
		{"hex", 255, 16, "ff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h Header
			h.Reset(nil)
			h.SetInt("Content-Length", tc.value, tc.base)
			if got := string(h.Get("Content-Length")); got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}

// SetInt on an existing key must reuse the slot in place (single field, latest value).
func TestHeader_SetIntOverwrite(t *testing.T) {
	var h Header
	h.Reset(nil)
	h.SetMethod("GET")
	h.SetRequestURI("/")
	h.SetProtocol("HTTP/1.1")

	h.SetInt("Content-Length", 100, 10)
	h.SetInt("Content-Length", 5, 10) // shorter, must fit in old slot.

	if got := string(h.Get("Content-Length")); got != "5" {
		t.Fatalf("want Content-Length %q, got %q", "5", got)
	}
	req, err := h.AppendRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(req), "Content-Length:"); n != 1 {
		t.Errorf("want 1 Content-Length field, got %d:\n%s", n, req)
	}
}

// SetInt must not heap-allocate: it must format directly into the header buffer.
func TestHeader_SetIntNoAlloc(t *testing.T) {
	buf := make([]byte, 0, 256)
	var h Header
	h.Reset(buf)
	h.EnableBufferGrowth(false)
	h.Add("Content-Length", "0000000000000000000000") // pre-size a reusable slot.
	allocs := testing.AllocsPerRun(100, func() {
		h.SetInt("Content-Length", 1234567890, 10)
	})
	if allocs != 0 {
		t.Fatalf("SetInt allocated %v times, want 0", allocs)
	}
	if got := string(h.Get("Content-Length")); got != "1234567890" {
		t.Fatalf("want %q, got %q", "1234567890", got)
	}
}
