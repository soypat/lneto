package httpraw

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/soypat/lneto"
)

func TestTryParse_IncrementalRequest(t *testing.T) {
	// Full HTTP request split across multiple ReadFromBytes calls.
	full := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/html\r\n\r\nbody here"
	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 256), defaultKVCap)

	// Feed data in small chunks to exercise incremental parsing.
	chunks := splitInto(full, 10)
	var done bool
	var doneIdx int
	for i, chunk := range chunks {
		err := hdr.ReadFromBytes([]byte(chunk))
		if err != nil {
			t.Fatalf("ReadFromBytes: %v", err)
		}

		var needMore bool
		needMore, err = hdr.TryParse(false)
		if err != nil && needMore {
			continue // need more data
		}
		if err != nil {
			t.Fatalf("TryParse: %v", err)
		}
		done = !needMore
		doneIdx = i
		break
	}

	if !done {
		t.Fatal("header parsing did not complete")
	}
	// Feed remaining chunks so body is complete.
	for _, chunk := range chunks[doneIdx+1:] {
		hdr.ReadFromBytes([]byte(chunk))
	}
	if !hdr.ParsingSuccess() {
		t.Fatal("ParsingSuccess should be true")
	}

	if string(hdr.Method()) != "GET" {
		t.Errorf("method = %q; want GET", hdr.Method())
	}
	if string(hdr.RequestTarget()) != "/index.html" {
		t.Errorf("URI = %q; want /index.html", hdr.RequestTarget())
	}

	// Verify headers via ForEach.
	headers := make(map[string]string)
	hdr.ForEach(func(key, value []byte) bool {
		headers[string(key)] = string(value)
		return true
	})
	if headers["Host"] != "example.com" {
		t.Errorf("Host = %q; want example.com", headers["Host"])
	}
	if headers["Content-Type"] != "text/html" {
		t.Errorf("Content-Type = %q; want text/html", headers["Content-Type"])
	}

	// Verify body is accessible.
	body, err := hdr.Body()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "body here" {
		t.Errorf("body = %q; want %q", body, "body here")
	}
}

func TestTryParse_IncrementalResponse(t *testing.T) {
	full := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nServer: lneto\r\n\r\nhello"
	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 256), defaultKVCap)

	chunks := splitInto(full, 8)
	var done bool
	var doneIdx int
	for i, chunk := range chunks {
		hdr.ReadFromBytes([]byte(chunk))
		needMore, err := hdr.TryParse(true)
		if err != nil && needMore {
			continue
		}
		if err != nil {
			t.Fatalf("TryParse response: %v", err)
		}
		done = !needMore
		doneIdx = i
		break
	}

	if !done {
		t.Fatal("response parsing did not complete")
	}
	for _, chunk := range chunks[doneIdx+1:] {
		hdr.ReadFromBytes([]byte(chunk))
	}

	code, text := hdr.Status()
	if string(code) != "200" {
		t.Errorf("status code = %q; want 200", code)
	}
	if !bytes.Contains(text, []byte("OK")) {
		t.Errorf("status text = %q; want to contain OK", text)
	}

	if string(hdr.Get("Server")) != "lneto" {
		t.Errorf("Server header = %q; want lneto", hdr.Get("Server"))
	}

	body, err := hdr.Body()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q; want hello", body)
	}
}

func TestReadFromLimited(t *testing.T) {
	data := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
	r := strings.NewReader(data)

	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 256), defaultKVCap)

	// Read in one shot.
	n, err := hdr.ReadFromLimited(r, 256)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("expected %d bytes, got %d", len(data), n)
	}

	if hdr.BufferReceived() != len(data) {
		t.Errorf("BufferReceived = %d; want %d", hdr.BufferReceived(), len(data))
	}

	err = hdr.Parse(false)
	if err != nil {
		t.Fatal(err)
	}
	if string(hdr.Method()) != "GET" {
		t.Errorf("method = %q; want GET", hdr.Method())
	}
}

func TestReadFromLimited_MaxBytes(t *testing.T) {
	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 256), defaultKVCap)

	// Zero maxBytesToRead should error.
	_, err := hdr.ReadFromLimited(strings.NewReader("data"), 0)
	if err == nil {
		t.Fatal("expected error for maxBytesToRead=0")
	}
}

func TestReadFromBytes_Empty(t *testing.T) {
	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 256), defaultKVCap)

	err := hdr.ReadFromBytes(nil)
	if err == nil {
		t.Fatal("expected error for empty bytes")
	}
}

func TestBufferFreeAndCapacity(t *testing.T) {
	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 100), defaultKVCap)

	if hdr.BufferCapacity() != 100 {
		t.Errorf("capacity = %d; want 100", hdr.BufferCapacity())
	}
	if hdr.BufferFree() != 100 {
		t.Errorf("free = %d; want 100", hdr.BufferFree())
	}

	hdr.ReadFromBytes([]byte("1234567890"))
	if hdr.BufferFree() != 90 {
		t.Errorf("free after read = %d; want 90", hdr.BufferFree())
	}
}

func TestEnableBufferGrowth(t *testing.T) {
	var hdr HeaderV1
	buf := make([]byte, 0, 64)
	hdr.Reset(buf, defaultKVCap)
	hdr.ConfigBufferGrowth(false)
	// With growth disabled, reading more than capacity should fail.
	big := make([]byte, 128)
	for i := range big {
		big[i] = 'A'
	}
	err := hdr.ReadFromBytes(big)
	if err == nil {
		t.Fatal("expected error when buffer growth disabled and data exceeds capacity")
	}
}

func TestHeader_Add(t *testing.T) {
	full := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(false, []byte(full))
	if err != nil {
		t.Fatal(err)
	}

	hdr.Add("X-Custom", "value1")
	hdr.Add("X-Custom", "value2")

	// ForEach should find both.
	var values []string
	hdr.ForEach(func(key, value []byte) bool {
		if string(key) == "X-Custom" {
			values = append(values, string(value))
		}
		return true
	})
	if len(values) != 2 {
		t.Fatalf("expected 2 X-Custom headers, got %d", len(values))
	}
	if values[0] != "value1" || values[1] != "value2" {
		t.Errorf("values = %v; want [value1 value2]", values)
	}
}

func TestHeader_SetBytes(t *testing.T) {
	full := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(false, []byte(full))
	if err != nil {
		t.Fatal(err)
	}

	hdr.SetBytes("X-Data", []byte("binary-value"))
	got := hdr.Get("X-Data")
	if string(got) != "binary-value" {
		t.Errorf("X-Data = %q; want binary-value", got)
	}
}

func TestConnectionClose(t *testing.T) {
	t.Run("HTTP11_NoConnectionHeader", func(t *testing.T) {
		full := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
		var hdr HeaderV1
		hdr.ParseBytes(false, []byte(full))
		if hdr.ConnectionClose() {
			t.Error("HTTP/1.1 without Connection:close should not close")
		}
	})

	t.Run("ExplicitClose", func(t *testing.T) {
		full := "GET / HTTP/1.1\r\nConnection: close\r\nHost: test\r\n\r\n"
		var hdr HeaderV1
		hdr.ParseBytes(false, []byte(full))
		if !hdr.ConnectionClose() {
			t.Error("Connection:close header should trigger close")
		}
	})

	t.Run("HTTP10_NoKeepAlive", func(t *testing.T) {
		full := "GET / HTTP/1.0\r\nHost: test\r\n\r\n"
		var hdr HeaderV1
		hdr.ParseBytes(false, []byte(full))
		if !hdr.ConnectionClose() {
			t.Error("HTTP/1.0 without keep-alive should close")
		}
	})

	t.Run("HTTP10_KeepAlive", func(t *testing.T) {
		full := "GET / HTTP/1.0\r\nConnection: keep-alive\r\nHost: test\r\n\r\n"
		var hdr HeaderV1
		hdr.ParseBytes(false, []byte(full))
		if hdr.ConnectionClose() {
			t.Error("HTTP/1.0 with keep-alive should not close")
		}
	})
}

func TestTryParse_AlreadyParsed(t *testing.T) {
	full := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
	var hdr HeaderV1
	hdr.ParseBytes(false, []byte(full))

	// Calling TryParse again should return error.
	_, err := hdr.TryParse(false)
	if err == nil {
		t.Fatal("TryParse after completed parse should error")
	}
}

func TestParseResponse_BadStatusCode(t *testing.T) {
	full := "HTTP/1.1 abc Bad\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(true, []byte(full))
	if err == nil {
		t.Fatal("expected error for non-numeric status code")
	}
}

func TestCookie_ParseBytes(t *testing.T) {
	var c Cookie
	err := c.ParseBytes([]byte("session=abc123; Path=/; Secure"))
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Name()) != "session" {
		t.Errorf("name = %q; want session", c.Name())
	}
	if string(c.Value()) != "abc123" {
		t.Errorf("value = %q; want abc123", c.Value())
	}
	if string(c.Get("Path")) != "/" {
		t.Errorf("Path = %q; want /", c.Get("Path"))
	}
	// The first pair sits at buffer offset 0, which a presence check keyed on
	// the offset rather than the length reads as absent.
	if string(c.Get("session")) != "abc123" {
		t.Errorf("Get(session) = %q; want abc123", c.Get("session"))
	}
	if !c.HasKeyOrSingleValue("session") {
		t.Error("expected first pair to be present by key")
	}
	if !c.HasKeyOrSingleValue("Secure") {
		t.Error("expected Secure flag")
	}
}

func TestCookie_CopyFrom(t *testing.T) {
	var src Cookie
	src.ParseBytes([]byte("key=val; HttpOnly"))

	var dst Cookie
	dst.CopyFrom(src)

	if string(dst.Name()) != "key" {
		t.Errorf("copied name = %q; want key", dst.Name())
	}
	if string(dst.Value()) != "val" {
		t.Errorf("copied value = %q; want val", dst.Value())
	}
}

func TestCookie_ForEach(t *testing.T) {
	var c Cookie
	c.ParseBytes([]byte("a=1; b=2; c=3"))

	var keys []string
	c.ForEach(func(key, value []byte) bool {
		keys = append(keys, string(key))
		return true
	})
	if len(keys) != 3 {
		t.Fatalf("expected 3 cookie entries, got %d", len(keys))
	}
}

func TestHeader_MultilineValue(t *testing.T) {
	// RFC 7230: obsolete line folding with \r\n followed by space/tab.
	full := "GET / HTTP/1.1\r\nX-Multi: line1\r\n\tline2\r\nHost: test\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(false, []byte(full))
	if err != nil {
		t.Fatal(err)
	}
	val := hdr.Get("X-Multi")
	if val == nil {
		t.Fatal("X-Multi header not found")
	}
	// Value should contain both lines (raw, before normalization).
	if !bytes.Contains(val, []byte("line1")) {
		t.Error("missing line1 in multiline value")
	}
}

func TestHeader_ResponseRoundTrip(t *testing.T) {
	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 256), defaultKVCap)
	hdr.SetProtocol("HTTP/1.1")
	hdr.SetStatus("404", "Not Found")
	hdr.Add("Content-Type", "text/plain")

	buf, err := hdr.AppendResponse(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := string(buf)
	if !strings.Contains(resp, "HTTP/1.1") {
		t.Errorf("response missing protocol: %s", resp)
	}
	if !strings.Contains(resp, "404") {
		t.Errorf("response missing status code: %s", resp)
	}
	if !strings.Contains(resp, "Not Found") {
		t.Errorf("response missing status text: %s", resp)
	}
	if !strings.Contains(resp, "Content-Type: text/plain") {
		t.Errorf("response missing header: %s", resp)
	}

	// Parse back the generated response.
	var hdr2 HeaderV1
	err = hdr2.ParseBytes(true, buf)
	if err != nil {
		t.Fatalf("re-parse response: %v", err)
	}
	code, text := hdr2.Status()
	if string(code) != "404" {
		t.Errorf("re-parsed code = %q; want 404", code)
	}
	if string(text) != "Not Found" {
		t.Errorf("re-parsed text = %q; want Not Found", text)
	}
}

func TestHeader_RequestRoundTrip(t *testing.T) {
	var hdr HeaderV1
	hdr.Reset(make([]byte, 0, 256), defaultKVCap)
	hdr.SetProtocol("HTTP/1.1")
	hdr.SetMethod("POST")
	hdr.SetRequestTarget("/api/data")
	hdr.Add("Host", "example.com")
	hdr.Add("Content-Type", "application/json")

	buf, err := hdr.AppendRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	req := string(buf)
	if !strings.HasPrefix(req, "POST /api/data HTTP/1.1\r\n") {
		t.Errorf("unexpected request line: %s", req)
	}

	// Parse back the generated request.
	var hdr2 HeaderV1
	err = hdr2.ParseBytes(false, buf)
	if err != nil {
		t.Fatalf("re-parse request: %v", err)
	}
	if string(hdr2.Method()) != "POST" {
		t.Errorf("re-parsed method = %q; want POST", hdr2.Method())
	}
	if string(hdr2.RequestTarget()) != "/api/data" {
		t.Errorf("re-parsed URI = %q; want /api/data", hdr2.RequestTarget())
	}
	if string(hdr2.Get("Host")) != "example.com" {
		t.Errorf("re-parsed Host = %q; want example.com", hdr2.Get("Host"))
	}
}

func TestParseResponse_StatusCodeOnly(t *testing.T) {
	// Response with status code but no status text.
	full := "HTTP/1.1 204\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(true, []byte(full))
	if err != nil {
		t.Fatal(err)
	}
	code, text := hdr.Status()
	if string(code) != "204" {
		t.Errorf("code = %q; want 204", code)
	}
	_ = text // Text may be empty, that's OK.
}

func TestParseResponse_HTTP10(t *testing.T) {
	full := "HTTP/1.0 200 OK\r\nServer: old\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(true, []byte(full))
	if err != nil {
		t.Fatal(err)
	}
	code, _ := hdr.Status()
	if string(code) != "200" {
		t.Errorf("code = %q; want 200", code)
	}
	if !hdr.ConnectionClose() {
		t.Error("HTTP/1.0 response should default to connection close")
	}
}

func TestParseRequest_NoProtocol(t *testing.T) {
	// HTTP/0.9 style: just method and URI, no version. Refused, but the
	// request-line it did read stays readable so a caller can answer 400 and say
	// what it saw.
	full := "GET /simple\r\nHost: test\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(false, []byte(full))
	if !errors.Is(err, lneto.ErrUnsupported) {
		t.Fatalf("want lneto.ErrUnsupported for a version-less request, got %v", err)
	}
	if string(hdr.Method()) != "GET" {
		t.Errorf("method = %q; want GET", hdr.Method())
	}
	if string(hdr.RequestTarget()) != "/simple" {
		t.Errorf("URI = %q; want /simple", hdr.RequestTarget())
	}
	// An empty protocol is what tells HTTP/0.9 apart from a named version, which
	// is how [httphi] picks 400 over 505.
	if hdr.Protocol() != nil {
		t.Errorf("protocol should be nil for version-less request, got %q", hdr.Protocol())
	}
}

func TestCookie_QuotedValue(t *testing.T) {
	var c Cookie
	c.ParseBytes([]byte("token=\"abc123\""))
	if string(c.Value()) != "abc123" {
		t.Errorf("quoted value = %q; want abc123", c.Value())
	}
}

func TestParseRequest_InvalidHeaderSpaceBeforeColon(t *testing.T) {
	// RFC 7230 §3.2.4: No whitespace allowed between header name and colon.
	full := "GET / HTTP/1.1\r\nBad Header : value\r\n\r\n"
	var hdr HeaderV1
	err := hdr.ParseBytes(false, []byte(full))
	if err == nil {
		t.Fatal("expected error for space before colon in header name")
	}
}

func splitInto(s string, n int) []string {
	var chunks []string
	for len(s) > 0 {
		end := min(n, len(s))
		chunks = append(chunks, s[:end])
		s = s[end:]
	}
	return chunks
}

// Connection is a case-insensitive list of case-insensitive tokens, RFC 9110
// 7.6.1, and its field name folds like any other, RFC 9110 5.1. Missing a close
// token keeps serving a peer that asked to hang up; missing keep-alive hangs up
// on an HTTP/1.0 peer that asked to stay.
func TestConnectionCloseFolded(t *testing.T) {
	for _, test := range []struct {
		proto     string
		field     string
		wantClose bool
	}{
		{proto: "HTTP/1.1", field: "Connection: close", wantClose: true},
		{proto: "HTTP/1.1", field: "connection: close", wantClose: true},
		{proto: "HTTP/1.1", field: "CONNECTION: close", wantClose: true},
		{proto: "HTTP/1.1", field: "Connection: Close", wantClose: true},
		{proto: "HTTP/1.1", field: "Connection: CLOSE", wantClose: true},
		{proto: "HTTP/1.1", field: "Connection: keep-alive, close", wantClose: true},
		{proto: "HTTP/1.1", field: "Connection: close, keep-alive", wantClose: true},
		{proto: "HTTP/1.1", field: "Connection: TE, Close", wantClose: true},
		// A token that merely contains "close" is not the close token.
		{proto: "HTTP/1.1", field: "Connection: closed", wantClose: false},
		{proto: "HTTP/1.1", field: "Connection: keep-alive", wantClose: false},
		// HTTP/1.0 closes unless the peer asks to keep the connection.
		{proto: "HTTP/1.0", field: "Connection: keep-alive", wantClose: false},
		{proto: "HTTP/1.0", field: "connection: keep-alive", wantClose: false},
		{proto: "HTTP/1.0", field: "Connection: Keep-Alive", wantClose: false},
		{proto: "HTTP/1.0", field: "Connection: TE, keep-alive", wantClose: false},
		{proto: "HTTP/1.0", field: "Host: h", wantClose: true},
	} {
		t.Run(test.proto+" "+test.field, func(t *testing.T) {
			var hdr HeaderV1
			full := "GET / " + test.proto + "\r\nHost: h\r\n" + test.field + "\r\n\r\n"
			if err := hdr.ParseBytes(false, []byte(full)); err != nil {
				t.Fatal(err)
			}
			if got := hdr.ConnectionClose(); got != test.wantClose {
				t.Errorf("want ConnectionClose=%v, got %v", test.wantClose, got)
			}
		})
	}
}

// HeaderV1 speaks HTTP/1.x and nothing else, so a request or response naming
// another version is refused on the first line. That skips the field loop, which
// is where nearly all the parse cost is, and refuses the h2c preface a modern
// client opens with before it is mistaken for a request.
func TestHeaderV1RejectsUnsupportedVersion(t *testing.T) {
	for _, test := range []struct {
		name       string
		raw        string
		asResponse bool
	}{
		{name: "request http2", raw: "GET / HTTP/2.0\r\nHost: h\r\n\r\n"},
		{name: "request http3", raw: "GET / HTTP/3.0\r\nHost: h\r\n\r\n"},
		{name: "h2c preface", raw: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
		{name: "request http09 no version", raw: "GET /index.html\r\nHost: h\r\n\r\n"},
		{name: "request bogus proto", raw: "GET / BANANA\r\nHost: h\r\n\r\n"},
		{name: "response http2", raw: "HTTP/2.0 200 OK\r\nServer: s\r\n\r\n", asResponse: true},
		{name: "response http09", raw: "HTTP/0.9 200 OK\r\nServer: s\r\n\r\n", asResponse: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var h HeaderV1
			err := h.ParseBytes(test.asResponse, []byte(test.raw))
			if !errors.Is(err, lneto.ErrUnsupported) {
				t.Fatalf("want lneto.ErrUnsupported, got %v", err)
			}
			// The field loop must not have run: refusing early is the point.
			fields := 0
			h.ForEach(func(key, value []byte) bool { fields++; return true })
			if fields != 0 {
				t.Errorf("want no fields parsed, got %d", fields)
			}
			if h.ParsingSuccess() {
				t.Error("a refused header must not report a successful parse")
			}
		})
	}
}

// Both HTTP/1 versions stay supported: only non-1.x is refused.
func TestHeaderV1AcceptsV1Versions(t *testing.T) {
	for _, test := range []struct {
		raw        string
		asResponse bool
	}{
		{raw: "GET / HTTP/1.1\r\nHost: h\r\n\r\n"},
		{raw: "GET / HTTP/1.0\r\nHost: h\r\n\r\n"},
		{raw: "HTTP/1.1 200 OK\r\nServer: s\r\n\r\n", asResponse: true},
		{raw: "HTTP/1.0 200 OK\r\nServer: s\r\n\r\n", asResponse: true},
	} {
		t.Run(test.raw[:12], func(t *testing.T) {
			var h HeaderV1
			if err := h.ParseBytes(test.asResponse, []byte(test.raw)); err != nil {
				t.Fatalf("want parsed, got %v", err)
			}
			if !h.ParsingSuccess() {
				t.Error("want a successful parse")
			}
		})
	}
}
