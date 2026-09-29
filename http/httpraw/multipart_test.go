package httpraw

import (
	"io"
	"strconv"
	"strings"
	"testing"
)

// A two part body: a text field and a PNG upload whose bytes contain CRLFs and
// even the boundary text, which must not desync the parser.
const (
	multiBoundary = "----abc123"
	multiBody     = "------abc123\r\n" +
		"Content-Disposition: form-data; name=\"caption\"\r\n" +
		"\r\n" +
		"hi there\r\n" +
		"------abc123\r\n" +
		"Content-Disposition: form-data; name=\"photo\"; filename=\"beach.png\"\r\n" +
		"Content-Type: image/png\r\n" +
		"\r\n" +
		"\x89PNG\r\n--not-the-boundary\r\n\x00\xff\r\n" +
		"------abc123--\r\n"
)

func TestMultipartBoundary(t *testing.T) {
	var mp Multipart
	for _, test := range []struct {
		contentType string
		want        string
		wantErr     bool
	}{
		{contentType: "multipart/form-data; boundary=abc123", want: "abc123"},
		{contentType: "multipart/form-data; boundary=\"a b\"", want: "a b"},
		{contentType: "multipart/form-data; charset=utf-8; boundary=xyz", want: "xyz"},
		{contentType: "multipart/form-data; BOUNDARY=xyz", want: "xyz"},   // Keys are case insensitive.
		{contentType: "multipart/form-data", wantErr: true},               // Absent, RFC 2046 5.1.1 requires it.
		{contentType: "application/x-www-form-urlencoded", wantErr: true}, // Not multipart at all.
		{contentType: "multipart/form-data; boundary=", wantErr: true},    // Empty matches every "--".
	} {
		err := mp.SetContentType([]byte(test.contentType))
		if test.wantErr {
			if err == nil {
				t.Errorf("%q: want error, got boundary %q", test.contentType, mp.Boundary)
			}
			continue
		} else if err != nil {
			t.Errorf("%q: %s", test.contentType, err)
			continue
		}
		got := string(mp.Boundary)
		if got != test.want {
			t.Errorf("%q: want %q, got %q", test.contentType, test.want, got)
		}
	}
}

func TestMediaTypeIs(t *testing.T) {
	for _, test := range []struct {
		value string
		media string
		want  bool
	}{
		{value: "text/plain", media: "text/plain", want: true},
		{value: "text/plain; charset=utf-8", media: "text/plain", want: true},
		{value: "text/plain;charset=utf-8", media: "text/plain", want: true},
		{value: "Text/Plain", media: "text/plain", want: true}, // Case insensitive, RFC 9110 8.3.1.
		{value: " text/plain ; x=1", media: "text/plain", want: true},
		{value: "text/plain", media: "text/html"},
		{value: "text/plainish", media: "text/plain"}, // Prefix must not match.
		{value: "", media: "text/plain"},
		{value: "multipart/form-data; boundary=abc", media: "multipart/form-data", want: true},
	} {
		if got := MediaTypeIs([]byte(test.value), test.media); got != test.want {
			t.Errorf("%q is %q: want %v, got %v", test.value, test.media, test.want, got)
		}
	}
}

func TestContentParam(t *testing.T) {
	for _, test := range []struct {
		value string
		key   string
		want  string
	}{
		{value: "text/plain; charset=utf-8", key: "charset", want: "utf-8"},
		{value: "text/plain;charset=utf-8", key: "charset", want: "utf-8"}, // No space.
		{value: "text/plain; charset=\"utf-8\"", key: "charset", want: "utf-8"},
		{value: "form-data; name=\"photo\"; filename=\"a;b.png\"", key: "filename", want: "a;b.png"},
		{value: "form-data; name=\"photo\"", key: "nope", want: ""},
		{value: "form-data; names=x; name=y", key: "name", want: "y"}, // Prefix must not match.
		{value: "text/plain", key: "charset", want: ""},
	} {
		got := ContentParam([]byte(test.value), test.key)
		if string(got) != test.want {
			t.Errorf("%q key %q: want %q, got %q", test.value, test.key, test.want, got)
		}
	}
}

func TestNextPartHeader(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	var hdr MultipartHeader
	parsed, err := m.NextHeader(&hdr, []byte(multiBody))
	if err != nil {
		t.Fatal(err)
	}
	const wantHdr = "Content-Disposition: form-data; name=\"caption\"\r\n"
	if string(hdr.PartView) != wantHdr {
		t.Errorf("want header %q, got %q", wantHdr, hdr.PartView)
	}
	if string(hdr.Name) != "caption" {
		t.Errorf("want name %q, got %q", "caption", hdr.Name)
	}
	if len(hdr.Filename) != 0 {
		t.Errorf("want no filename for a non file part, got %q", hdr.Filename)
	}
	if !strings.HasPrefix(multiBody[parsed:], "hi there\r\n") {
		t.Errorf("want rest at part body, got %q", multiBody[parsed:])
	}
}

// Names and filenames must outlive the buffer they were parsed from, so a
// caller may compact it and read more without losing the part it is reading.
func TestNextPartHeaderOutlivesBuffer(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	data := []byte(multiBody)
	var hdr MultipartHeader
	if _, err := m.NextHeader(&hdr, data); err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 'x' // Buffer reused for the next read.
	}
	if string(hdr.Name) != "caption" {
		t.Errorf("want name %q to survive the buffer, got %q", "caption", hdr.Name)
	}
}

// Incomplete data must ask for more, never guess.
func TestNextPartHeaderNeedMore(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	for _, data := range []string{
		"",
		"------abc",        // Delimiter cut short.
		"------abc123\r\n", // No header block yet.
		"------abc123\r\nContent-Disposition: form-", // Header block unterminated.
	} {
		var hdr MultipartHeader
		parsed, err := m.NextHeader(&hdr, []byte(data))
		if parsed != 0 || err != nil {
			t.Errorf("%q: want (0, nil) asking for more data, got (%d, %v)", data, parsed, err)
		}
	}
}

// Junk between the delimiter and the part header is a multipart framing error,
// not a header field name error.
func TestNextPartHeaderJunk(t *testing.T) {
	m := Multipart{Boundary: []byte("abc")}
	var hdr MultipartHeader
	if _, err := m.NextHeader(&hdr, []byte("--abcX\r\nA: b\r\n\r\n")); err != errBadDelimiter {
		t.Errorf("want errBadDelimiter, got %v", err)
	}
}

// The closing delimiter ends iteration.
func TestNextPartHeaderEnd(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	var hdr MultipartHeader
	if _, err := m.NextHeader(&hdr, []byte("------abc123--\r\n")); err != io.EOF {
		t.Errorf("want io.EOF, got %v", err)
	}
}

func TestNextPartBody(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	var hdr MultipartHeader
	parsed, err := m.NextHeader(&hdr, []byte(multiBody))
	if err != nil {
		t.Fatal(err)
	}
	rest := multiBody[parsed:]
	bodyLen, restOff, done := m.NextBody([]byte(rest))
	if !done {
		t.Fatal("want the part to end within the buffer")
	}
	if rest[:bodyLen] != "hi there" {
		t.Errorf("want body %q, got %q", "hi there", rest[:bodyLen])
	}
	if !strings.HasPrefix(rest[restOff:], "------abc123\r\n") {
		t.Errorf("want rest at next delimiter, got %q", rest[restOff:])
	}
}

// A part whose bytes contain CRLFs and boundary-like text must survive intact.
func TestNextPartBodyBinary(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	rest := []byte(multiBody)
	var hdr MultipartHeader
	parsed, err := m.NextHeader(&hdr, rest) // caption part.
	if err != nil {
		t.Fatal(err)
	}
	_, restOff, _ := m.NextBody(rest[parsed:])
	rest = rest[parsed+restOff:]
	parsed, err = m.NextHeader(&hdr, rest) // photo part.
	if err != nil {
		t.Fatal(err)
	}
	rest = rest[parsed:]
	bodyLen, restOff, done := m.NextBody(rest)
	if !done {
		t.Fatal("want the part to end within the buffer")
	}
	const want = "\x89PNG\r\n--not-the-boundary\r\n\x00\xff"
	if string(rest[:bodyLen]) != want {
		t.Errorf("want body %q, got %q", want, rest[:bodyLen])
	}
	if _, err = m.NextHeader(&hdr, rest[restOff:]); err != io.EOF {
		t.Errorf("want io.EOF after last part, got %v", err)
	}
}

// A delimiter split across two reads must not be mistaken for part data: the
// tail is held back until proven not to be a delimiter.
func TestNextPartBodySplitDelimiter(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	const part = "hi there"
	full := part + "\r\n------abc123\r\n"
	for split := 1; split < len(full); split++ {
		data := full[:split]
		bodyLen, restOff, done := m.NextBody([]byte(data))
		if done {
			continue // Whole delimiter already present, nothing to prove.
		}
		if bodyLen > len(part) {
			t.Fatalf("split %d: emitted %q, past the end of the part", split, data[:bodyLen])
		}
		if data[:bodyLen]+data[restOff:] != data {
			t.Fatalf("split %d: body+rest %q%q does not reconstruct input", split, data[:bodyLen], data[restOff:])
		}
	}
}

// A file part carries both parameters, and the raw block stays available.
func TestNextHeaderFilePart(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	var hdr MultipartHeader
	parsed, err := m.NextHeader(&hdr, []byte(multiBody)) // caption part.
	if err != nil {
		t.Fatal(err)
	}
	rest := []byte(multiBody[parsed:])
	_, restOff, _ := m.NextBody(rest)
	if _, err = m.NextHeader(&hdr, rest[restOff:]); err != nil { // photo part.
		t.Fatal(err)
	}
	if got := string(hdr.Name); got != "photo" {
		t.Errorf("want name %q, got %q", "photo", got)
	}
	if got := string(hdr.Filename); got != "beach.png" {
		t.Errorf("want filename %q, got %q", "beach.png", got)
	}
	if !strings.Contains(string(hdr.PartView), "Content-Type: image/png") {
		t.Errorf("want the raw block to hold every field, got %q", hdr.PartView)
	}
}

// A failed call must not leave the previous part's fields behind.
func TestNextHeaderResetsOnError(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	var hdr MultipartHeader
	if _, err := m.NextHeader(&hdr, []byte(multiBody)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.NextHeader(&hdr, []byte("------abc123--\r\n")); err != io.EOF {
		t.Fatalf("want io.EOF, got %v", err)
	}
	if hdr.PartView != nil || len(hdr.Name) != 0 || len(hdr.Filename) != 0 {
		t.Errorf("want cleared header on error, got %+v", hdr)
	}
}

// A header reused across parts must stop allocating once its name and filename
// buffers are big enough.
func TestNextHeaderReuseNoAlloc(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	data := []byte(multiBody)
	var hdr MultipartHeader
	allocs := testing.AllocsPerRun(10, func() {
		if _, err := m.NextHeader(&hdr, data); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("want a reused header to allocate 0 times, got %v", allocs)
	}
}

// The whole loop, as a caller writes it over a buffer it compacts.
func TestMultipartLoop(t *testing.T) {
	m := Multipart{Boundary: []byte(multiBoundary)}
	rest := []byte(multiBody)
	var got []string
	var hdr MultipartHeader
	for {
		parsed, err := m.NextHeader(&hdr, rest)
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		} else if parsed == 0 {
			t.Fatal("header must complete within the buffer")
		}
		name := string(hdr.Name)
		total := 0
		rest = rest[parsed:]
		for {
			bodyLen, restOff, done := m.NextBody(rest)
			total += bodyLen
			rest = rest[restOff:]
			if done {
				break
			}
			t.Fatal("part must complete within the buffer")
		}
		got = append(got, name+":"+strconv.Itoa(total))
	}
	want := "caption:8|photo:28"
	if strings.Join(got, "|") != want {
		t.Errorf("want %q, got %q", want, strings.Join(got, "|"))
	}
}
