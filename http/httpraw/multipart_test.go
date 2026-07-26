package httpraw

import (
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
	for _, test := range []struct {
		contentType string
		want        string
	}{
		{contentType: "multipart/form-data; boundary=abc123", want: "abc123"},
		{contentType: "multipart/form-data; boundary=\"a b\"", want: "a b"},
		{contentType: "multipart/form-data; charset=utf-8; boundary=xyz", want: "xyz"},
		{contentType: "multipart/form-data; BOUNDARY=xyz", want: "xyz"}, // Keys are case insensitive.
		{contentType: "multipart/form-data", want: ""},                  // Absent.
		{contentType: "application/x-www-form-urlencoded", want: ""},
	} {
		got := MultipartBoundary([]byte(test.contentType))
		if string(got) != test.want {
			t.Errorf("%q: want %q, got %q", test.contentType, test.want, got)
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
	boundary := []byte(multiBoundary)
	hdr, rest, err := NextPartHeader([]byte(multiBody), boundary)
	if err != nil {
		t.Fatal(err)
	}
	const wantHdr = "Content-Disposition: form-data; name=\"caption\"\r\n"
	if string(hdr) != wantHdr {
		t.Errorf("want header %q, got %q", wantHdr, hdr)
	}
	if !strings.HasPrefix(string(rest), "hi there\r\n") {
		t.Errorf("want rest at part body, got %q", rest)
	}
}

// Incomplete data must ask for more, never guess.
func TestNextPartHeaderNeedMore(t *testing.T) {
	boundary := []byte(multiBoundary)
	for _, data := range []string{
		"",
		"------abc",        // Delimiter cut short.
		"------abc123\r\n", // No header block yet.
		"------abc123\r\nContent-Disposition: form-", // Header block unterminated.
	} {
		if _, _, err := NextPartHeader([]byte(data), boundary); err != ErrNeedMoreData {
			t.Errorf("%q: want ErrNeedMoreData, got %v", data, err)
		}
	}
}

// The closing delimiter ends iteration.
func TestNextPartHeaderEnd(t *testing.T) {
	boundary := []byte(multiBoundary)
	if _, _, err := NextPartHeader([]byte("------abc123--\r\n"), boundary); err != ErrEndOfParts {
		t.Errorf("want ErrEndOfParts, got %v", err)
	}
}

func TestNextPartBody(t *testing.T) {
	boundary := []byte(multiBoundary)
	_, rest, err := NextPartHeader([]byte(multiBody), boundary)
	if err != nil {
		t.Fatal(err)
	}
	body, rest, done := NextPartBody(rest, boundary)
	if !done {
		t.Fatal("want the part to end within the buffer")
	}
	if string(body) != "hi there" {
		t.Errorf("want body %q, got %q", "hi there", body)
	}
	if !strings.HasPrefix(string(rest), "------abc123\r\n") {
		t.Errorf("want rest at next delimiter, got %q", rest)
	}
}

// A part whose bytes contain CRLFs and boundary-like text must survive intact.
func TestNextPartBodyBinary(t *testing.T) {
	boundary := []byte(multiBoundary)
	data := []byte(multiBody)
	_, rest, err := NextPartHeader(data, boundary) // caption part.
	if err != nil {
		t.Fatal(err)
	}
	_, rest, _ = NextPartBody(rest, boundary)
	_, rest, err = NextPartHeader(rest, boundary) // photo part.
	if err != nil {
		t.Fatal(err)
	}
	body, rest, done := NextPartBody(rest, boundary)
	if !done {
		t.Fatal("want the part to end within the buffer")
	}
	const want = "\x89PNG\r\n--not-the-boundary\r\n\x00\xff"
	if string(body) != want {
		t.Errorf("want body %q, got %q", want, body)
	}
	if _, _, err = NextPartHeader(rest, boundary); err != ErrEndOfParts {
		t.Errorf("want ErrEndOfParts after last part, got %v", err)
	}
}

// A delimiter split across two reads must not be mistaken for part data: the
// tail is held back until proven not to be a delimiter.
func TestNextPartBodySplitDelimiter(t *testing.T) {
	boundary := []byte(multiBoundary)
	const part = "hi there"
	full := part + "\r\n------abc123\r\n"
	for split := 1; split < len(full); split++ {
		body, rest, done := NextPartBody([]byte(full[:split]), boundary)
		if done {
			continue // Whole delimiter already present, nothing to prove.
		}
		if len(body) > len(part) {
			t.Fatalf("split %d: emitted %q, past the end of the part", split, body)
		}
		if string(body)+string(rest) != full[:split] {
			t.Fatalf("split %d: body+rest %q%q does not reconstruct input", split, body, rest)
		}
	}
}

func TestPartNameFileName(t *testing.T) {
	const photo = "Content-Disposition: form-data; name=\"photo\"; filename=\"beach.png\"\r\n" +
		"Content-Type: image/png\r\n"
	if got := string(PartName([]byte(photo))); got != "photo" {
		t.Errorf("want name %q, got %q", "photo", got)
	}
	if got := string(PartFileName([]byte(photo))); got != "beach.png" {
		t.Errorf("want filename %q, got %q", "beach.png", got)
	}
	const caption = "Content-Disposition: form-data; name=\"caption\"\r\n"
	if got := string(PartName([]byte(caption))); got != "caption" {
		t.Errorf("want name %q, got %q", "caption", got)
	}
	if got := PartFileName([]byte(caption)); got != nil {
		t.Errorf("want nil filename for a non file part, got %q", got)
	}
}

// The whole loop, as a caller writes it.
func TestMultipartLoop(t *testing.T) {
	boundary := []byte(multiBoundary)
	rest := []byte(multiBody)
	var got []string
	for {
		hdr, next, err := NextPartHeader(rest, boundary)
		if err == ErrEndOfParts {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		name := string(PartName(hdr))
		total := 0
		rest = next
		for {
			body, next, done := NextPartBody(rest, boundary)
			total += len(body)
			rest = next
			if done {
				break
			}
			t.Fatal("part must complete within the buffer")
		}
		got = append(got, name+":"+strconv.Itoa(total))
	}
	want := "caption:8|photo:29"
	if strings.Join(got, "|") != want {
		t.Errorf("want %q, got %q", want, strings.Join(got, "|"))
	}
}
