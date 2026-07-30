package httpraw

import (
	"strings"
	"testing"
)

// render joins a form's pairs as "key=value", a valueless key as "key".
func render(f *Form) string {
	var sb strings.Builder
	for i := range f.Len() {
		key, value := f.Pair(i)
		if i > 0 {
			sb.WriteByte('|')
		}
		sb.Write(key)
		if value != nil {
			sb.WriteByte('=')
			sb.Write(value)
		}
	}
	return sb.String()
}

func TestFormParse(t *testing.T) {
	for _, test := range []struct {
		body string
		want string
	}{
		{body: "", want: ""},
		{body: "q=go", want: "q=go"},
		{body: "name=Jos%C3%A9+P%C3%A9rez&msg=hi+there&ok=on", want: "name=Jos%C3%A9+P%C3%A9rez|msg=hi+there|ok=on"},
		{body: "ok", want: "ok"},                   // Flag: no '=' at all.
		{body: "ok=", want: "ok="},                 // Present but empty.
		{body: "&&q=go&", want: "q=go"},            // Empty sequences skipped.
		{body: "tag=a&tag=b", want: "tag=a|tag=b"}, // Duplicates kept in order.
		{body: "=v", want: "=v"},                   // Empty name kept.
		{body: "a=b=c", want: "a=b=c"},             // Only the first '=' splits.
	} {
		var f Form
		if err := f.ParseBytes([]byte(test.body)); err != nil {
			t.Fatalf("%q: %s", test.body, err)
		}
		if got := render(&f); got != test.want {
			t.Errorf("%q: want %q, got %q", test.body, test.want, got)
		}
	}
}

// Decode rewrites keys and values in place: percent escapes and '+' as space.
func TestFormDecode(t *testing.T) {
	var f Form
	const body = "name=Jos%C3%A9+P%C3%A9rez&a%20b=c%2Bd&ok"
	if err := f.ParseBytes([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := f.Decode(); err != nil {
		t.Fatal(err)
	}
	const want = "name=José Pérez|a b=c+d|ok"
	if got := render(&f); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
	if got := string(f.Get("a b")); got != "c+d" {
		t.Errorf("want decoded key lookup %q, got %q", "c+d", got)
	}
}

// Decoding a valueless key that shrinks must rewrite the key without inventing
// a value: the pair has no '=' before Decode and must have none after.
func TestFormDecodeValuelessKeyShrinks(t *testing.T) {
	var f Form
	const body = "a=1&o%6Bay"
	if err := f.ParseBytes([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := f.Decode(); err != nil {
		t.Fatal(err)
	}
	const want = "a=1|okay"
	if got := render(&f); got != want {
		t.Errorf("want %q, got %q", want, got)
	}
	if _, value := f.Pair(1); value != nil {
		t.Errorf("want valueless pair to stay valueless, got value %q", value)
	}
	if !f.Has("okay") {
		t.Error("want decoded valueless key present")
	}
}

// A malformed escape must be reported, never silently passed through.
func TestFormDecodeMalformed(t *testing.T) {
	for _, body := range []string{"q=%zz", "%zz=v", "q=%4"} {
		var f Form
		if err := f.ParseBytes([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := f.Decode(); err == nil {
			t.Errorf("%q: want decode error, got nil", body)
		}
	}
}

func TestFormGetHas(t *testing.T) {
	var f Form
	if err := f.ParseBytes([]byte("tag=a&tag=b&ok&empty=")); err != nil {
		t.Fatal(err)
	}
	if got := string(f.Get("tag")); got != "a" {
		t.Errorf("want first value %q, got %q", "a", got)
	}
	if got := f.Get("ok"); got != nil {
		t.Errorf("want nil value for valueless key, got %q", got)
	}
	if got := f.Get("nope"); got != nil {
		t.Errorf("want nil for absent key, got %q", got)
	}
	if v := f.Get("empty"); v == nil || len(v) != 0 {
		t.Errorf("want present empty value, got %v", v)
	}
	for _, key := range []string{"tag", "ok", "empty"} {
		if !f.Has(key) {
			t.Errorf("want Has(%q) true", key)
		}
	}
	if f.Has("nope") {
		t.Error("want Has(nope) false")
	}
}

func TestFormAppendKeyValues(t *testing.T) {
	const body = "name=go&ok&empty=&tag=a&tag=b"
	var f Form
	if err := f.ParseBytes([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if got := string(f.AppendKeyValues(nil)); got != body {
		t.Errorf("want round trip %q, got %q", body, got)
	}
}

// Parsing into a reused Form must not allocate: the pair storage is reused.
func TestFormParseReuseNoAlloc(t *testing.T) {
	body := []byte("name=go&tag=a&tag=b&ok")
	var f Form
	if err := f.ParseBytes(body); err != nil { // Warm up the pair storage.
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		f.Reset(body, 0) // 0 preserves the pair storage warmed up above, the reuse under test.
		f.Parse()
	})
	if allocs != 0 {
		t.Errorf("reused Form allocated %v times, want 0", allocs)
	}
}

// BufferUsed reports buffered bytes, not parsed pairs, so a caller appending
// from several sources can tell whether a separator is needed before the next
// one. Form.Len is zero until Parse runs and cannot answer that.
func TestFormBufferUsed(t *testing.T) {
	var f Form
	f.Reset(nil, defaultKVCap)
	if got := f.BufferUsed(); got != 0 {
		t.Errorf("want 0 on a fresh form, got %d", got)
	}
	if err := f.ReadFromBytes([]byte("a=1")); err != nil {
		t.Fatal(err)
	}
	if got := f.BufferUsed(); got != 3 {
		t.Errorf("want 3 buffered, got %d", got)
	}
	if got := f.Len(); got != 0 {
		t.Errorf("Len must stay 0 until Parse, got %d", got)
	}
	// A second source appended behind a separator.
	if err := f.ReadFromBytes([]byte("&b=2")); err != nil {
		t.Fatal(err)
	}
	if got := f.BufferUsed(); got != 7 {
		t.Errorf("want 7 buffered, got %d", got)
	}
	if err := f.Parse(); err != nil {
		t.Fatal(err)
	}
	if got := render(&f); got != "a=1|b=2" {
		t.Errorf("want a=1|b=2, got %q", got)
	}
	if got := f.BufferUsed(); got != 7 {
		t.Errorf("BufferUsed must not change on Parse, got %d", got)
	}
	// Reset discards the pairs and the buffered bytes with them.
	f.Reset(nil, defaultKVCap)
	if got := f.BufferUsed(); got != 0 {
		t.Errorf("want 0 after Reset, got %d", got)
	}
}
