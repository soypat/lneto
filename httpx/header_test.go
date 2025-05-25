package httpx

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestHeaderParseRequest(t *testing.T) {
	const (
		wantMethod  = "GET"
		wantURI     = "/"
		wantMessage = "hello world!"
	)
	req, err := http.NewRequest(wantMethod, wantURI, strings.NewReader(wantMessage))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	req.Write(&buf)
	var hdr header
	err = hdr.ParseBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !hdr.MethodIs(wantMethod) {
		t.Errorf("want method %s, got %q", wantMethod, hdr.Method())
	}
	if !bytes.Equal(hdr.RequestURI(), []byte(wantURI)) {
		t.Errorf("want request URI %q, got %q", wantURI, hdr.RequestURI())
	}
}
