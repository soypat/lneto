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
	var buf bytes.Buffer
	req.Write(&buf)
	data := buf.Bytes()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		var hdr Header
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
