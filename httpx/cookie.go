package httpx

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var zeroTime time.Time

var (
	// cookieExpireDelete may be set on Cookie.Expire for expiring the given cookie.
	cookieExpireDelete = time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	// cookieExpireUnlimited indicates that the cookie doesn't expire.
	cookieExpireUnlimited = zeroTime
)

// CookieSameSite is an enum for the mode in which the SameSite flag should be set for the given cookie.
// See https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00 for details.
type CookieSameSite int

const (
	// CookieSameSiteDisabled removes the SameSite flag.
	CookieSameSiteDisabled CookieSameSite = iota
	// CookieSameSiteDefaultMode sets the SameSite flag.
	CookieSameSiteDefaultMode
	// CookieSameSiteLaxMode sets the SameSite flag with the "Lax" parameter.
	CookieSameSiteLaxMode
	// CookieSameSiteStrictMode sets the SameSite flag with the "Strict" parameter.
	CookieSameSiteStrictMode
	// CookieSameSiteNoneMode sets the SameSite flag with the "None" parameter.
	// See https://tools.ietf.org/html/draft-west-cookie-incrementalism-00
	CookieSameSiteNoneMode
)

// acquireCookie returns an empty Cookie object from the pool.
//
// The returned object may be returned back to the pool with ReleaseCookie.
// This allows reducing GC load.
func acquireCookie() *Cookie {
	return cookiePool.Get().(*Cookie)
}

// releaseCookie returns the Cookie object acquired with AcquireCookie back
// to the pool.
//
// Do not access released Cookie object, otherwise data races may occur.
func releaseCookie(c *Cookie) {
	c.Reset()
	cookiePool.Put(c)
}

var cookiePool = &sync.Pool{
	New: func() any {
		return &Cookie{}
	},
}

// Cookie represents HTTP response cookie.
//
// Do not copy Cookie objects. Create new object and use CopyTo instead.
//
// Cookie instance MUST NOT be used from concurrently running goroutines.
type Cookie struct {
	noCopy noCopy

	key    []byte
	value  []byte
	expire time.Time
	maxAge int
	domain []byte
	path   []byte

	httpOnly bool
	secure   bool
	sameSite CookieSameSite

	bufKV argsKV
	buf   []byte
}

// CopyTo copies src cookie to c.
func (c *Cookie) CopyTo(src *Cookie) {
	c.Reset()
	c.key = append(c.key, src.key...)
	c.value = append(c.value, src.value...)
	c.expire = src.expire
	c.maxAge = src.maxAge
	c.domain = append(c.domain, src.domain...)
	c.path = append(c.path, src.path...)
	c.httpOnly = src.httpOnly
	c.secure = src.secure
	c.sameSite = src.sameSite
}

// HTTPOnly returns true if the cookie is http only.
func (c *Cookie) HTTPOnly() bool {
	return c.httpOnly
}

// SetHTTPOnly sets cookie's httpOnly flag to the given value.
func (c *Cookie) SetHTTPOnly(httpOnly bool) {
	c.httpOnly = httpOnly
}

// Secure returns true if the cookie is secure.
func (c *Cookie) Secure() bool {
	return c.secure
}

// SetSecure sets cookie's secure flag to the given value.
func (c *Cookie) SetSecure(secure bool) {
	c.secure = secure
}

// SameSite returns the SameSite mode.
func (c *Cookie) SameSite() CookieSameSite {
	return c.sameSite
}

// SetSameSite sets the cookie's SameSite flag to the given value.
// Set value CookieSameSiteNoneMode will set Secure to true also to avoid browser rejection.
func (c *Cookie) SetSameSite(mode CookieSameSite) {
	c.sameSite = mode
	if mode == CookieSameSiteNoneMode {
		c.SetSecure(true)
	}
}

// Path returns cookie path.
func (c *Cookie) Path() []byte {
	return c.path
}

// SetPath sets cookie path.
func (c *Cookie) SetPath(path string) {
	c.buf = append(c.buf[:0], path...)
	c.path = normalizePath(c.path, b2s(c.buf))
}

// SetPathBytes sets cookie path.
func (c *Cookie) SetPathBytes(path []byte) {
	c.buf = append(c.buf[:0], path...)
	c.path = normalizePath(c.path, b2s(c.buf))
}

// Domain returns cookie domain.
//
// The returned value is valid until the Cookie reused or released (ReleaseCookie).
// Do not store references to the returned value. Make copies instead.
func (c *Cookie) Domain() []byte {
	return c.domain
}

// SetDomain sets cookie domain.
func (c *Cookie) SetDomain(domain string) {
	c.domain = append(c.domain[:0], domain...)
}

// SetDomainBytes sets cookie domain.
func (c *Cookie) SetDomainBytes(domain []byte) {
	c.domain = append(c.domain[:0], domain...)
}

// MaxAge returns the seconds until the cookie is meant to expire or 0
// if no max age.
func (c *Cookie) MaxAge() int {
	return c.maxAge
}

// SetMaxAge sets cookie expiration time based on seconds. This takes precedence
// over any absolute expiry set on the cookie.
//
// Set max age to 0 to unset.
func (c *Cookie) SetMaxAge(seconds int) {
	c.maxAge = seconds
}

// Expire returns cookie expiration time.
//
// CookieExpireUnlimited is returned if cookie doesn't expire.
func (c *Cookie) Expire() time.Time {
	expire := c.expire
	if expire.IsZero() {
		expire = cookieExpireUnlimited
	}
	return expire
}

// SetExpire sets cookie expiration time.
//
// Set expiration time to CookieExpireDelete for expiring (deleting)
// the cookie on the client.
//
// By default cookie lifetime is limited by browser session.
func (c *Cookie) SetExpire(expire time.Time) {
	c.expire = expire
}

// Value returns cookie value.
//
// The returned value is valid until the Cookie reused or released (ReleaseCookie).
// Do not store references to the returned value. Make copies instead.
func (c *Cookie) Value() []byte {
	return c.value
}

// SetValue sets cookie value.
func (c *Cookie) SetValue(value string) {
	c.value = append(c.value[:0], value...)
}

// SetValueBytes sets cookie value.
func (c *Cookie) SetValueBytes(value []byte) {
	c.value = append(c.value[:0], value...)
}

// Key returns cookie name.
//
// The returned value is valid until the Cookie reused or released (ReleaseCookie).
// Do not store references to the returned value. Make copies instead.
func (c *Cookie) Key() []byte {
	return c.key
}

// SetKey sets cookie name.
func (c *Cookie) SetKey(key string) {
	c.key = append(c.key[:0], key...)
}

// SetKeyBytes sets cookie name.
func (c *Cookie) SetKeyBytes(key []byte) {
	c.key = append(c.key[:0], key...)
}

// Reset clears the cookie.
func (c *Cookie) Reset() {
	c.key = c.key[:0]
	c.value = c.value[:0]
	c.expire = zeroTime
	c.maxAge = 0
	c.domain = c.domain[:0]
	c.path = c.path[:0]
	c.httpOnly = false
	c.secure = false
	c.sameSite = CookieSameSiteDisabled
}

// AppendBytes appends cookie representation to dst and returns
// the extended dst.
func (c *Cookie) AppendBytes(dst []byte) []byte {
	if len(c.key) > 0 {
		dst = append(dst, c.key...)
		dst = append(dst, '=')
	}
	dst = append(dst, c.value...)

	if c.maxAge > 0 {
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieMaxAge...)
		dst = append(dst, '=')
		dst = appendUint(dst, c.maxAge)
	} else if !c.expire.IsZero() {
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieExpires...)
		dst = append(dst, '=')
		dst = AppendHTTPDate(dst, c.expire)
	}
	if len(c.domain) > 0 {
		dst = appendCookiePart(dst, strCookieDomain, b2s(c.domain))
	}
	if len(c.path) > 0 {
		dst = appendCookiePart(dst, strCookiePath, b2s(c.path))
	}
	if c.httpOnly {
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieHTTPOnly...)
	}
	if c.secure {
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieSecure...)
	}
	switch c.sameSite {
	case CookieSameSiteDefaultMode:
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieSameSite...)
	case CookieSameSiteLaxMode:
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieSameSite...)
		dst = append(dst, '=')
		dst = append(dst, strCookieSameSiteLax...)
	case CookieSameSiteStrictMode:
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieSameSite...)
		dst = append(dst, '=')
		dst = append(dst, strCookieSameSiteStrict...)
	case CookieSameSiteNoneMode:
		dst = append(dst, ';', ' ')
		dst = append(dst, strCookieSameSite...)
		dst = append(dst, '=')
		dst = append(dst, strCookieSameSiteNone...)
	}
	return dst
}

// Cookie returns cookie representation.
//
// The returned value is valid until the Cookie reused or released (ReleaseCookie).
// Do not store references to the returned value. Make copies instead.
func (c *Cookie) Cookie() []byte {
	c.buf = c.AppendBytes(c.buf[:0])
	return c.buf
}

// String returns cookie representation.
func (c *Cookie) String() string {
	return string(c.Cookie())
}

// WriteTo writes cookie representation to w.
//
// WriteTo implements io.WriterTo interface.
func (c *Cookie) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(c.Cookie())
	return int64(n), err
}

var errNoCookies = errors.New("no cookies found")

// Parse parses Set-Cookie header.
func (c *Cookie) Parse(src string) error {
	c.buf = append(c.buf[:0], src...)
	return c.ParseBytes(c.buf)
}

// ParseBytes parses Set-Cookie header.
func (c *Cookie) ParseBytes(src []byte) error {
	c.Reset()
	ntot := 0
	for {
		k, v, n := parseCookie(src)
		if n == 0 {
			break
		} else if ntot == 0 {
			c.key = append(c.key, k...)
			c.value = append(c.value, v...)
		}
		key := b2s(k)
		value := b2s(v)
		ntot += n
		src = src[n:]
		if len(key) != 0 {
			// Case insensitive switch on first char
			switch key[0] | 0x20 {
			case 'm':
				if caseInsensitiveCompare(strCookieMaxAge, key) {
					maxAge, err := strconv.ParseUint(value, 10, 32)
					if err != nil {
						return err
					}
					c.maxAge = int(maxAge)
				}

			case 'e': // "expires"
				if caseInsensitiveCompare(strCookieExpires, key) {

					// Try the same two formats as net/http
					// See: https://github.com/golang/go/blob/00379be17e63a5b75b3237819392d2dc3b313a27/src/net/http/cookie.go#L133-L135
					exptime, err := time.ParseInLocation(time.RFC1123, value, time.UTC)
					if err != nil {
						exptime, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", value)
						if err != nil {
							return err
						}
					}
					c.expire = exptime
				}

			case 'd': // "domain"
				if caseInsensitiveCompare(strCookieDomain, key) {
					c.domain = append(c.domain, value...)
				}

			case 'p': // "path"
				if caseInsensitiveCompare(strCookiePath, key) {
					c.path = append(c.path, value...)
				}

			case 's': // "samesite"
				if caseInsensitiveCompare(strCookieSameSite, key) {
					if len(value) > 0 {
						// Case insensitive switch on first char
						switch value[0] | 0x20 {
						case 'l': // "lax"
							if caseInsensitiveCompare(strCookieSameSiteLax, value) {
								c.sameSite = CookieSameSiteLaxMode
							}
						case 's': // "strict"
							if caseInsensitiveCompare(strCookieSameSiteStrict, value) {
								c.sameSite = CookieSameSiteStrictMode
							}
						case 'n': // "none"
							if caseInsensitiveCompare(strCookieSameSiteNone, value) {
								c.sameSite = CookieSameSiteNoneMode
							}
						}
					}
				}
			}
		} else if len(value) != 0 {
			// Case insensitive switch on first char
			switch value[0] | 0x20 {
			case 'h': // "httponly"
				if caseInsensitiveCompare(strCookieHTTPOnly, value) {
					c.httpOnly = true
				}

			case 's': // "secure"
				if caseInsensitiveCompare(strCookieSecure, value) {
					c.secure = true
				} else if caseInsensitiveCompare(strCookieSameSite, value) {
					c.sameSite = CookieSameSiteDefaultMode
				}
			}
		} // else empty or no match
	}
	if len(c.key) == 0 && len(c.value) == 0 {
		return errNoCookies
	}
	return nil
}

func appendCookiePart(dst []byte, key, value string) []byte {
	dst = append(dst, ';', ' ')
	dst = append(dst, key...)
	dst = append(dst, '=')
	return append(dst, value...)
}

func (hb *headerBuf) appendRequestCookieBytes(dst []byte) []byte {
	n := len(hb.cookies)
	for i := 0; i < n; i++ {
		kv := hb.cookies[i]
		if !kv.isValid() {
			continue
		} else if kv.key.len > 0 {
			dst = append(dst, hb.musttoken(kv.key)...)
			dst = append(dst, '=')
		}
		dst = append(dst, hb.musttoken(kv.value)...)
		if i+1 < n {
			dst = append(dst, ';', ' ')
		}
	}
	return dst
}
func (hb *headerBuf) appendResponseCookieBytes(dst []byte) []byte {
	n := len(hb.cookies)
	for i := 0; i < n; i++ {
		kv := hb.cookies[i]
		if !kv.isValid() {
			continue
		}
		dst = append(dst, hb.musttoken(kv.value)...)
		if i+1 < n {
			dst = append(dst, ';', ' ')
		}
	}
	return dst
}

type cookieScanner struct {
	b []byte
}

// parseCookie parses a cookie inside cookie buffer and adds it to cookie buffer..
//
//	Cookie: <cookie>\r\n
func parseCookie(cookie []byte) (key, value []byte, cookieEnd int) {
	if len(cookie) == 0 {
		return nil, nil, 0
	}
	eqIdx := bytes.IndexByte(cookie, '=')
	semiIdx := bytes.IndexByte(cookie, ';')
	if eqIdx > 0 && eqIdx < semiIdx {
		// cookies has form key=value;
		key = trimCookie(cookie[:eqIdx], false)
	} else {
		// cookie has no key.
		eqIdx = -1 // ensure is -1.
	}
	if semiIdx > 0 {
		// found ';'
		value = trimCookie(cookie[eqIdx+1:semiIdx], true)
	} else {
		value = trimCookie(cookie[eqIdx+1:], true)
	}
	return key, value, max(len(cookie), semiIdx+1)
}

func trimCookie(src []byte, trimQuotes bool) []byte {
	for len(src) > 0 && src[0] == ' ' {
		src = src[1:] // skip leading whitespace.
	}
	for len(src) > 0 && src[len(src)-1] == ' ' {
		src = src[:len(src)-1] // skip trailing whitespace
	}
	if trimQuotes {
		if len(src) > 1 && src[0] == '"' && src[len(src)-1] == '"' {
			src = src[1 : len(src)-1] // Trim leading+trailing quotes.
		}
	}
	return src
}

// caseInsensitiveCompare does a case insensitive equality comparison of
// two []byte. Assumes only letters need to be matched.
func caseInsensitiveCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i]|0x20 != b[i]|0x20 {
			return false
		}
	}
	return true
}

func normalizePath(dst []byte, src string) []byte {
	dst = dst[:0]
	dst = addLeadingSlash(dst, src)
	dst = decodeArgAppendNoPlus(dst, src)

	// remove duplicate slashes
	b := dst
	bSize := len(b)
	for {
		n := strings.Index(b2s(b), strSlashSlash)
		if n < 0 {
			break
		}
		b = b[n:]
		copy(b, b[1:])
		b = b[:len(b)-1]
		bSize--
	}
	dst = dst[:bSize]

	// remove /./ parts
	b = dst
	for {
		n := strings.Index(b2s(b), strSlashDotSlash)
		if n < 0 {
			break
		}
		nn := n + len(strSlashDotSlash) - 1
		copy(b[n:], b[nn:])
		b = b[:len(b)-nn+n]
	}

	// remove /foo/../ parts
	for {
		n := strings.Index(b2s(b), strSlashDotDotSlash)
		if n < 0 {
			break
		}
		nn := strings.LastIndexByte(b2s(b[:n]), slashChar)
		if nn < 0 {
			nn = 0
		}
		n += len(strSlashDotDotSlash) - 1
		copy(b[nn:], b[n:])
		b = b[:len(b)-n+nn]
	}

	// remove trailing /foo/..
	n := strings.LastIndex(b2s(b), strSlashDotDot)
	if n >= 0 && n+len(strSlashDotDot) == len(b) {
		nn := strings.LastIndexByte(b2s(b[:n]), slashChar)
		if nn < 0 {
			return append(dst[:0], slashChar)
		}
		b = b[:nn+1]
	}

	if filepath.Separator == '\\' {
		// remove \.\ parts
		for {
			n := strings.Index(b2s(b), strBackSlashDotBackSlash)
			if n < 0 {
				break
			}
			nn := n + len(strSlashDotSlash) - 1
			copy(b[n:], b[nn:])
			b = b[:len(b)-nn+n]
		}

		// remove /foo/..\ parts
		for {
			n := strings.Index(b2s(b), strSlashDotDotBackSlash)
			if n < 0 {
				break
			}
			nn := strings.LastIndexByte(b2s(b[:n]), slashChar)
			if nn < 0 {
				nn = 0
			}
			nn++
			n += len(strSlashDotDotBackSlash)
			copy(b[nn:], b[n:])
			b = b[:len(b)-n+nn]
		}

		// remove /foo\..\ parts
		for {
			n := strings.Index(b2s(b), strBackSlashDotDotBackSlash)
			if n < 0 {
				break
			}
			nn := strings.LastIndexByte(b2s(b[:n]), slashChar)
			if nn < 0 {
				nn = 0
			}
			n += len(strBackSlashDotDotBackSlash) - 1
			copy(b[nn:], b[n:])
			b = b[:len(b)-n+nn]
		}

		// remove trailing \foo\..
		n := strings.LastIndex(b2s(b), strBackSlashDotDot)
		if n >= 0 && n+len(strSlashDotDot) == len(b) {
			nn := strings.LastIndexByte(b2s(b[:n]), slashChar)
			if nn < 0 {
				return append(dst[:0], slashChar)
			}
			b = b[:nn+1]
		}
	}

	return b
}

func addLeadingSlash(dst []byte, src string) []byte {
	// add leading slash for unix paths
	if len(src) == 0 || src[0] != slashChar {
		dst = append(dst, slashChar)
	}

	return dst
}

// decodeArgAppendNoPlus is almost identical to decodeArgAppend, but it doesn't
// substitute '+' with ' '.
//
// The function is copy-pasted from decodeArgAppend due to the performance
// reasons only.
func decodeArgAppendNoPlus(dst []byte, src string) []byte {
	idx := strings.IndexByte(src, '%')
	if idx < 0 {
		// fast path: src doesn't contain encoded chars
		return append(dst, src...)
	}
	dst = append(dst, src[:idx]...)

	// slow path
	for i := idx; i < len(src); i++ {
		c := src[i]
		if c == '%' {
			if i+2 >= len(src) {
				return append(dst, src[i:]...)
			}
			x2 := hex2intTable[src[i+2]]
			x1 := hex2intTable[src[i+1]]
			if x1 == 16 || x2 == 16 {
				dst = append(dst, '%')
			} else {
				dst = append(dst, x1<<4|x2)
				i += 2
			}
		} else {
			dst = append(dst, c)
		}
	}
	return dst
}

// AppendHTTPDate appends HTTP-compliant (RFC1123) representation of date
// to dst and returns the extended dst.
func AppendHTTPDate(dst []byte, date time.Time) []byte {
	dst = date.In(time.UTC).AppendFormat(dst, time.RFC1123)
	copy(dst[len(dst)-3:], strGMT)
	return dst
}
