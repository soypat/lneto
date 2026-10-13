package xnet

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
)

func TestDNS_DoLookupIPFreesLookupOnTimeout(t *testing.T) {
	client := newDNSTestClient(t)
	// Each poll of a lookup no server answers moves the clock forward.
	var now int64
	client.mono.Config(func() int64 { return now })
	silent := client.StackBlocking(func(uint) time.Duration {
		now += int64(time.Millisecond)
		return lneto.BackoffFlagNop
	})
	// More timed out lookups than concurrent lookups allowed: each must free its slot.
	var dst [4]netip.Addr
	for i := range 3 {
		_, err := silent.DoLookupIP(dst[:], dns.MustNewName("timeout.example.com"), time.Millisecond)
		if err != errDeadlineExceed {
			t.Fatalf("lookup %d: got err=%v, want %v", i, err, errDeadlineExceed)
		}
	}
	const host = "www.example.com"
	srv := &dnsTestServer{t: t, client: client, zone: map[string][]dnsRR{host: {rrA(host, "192.0.2.9")}}}
	pump := client.StackBlocking(func(uint) time.Duration {
		srv.respond()
		return lneto.BackoffFlagNop
	})
	n, err := pump.DoLookupIP(dst[:], dns.MustNewName(host), time.Second)
	if err != nil || n != 1 || dst[0] != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("lookup after timeouts: %v %v", dst[:n], err)
	}
}

// TestDNS_DoLookupIPCNAMEHeadroom checks a destination sized for the addresses alone still
// resolves an answer whose CNAME records precede the address in a single query.
func TestDNS_DoLookupIPCNAMEHeadroom(t *testing.T) {
	const host = "www.example.com"
	client := newDNSTestClient(t)
	srv := &dnsTestServer{t: t, client: client, zone: map[string][]dnsRR{host: {
		rrCNAME(host, "cdn1.example.net"),
		rrCNAME("cdn1.example.net", "cdn2.example.net"),
		rrA("cdn2.example.net", "192.0.2.10"),
	}}}
	pump := client.StackBlocking(func(uint) time.Duration {
		srv.respond()
		return lneto.BackoffFlagNop
	})
	var dst [1]netip.Addr
	n, err := pump.DoLookupIP(dst[:], dns.MustNewName(host), time.Second)
	if err != nil || n != 1 || dst[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("got %v err=%v", dst[:n], err)
	}
	if srv.queries != 1 {
		t.Fatalf("got %d queries, want 1: CNAME records must not crowd out the address", srv.queries)
	}
}

func TestDNS_DoLookupIPEmptyDst(t *testing.T) {
	client := newDNSTestClient(t)
	pump := client.StackBlocking(func(uint) time.Duration { return lneto.BackoffFlagNop })
	if _, err := pump.DoLookupIP(nil, dns.MustNewName("www.example.com"), time.Second); !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("got err=%v, want ErrShortBuffer", err)
	}
}
