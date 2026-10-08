package edns0

import (
	"math"

	"github.com/soypat/lneto/dns"
)

type Flags uint16

var rootDomain = dns.MustNewName(".")

func SetResource(r *dns.Resource, UDPlength uint16, rcode dns.RCode, zflags Flags, data []byte) {
	if len(data) > math.MaxUint16-2 || len(data)+8+2*dns.SizeHeader > int(UDPlength) {
		panic("too large data")
	}
	r.RawSet(dns.ResourceHeader{
		Name:   rootDomain,
		Type:   dns.TypeOPT,
		Class:  dns.Class(UDPlength),
		TTL:    uint32(rcode)<<24 | 0<<16 | uint32(zflags),
		Length: uint16(len(data)),
	}, append(r.RawData()[:0], data...))
}
