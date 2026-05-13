package mdns

import (
	"github.com/soypat/lneto/dns"
)

// IPv4MulticastAddr is the IPv4 multicast address used by mDNS (224.0.0.251).
// Defined by RFC 6762. Packets sent to this address use UDP port 5353 and are
// link-local (not routed beyond the local network segment).
func IPv4MulticastAddr() [4]byte {
	return [4]byte{224, 0, 0, 251}
}

// IPv4MulticastMAC is the Ethernet multicast MAC address corresponding to
// 224.0.0.251 (01:00:5e:00:00:fb). Used for L2 delivery of mDNS over Ethernet.
func IPv4MulticastMAC() [6]byte {
	return [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}
}

// Service describes a service to advertise via mDNS.
// A single Service produces PTR, SRV, TXT, and A resource records.
//
// i.e: To generate a hostname styled A record like the one
// linux machines provide to reach them at hostname.local:
//
//	s := Service{
//		Host: dns.NewName("yourhostname.local"),
//		Addr: ipAddressSlice,
//	}
type Service struct {
	// Name is the fully-qualified service instance name in wire format,
	//  e.g. "My Web Server._http._tcp.local".
	Name dns.Name
	// Host is the hostname in wire format, e.g. "mydevice.local".
	Host dns.Name
	// TXTData is raw TXT record data (length-prefixed strings).
	TXTData []byte
	// Addr is the IP address for the A record.
	Addr []byte
	// TTL is the record TTL in seconds. Zero uses DefaultTTL.
	TTL uint32
	// Port is the TCP/UDP port for the SRV record.
	Port uint16
}

func (s *Service) ttl() uint32 {
	if s.TTL == 0 {
		return DefaultTTL
	}
	return s.TTL
}

// serviceType extracts the service type portion of the instance name.
// For "_http._tcp.local" it returns the same; for "My Web._http._tcp.local"
// it returns "_http._tcp.local" by trimming the first label.
// Returns a view into the original Name data — zero allocation.
func (s *Service) serviceType() dns.Name {
	var totalLabels int
	s.Name.VisitLabels(func(label []byte) {
		totalLabels++
	})
	if totalLabels <= 3 {
		return s.Name
	}
	return s.Name.TrimLabels(1)
}

// matchQuestion reports whether the question matches the given service.
func matchQuestion(q *dns.Question, svc *Service) bool {
	switch q.Type {
	case dns.TypePTR:
		svcType := svc.serviceType()
		return dns.NamesEqual(q.Name, svcType)
	case dns.TypeSRV, dns.TypeTXT:
		return dns.NamesEqual(q.Name, svc.Name)
	case dns.TypeA:
		return dns.NamesEqual(q.Name, svc.Host)
	case dns.TypeALL:
		svcType := svc.serviceType()
		return dns.NamesEqual(q.Name, svc.Name) || dns.NamesEqual(q.Name, svc.Host) || dns.NamesEqual(q.Name, svcType)
	}
	return false
}
func MulticastMAC(ip [4]byte) (mac [6]byte, ok bool) {
	// Check IPv4 multicast range: 224.0.0.0/4
	if ip[0]&0xf0 != 0xe0 {
		return mac, false
	}

	mac[0] = 0x01
	mac[1] = 0x00
	mac[2] = 0x5e

	// Lower 23 bits of IP
	mac[3] = ip[1] & 0x7f // drop top bit
	mac[4] = ip[2]
	mac[5] = ip[3]

	return mac, true
}

// addServiceAnswers adds the appropriate answer records for a matched question.
// It grows ans in-place, reusing existing Resource buffers when available.
func addServiceAnswers(dst *[]dns.Resource, q *dns.Question, svc *Service) {
	cacheFlush := dns.Class(uint16(dns.ClassINET) | classCacheFlush)
	ttl := svc.ttl()
	txtData := svc.TXTData
	avail := cap(*dst) - len(*dst)
	switch q.Type {
	case dns.TypePTR:
		if avail < 1 {
			return
		}
		setPTR(growSlice(dst), svc)
	case dns.TypeSRV:
		if avail < 2 {
			return
		}
		growSlice(dst).SetSRV(svc.Name, cacheFlush, ttl, 0, 0, svc.Port, svc.Host)
		growSlice(dst).SetA(svc.Host, cacheFlush, ttl, svc.Addr)
	case dns.TypeTXT:
		if avail < 1 {
			return
		}
		growSlice(dst).SetTXT(svc.Name, cacheFlush, ttl, txtData)
	case dns.TypeA:
		if avail < 1 {
			return
		}
		growSlice(dst).SetA(svc.Host, cacheFlush, ttl, svc.Addr)
	case dns.TypeALL:
		if avail < 4 {
			return
		}
		setPTR(growSlice(dst), svc)
		growSlice(dst).SetSRV(svc.Name, cacheFlush, ttl, 0, 0, svc.Port, svc.Host)
		growSlice(dst).SetTXT(svc.Name, cacheFlush, ttl, txtData)
		growSlice(dst).SetA(svc.Host, cacheFlush, ttl, svc.Addr)
	}
}

// growSlice grows the slice by one element and returns a pointer to the new last element.
// Panics if at capacity — callers must check available space before calling.
func growSlice[T any](s *[]T) *T {
	*s = (*s)[:len(*s)+1]
	return &(*s)[len(*s)-1]
}

func setPTR(ans *dns.Resource, svc *Service) {
	svcType := svc.serviceType()
	ans.SetPTR(svcType, dns.ClassINET, svc.ttl(), svc.Name)
}
