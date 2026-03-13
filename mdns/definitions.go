package mdns

import (
	"encoding/binary"
	"errors"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
)

// Service describes a service to advertise via mDNS.
// A single Service produces PTR, SRV, TXT, and A resource records.
type Service struct {
	// Name is the fully-qualified service instance name in wire format,
	// e.g. "My Web Server._http._tcp.local".
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
// it returns "_http._tcp.local" by skipping the first label.
func (s *Service) serviceType() dns.Name {
	// Skip first label (instance name) to get service type.
	var labels int
	var totalLabels int
	s.Name.VisitLabels(func(label []byte) {
		totalLabels++
	})
	if totalLabels <= 3 {
		// Already a bare service type, no instance prefix.
		return s.Name
	}
	var name dns.Name
	s.Name.VisitLabels(func(label []byte) {
		labels++
		if labels > 1 {
			name.AddLabel(string(label))
		}
	})
	return name
}

// matchQuestion reports whether the question matches the given service.
func matchQuestion(q *dns.Question, svc *Service) bool {
	switch q.Type {
	case dns.TypePTR:
		svcType := svc.serviceType()
		return namesEqual(&q.Name, &svcType)
	case dns.TypeSRV, dns.TypeTXT:
		return namesEqual(&q.Name, &svc.Name)
	case dns.TypeA:
		return namesEqual(&q.Name, &svc.Host)
	case dns.TypeALL:
		svcType := svc.serviceType()
		return namesEqual(&q.Name, &svc.Name) || namesEqual(&q.Name, &svc.Host) || namesEqual(&q.Name, &svcType)
	}
	return false
}

// namesEqual compares two DNS names by their dotted representation.
func namesEqual(a, b *dns.Name) bool {
	la, lb := a.Len(), b.Len()
	return la == lb && a.String() == b.String()
}

// addServiceAnswers adds the appropriate answer records for a matched question to msg.
func addServiceAnswers(ans *[]dns.Resource, q *dns.Question, svc *Service) {
	switch q.Type {
	case dns.TypePTR:
		addPTRRecord(ans, svc)
	case dns.TypeSRV:
		addSRVRecord(ans, svc)
		addARecord(ans, svc)
	case dns.TypeTXT:
		addTXTRecord(ans, svc)
	case dns.TypeA:
		addARecord(ans, svc)
	case dns.TypeALL:
		addAllRecords(ans, svc)
	}
}

// addAllRecords adds PTR, SRV, TXT, and A records for a service.
func addAllRecords(ans *[]dns.Resource, svc *Service) {
	addPTRRecord(ans, svc)
	addSRVRecord(ans, svc)
	addTXTRecord(ans, svc)
	addARecord(ans, svc)
}

func addPTRRecord(ans *[]dns.Resource, svc *Service) {
	svcType := svc.serviceType()
	var buf [255]byte
	nameData, _ := svc.Name.AppendTo(buf[:0])
	rsc := dns.NewResource(svcType, dns.TypePTR, dns.ClassINET, svc.ttl(), nameData)
	*ans = append(*ans, rsc)
}

func addSRVRecord(ans *[]dns.Resource, svc *Service) {
	var buf [6 + 255]byte
	n, err := encodeSRVData(buf[:], 0, 0, svc.Port, svc.Host)
	if err != nil {
		return
	}
	class := dns.Class(uint16(dns.ClassINET) | classCacheFlush)
	rsc := dns.NewResource(svc.Name, dns.TypeSRV, class, svc.ttl(), buf[:n])
	*ans = append(*ans, rsc)
}

func addTXTRecord(ans *[]dns.Resource, svc *Service) {
	txtData := svc.TXTData
	if len(txtData) == 0 {
		txtData = []byte{0}
	}
	class := dns.Class(uint16(dns.ClassINET) | classCacheFlush)
	rsc := dns.NewResource(svc.Name, dns.TypeTXT, class, svc.ttl(), txtData)
	*ans = append(*ans, rsc)
}

func addARecord(ans *[]dns.Resource, svc *Service) {
	class := dns.Class(uint16(dns.ClassINET) | classCacheFlush)
	rsc := dns.NewResource(svc.Host, dns.TypeA, class, svc.ttl(), svc.Addr[:])
	*ans = append(*ans, rsc)
}

// encodeSRVData encodes SRV record data (priority, weight, port, target) into dst.
// Returns bytes written. dst must be at least 6+target.Len() bytes.
func encodeSRVData(dst []byte, priority, weight, port uint16, target dns.Name) (int, error) {
	tlen := target.Len()
	need := 6 + int(tlen)
	if len(dst) < need {
		return 0, lneto.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(dst[0:2], priority)
	binary.BigEndian.PutUint16(dst[2:4], weight)
	binary.BigEndian.PutUint16(dst[4:6], port)
	b, err := target.AppendTo(dst[:6])
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

var (
	errNoServices = errors.New("mdns: no services configured")
	errNoQuery    = errors.New("mdns: no query questions provided")
)
