package mdns

import (
	"errors"

	"github.com/soypat/lneto/dns"
)

// mDNS constants per RFC 6762.
const (
	// Port is the mDNS UDP port (RFC 6762 §1).
	Port = 5353

	// Default TTL for mDNS records (RFC 6762 §11).
	DefaultTTL uint32 = 120

	// classCacheFlush is bit 15 of the Class field, indicating the record
	// is from a unique source and should replace cached entries (RFC 6762 §10.2).
	classCacheFlush uint16 = 1 << 15
)

// IPv4 multicast address 224.0.0.251 in network byte order.
var IPv4Multicast = [4]byte{224, 0, 0, 251}

// Service describes a service to advertise via mDNS.
// A single Service produces PTR, SRV, TXT, and A resource records.
type Service struct {
	// Name is the fully-qualified service instance name in wire format,
	// e.g. "My Web Server._http._tcp.local".
	Name dns.Name
	// Host is the hostname in wire format, e.g. "mydevice.local".
	Host dns.Name
	// Addr is the IPv4 address for the A record.
	Addr [4]byte
	// Port is the TCP/UDP port for the SRV record.
	Port uint16
	// TTL is the record TTL in seconds. Zero uses DefaultTTL.
	TTL uint32
	// TXTData is raw TXT record data (length-prefixed strings).
	TXTData []byte
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

// Querier/Responder states.

type querierState uint8

const (
	querierIdle          querierState = iota
	querierSendQuery                  // Query ready to be sent.
	querierAwaitResponse              // Waiting for answers.
	querierDone                       // Answers collected.
)

type responderState uint8

const (
	responderIdle     responderState = iota
	responderProbing                 // Probing for name uniqueness (RFC 6762 §8.1).
	responderAnnounce                // Sending unsolicited announcements.
	responderReady                   // Stable, answering incoming queries.
)

var (
	errNoServices = errors.New("mdns: no services configured")
	errNoQuery    = errors.New("mdns: no query questions provided")
)
