package mdns

import (
	"net"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
)

// Responder answers incoming mDNS queries for registered services.
// It implements the [internet.StackNode] interface via Encapsulate/Demux.
type Responder struct {
	connID   uint64
	state    responderState
	pending  int
	services []Service
	msg      dns.Message
	auxbuf   [512]byte
}

// Configure resets and configures the responder with the given services.
// The responder transitions to responderReady and will answer queries
// matching the configured service names.
func (r *Responder) Configure(services []Service) error {
	if len(services) == 0 {
		return errNoServices
	}
	r.connID++
	r.state = responderReady
	r.pending = 0
	r.msg.Reset()
	r.services = append(r.services[:0], services...)
	return nil
}

// Demux processes an incoming mDNS query packet.
// It matches questions against registered services and prepares
// response records as pending for the next Encapsulate call.
func (r *Responder) Demux(carrierData []byte, frameOffset int) error {
	if r.state == responderIdle {
		return net.ErrClosed
	} else if r.state != responderReady {
		return nil
	}
	frame := carrierData[frameOffset:]
	f, err := dns.NewFrame(frame)
	if err != nil {
		return err
	}
	flags := f.Flags()
	if flags.IsResponse() {
		return nil // Ignore responses.
	}

	// Decode the incoming query.
	var query dns.Message
	nq := f.QDCount()
	query.LimitResourceDecoding(nq, 0, 0, 0)
	_, _, err = query.Decode(frame)
	if err != nil {
		return err
	}

	// Match questions against our services.
	r.msg.Reset()
	matched := false
	for i := range query.Questions {
		q := &query.Questions[i]
		for j := range r.services {
			if r.matchQuestion(q, &r.services[j]) {
				r.addServiceAnswers(q, &r.services[j])
				matched = true
			}
		}
	}
	if matched {
		r.pending++
	}
	return nil
}

// Encapsulate writes a pending mDNS packet into carrierData[offsetToFrame:].
// When in the ready state, the packet is a response with QR=1, AA=1.
// When probing, the packet is a query with QR=0.
func (r *Responder) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if r.state == responderIdle {
		return 0, net.ErrClosed
	}
	if r.pending == 0 {
		return 0, nil // Nothing to send.
	}

	msg := &r.msg
	frame := carrierData[offsetToFrame:]
	msglen := msg.Len()
	if int(msglen) > len(frame) {
		return 0, lneto.ErrShortBuffer
	}

	var flags dns.HeaderFlags
	if r.state != responderProbing {
		// mDNS responses: txid=0, QR=1, AA=1 (RFC 6762 §18.4, §6).
		flags = dns.HeaderFlags(1<<15 | 1<<10)
	}
	data, err := msg.AppendTo(frame[:0], 0, flags)
	if err != nil {
		return 0, err
	}
	r.pending--
	if r.pending == 0 {
		r.msg.Reset()
	}
	return len(data), nil
}

// Announce triggers an unsolicited announcement of all registered services.
// The announcement is sent on the next Encapsulate call.
func (r *Responder) Announce() {
	if r.state != responderReady {
		return
	}
	r.msg.Reset()
	for i := range r.services {
		svc := &r.services[i]
		// Announce all record types for each service.
		r.addAllRecords(svc)
	}
	r.pending++
}

// Probe initiates the probing sequence for name uniqueness (RFC 6762 §8.1).
// The probe query is sent on the next Encapsulate call. After probing
// completes (caller manages timing), call [Responder.FinishProbe] to
// transition to the ready state.
func (r *Responder) Probe() {
	if r.state == responderIdle {
		return
	}
	r.state = responderProbing
	r.msg.Reset()
	// Build probe: QU questions for each service's host name, with
	// proposed records in the Authority section (RFC 6762 §8.1).
	for i := range r.services {
		svc := &r.services[i]
		q := dns.Question{
			Type:  dns.TypeALL,
			Class: dns.ClassINET,
		}
		q.Name.CopyFrom(svc.Host)
		r.msg.AddQuestions([]dns.Question{q})
	}
	r.pending++
}

// FinishProbe transitions from probing to the announce+ready state.
// The caller is responsible for verifying that no conflicting responses
// were received during the probe period.
func (r *Responder) FinishProbe() {
	if r.state == responderProbing {
		r.state = responderReady
		r.Announce()
	}
}

// State returns the current responder state.
func (r *Responder) State() responderState { return r.state }

// Reset clears all state for reuse.
func (r *Responder) Reset() {
	r.connID++
	r.state = responderIdle
	r.pending = 0
	r.msg.Reset()
	r.services = r.services[:0]
}

// Protocol returns the IP protocol number (UDP).
func (r *Responder) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }

// LocalPort returns the mDNS port 5353.
func (r *Responder) LocalPort() uint16 { return Port }

// ConnectionID returns a pointer to the connection ID for stack invalidation.
func (r *Responder) ConnectionID() *uint64 { return &r.connID }

// matchQuestion reports whether the question matches the given service.
func (r *Responder) matchQuestion(q *dns.Question, svc *Service) bool {
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

// addServiceAnswers adds the appropriate answer records for a matched question.
func (r *Responder) addServiceAnswers(q *dns.Question, svc *Service) {
	switch q.Type {
	case dns.TypePTR:
		r.addPTRRecord(svc)
	case dns.TypeSRV:
		r.addSRVRecord(svc)
		r.addARecord(svc) // Include A as additional.
	case dns.TypeTXT:
		r.addTXTRecord(svc)
	case dns.TypeA:
		r.addARecord(svc)
	case dns.TypeALL:
		r.addAllRecords(svc)
	}
}

// addAllRecords adds PTR, SRV, TXT, and A records for a service.
func (r *Responder) addAllRecords(svc *Service) {
	r.addPTRRecord(svc)
	r.addSRVRecord(svc)
	r.addTXTRecord(svc)
	r.addARecord(svc)
}

// addPTRRecord adds a PTR record pointing from the service type to the instance name.
func (r *Responder) addPTRRecord(svc *Service) {
	svcType := svc.serviceType()
	// PTR data is the instance name in wire format.
	nameData := r.auxbuf[:0]
	nameData, _ = svc.Name.AppendTo(nameData)
	rsc := dns.NewResource(svcType, dns.TypePTR, dns.ClassINET, svc.ttl(), nameData)
	r.msg.Answers = append(r.msg.Answers, rsc)
}

// addSRVRecord adds a SRV record for the service.
func (r *Responder) addSRVRecord(svc *Service) {
	buf := r.auxbuf[:]
	n, err := encodeSRVData(buf, 0, 0, svc.Port, svc.Host)
	if err != nil {
		return
	}
	class := dns.Class(uint16(dns.ClassINET) | classCacheFlush)
	rsc := dns.NewResource(svc.Name, dns.TypeSRV, class, svc.ttl(), buf[:n])
	r.msg.Answers = append(r.msg.Answers, rsc)
}

// addTXTRecord adds a TXT record for the service.
func (r *Responder) addTXTRecord(svc *Service) {
	txtData := svc.TXTData
	if len(txtData) == 0 {
		txtData = []byte{0} // Empty TXT record has single zero-length string.
	}
	class := dns.Class(uint16(dns.ClassINET) | classCacheFlush)
	rsc := dns.NewResource(svc.Name, dns.TypeTXT, class, svc.ttl(), txtData)
	r.msg.Answers = append(r.msg.Answers, rsc)
}

// addARecord adds an A record for the service's host.
func (r *Responder) addARecord(svc *Service) {
	class := dns.Class(uint16(dns.ClassINET) | classCacheFlush)
	rsc := dns.NewResource(svc.Host, dns.TypeA, class, svc.ttl(), svc.Addr[:])
	r.msg.Answers = append(r.msg.Answers, rsc)
}