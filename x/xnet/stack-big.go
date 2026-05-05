package xnet

import (
	"net/netip"
	"sync"

	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcpv4"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv4/icmpv4"
	"github.com/soypat/lneto/ntp"
)

type StackBigAsync struct {
	mu       sync.Mutex
	hostname string
	clientID string
	link     internet.StackEthernet
	ip       internet.StackIP
	arp      arp.Handler
	icmp     icmpv4.Client
	udps     internet.StackPortsMACFiltered
	tcps     internet.StackPortsMACFiltered

	dhcpUDP     internet.StackUDPPort
	dhcp        dhcpv4.Client
	dhcpResults DHCPResults
	arpt        subnetTable

	dnsUDP  internet.StackUDPPort
	dns     dns.Client
	ednsopt dns.Resource
	lookup  dns.Message
	dnssv   netip.Addr

	ntpUDP internet.StackUDPPort
	ntp    ntp.Client

	userUDPs []internet.StackUDPPort

	sysprec int8 // NTP system precision.

	prng uint32

	addrBuf [6]byte // Temporary buffer for As4()/HardwareAddr6() results to avoid heap escapes.

	totalsent uint64
	totalrecv uint64
}
