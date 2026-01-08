# lneto
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/lneto)](https://pkg.go.dev/github.com/soypat/lneto)
[![Go Report Card](https://goreportcard.com/badge/github.com/soypat/lneto)](https://goreportcard.com/report/github.com/soypat/lneto)
[![codecov](https://codecov.io/gh/soypat/lneto/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/lneto)
[![Go](https://github.com/soypat/lneto/actions/workflows/go.yml/badge.svg)](https://github.com/soypat/lneto/actions/workflows/go.yml)
[![sourcegraph](https://sourcegraph.com/github.com/soypat/lneto/-/badge.svg)](https://sourcegraph.com/github.com/soypat/lneto?badge)

Userspace networking primitives. 

`lneto` is pronounced "L-net-oh", a.k.a. "El Neto"; a.k.a. "Don Networkio"; a.k.a "Neto, connector of worlds".

## Features
`lneto` provides the following features:
- Heapless packet processing
    - [`httpraw`](https://github.com/soypat/lneto/tree/main/http/httpraw) is likely the most performant HTTP/1.1 processing package in the Go ecosystem. Based on [`fasthttp`](https://github.com/valyala/fasthttp) but simpler and more thoughtful memory use.
- Lean memory footprint
    - HTTP header struct is 80 bytes with no runtime usage nor heap usage other than buffer
    - Entire Ethernet+IPv4+UDP+DHCP+DNS+NTP stack in ~1kB.
- Empty go.mod file. No dependencies except for basic standard library packages such as `bytes`, `errors`, `io`.
    - `net` only imported for `net.ErrClosed`.
    - Can produce **very** small binaries. Ideal for embedded systems.
- Extremely simple networking stack construction. Can be used to teach basics of networking
    - Only one networking interface fulfilled by all implementations. See [abstractions](#abstractions).

## `xcurl` example
You may try lneto out on linux with the [xcurl example](./examples/xcurl/) which gets an HTTP page by doing all the low-level networking part using absolutely no standard library. 

- DHCP client address lease
- ARP address resolution
- DNS address resolution of requested host
- HTTP over TCP/IPv4/Ethernet connection using
- NTP time check (optional)
- Print packet captures using lneto's [internet/pcap](./internet/pcap) package 

See Developing section below for more information.

## Why?(!)
`lneto` was created to have networking on systems with a networking interface (wifi or ethernet cable) but no operating-system provided networking facilties. 

#### Use Case: Raspberry Pi Pico W
[Raspberry Pi Pico W](https://www.raspberrypi.com/documentation/microcontrollers/pico-series.html), a microcontroller with a wifi chip. One can program these microcontrollers using [TinyGo](https://tinygo.org/). To have access to the wifi interface one must use a driver for the on-board wifi chip called the CYW43439. The driver is available at [`soypat/cyw43439`](https://github.com/soypat/cyw43439) with examples in the [`examples`](https://github.com/soypat/cyw43439/tree/main/examples) directory. At the time of writing this the predecessor library [seqs](https://github.com/soypat/seqs) is still the go-to library to program the Pico W with [plans to replace it soon](https://github.com/soypat/cyw43439/pull/63).

**Why run Go on a Raspberry Pi Pico instead of on a fully OS features Raspberry Pi 3/4/5?** I answer this question in my [talk at Gophercon](https://youtu.be/CQJJ6KS-PF4?si=RgEOYzpUZu-bX_QT&t=1313).

#### Use Case: net package replacement
If you can use the `net` package, use it. Need something faster and less-heap allocating, use [`fasthttp`](https://github.com/valyala/fasthttp). Need something that does not heap allocate at all and that is marginally faster, OK, **maybe** `lneto` is for you. If you do use `lneto` do consider it is in early development!

#### Use Case: gopacket package replacement
`gopacket` is fully featured, mature and can do BPF hooks. If you need extensive packet decoding facilities, consider using gopacket instead of `lneto`. If you need something simpler, easier to use and even more low level, lneto may be for you. `lneto`'s packet decoding is VERY flexible and provides features for bit-by-bit interpreting. That said, lneto is in early development and you may need to implement some packet processing features yourself!


## Packages
- `lneto`: Low-level Networking Operations, or "El Neto", the networking package. Zero copy network frame marshalling and unmarshalling.
    - [`lneto/validation.go`](./validation.go): Packet validation utilities
- [`lneto/internet`](./internet): Userspace IP/TCP networking stack. This is where the magic happens. Integrates many of the listed packages.
    - [`lneto/internet/pcap`](./internal/pcap): Packet capture and field breakdown utilities. Wireshark in the making.
- [`lneto/http/httpraw`](./http/httpraw/): Heapless HTTP header processing and validation. Does no implement header normalization.
- [`lneto/tcp`](./ntp): TCP implementation and low level logic.
- [`lneto/dhcpv4`](./dhcpv4): DHCP version 4 protocol implementation and low level logic.
- [`lneto/dns`](./dns): DNS protocol implementation and low level logic.
- [`lneto/ntp`](./ntp): NTP implementation and low level logic. Includes NTP time primitives manipulation and conversion to Go native types.
- [`lneto/internal`](./internal): Lightweight and flexible ring buffer implementation and debugging primitives.
- [`lneto/x`](./x): Experimental packages.
    - [`lneto/x/xnet`](./x/xnet/): `net` package like abstractions of stack implementations for ease of reuse. Still in testing phase and likely subject to breaking API change.

### Abstractions
The following interface is implemented by networking stack nodes and the stack themselves.

```go
type StackNode interface {
    // Encapsulate receives a buffer the receiver must fill with data. 
    // The receiver's start byte is at carrierData[offsetToFrame].
	Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error)
	// Demux receives a buffer the receiver must decode and pass on to corresponding child StackNode(s).
    // The receiver's start byte is at carrierData[offsetToFrame].
	Demux(carrierData []byte, offsetToFrame int) error
    // LocalPort returns the port of the node if applicable or zero. Used for UDP/TCP nodes.
	LocalPort() uint16
    // Protocol returns the protocol of this node if applicable or zero. Usually either a ethernet.Type (EtherType) or lneto.IPProto (IP Protocol number).
	Protocol() uint64
    // ConnectionID returns a pointer to the connection ID of the StackNode.
    // A change in the ID means the node is no longer valid and should be discarded.
    // A change in the ID could mean the connection was closed by the user or that the node will not send nor receive any more data over said connection ID.
	ConnectionID() *uint64
}
```

## Install
How to install package with newer versions of Go (+1.16):
```sh
go mod download github.com/soypat/lneto@latest
```


## Developing (linux)

- [`examples/httptap`](./examples/httptap) (linux only, root privilidges required) Program opens a TAP interface and assigns an IP address to it and exposes the interface via a HTTP interface. This program is run with root privilidges to facilitate debugging of lneto since no root privilidges are required to interact with the HTTP interface exposed.
    - `POST http://127.0.0.1:7070/send`: Receives a POST with request body containing JSON string of data to send over TAP interface. Response contains only status code.
    - `GET http://127.0.0.1:7070/recv`: Receives a GET request. Response contains a JSON string of oldest unread TAP interface packet. If string is empty then there is no more data to read.

- [`xcurl`](./examples/xcurl) Contains example of a application that uses lneto and can attach to a linux tap/bridge interface or a [httptap](./examples/httptap)(with -ihttp flag) to work. When using httptap can be run as non-root user to be debugged comfortably. 
    - Example: `go run ./examples/xcurl -host google.com -ihttp`

### Quick run xcurl
Run xcurl over httptap interface. Requires running two programs in separate shell/consoles in linux:
```sh
# Build+Run HTTP Tap server from one shell, this will expose the `tap0` TAP interface over an HTTP interface at http://127.0.0.1:7070 on /recv and /send endpoints.
go build ./examples/httptap && sudo ./httpap
```
No privilidge escalation required for xcurl using `-ihttp` flag which taps using `httptap`:
```sh
go run ./examples/xcurl -host google.com -ihttp
```



### Wireshark and Packet Capture API
Using the provided method of interfacing mean's you'll always be able to easily reach the TAP interface on your machine over HTTP from any process, be it Python or Go. To visualize the packets over the interface we suggest using **Wireshark** and selecting the `tap0` interface which will show all activity over the HTTP TAP interface created with [`./examples/httptap`](./examples/httptap/main.go).

Alternatively there's the [`internet/pcap`](./internet/pcap) package that does the same thing as Wireshark but as a Go API. Here's the result of running xcurl example with pcap logging:


```log
go run ./examples/xcurl -host google.com -ihttp -ntp
softrand 1767229198
NIC hardware address: d8:5e:d3:43:03:eb bridgeHW: d8:5e:d3:43:03:eb mtu: 1500 addr: 192.168.1.53/24
OUT 328 [Ethernet len=14; destination=ff:ff:ff:ff:ff:ff; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=255.255.255.255 | UDP [RFC768] len=8; (Source port)=68; (Destination port)=67 | DHCPv4 len=285; op=1; Flags=0x0000; (Client Address)=us; (Offered Address)=us; (Server Next Address)=255.255.255.255; (Relay Agent Address)=us; (Client Hardware Address)=d85e:d343:3eb::]
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=192.168.1.53 | ICMP [RFC792] len=64]
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=192.168.1.53 | ICMP [RFC792] len=64]
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=192.168.1.53 | ICMP [RFC792] len=64]
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=192.168.1.53 | ICMP [RFC792] len=64]
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=192.168.1.53 | ICMP [RFC792] len=64]
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=192.168.1.53 | ICMP [RFC792] len=64]
IN   60 [Ethernet len=14; destination=ff:ff:ff:ff:ff:ff; source=e8:4d:74:9f:61:4a | ARP len=28; op=1; (Sender hardware address)=e8:4d:74:9f:61:4a; (Sender protocol address)=192.168.1.1; (Target hardware address)=00:00:00:00:00:00; (Target protocol address)=192.168.1.53]
IN  590 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x0000; source=192.168.1.1; destination=192.168.1.53 | UDP [RFC768] len=8; (Source port)=67; (Destination port)=68 | DHCPv4 len=273; op=2; Flags=0x0000; (Client Address)=us; (Offered Address)=192.168.1.53; (Server Next Address)=us; (Relay Agent Address)=us; (Client Hardware Address)=d85e:d343:3eb::]
OUT 326 [Ethernet len=14; destination=ff:ff:ff:ff:ff:ff; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=255.255.255.255 | UDP [RFC768] len=8; (Source port)=68; (Destination port)=67 | DHCPv4 len=283; op=1; Flags=0x0000; (Client Address)=us; (Offered Address)=192.168.1.53; (Server Next Address)=us; (Relay Agent Address)=us; (Client Hardware Address)=d85e:d343:3eb::]
IN  590 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x0000; source=192.168.1.1; destination=192.168.1.53 | UDP [RFC768] len=8; (Source port)=67; (Destination port)=68 | DHCPv4 len=273; op=2; Flags=0x0000; (Client Address)=us; (Offered Address)=192.168.1.53; (Server Next Address)=us; (Relay Agent Address)=us; (Client Hardware Address)=d85e:d343:3eb::]
[119ms] DHCP request completed
2025/12/31 21:59:58 INFO dhcp-complete assignedIP=192.168.1.53 routerIP=192.168.1.1 DNS=[192.168.1.1] subnet=192.168.1.0/24
OUT  42 [Ethernet len=14; destination=ff:ff:ff:ff:ff:ff; source=us | ARP len=28; op=1; (Sender hardware address)=us; (Sender protocol address)=us; (Target hardware address)=00:00:00:00:00:00; (Target protocol address)=192.168.1.1]
IN   60 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | ARP len=28; op=2; (Sender hardware address)=e8:4d:74:9f:61:4a; (Sender protocol address)=192.168.1.1; (Target hardware address)=us; (Target protocol address)=us]
[1.1s] Router ARP resolution
IN   60 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | ARP len=28; op=1; (Sender hardware address)=e8:4d:74:9f:61:4a; (Sender protocol address)=192.168.1.1; (Target hardware address)=00:00:00:00:00:00; (Target protocol address)=us]
OUT  42 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | ARP len=28; op=2; (Sender hardware address)=us; (Sender protocol address)=us; (Target hardware address)=e8:4d:74:9f:61:4a; (Target protocol address)=192.168.1.1]
OUT  83 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=192.168.1.1 | UDP [RFC768] len=8; (Source port)=57216; (Destination port)=53 | DNS len=41]
IN  147 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=us | UDP [RFC768] len=8; (Source port)=53; (Destination port)=57216 | DNS len=105]
[3.5s] NTP IP lookup
OUT  90 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=170.210.222.10 | UDP [RFC768] len=8; (Source port)=1023; (Destination port)=123 | NTP len=48; (Reference Time)=1900-01-01T00:00:00; (Origin Time)=1900-01-01T00:00:00; (Receive Time)=1900-01-01T00:00:00; (Transit Time)=1900-01-01T00:00:00]
IN   90 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x0000; source=170.210.222.10; destination=us | UDP [RFC768] len=8; (Source port)=123; (Destination port)=1023 | NTP len=48; (Reference Time)=2026-01-01T00:43:04; (Origin Time)=1900-01-01T00:00:00; (Receive Time)=2026-01-01T01:00:03; (Transit Time)=2026-01-01T01:00:03]
[786ms] NTP exchange
NTP completed. You are 11.493283ms ahead of the NTP server
OUT  81 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=192.168.1.1 | UDP [RFC768] len=8; (Source port)=56316; (Destination port)=53 | DNS len=39]
IN   97 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=us | UDP [RFC768] len=8; (Source port)=53; (Destination port)=56316 | DNS len=55]
[1s] resolve google.com
DNS resolution of "google.com" complete and resolved to [142.251.129.142]
[10µs] create HTTP GET request
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=us | ICMP [RFC792] len=64]
OUT  58 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=142.251.129.142 | TCP [RFC9293] len=24; (Source port)=51982; (Destination port)=80; flags=SYN]
IN   98 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=192.168.1.1; destination=us | ICMP [RFC792] len=64]
IN   60 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=142.251.129.142; destination=us | TCP [RFC9293] len=24; (Source port)=80; (Destination port)=51982; flags=SYN,ACK | payload? len=2]
OUT  54 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=142.251.129.142 | TCP [RFC9293] len=20; (Source port)=51982; (Destination port)=80; flags=ACK]
[646ms] TCP dial (handshake)
[5µs] send HTTP request
OUT 161 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=142.251.129.142 | TCP [RFC9293] len=20; (Source port)=51982; (Destination port)=80; flags=PSH,ACK | HTTP len=107]
IN   60 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x0000; source=142.251.129.142; destination=us | TCP [RFC9293] len=20; (Source port)=80; (Destination port)=51982; flags=ACK | payload? len=6]
IN  846 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x0000; source=142.251.129.142; destination=us | TCP [RFC9293] len=20; (Source port)=80; (Destination port)=51982; flags=PSH,ACK | HTTP len=792]
IN   60 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x0000; source=142.251.129.142; destination=us | TCP [RFC9293] len=20; (Source port)=80; (Destination port)=51982; flags=FIN,ACK | payload? len=6]
IN  804 [Ethernet len=14; destination=us; source=e8:4d:74:9f:61:4a | IPv4 len=20; (Type of Service)=0x00; flags=0x0000; source=142.251.129.142; destination=us | TCP [RFC9293] len=20; (Source port)=80; (Destination port)=51982; flags=ACK | HTTP len=750]
OUT  54 [Ethernet len=14; destination=e8:4d:74:9f:61:4a; source=us | IPv4 len=20; (Type of Service)=0x00; flags=0x4000; source=us; destination=142.251.129.142 | TCP [RFC9293] len=20; (Source port)=51982; (Destination port)=80; flags=ACK]
[2.9s] recv http request
HTTP/1.1 301 Moved Permanently
Location: http://www.google.com/
Content-Type: text/html; charset=UTF-8
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-v-ysoE0WjLlAMlo2ek5UrA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
Date: Thu, 01 Jan 2026 01:00:08 GMT
Expires: Sat, 31 Jan 2026 01:00:08 GMT
Cache-Control: public, max-age=2592000
Server: gws
Content-Length: 219
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Connection: close

<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
success
```