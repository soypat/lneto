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

- [`tap`](./examples/tap) (linux only, root privilidges required) Program opens a TAP interface and assigns an IP address to it and exposes the interface via a HTTP interface. This program is run with root privilidges to facilitate debugging of lneto since no root privilidges are required to interact with the HTTP interface exposed.
    - `POST http://127.0.0.1:7070/send`: Receives a POST with request body containing JSON string of data to send over TAP interface. Response contains only status code.
    - `GET http://127.0.0.1:7070/recv`: Receives a GET request. Response contains a JSON string of oldest unread TAP interface packet. If string is empty then there is no more data to read.

- [`stack`](./examples/stack) Contains stack implementation which can interact with `tap` program. No root privilidges required.
    - Can expose a HTTP server.

To run the HTTP TAP server run the following commands. Requires elevated privilidges!
```sh
# Build+Run HTTP Tap server from one shell, this will expose the `tap0` TAP interface over an HTTP interface at http://127.0.0.1:7070 on /recv and /send endpoints.
go build ./examples/tap && sudo ./tap
```

Now run the application you wish to test without elevated privilidges. Stackbasic shows a basic HTTP demo in action.
```sh
go run ./examples/stackbasic
```

**Wireshark**: Using the provided method of interfacing mean's you'll always be able to easily reach the TAP interface on your machine over HTTP from any process, be it Python or Go. To visualize the packets over the interface we suggest using wireshark and selecting the `tap0` interface which will show all activity over the HTTP TAP interface created with [`./examples/tap`](./examples/tap/main.go).

