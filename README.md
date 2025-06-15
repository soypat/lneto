# lneto
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/lneto)](https://pkg.go.dev/github.com/soypat/lneto)
[![Go Report Card](https://goreportcard.com/badge/github.com/soypat/lneto)](https://goreportcard.com/report/github.com/soypat/lneto)
[![codecov](https://codecov.io/gh/soypat/lneto/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/lneto)
[![Go](https://github.com/soypat/lneto/actions/workflows/go.yml/badge.svg)](https://github.com/soypat/lneto/actions/workflows/go.yml)
[![sourcegraph](https://sourcegraph.com/github.com/soypat/lneto/-/badge.svg)](https://sourcegraph.com/github.com/soypat/lneto?badge)

Userspace networking primitives. 

`lneto` is pronounced "L-net-oh", a.k.a. "El Neto"; a.k.a. "Don Networkio"; a.k.a "Neto, connector of worlds".

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

### Abstractions
The following interface is implemented by networking stack nodes and the stack themselves.

```go
type StackNode interface {
    // Encapsulate receives a buffer the receiver must fill with data. 
    // The receiver's start byte is at carrierData[frameOffset].
	Encapsulate(carrierData []byte, frameOffset int) (int, error)
	// Demux receives a buffer the receiver must decode and pass on to corresponding child StackNode(s).
    // The receiver's start byte is at carrierData[frameOffset].
	Demux(carrierData []byte, frameOffset int) error
    // LocalPort returns the port of the node if applicable or zero. Used for UDP/TCP nodes.
	LocalPort() uint16
    // Protocol returns the protocol of this node if applicable or zero. Usually either a ethernet.Type (EtherType) or lneto.IPProto (IP Protocol number).
	Protocol() uint64
    // ConnectionID returns a pointer to the connection ID of the StackNode.
    // A change in the ID means the node is no longer valid and should be discarded.
    // A change in the ID could mean the connection was closed by the user or that the node will not send nor receive any more data over said connection ID.
	ConnectionID() *uint64
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

