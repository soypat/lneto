# lneto
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/lneto)](https://pkg.go.dev/github.com/soypat/lneto)
[![codecov](https://codecov.io/gh/soypat/lneto/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/lneto)
[![Go](https://github.com/soypat/lneto/actions/workflows/ci.yaml/badge.svg)](https://github.com/soypat/lneto/actions/workflows/ci.yaml)
[![sourcegraph](https://sourcegraph.com/github.com/soypat/lneto/-/badge.svg)](https://github.com/soypat/lneto/network/dependents)

Low-level networking operations.

`lneto` is pronounced "L-net-oh", a.k.a. "El Neto"; a.k.a. "Don Networkio"; a.k.a "Neto, connector of worlds".

## Features
`lneto` provides the following features:
- Zero Operating System required. ***Zero***. All protocols (including TCP, excepting NTP) are time-independent.
    - Explicit HAL needed. Lneto performs no `time.Sleep` nor `time.Now` calls unless configured by user.
    - Zero scheduling required. No goroutines/channels use in Lneto. Can be run in event loop.
- Heapless packet processing
    - [`httpraw`](https://github.com/soypat/lneto/tree/main/http/httpraw) is likely the most performant HTTP/1.1 processing package in the Go ecosystem. Based on [`fasthttp`](https://github.com/valyala/fasthttp) but simpler and more thoughtful memory use.
    - [`httφ`](https://github.com/soypat/lneto/tree/main/http/httphi) - Heapless HTTP router and zero-copy response writing with Go's standard library API.
- Lean memory footprint
    - HTTP header struct is 80 bytes with no runtime usage nor heap usage other than buffer
    - Entire Ethernet+IPv4+UDP+DHCP+DNS+NTP stack in ~2kB RAM.
- Empty go.mod file. No dependencies except for basic standard library packages such as `bytes`, `errors`, `io`.
    - `net` only imported for `net.ErrClosed`.
    - Can produce **very** small binaries. Ideal for embedded systems.
- Extremely simple networking stack construction. Can be used to teach basics of networking
    - Only one networking interface fulfilled by all implementations. See [abstractions](#abstractions).
- Stack can be fuzz tested efficiently, see benchmarks below: 
    - `go test ./x/xnet/ -run FuzzStackAsyncHTTP -fuzz=.` fuzzes Ethernet/IP/TCP/HTTP stack with 170k HTTP exchanges per second on 12 core machine: `fuzz: elapsed: 4m9s, execs: 42649941 (169428/sec), new interesting: 5 (total: 52)`
- TLS: Heapless and memory constrained for use on microcontrollers. Not externally audited, use only if you understand the risks!

## Docs and reference
Examples, API reference, protocol support matrix, benchmarks can be found in [`docs`](./docs/) 

## Users
lneto is currently being used primarily by embedded developers and those who need a lighter alternative to gVisor in terms of memory usage and binary size.
- [**Hewlett Packard Enterprise**](https://www.linkedin.com/posts/patriciowhittingslow_thousands-of-servers-will-boot-depending-activity-7508234992238387200-5UTI)([2](https://www.linkedin.com/posts/jean-marie-verdun-5669902_happy-to-be-in-amsterdam-osfc-2026-one-of-activity-7505529081736699905-MOA1)): TCP stack used to stream firmware to datacenter servers at boot time.
- [**9elements**](https://lnkd.in/p/dh-aMbjE): Bootloader networking stack on AST 2700
- [**soypat/cyw43439**](https://github.com/soypat/cyw43439): Enabling internet access on [Raspberry Pi Pico W](https://www.raspberrypi.com/products/raspberry-pi-pico/). See [`examples`](https://github.com/soypat/cyw43439/tree/main/examples).
- [**tinygo-org/espradio**](https://github.com/tinygo-org/espradio): Enabling internet access on [Espressif's ESP32s](https://www.espressif.com/en/products/socs/esp32).
- [**TamaGo**](https://github.com/usbarmory/tamago): Enabling networking on Go baremetal projects. See [go-net project](https://github.com/usbarmory/go-net).
- [**netbird.io**](https://netbird.io/)(planned): Secure remote P2P access.
- [**soypat/lan8720**](https://github.com/soypat/lan8720): Enabling internet access with 100M ethernet PHY devices. 

### Lneto in the media
- **Talk** [FOSDEM26 Networking on Microcontrollers with Go/Lneto](https://www.youtube.com/watch?v=-u0X8MWXkeg) - History of Lneto and the reasoning behind its design
- **Talk** [OSFC26 Running baremetal Go in the AST2700 for simpler server management](https://talks.osfc.io/osfc-2026/talk/UYLY99/) - Running Tamago with Lneto on server hardware, no operating system
- **Talk** [GopherconEU26 Andrea Barisani TamaGo talk](https://social.tinygo.org/@conejo/116759181540883620) - TamaGo showcase mentioning Lneto as a alternative option to gVisor
- **Developer tutorial** [Official Espressif TinyGo Embedded Workshop](https://developer.espressif.com/workshops/tinygo/assignment-5/) - Espressif uses Lneto as the networking stack for ESP32 microcontrollers

## Packages
- `lneto`: Low-level Networking Operations, or "El Neto", the networking package. Zero copy network frame marshalling and unmarshalling.
    - [`lneto/validation.go`](./validation.go): Packet validation utilities
- [`lneto/internet`](./internet): Userspace IP/TCP networking stack. This is where the magic happens. Integrates many of the listed packages.
    - [`lneto/internet/pcap`](./internal/pcap): Packet capture and field breakdown utilities. Wireshark in the making.
- [`lneto/http/httpraw`](./http/httpraw/): Heapless HTTP header processing and validation. Does no implement header normalization.
- [`lneto/tcp`](./tcp): TCP implementation and low level logic.
- [`lneto/ipv4/linklocal4`](./ipv4/linklocal4): RFC 3927 IPv4 link-local (APIPA) address autoconfiguration. Heapless claim-and-defend state machine for self-assigned 169.254.x.x addresses when no DHCP server is available.
- [`lneto/dhcpv4`](./dhcpv4): DHCP version 4 protocol implementation and low level logic.
- [`lneto/dns`](./dns): DNS protocol implementation and low level logic.
- [`lneto/ntp`](./ntp): NTP implementation and low level logic. Includes NTP time primitives manipulation and conversion to Go native types.
- [`lneto/internal`](./internal): Lightweight and flexible ring buffer implementation and debugging primitives.
- [`lneto/x`](./x): Experimental packages.
    - [`lneto/x/xnet`](./x/xnet/): `net` package like abstractions of stack implementations for ease of reuse. Still in testing phase and likely subject to breaking API change.
    - [`lneto/x/nts`](./x/nts/): Network Time Security (RFC 8915). NTS-KE key exchange over TLS 1.3 and AEAD-authenticated NTP client/server. Ships no cryptography itself; the caller supplies the mandated `AEAD_AES_SIV_CMAC_256` `cipher.AEAD` implementation.


### LLM Policy / AI Policy
LLMs are a tool. As such they should be used carefully. The policy for this project is [covered in Oxide's RFD576](https://rfd.shared.oxide.computer/rfd/0576).

Examples of LLM contribution in lneto:
- https://github.com/soypat/lneto/pull/19 and https://github.com/soypat/lneto/pull/18: Egon told me he was using an LLM to find bugs in lneto before submitting these PRs.
- https://github.com/soypat/lneto/commit/6b06cb1237071a0c22f86821db5aaa6135996e98: Writing tests to capture functionality in lneto that has been tested and works.
- https://github.com/soypat/lneto/commit/7042a653a6e46999314c2e36dd5c868bcbc68908: adding mutex locking on tcp.Conn
