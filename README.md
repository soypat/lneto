# tseq
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/tseq)](https://pkg.go.dev/github.com/soypat/tseq)
[![Go Report Card](https://goreportcard.com/badge/github.com/soypat/tseq)](https://goreportcard.com/report/github.com/soypat/tseq)
[![codecov](https://codecov.io/gh/soypat/tseq/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/tseq)
[![Go](https://github.com/soypat/tseq/actions/workflows/go.yml/badge.svg)](https://github.com/soypat/tseq/actions/workflows/go.yml)
[![sourcegraph](https://sourcegraph.com/github.com/soypat/tseq/-/badge.svg)](https://sourcegraph.com/github.com/soypat/tseq?badge)

Userspace networking primitives.

## Packages
- `lneto`: Low-level Networking Operations, or "El Neto", the big networking package. Zero copy network frame marshalling and unmarshalling.
    - [`lneto/frames.go`](./lneto/frames.go): Ethernet, IPv4/IPv6, ARP, TCP, UDP packet marshalling/unmarshalling.

- [`lneto/tcp`](./lneto/ntp): TCP implementation and low level logic.
- [`lneto/dhcp`](./lneto/dhcp): DHCP protocol implementation and low level logic.
- [`lneto/dns`](./lneto/dns): DNS protocol implementation and low level logic.
- [`lneto/ntp`](./lneto/ntp): NTP implementation and low level logic. Includes NTP time primitive manipulation and conversion to Go native types.


## Install
How to install package with newer versions of Go (+1.16):
```sh
go mod download github.com/soypat/tseq@latest
```



