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
    - [`lneto/frames.go`](./frames.go): Ethernet, IPv4/IPv6, ARP, TCP, UDP packet marshalling/unmarshalling.

- [`lneto/tcp`](./ntp): TCP implementation and low level logic.
- [`lneto/dhcpv4`](./dhcpv4): DHCP version 4 protocol implementation and low level logic.
- [`lneto/dns`](./dns): DNS protocol implementation and low level logic.
- [`lneto/ntp`](./ntp): NTP implementation and low level logic. Includes NTP time primitives manipulation and conversion to Go native types.
- [`lneto/internal`](./internal): Lightweight and flexible ring buffer implementation and debugging primitives.


## Install
How to install package with newer versions of Go (+1.16):
```sh
go mod download github.com/soypat/lneto@latest
```



