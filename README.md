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
    - [`lneto/frames.go`](./lneto/frames.go): Ethernet, IPv4/IPv6, ARP, TCP, UDP packet marshalling/unmarshalling.

- [`lneto/tcp`](./lneto/ntp): TCP implementation and low level logic.
- [`lneto/dhcp`](./lneto/dhcp): DHCP protocol implementation and low level logic.
- [`lneto/dns`](./lneto/dns): DNS protocol implementation and low level logic.
- [`lneto/ntp`](./lneto/ntp): NTP implementation and low level logic. Includes NTP time primitive manipulation and conversion to Go native types.


## Install
How to install package with newer versions of Go (+1.16):
```sh
go mod download github.com/soypat/lneto@latest
```



