# espradio AP mode: DHCP server never answers DISCOVER

Diagnosis of `espradio.log` (ESP32 running `espradio` AP + `dhcpv4.Server`).

## Symptom

A client (`e4:c7:67:65:0e:46`) broadcasts DHCP DISCOVER every few seconds and is
never answered. Log shows only `IN` DHCP frames, never an `OUT` OFFER:

```
21.866 IN  342 Ethernet ... destination=ff:ff:ff:ff:ff:ff ... | IPv4 ... source=0.0.0.0; destination=255.255.255.255 | UDP ... (Source port)=68; (Destination port)=67 | DHCPv4 op=1 ...
24.318 IN  342 ... (Transaction ID)=0x65be2ff3 ...
28.589 IN  342 ... (Transaction ID)=0x503e5f09 ...
36.971 IN  342 ... (Transaction ID)=0x32b12d21 ...
53.928 IN  342 ... (Transaction ID)=0x7922b680 ...
```

Retries with fresh XIDs and growing `secs` (0x0001 → 0x0020) = client never got
an OFFER, i.e. it is standard client backoff, not a malformed reply.

## Cause: espradio side, not lneto

The DISCOVER is destined to `255.255.255.255`. lneto's IPv4 layer drops packets
not addressed to the stack unless broadcast acceptance is on
([internet/stack-ip4.go:109-119](internet/stack-ip4.go#L109-L119)):

```go
if si4.ip4 != ([4]byte{}) && *dst != si4.ip4 {
	switch {
	case si4.acceptMulticast && ipv4.IsMulticast(*dst):
	case si4.acceptBroadcast && ipv4.IsBroadcast(*dst):
	default:
		si4.handlers.debug("ip:not-for-us")
		return lneto.ErrPacketDrop
	}
}
```

`acceptBroadcast` comes only from `xnet.StackConfig.AcceptIPv4Broadcast`
([x/xnet/stack-async.go:250](x/xnet/stack-async.go#L250)). espradio's
`NewStack` builds `xnet.StackConfig` (`espstack.go:59`) and **never sets that
field**, so the flag is false in AP mode too. The DISCOVER dies at the IPv4
layer; `dhcpv4.Server.Demux` is never reached, so nothing is ever pending and
`Encapsulate` emits nothing. The Ethernet layer is not the problem — it accepts
broadcast destinations unconditionally
([internet/stack-ethernet.go:148](internet/stack-ethernet.go#L148)).

Everything else in espradio's AP setup is correct:
`RegisterUDP4(&stack.dhcpSrv, [4]byte{}, dhcpv4.DefaultClientPort)` registers
local port 67 (`Server.LocalPort()`) with remote port 68 and no source-IP filter.

## lneto-side change

None needed beyond tests: `StackConfig.AcceptIPv4Broadcast` already covers this
and espradio knows it is starting an AP before it builds the stack. Regression
tests in [x/xnet/xnet_dhcpserver_test.go](x/xnet/xnet_dhcpserver_test.go):

- `TestDHCPServerAPBroadcastOffer` — broadcast DISCOVER through the full
  Ethernet/IPv4/UDP demux chain; asserts the egress OFFER is unicast to the
  client MAC (over the gateway MAC the Ethernet layer wrote), src=server address,
  dst=offered address, ports 67→68, and both checksums valid despite the server
  writing addresses inside the IPv4 layer's encapsulation.
- `TestDHCPServerAPRequiresBroadcastAccept` — pins the failure in this log: with
  the flag off, `IngressEthernet` returns `ErrPacketDrop` and no reply is produced.

Deliberately not retested here: DORA state machine, address allocation and the
chaddr/ciaddr lookups — `dhcp/dhcpv4`'s own tests own those.

## Fix in espradio

Plumb it through espradio's own `StackConfig` and set it in the `xnet.StackConfig`
built by `NewStack` (`espstack.go:59`):

```go
xcfg := xnet.StackConfig{
	...
	AcceptIPv4Broadcast: cfg.AcceptIPv4Broadcast,
}
```

AP-ness is already known before that call: `netlink/ap.go` reads
`params.EnableDHCPServer` to size `udpPorts` a few lines above `NewStack`, so it
can pass `AcceptIPv4Broadcast: params.EnableDHCPServer` there. Same for
`examples/ap/main-ap.go`, which registers the DHCP server itself.
