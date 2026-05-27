module espradio-netdev

go 1.25.7

// These replace directives point to local checkouts during development.
// Remove them when using as a standalone program with published releases.
replace github.com/soypat/lneto => ../../../.

replace tinygo.org/x/espradio => ../../../../espradio

require (
	github.com/soypat/lneto v0.1.1-0.20260425023453-aa77403a2b32
	tinygo.org/x/espradio v0.1.0
)
