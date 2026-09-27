module sshtransport

go 1.26.3

require (
	github.com/soypat/lcrypto v0.0.0-20260926162243-a1194659b688
	github.com/soypat/lneto v0.1.1-0.20260425023453-aa77403a2b32
	golang.org/x/crypto v0.57.0
)

require golang.org/x/sys v0.48.0 // indirect

// This is an example taken grom github.com/soypat/lneto
// Remove this replace directive when using as own program.
replace github.com/soypat/lneto => ../../../.
