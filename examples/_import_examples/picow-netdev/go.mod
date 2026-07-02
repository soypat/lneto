module piconetdev

go 1.25.7

require (
	github.com/soypat/cyw43439 v0.1.1
	github.com/soypat/lneto v0.1.1-0.20260425023453-aa77403a2b32
)

require (
	github.com/soypat/seqs v0.0.0-20250124201400-0d65bc7c1710 // indirect
	github.com/tinygo-org/pio v0.2.0 // indirect
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa // indirect
)

// This is an example taken grom github.com/soypat/lneto
// Remove this replace directive when using as own program.
replace github.com/soypat/lneto => ../../../.

// Local cyw43439 with the poll-based EthPoll API.
replace github.com/soypat/cyw43439 => ../../../../cyw43439
