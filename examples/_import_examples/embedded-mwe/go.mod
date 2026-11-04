module embeddedmwe

go 1.26.0

require (
	github.com/soypat/cyw43439 v0.2.0
	github.com/soypat/lneto v0.4.0
	tinygo.org/x/espradio v0.5.0
)

require (
	github.com/soypat/seqs v0.0.0-20260125140838-2c1c6b1bd69e // indirect
	github.com/tinygo-org/pio v0.3.0 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
)

// These replace directives point to local checkouts during development.
// Remove them when using as a standalone program with published releases.
replace github.com/soypat/lneto => ../../../.
