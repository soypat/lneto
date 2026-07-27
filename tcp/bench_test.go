package tcp

import (
	"math/rand"
	"testing"

	"github.com/soypat/lneto/ethernet"
)

// benchPayload is the application payload size used by the datapath
// benchmarks. It is small enough to always fit a single segment so the
// benchmarks measure per-segment fixed cost rather than segmentation.
const benchPayload = 512

// benchEstablished returns an established client/server Handler pair and a
// packet buffer sized for a full ethernet MTU.
func benchEstablished(b *testing.B) (client, server *Handler, packetBuf []byte) {
	b.Helper()
	const mtu = ethernet.MaxMTU
	rng := rand.New(rand.NewSource(1))
	client, server = newHandler(b, mtu, 3), newHandler(b, mtu, 3)
	setupClientServer(b, rng, client, server)
	packetBuf = make([]byte, mtu)
	establish(b, client, server, packetBuf)
	return client, server, packetBuf
}

// benchExchange performs one full application-to-application transfer:
// client.Write -> client.Send -> server.Recv -> server.Read, then drains the
// server's ACK back into the client so the connection stays in steady state.
func benchExchange(b *testing.B, client, server *Handler, data, packetBuf, readBuf []byte) {
	n, err := client.Write(data)
	if err != nil {
		b.Fatal("client write:", err)
	} else if n != len(data) {
		b.Fatal("short client write:", n)
	}
	n, err = client.Send(packetBuf)
	if err != nil {
		b.Fatal("client send:", err)
	} else if n == 0 {
		b.Fatal("client sent nothing")
	}
	err = server.Recv(packetBuf[:n])
	if err != nil {
		b.Fatal("server recv:", err)
	}
	n, err = server.Read(readBuf)
	if err != nil {
		b.Fatal("server read:", err)
	} else if n != len(data) {
		b.Fatal("short server read:", n)
	}
	// Drain the server's ACK so the send window does not fill up.
	n, err = server.Send(packetBuf)
	if err != nil {
		b.Fatal("server send:", err)
	}
	if n > 0 {
		err = client.Recv(packetBuf[:n])
		if err != nil {
			b.Fatal("client recv:", err)
		}
	}
}

// BenchmarkHandlerDatapath measures the steady-state cost of moving one
// segment of application data across an established connection with no loss
// recovery installed. This is the plain-TCP datapath that optional policy work
// must not regress.
func BenchmarkHandlerDatapath(b *testing.B) {
	client, server, packetBuf := benchEstablished(b)
	data := make([]byte, benchPayload)
	readBuf := make([]byte, benchPayload)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchExchange(b, client, server, data, packetBuf, readBuf)
	}
}
