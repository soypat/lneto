package tcp

import (
	"math/rand"
	"testing"
)

func TestHandler(t *testing.T) {

}

func setupClientServer(rng *rand.Rand) (client, server Handler) {

	// err := server.Open(StateListen, uint16(rng.Uint32()), 0, 0)
	// if err != nil {
	// 	panic(err)
	// }
	// err = client.Open(State)
	return client, server
}
