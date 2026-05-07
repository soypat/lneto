package dns

// ClientTCP is a
type ClientTCP struct {
	c         Client
	responses []struct {
		txid   uint16
		msglen uint16
		done   bool
		msg    Message
	}
	buf []byte
}
