package tls

type HelloClientMsg struct {
}

func (d *HelloClientMsg) Decode(buf []byte) (int, error) {
	return 0, nil
}
