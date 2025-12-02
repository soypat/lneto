package internal

type EncData struct {
	RemoteAddr []byte
}

func (ed *EncData) Reset() {
	*ed = EncData{}
}
