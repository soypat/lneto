package internet

import "github.com/soypat/lneto"

type PortStack struct {
	handlers []porthandler
	proto    lneto.IPProto
}

type porthandler struct {
	recv   func([]byte, int) error
	handle func([]byte, int) (int, error)
	port   uint16
}
