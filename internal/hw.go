package internal

func GetHWAddr(buf []byte) (src, dst [6]byte) {
	copy(src[:], buf[6:12])
	copy(dst[:], buf[0:6])
	return
}

func SetDestHWAddr(buf []byte, dst [6]byte) {
	copy(buf, dst[:])
}
