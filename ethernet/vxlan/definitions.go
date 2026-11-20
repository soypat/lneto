package vxlan

type Flags uint8

const (
	FlagValidVNI = Flags(1 << 3)
)

func (f Flags) ValidVNI() bool {
	return f&FlagValidVNI != 0
}
