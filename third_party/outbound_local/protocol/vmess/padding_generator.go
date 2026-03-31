package vmess

type PaddingLengthGenerator interface {
	MaxPaddingLen() uint16
	NextPaddingLen() uint16
}

type PlainPaddingGenerator struct {
	PaddingLengthGenerator
}

func (PlainPaddingGenerator) MaxPaddingLen() uint16 {
	return 0
}

func (PlainPaddingGenerator) NextPaddingLen() uint16 {
	return 0
}
