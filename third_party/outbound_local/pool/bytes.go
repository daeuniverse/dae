package pool

import "github.com/daeuniverse/outbound/common"

type Bytes interface {
	Put()
	Bytes() []byte
	HeadOverlap([]byte) bool
}

type B []byte

func (B) Put() {}
func (b B) Bytes() []byte {
	return b
}
func (b B) HeadOverlap(p []byte) bool {
	return common.HeadOverlap(p, b)
}

type PB []byte

func (b PB) Put() {
	Put(b)
}
func (b PB) Bytes() []byte {
	return b
}
func (b PB) HeadOverlap(p []byte) bool {
	return common.HeadOverlap(p, b)
}
