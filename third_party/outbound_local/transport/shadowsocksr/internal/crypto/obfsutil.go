package crypto

import (
	"encoding/binary"
)

type Shift128plusContext struct {
	v [2]uint64
}

func (ctx *Shift128plusContext) InitFromBin(bin []byte) {
	var fillBin [16]byte
	copy(fillBin[:], bin)

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])
}

func (ctx *Shift128plusContext) InitFromBinDatalen(bin []byte, datalen int) {
	var fillBin [16]byte
	copy(fillBin[:], bin)
	binary.LittleEndian.PutUint16(fillBin[:2], uint16(datalen))

	ctx.v[0] = binary.LittleEndian.Uint64(fillBin[:8])
	ctx.v[1] = binary.LittleEndian.Uint64(fillBin[8:])

	for i := 0; i < 4; i++ {
		ctx.Next()
	}
}

func (ctx *Shift128plusContext) Next() uint64 {
	x := ctx.v[0]
	y := ctx.v[1]
	ctx.v[0] = y
	x ^= x << 23
	x ^= y ^ (x >> 17) ^ (y >> 26)
	ctx.v[1] = x
	return x + y
}
