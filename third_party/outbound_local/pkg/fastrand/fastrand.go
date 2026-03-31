package fastrand

import (
	"math/rand/v2"

	"github.com/awnumar/fastrand"
)

func Intn(n int) int                   { return rand.IntN(n) }
func Int() int                         { return rand.Int() }
func Int31n(n int32) int32             { return rand.Int32N(n) }
func Int63n(n int64) int64             { return rand.Int64N(n) }
func Uint32() uint32                   { return rand.Uint32() }
func Float64() float64                 { return rand.Float64() }
func Read(p []byte) (n int, err error) { return fastrand.Reader.Read(p) }
