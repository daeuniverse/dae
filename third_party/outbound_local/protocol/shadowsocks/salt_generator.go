package shadowsocks

import (
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
)

type SaltGenerator interface {
	Get() []byte
	Close() error
}

type RandomSaltGenerator struct {
	saltSize int
}

func NewRandomSaltGenerator(saltSize int) (*RandomSaltGenerator, error) {
	return &RandomSaltGenerator{
		saltSize: saltSize,
	}, nil
}

func (g *RandomSaltGenerator) Get() []byte {
	salt := pool.Get(g.saltSize)
	_, _ = fastrand.Read(salt)
	return salt
}

func (g *RandomSaltGenerator) Close() error {
	return nil
}
