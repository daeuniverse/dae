package netproxy

import "io"

var (
	_ io.Reader = (*ReadWrapper)(nil)
)

type ReadWrapper struct {
	ReadFunc func([]byte) (int, error)
}

func (r *ReadWrapper) Read(p []byte) (n int, err error) {
	return r.ReadFunc(p)
}
