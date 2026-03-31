package pool

import (
	"sync"

	"github.com/daeuniverse/outbound/pool/bytes"
)

var bufferPool = sync.Pool{New: func() any { return bytes.NewBuffer(nil) }}

func GetBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func PutBuffer(buf *bytes.Buffer) {
	// Prevent slice drift leak for ridiculously large buffers
	if buf.Cap() > 32*1024 {
		return
	}
	buf.Reset()
	bufferPool.Put(buf)
}
