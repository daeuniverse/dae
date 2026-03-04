//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

const (
	relayCopyBufferSize = 32 << 10
)

var relayCopyBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, relayCopyBufferSize)
	},
}

func relayAdaptiveCopy(_ context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	// If src implements io.WriterTo (e.g. ConnSniffer), let io.Copy drive it.
	// ConnSniffer.WriteTo flushes the sniff buffer then forwards with a per-relay
	// buffer; ConnSniffer.ReadFrom (if dst is sniffer) uses copyDirect with its
	// own per-relay buf to bypass net.TCPConn.ReadFrom's internal allocation.
	if _, ok := src.(io.WriterTo); ok {
		return io.Copy(dst, src)
	}
	// Reuse relay buffer to reduce per-connection heap churn.
	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}
