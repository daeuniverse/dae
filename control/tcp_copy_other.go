//go:build !linux

package control

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
)

func relayFastCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64)) (int64, error) {
	// Non-Linux platforms: always use buffered copy.
	// Check context cancellation before starting copy.
	// relayCore.run ensures ctx is never nil, but keep nil check for direct callers.
	if ctx != nil {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
	}
	bufPtr := relayCopyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayCopyBufferPool.Put(bufPtr)
	return relayCopyLoop(ctx, dst, src, buf, record)
}

func shouldUseRelayFastPath(_ netproxy.Conn, _ netproxy.Conn) bool {
	return false
}
