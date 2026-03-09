//go:build !linux
// +build !linux

package control

import (
	"context"
	"io"

	"github.com/daeuniverse/outbound/netproxy"
)

func relayAdaptiveCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return defaultRelayCopyEngine{}.Copy(ctx, dst, src)
}

func relayFastCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
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
	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

func shouldUseRelayFastPath(_ netproxy.Conn, _ netproxy.Conn) bool {
	return false
}
