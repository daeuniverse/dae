//go:build linux
// +build linux

package control

import (
	"context"
	"github.com/daeuniverse/outbound/netproxy"
	"io"
)

func relayAdaptiveCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return defaultRelayCopyEngine{}.Copy(ctx, dst, src)
}

func relayFastCopy(_ context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

func shouldUseRelayFastPath(dst netproxy.Conn, src netproxy.Conn) bool {
	return isRelayFastPathWhitelistedConn(dst) && isRelayFastPathWhitelistedConn(src)
}

func isRelayFastPathWhitelistedConn(c netproxy.Conn) bool {
	_, ok := unwrapRelayTCPConn(c)
	return ok
}
