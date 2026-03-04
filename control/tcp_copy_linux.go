//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
)

func relayAdaptiveCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return defaultRelayCopyEngine{}.Copy(ctx, dst, src)
}

func relayFastCopy(_ context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return io.Copy(dst, src)
}

func shouldUseRelayFastPath(dst netproxy.Conn, src netproxy.Conn) bool {
	return isRelayFastPathWhitelistedConn(dst) && isRelayFastPathWhitelistedConn(src)
}

func isRelayFastPathWhitelistedConn(c netproxy.Conn) bool {
	_, ok := c.(*net.TCPConn)
	return ok
}
