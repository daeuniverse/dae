//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"net"

	"github.com/daeuniverse/dae/component/sniffing"
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
	// Fast path: direct *net.TCPConn
	if _, ok := c.(*net.TCPConn); ok {
		return true
	}

	// Sniffing path: unwrap ConnSniffer when its underlying connection is TCP.
	if snifferConn, ok := c.(*sniffing.ConnSniffer); ok {
		if _, ok := snifferConn.UnderlyingConn().(*net.TCPConn); ok {
			return true
		}
	}
	return false
}
