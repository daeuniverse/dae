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

func relayFastCopy(_ context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return io.Copy(dst, src)
}

func shouldUseRelayFastPath(_ netproxy.Conn, _ netproxy.Conn) bool {
	return false
}
