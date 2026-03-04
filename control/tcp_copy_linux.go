//go:build linux
// +build linux

package control

import (
	"context"
	"io"

	"github.com/daeuniverse/outbound/netproxy"
)

func relayAdaptiveCopy(_ context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return io.Copy(dst, src)
}
