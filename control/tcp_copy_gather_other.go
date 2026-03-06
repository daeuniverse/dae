//go:build !linux
// +build !linux

package control

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
)

func tryRelayGatherWrite(_ context.Context, _ netproxy.Conn, _ netproxy.Conn) (written int64, err error, ok bool) {
	return 0, nil, false
}
