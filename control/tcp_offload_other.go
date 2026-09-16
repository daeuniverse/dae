//go:build !linux

package control

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
)

func (c *ControlPlane) tryOffloadTCPRelay(_ context.Context, _ netproxy.Conn, _ netproxy.Conn, _ func(int64), _ func(int64)) (bool, string, error) {
	return false, "platform unsupported", nil
}
