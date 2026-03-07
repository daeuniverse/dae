//go:build !linux
// +build !linux

package control

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
)

func (c *ControlPlane) tryOffloadTCPRelay(_ context.Context, _ netproxy.Conn, _ netproxy.Conn) (bool, string, error) {
	return false, "platform unsupported", nil
}
