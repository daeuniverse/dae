//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
)

func (c *ControlPlane) tryOffloadTCPRelay(_ context.Context, _ netproxy.Conn, _ netproxy.Conn, _ func(int64), _ func(int64)) (bool, string, error) {
	return false, "platform unsupported", nil
}
