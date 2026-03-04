/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
)

// relayCopyEngine defines the pluggable data plane used by relayCore.
// Implementations can optimize copy strategy without changing relay semantics.
type relayCopyEngine interface {
	Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error)
}

type defaultRelayCopyEngine struct{}

func (defaultRelayCopyEngine) Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return relayAdaptiveCopy(ctx, dst, src)
}
