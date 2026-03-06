/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

const relayCopyBufferSize = 32 << 10

var relayCopyBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, relayCopyBufferSize)
	},
}

// relayCopyEngine defines the pluggable data plane used by relayCore.
// Implementations can optimize copy strategy without changing relay semantics.
type relayCopyEngine interface {
	Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error)
}

type defaultRelayCopyEngine struct{}

func (defaultRelayCopyEngine) Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	if n, err, ok := tryRelayGatherWrite(ctx, dst, src); ok {
		return n, err
	}
	if shouldUseRelayFastPath(dst, src) {
		return relayFastCopy(ctx, dst, src)
	}
	// Slow path: will call Read() on wrapped connections
	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)
	return relayCopyLoop(ctx, dst, src, buf)
}

func relayCopyLoop(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, buf []byte) (written int64, err error) {
	for {
		if ctx != nil {
			if cerr := ctx.Err(); cerr != nil {
				return written, cerr
			}
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}
