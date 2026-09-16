/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

// relayCopyBufferSize must stay an integer multiple of the anytls
// maxFramePayloadSize (32768 in the pinned outbound fork): a whole read
// buffer handed to stream.Write then chunks into exactly N full frames.
// A non-multiple (e.g. 64 KiB over a 65535-byte frame budget) degrades
// every read into a full frame plus a one-byte tail frame. The fork's
// TestRelayBufferAlignment locks the property on its side; if the pin
// advances and that test breaks the build, retune this constant too.
const relayCopyBufferSize = 32 << 10

var relayCopyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayCopyBufferSize)
		return &b
	},
}

func noopTrafficRecord(int64) {}

func normalizeTrafficRecord(record func(int64)) func(int64) {
	if record == nil {
		return noopTrafficRecord
	}
	return record
}

// relayCopyEngine defines the pluggable data plane used by relayCore.
// Implementations can optimize copy strategy without changing relay semantics.
type relayCopyEngine interface {
	Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64), onActive func(int64)) (int64, error)
}

type defaultRelayCopyEngine struct{}

func (defaultRelayCopyEngine) Copy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64), onActive func(int64)) (int64, error) {
	// First, handle any prefix via gather-write path.
	// This ensures FTP/server-first flows use stable copy loops for continuation.
	if n, err, ok := tryRelayGatherWrite(ctx, dst, src, record, onActive); ok {
		return n, err
	}
	// Fast path for unwrapped TCP pairs: use splice(2) on Linux.
	// Only enabled when both ends resolve to concrete *net.TCPConn without wrappers.
	// This preserves performance for pure TCP-to-TCP relay while keeping FTP safe.
	if shouldUseRelayFastPath(dst, src) {
		return relayFastCopy(ctx, dst, src, record, onActive)
	}
	// Slow path: will call Read() on wrapped connections
	bufPtr := relayCopyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayCopyBufferPool.Put(bufPtr)
	return relayCopyLoop(ctx, dst, src, buf, record, onActive)
}

func relayCopyLoop(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, buf []byte, record func(int64), onActive func(int64)) (written int64, err error) {
	record = normalizeTrafficRecord(record)
	onActive = normalizeTrafficRecord(onActive)
	for {
		// Check context cancellation. relayCore.run ensures ctx is never nil.
		if cerr := ctx.Err(); cerr != nil {
			return written, cerr
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			onActive(int64(nr))
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if nw > 0 {
				record(int64(nw))
				onActive(int64(nw))
			}
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

// relayCopyDirect copies from src to dst using the provided buf. ctx carries
// the owning relay's cancellation so continuation slow paths observe it like
// relayCopyLoop does instead of relying solely on socket close.
// buf must be non-empty and is typically obtained from relayCopyBufferPool.
func relayCopyDirect(ctx context.Context, dst io.Writer, src io.Reader, buf []byte, record func(int64), onActive func(int64)) (written int64, err error) {
	record = normalizeTrafficRecord(record)
	onActive = normalizeTrafficRecord(onActive)
	for {
		// relayCore.run guarantees a non-nil ctx at the interface boundary;
		// tolerate nil defensively for direct callers.
		if ctx != nil {
			if cerr := ctx.Err(); cerr != nil {
				return written, cerr
			}
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			onActive(int64(nr))
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if nw > 0 {
				record(int64(nw))
				onActive(int64(nw))
			}
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
