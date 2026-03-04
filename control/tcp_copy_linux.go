//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"sync"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
)

const (
	relaySpliceThreshold = 64 << 10
	relayCopyBufferSize  = 32 << 10
)

var relayCopyBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, relayCopyBufferSize)
	},
}

func relayAdaptiveCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	if _, hasWriterTo := src.(io.WriterTo); hasWriterTo {
		return io.Copy(dst, src)
	}

	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)

	n, err := copyPrefix(ctx, dst, src, buf, relaySpliceThreshold)
	if err != nil {
		return n, err
	}

	if srcConn, ok := src.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		sn, usedSplice, serr := netproxy.SpliceTo(dst, srcConn)
		if usedSplice {
			if serr == nil {
				return n + sn, nil
			}
			// Context cancellation should end relay immediately.
			if ctx.Err() != nil {
				return n + sn, ctx.Err()
			}
			n += sn
		}
	}

	cn, cerr := io.CopyBuffer(dst, src, buf)
	return n + cn, cerr
}

func copyPrefix(ctx context.Context, dst io.Writer, src io.Reader, buf []byte, limit int64) (int64, error) {
	var copied int64
	for copied < limit {
		if err := ctx.Err(); err != nil {
			return copied, err
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := writeFull(dst, buf[:nr])
			copied += int64(nw)
			if ew != nil {
				return copied, ew
			}
			if nw != nr {
				return copied, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return copied, nil
			}
			return copied, er
		}
	}
	return copied, nil
}

func writeFull(dst io.Writer, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := dst.Write(p[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
