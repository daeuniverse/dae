//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"runtime"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

const (
	relaySpliceThreshold = 64 << 10
	relayCopyBufferSize  = 32 << 10
	relaySpliceChunkSize = 1 << 20
)

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func relayAdaptiveCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	buf := make([]byte, relayCopyBufferSize)

	n, err := copyPrefix(ctx, dst, src, buf, relaySpliceThreshold)
	if err != nil {
		return n, err
	}

	if srcSC, ok := src.(syscallConn); ok {
		if dstSC, ok := dst.(syscallConn); ok {
			sn, serr := splicePipeToEOF(ctx, dstSC, srcSC)
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

func connFD(c syscallConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	if err := raw.Control(func(u uintptr) { fd = int(u) }); err != nil {
		return 0, err
	}
	return fd, nil
}

func splicePipeToEOF(ctx context.Context, dst syscallConn, src syscallConn) (int64, error) {
	srcFD, err := connFD(src)
	if err != nil {
		return 0, err
	}
	dstFD, err := connFD(dst)
	if err != nil {
		return 0, err
	}

	pipeFD := make([]int, 2)
	if err := unix.Pipe2(pipeFD, unix.O_CLOEXEC); err != nil {
		return 0, err
	}
	defer unix.Close(pipeFD[0])
	defer unix.Close(pipeFD[1])

	var copied int64
	for {
		if err := ctx.Err(); err != nil {
			return copied, err
		}

		var in int64
		for {
			in, err = spliceCount(srcFD, pipeFD[1], relaySpliceChunkSize)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN {
				if ctx.Err() != nil {
					return copied, ctx.Err()
				}
				runtime.Gosched()
				continue
			}
			if err != nil {
				return copied, err
			}
			break
		}

		if in == 0 {
			return copied, nil
		}

		remaining := in
		for remaining > 0 {
			var out int64
			for {
				out, err = spliceCount(pipeFD[0], dstFD, int(remaining))
				if err == unix.EINTR {
					continue
				}
				if err == unix.EAGAIN {
					if ctx.Err() != nil {
						return copied, ctx.Err()
					}
					runtime.Gosched()
					continue
				}
				if err != nil {
					return copied, err
				}
				break
			}
			remaining -= out
		}
		copied += in
	}
}
