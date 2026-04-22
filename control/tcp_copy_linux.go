//go:build linux

package control

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

const (
	relaySpliceAccountingChunkSize = 256 << 10
	relaySplicePipeTargetSize      = 256 << 10
	relaySpliceMaxStep             = relaySplicePipeTargetSize
	relaySplicePipePoolLimit       = 64
	relaySpliceFlags               = unix.SPLICE_F_MOVE | unix.SPLICE_F_MORE | unix.SPLICE_F_NONBLOCK
)

type relaySplicePipe struct {
	readFD  int
	writeFD int
	data    int
}

var relaySplicePipePool = make(chan *relaySplicePipe, relaySplicePipePoolLimit)

func relayFastCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn, record func(int64)) (int64, error) {
	// shouldUseRelayFastPath guarantees both sides resolve to a *net.TCPConn.
	// Bypass outer wrapper interfaces (*ConnSniffer, *prefixedConn) and operate
	// on the raw socket pair directly: io.Copy on two *net.TCPConn invokes
	// (*net.TCPConn).WriteTo → (*net.TCPConn).ReadFrom → splice(2) on Linux,
	// eliminating userspace memcopy.
	//
	// Without this unwrap:
	//   • l2r, src=*ConnSniffer(prefixedConn): ConnSniffer.WriteTo → inner
	//     dst.ReadFrom(*prefixedConn) → genericReadFrom → alloc 32 KiB per conn
	//   • l2r, src=*prefixedConn: dst.ReadFrom(*prefixedConn) → same 32 KiB alloc
	//   • r2l, dst=*ConnSniffer: ConnSniffer.ReadFrom → copyDirect → no splice
	//
	// Safety: tryRelayGatherWrite has already drained any userspace prefix via
	// TakeRelayPrefix/TakeRelaySegments before this function is called, so the
	// inner socket pair is at the correct read/write position in both directions.
	//
	// Cancellation handling: This function runs inside relayCore's directional
	// goroutines. When an error occurs in one direction, relayCore.forceClose()
	// sets SetReadDeadline(past) on both connections, which causes io.Copy to
	// return with a timeout error, unblocking the pending direction immediately.

	dstTCP, dstOk := unwrapRelayTCPConn(dst)
	srcTCP, srcOk := unwrapRelayTCPConn(src)

	// Fast path: both sides are plain TCP connections
	if dstOk && srcOk {
		// Propagate context deadline to TCP connections if present.
		// relayCore.run ensures ctx is never nil.
		if ctx != nil {
			if deadline, ok := ctx.Deadline(); ok {
				// Check if already canceled (only when we have a deadline)
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				default:
				}
				// Set deadline on both connections.
				// Ignore errors: connections may be closed by forceClose concurrently.
				_ = srcTCP.SetReadDeadline(deadline)
				_ = dstTCP.SetWriteDeadline(deadline)
				defer func() {
					// Clear deadline on exit. Ignore errors for same reason.
					_ = srcTCP.SetReadDeadline(time.Time{})
					_ = dstTCP.SetWriteDeadline(time.Time{})
				}()
			}
		}
		// Direct splice remains enabled. When runtime accounting is requested,
		// use an explicit splice loop so we can account exact bytes written while
		// staying in the kernel zero-copy path. relayCore.forceClose() will
		// unblock blocked splice calls via SetReadDeadline(past).
		if record == nil {
			return io.Copy(dstTCP, srcTCP)
		}
		return relaySpliceCopyExact(ctx, dstTCP, srcTCP, record)
	}

	// Fallback: use WriterTo if available, or buffered copy
	if dstOk {
		if _, ok := src.(io.WriterTo); ok {
			if record == nil {
				return io.Copy(dstTCP, src)
			}
			bufPtr := relayCopyBufferPool.Get().(*[]byte)
			buf := *bufPtr
			defer relayCopyBufferPool.Put(bufPtr)
			return relayCopyLoop(ctx, dst, src, buf, record)
		}
	}

	// Slow path: buffered copy (e.g., when wrapper doesn't support fast path)
	bufPtr := relayCopyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayCopyBufferPool.Put(bufPtr)
	return relayCopyLoop(ctx, dst, src, buf, record)
}

func relaySpliceCopyExact(ctx context.Context, dst, src *net.TCPConn, record func(int64)) (int64, error) {
	record = normalizeTrafficRecord(record)

	srcRaw, err := src.SyscallConn()
	if err != nil {
		return relayChunkedSpliceCopy(ctx, dst, src, record)
	}
	dstRaw, err := dst.SyscallConn()
	if err != nil {
		return relayChunkedSpliceCopy(ctx, dst, src, record)
	}

	pipe, err := getRelaySplicePipe()
	if err != nil {
		return relayChunkedSpliceCopy(ctx, dst, src, record)
	}
	defer putRelaySplicePipe(pipe)

	var (
		written int64
		inPipe  int
	)
	for {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return written, err
			}
		}

		if inPipe == 0 {
			n, err := spliceSocketToPipe(srcRaw, pipe.writeFD, relaySpliceMaxStep)
			if n > 0 {
				inPipe = n
				pipe.data += n
			}
			if err != nil {
				if stderrors.Is(err, io.EOF) && inPipe == 0 {
					return written, nil
				}
				return written, err
			}
			if inPipe == 0 {
				return written, nil
			}
		}

		n, err := splicePipeToSocket(dstRaw, pipe.readFD, inPipe)
		if n > 0 {
			inPipe -= n
			pipe.data -= n
			written += int64(n)
			record(int64(n))
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
}

func getRelaySplicePipe() (*relaySplicePipe, error) {
	select {
	case pipe := <-relaySplicePipePool:
		return pipe, nil
	default:
		return newRelaySplicePipe()
	}
}

func newRelaySplicePipe() (*relaySplicePipe, error) {
	pipeFDs := make([]int, 2)
	if err := unix.Pipe2(pipeFDs, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return nil, err
	}

	// Best effort: 256 KiB cuts splice syscall churn without retaining the
	// 1 MiB pipe buffers used by Go's generic splice path.
	_, _ = unix.FcntlInt(uintptr(pipeFDs[0]), unix.F_SETPIPE_SZ, relaySplicePipeTargetSize)

	return &relaySplicePipe{
		readFD:  pipeFDs[0],
		writeFD: pipeFDs[1],
	}, nil
}

func putRelaySplicePipe(pipe *relaySplicePipe) {
	if pipe == nil {
		return
	}
	if pipe.data != 0 {
		pipe.close()
		return
	}

	select {
	case relaySplicePipePool <- pipe:
	default:
		pipe.close()
	}
}

func (p *relaySplicePipe) close() {
	if p == nil {
		return
	}
	_ = unix.Close(p.readFD)
	_ = unix.Close(p.writeFD)
	p.readFD = -1
	p.writeFD = -1
	p.data = 0
}

func relayChunkedSpliceCopy(ctx context.Context, dst, src *net.TCPConn, record func(int64)) (int64, error) {
	record = normalizeTrafficRecord(record)
	var written int64
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return written, ctx.Err()
			default:
			}
		}

		lr := &io.LimitedReader{
			R: src,
			N: relaySpliceAccountingChunkSize,
		}
		n, err := io.Copy(dst, lr)
		if n > 0 {
			written += n
			record(n)
		}
		if err != nil {
			return written, err
		}
		if n == 0 || lr.N > 0 {
			return written, nil
		}
	}
}

func spliceSocketToPipe(rawConn syscall.RawConn, pipeW int, maxBytes int) (int, error) {
	var (
		n         int
		eof       bool
		spliceErr error
	)
	err := rawConn.Read(func(fd uintptr) bool {
		for {
			nn, err := unix.Splice(int(fd), nil, pipeW, nil, maxBytes, relaySpliceFlags)
			if nn > 0 {
				n = int(nn)
				return true
			}
			if err == nil {
				eof = true
				return true
			}
			if stderrors.Is(err, syscall.EINTR) {
				continue
			}
			if stderrors.Is(err, syscall.EAGAIN) || stderrors.Is(err, syscall.EWOULDBLOCK) {
				return false
			}
			spliceErr = err
			return true
		}
	})
	if err != nil {
		return n, err
	}
	if spliceErr != nil {
		return n, spliceErr
	}
	if eof {
		return 0, io.EOF
	}
	return n, nil
}

func splicePipeToSocket(rawConn syscall.RawConn, pipeR int, maxBytes int) (int, error) {
	var (
		n         int
		spliceErr error
	)
	err := rawConn.Write(func(fd uintptr) bool {
		for {
			nn, err := unix.Splice(pipeR, nil, int(fd), nil, maxBytes, relaySpliceFlags)
			if nn > 0 {
				n = int(nn)
				return true
			}
			if err == nil {
				return true
			}
			if stderrors.Is(err, syscall.EINTR) {
				continue
			}
			if stderrors.Is(err, syscall.EAGAIN) || stderrors.Is(err, syscall.EWOULDBLOCK) {
				return false
			}
			spliceErr = err
			return true
		}
	})
	if err != nil {
		return n, err
	}
	if spliceErr != nil {
		return n, spliceErr
	}
	return n, nil
}

func shouldUseRelayFastPath(dst netproxy.Conn, src netproxy.Conn) bool {
	// Local connection splice restriction removed: splice(2) is now enabled for
	// local-to-local connections. Modern kernel implementations optimize splice
	// for loopback scenarios, providing zero-copy forwarding without the overhead
	// previously observed in early versions. This aligns with industry best
	// practices for local socket acceleration.
	return isRelayFastPathWhitelistedConn(dst) && isRelayFastPathWhitelistedConn(src)
}

func isRelayFastPathWhitelistedConn(c netproxy.Conn) bool {
	_, ok := unwrapRelayTCPConn(c)
	return ok
}
