//go:build linux
// +build linux

package control

import (
	"context"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"io"
)

func relayAdaptiveCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return defaultRelayCopyEngine{}.Copy(ctx, dst, src)
}

func relayFastCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
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
				_ = dstTCP.SetReadDeadline(deadline)
				_ = srcTCP.SetWriteDeadline(deadline)
				defer func() {
					// Clear deadline on exit. Ignore errors for same reason.
					_ = dstTCP.SetReadDeadline(time.Time{})
					_ = srcTCP.SetWriteDeadline(time.Time{})
				}()
			}
		}
		// Direct splice: zero-copy, zero extra goroutine
		// relayCore.forceClose() will unblock via SetReadDeadline(past)
		return io.Copy(dstTCP, srcTCP)
	}

	// Fallback: use WriterTo if available, or buffered copy
	if dstOk {
		if _, ok := src.(io.WriterTo); ok {
			return io.Copy(dstTCP, src)
		}
	}

	// Slow path: buffered copy (e.g., when wrapper doesn't support fast path)
	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

func shouldUseRelayFastPath(dst netproxy.Conn, src netproxy.Conn) bool {
	// Local-to-local forwarding should not use splice.
	// Splice on loopback can cause high CPU usage due to frequent system calls
	// with small data chunks, since loopback has extremely low latency.
	// For local forwarding, userspace copy (io.CopyBuffer) is more efficient.
	if isLocalConnAny(dst, src) {
		return false
	}
	return isRelayFastPathWhitelistedConn(dst) && isRelayFastPathWhitelistedConn(src)
}

// isLocalConnAny checks if two connections form a local-to-local forwarding path.
// This works with any netproxy.Conn by first unwrapping to *net.TCPConn.
// It detects the same cases as isLocalConnection in tcp_offload_linux.go:
// 1. Both peers are local (e.g., local client -> dae -> local service)
// 2. Right socket connects to a local service (e.g., remote client -> dae -> local service)
func isLocalConnAny(a, b netproxy.Conn) bool {
	aTCP, aOk := unwrapRelayTCPConn(a)
	if !aOk {
		return false
	}
	bTCP, bOk := unwrapRelayTCPConn(b)
	if !bOk {
		return false
	}
	return isLocalConnection(aTCP, bTCP)
}

func isRelayFastPathWhitelistedConn(c netproxy.Conn) bool {
	_, ok := unwrapRelayTCPConn(c)
	return ok
}
