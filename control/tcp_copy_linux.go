//go:build linux
// +build linux

package control

import (
	"context"
	"github.com/daeuniverse/outbound/netproxy"
	"io"
)

func relayAdaptiveCopy(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
	return defaultRelayCopyEngine{}.Copy(ctx, dst, src)
}

func relayFastCopy(_ context.Context, dst netproxy.Conn, src netproxy.Conn) (int64, error) {
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
	dstTCP, dstOk := unwrapRelayTCPConn(dst)
	srcTCP, srcOk := unwrapRelayTCPConn(src)
	if dstOk {
		if _, ok := src.(io.WriterTo); ok {
			return io.Copy(dstTCP, src)
		}
	}
	if dstOk && srcOk {
		return io.Copy(dstTCP, srcTCP)
	}
	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

func shouldUseRelayFastPath(dst netproxy.Conn, src netproxy.Conn) bool {
	return isRelayFastPathWhitelistedConn(dst) && isRelayFastPathWhitelistedConn(src)
}

func isRelayFastPathWhitelistedConn(c netproxy.Conn) bool {
	_, ok := unwrapRelayTCPConn(c)
	return ok
}
