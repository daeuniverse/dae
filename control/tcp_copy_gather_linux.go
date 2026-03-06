//go:build linux
// +build linux

package control

import (
	"context"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

var (
	relayGatherWriteTestHookMu sync.Mutex
	relayGatherWriteTestHook   func(prefixLen, bodyLen int)
)
var relayGatherWriteEnabled = true

func tryRelayGatherWrite(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (written int64, err error, ok bool) {
	if !relayGatherWriteEnabled {
		return 0, nil, false
	}
	prefixSource, ok := src.(relayPrefixSource)
	if !ok {
		return 0, nil, false
	}

	dstTCP, ok := relayGatherWriteTCPConn(dst)
	if !ok {
		return 0, nil, false
	}

	prefix := prefixSource.TakeRelayPrefix()
	if len(prefix) == 0 {
		return 0, nil, false
	}

	dstFD, err := tcpConnFD(dstTCP)
	if err != nil {
		return 0, err, true
	}

	buf := relayCopyBufferPool.Get().([]byte)
	defer relayCopyBufferPool.Put(buf)

	var (
		body    []byte
		readErr error
	)

	if srcTCP, ok := relayGatherWriteTCPConn(src); ok {
		pending, err := tcpConnHasPendingReadData(srcTCP)
		if err != nil {
			return 0, err, true
		}
		if pending {
			nr, er := src.Read(buf)
			if nr > 0 {
				body = buf[:nr]
			}
			readErr = er
		}
	}

	// Fast path: check nil without lock to avoid overhead in production
	if relayGatherWriteTestHook != nil {
		relayGatherWriteTestHookMu.Lock()
		hook := relayGatherWriteTestHook
		relayGatherWriteTestHookMu.Unlock()
		if hook != nil {
			hook(len(prefix), len(body))
		}
	}

	nw, err := relayWritevAll(dstFD, prefix, body)
	written += int64(nw)
	if err != nil {
		return written, err, true
	}

	if readErr != nil {
		if readErr == io.EOF {
			return written, nil, true
		}
		return written, readErr, true
	}

	n, err := relayCopyLoop(ctx, dst, src, buf)
	return written + n, err, true
}

func relayGatherWriteTCPConn(conn netproxy.Conn) (*net.TCPConn, bool) {
	return unwrapRelayTCPConn(conn)
}

func relayWritevAll(fd int, segs ...[]byte) (written int, err error) {
	segments := relayNonEmptySegments(segs)
	for len(segments) > 0 {
		n, err := unix.Writev(fd, segments)
		if n > 0 {
			written += n
			segments = relayAdvanceSegments(segments, n)
		}
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func relayNonEmptySegments(segs [][]byte) [][]byte {
	filtered := segs[:0]
	for _, seg := range segs {
		if len(seg) == 0 {
			continue
		}
		filtered = append(filtered, seg)
	}
	return filtered
}

func relayAdvanceSegments(segs [][]byte, n int) [][]byte {
	for len(segs) > 0 && n > 0 {
		if n >= len(segs[0]) {
			n -= len(segs[0])
			segs = segs[1:]
			continue
		}
		segs[0] = segs[0][n:]
		return segs
	}
	return segs
}
