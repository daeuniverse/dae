//go:build linux
// +build linux

package control

import (
	"context"
	"errors"
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
	relayWritevFunc            = unix.Writev
)

const relayGatherInlineSegmentCap = 8

var relayGatherWriteEnabled = true

func relayTakeSourceSegments(src netproxy.Conn, scratch *[relayGatherInlineSegmentCap][]byte) [][]byte {
	if segmentSource, ok := src.(relaySegmentSource); ok {
		segments := relayNonEmptySegments(segmentSource.TakeRelaySegments())
		if len(segments) > 0 {
			return segments
		}
	}
	if prefixSource, ok := src.(relayPrefixSource); ok {
		prefix := prefixSource.TakeRelayPrefix()
		if len(prefix) > 0 {
			scratch[0] = prefix
			return scratch[:1]
		}
	}
	return nil
}

func relayBuildWriteSegments(prefixSegs [][]byte, body []byte, scratch *[relayGatherInlineSegmentCap + 1][]byte) [][]byte {
	if len(prefixSegs) == 0 {
		if len(body) == 0 {
			return nil
		}
		scratch[0] = body
		return scratch[:1]
	}

	extra := 0
	if len(body) > 0 {
		extra = 1
	}
	total := len(prefixSegs) + extra

	if total <= len(scratch) {
		copy(scratch[:], prefixSegs)
		if extra == 1 {
			scratch[len(prefixSegs)] = body
		}
		return scratch[:total]
	}

	if extra == 0 {
		return prefixSegs
	}

	writeSegs := make([][]byte, 0, total)
	writeSegs = append(writeSegs, prefixSegs...)
	writeSegs = append(writeSegs, body)
	return writeSegs
}

func relaySegmentsLen(segs [][]byte) int {
	total := 0
	for _, seg := range segs {
		total += len(seg)
	}
	return total
}

func tryRelayGatherWrite(ctx context.Context, dst netproxy.Conn, src netproxy.Conn) (written int64, err error, ok bool) {
	if !relayGatherWriteEnabled {
		return 0, nil, false
	}
	var sourceSegScratch [relayGatherInlineSegmentCap][]byte
	segments := relayTakeSourceSegments(src, &sourceSegScratch)
	if len(segments) == 0 {
		return 0, nil, false
	}
	prefixLen := relaySegmentsLen(segments)

	bufPtr := relayCopyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayCopyBufferPool.Put(bufPtr)

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
			hook(prefixLen, len(body))
		}
	}

	var writeSegScratch [relayGatherInlineSegmentCap + 1][]byte
	writeSegs := relayBuildWriteSegments(segments, body, &writeSegScratch)

	nw, err := relayGatherWriteTo(dst, writeSegs)
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

	if continuationSource, ok := src.(relayContinuationSource); ok {
		// Check context cancellation. relayCore.run ensures ctx is never nil.
		if cerr := ctx.Err(); cerr != nil {
			return written, cerr, true
		}
		n, err := continuationSource.CopyRelayRemainder(dst, buf)
		return written + n, err, true
	}

	n, err := relayCopyLoop(ctx, dst, src, buf)
	return written + n, err, true
}

func relayGatherWriteTCPConn(conn netproxy.Conn) (*net.TCPConn, bool) {
	return unwrapRelayTCPConn(conn)
}

func relayGatherWriteTo(dst netproxy.Conn, segs [][]byte) (written int, err error) {
	if dstTCP, ok := relayGatherWriteTCPConn(dst); ok {
		rawConn, err := dstTCP.SyscallConn()
		if err != nil {
			return 0, err
		}
		return relayWritevAll(rawConn, segs)
	}

	segments := relayNonEmptySegments(segs)
	if len(segments) == 0 {
		return 0, nil
	}

	buffers := net.Buffers(segments)
	n, err := buffers.WriteTo(dst)
	return int(n), err
}

func relayWritevAll(rawConn syscall.RawConn, segs [][]byte) (written int, err error) {
	segments := relayNonEmptySegments(segs)
	if len(segments) == 0 {
		return 0, nil
	}

	var writeErr error
	err = rawConn.Write(func(fd uintptr) bool {
		for len(segments) > 0 {
			n, err := relayWritevFunc(int(fd), segments)
			if n > 0 {
				written += n
				segments = relayAdvanceSegments(segments, n)
			}
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					return false
				}
				writeErr = err
				return true
			}
			if n == 0 {
				writeErr = io.ErrShortWrite
				return true
			}
		}
		return true
	})
	if err != nil {
		return written, err
	}
	if writeErr != nil {
		return written, writeErr
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
func tcpConnHasPendingReadData(conn *net.TCPConn) (bool, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false, err
	}

	var (
		pending int
		ctrlErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		pending, ctrlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	}); err != nil {
		return false, err
	}
	if ctrlErr != nil {
		return false, ctrlErr
	}
	return pending > 0, nil
}
