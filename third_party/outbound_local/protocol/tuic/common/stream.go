package common

import (
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
)

type safeStreamConn struct {
	quic.Stream
	lock  sync.Mutex
	lAddr net.Addr
	rAddr net.Addr

	closeDeferFn func()

	closeOnce sync.Once
	closeErr  error
}

func (q *safeStreamConn) Write(p []byte) (n int, err error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.Stream.Write(p)
}

func (q *safeStreamConn) Close() error {
	q.closeOnce.Do(func() {
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (s *safeStreamConn) CloseWrite() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// As documented by the quic-go library, this doesn't actually close the entire stream.
	// It prevents further writes, which in turn will result in an EOF signal being sent the other side of stream when
	// reading.
	// We can still read from this stream.
	return s.Stream.Close()
}

func (q *safeStreamConn) close() error {
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = q.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	q.lock.Lock()
	defer q.lock.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	q.CancelRead(0)
	return q.Stream.Close()
}

func (q *safeStreamConn) LocalAddr() net.Addr {
	return q.lAddr
}

func (q *safeStreamConn) RemoteAddr() net.Addr {
	return q.rAddr
}

var _ netproxy.Conn = &safeStreamConn{}

func NewSafeStreamConn(stream quic.Stream, lAddr, rAddr net.Addr, closeDeferFn func()) *safeStreamConn {
	return &safeStreamConn{Stream: stream, lAddr: lAddr, rAddr: rAddr, closeDeferFn: closeDeferFn}
}
