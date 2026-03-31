package bufferred_conn

import (
	"net"

	"github.com/daeuniverse/outbound/pkg/zeroalloc/bufio"
)

type BufferedConn struct {
	r        *bufio.Reader
	net.Conn // So that most methods are embedded
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	return &BufferedConn{bufio.NewReader(c), c}
}

func NewBufferedConnSize(c net.Conn, n int) *BufferedConn {
	return &BufferedConn{bufio.NewReaderSize(c, n), c}
}

func (b BufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b BufferedConn) UnderlyingConn() net.Conn {
	return b.Conn
}

// TakeRelayPrefix returns currently buffered bytes and marks them consumed so
// relay can flush the prefix directly before continuing normal reads.
//
// The returned slice is only safe for immediate synchronous use before the
// next BufferedConn read.
func (b *BufferedConn) TakeRelayPrefix() []byte {
	if b == nil || b.r == nil {
		return nil
	}
	n := b.r.Buffered()
	if n == 0 {
		return nil
	}
	prefix, err := b.r.Peek(n)
	if err != nil || len(prefix) == 0 {
		return nil
	}
	if _, err := b.r.Discard(len(prefix)); err != nil {
		return nil
	}
	return prefix
}

func (b BufferedConn) Close() error {
	b.r.Put()
	return b.Conn.Close()
}

func (b BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (c *BufferedConn) ReadByte() (byte, error) {
	return c.r.ReadByte()
}

func (c *BufferedConn) UnreadByte() error {
	return c.r.UnreadByte()
}
