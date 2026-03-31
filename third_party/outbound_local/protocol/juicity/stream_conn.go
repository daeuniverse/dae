package juicity

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/olicesx/quic-go"
)

type Conn struct {
	quic.Stream
	Metadata *trojanc.Metadata

	writeMutex sync.Mutex
	onceWrite  bool
	onceRead   sync.Once

	closeDeferFn func()

	closeOnce sync.Once
	closeErr  error
}

func (c *Conn) reqHeaderFromPool(payload []byte) (buf []byte) {
	addrLen := c.Metadata.Len()
	buf = pool.Get(1 + addrLen + len(payload))
	buf[0] = trojanc.NetworkToByte(c.Metadata.Network)
	c.Metadata.PackTo(buf[1:])
	copy(buf[1+addrLen:], payload)
	return buf
}

func (c *Conn) readReqHeader() (err error) {
	buf := pool.Get(1)
	defer buf.Put()
	if _, err = io.ReadFull(c.Stream, buf[:1]); err != nil {
		return err
	}
	c.Metadata.Network = trojanc.ParseNetwork(buf[0])
	n := c.Metadata.Len()
	if n < 2 {
		return fmt.Errorf("invalid juicity header")
	}
	if _, err = c.Metadata.Unpack(c.Stream); err != nil {
		return err
	}
	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if !c.onceWrite {
		if c.Metadata.IsClient {
			buf := c.reqHeaderFromPool(b)
			defer pool.Put(buf)
			if _, err = c.Stream.Write(buf); err != nil {
				return 0, fmt.Errorf("write header: %w", err)
			}
			c.onceWrite = true
			return len(b), nil
		}
	}
	return c.Stream.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.onceRead.Do(func() {
		if !c.Metadata.IsClient {
			if err = c.readReqHeader(); err != nil {
				return
			}
		}
	})
	return c.Stream.Read(b)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.close()
	})
	return c.closeErr
}

func (c *Conn) CloseWrite() error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// As documented by the quic-go library, this doesn't actually close the entire stream.
	// It prevents further writes, which in turn will result in an EOF signal being sent the other side of stream when
	// reading.
	// We can still read from this stream.
	return c.Stream.Close()
}

func (c *Conn) close() error {
	if c.closeDeferFn != nil {
		defer c.closeDeferFn()
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = c.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	c.CancelRead(0)
	return c.Stream.Close()
}

var _ netproxy.Conn = &Conn{}

func NewConn(stream quic.Stream, mdata *trojanc.Metadata, closeDeferFn func()) *Conn {
	if mdata == nil {
		mdata = &trojanc.Metadata{}
	}
	return &Conn{
		Stream:       stream,
		Metadata:     mdata,
		closeDeferFn: closeDeferFn,
	}
}
