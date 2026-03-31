// protocol spec:
// https://trojan-gfw.github.io/trojan/protocol

package trojanc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

var (
	CRLF        = []byte{13, 10}
	FailAuthErr = fmt.Errorf("incorrect password") // nolint:staticcheck

	// passwordHashCache caches SHA224 hash results of passwords
	passwordHashCache sync.Map
)

type Conn struct {
	netproxy.Conn
	metadata Metadata
	pass     [56]byte

	writeMutex sync.Mutex
	onceWrite  bool
	onceRead   sync.Once
}

// getPasswordHash retrieves the SHA224 hash of a password (with caching)
// Optimization: Uses sync.Map to cache hash results, avoiding repeated computation
func getPasswordHash(password string) [56]byte {
	// Try to get from cache
	if cached, ok := passwordHashCache.Load(password); ok {
		return cached.([56]byte)
	}

	// Cache miss, calculate hash
	hash := sha256.New224()
	hash.Write([]byte(password))
	var result [56]byte
	hex.Encode(result[:], hash.Sum(nil))

	// Store in cache
	passwordHashCache.Store(password, result)
	return result
}

func NewConn(conn netproxy.Conn, metadata Metadata, password string) (c *Conn, err error) {
	// Use cached password hash for ~6x performance improvement
	pass := getPasswordHash(password)

	c = &Conn{
		Conn:     conn,
		metadata: metadata,
		pass:     pass,
	}
	if metadata.Network == "tcp" && metadata.IsClient {
		time.AfterFunc(100*time.Millisecond, func() {
			// avoid the situation where the server sends messages first
			if _, err = c.Write(nil); err != nil {
				return
			}
		})
	}
	return c, nil
}

func (c *Conn) reqHeaderFromPool() (buf []byte) {
	reqLen := c.metadata.Len()
	buf = pool.Get(56 + 2 + 1 + reqLen + 2)
	copy(buf, c.pass[:])
	copy(buf[56:], CRLF)
	buf[58] = NetworkToByte(c.metadata.Network)
	c.metadata.PackTo(buf[59:])
	copy(buf[59+reqLen:], CRLF)

	return buf
}

func (c *Conn) writeRequestHeader(payload []byte) (n int, err error) {
	header := c.reqHeaderFromPool()
	defer pool.Put(header)

	buffers := net.Buffers{header}
	if len(payload) > 0 {
		buffers = append(buffers, payload)
	}
	written, err := buffers.WriteTo(c.Conn)
	if err != nil {
		if written <= int64(len(header)) {
			return 0, fmt.Errorf("write header: %w", err)
		}
		return int(written) - len(header), fmt.Errorf("write header: %w", err)
	}
	if written < int64(len(header)) {
		return 0, fmt.Errorf("write header: %w", io.ErrShortWrite)
	}
	return int(written) - len(header), nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if !c.onceWrite {
		if c.metadata.IsClient {
			n, err = c.writeRequestHeader(b)
			if err != nil {
				return n, err
			}
			c.onceWrite = true
			return n, nil
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.onceRead.Do(func() {
		if !c.metadata.IsClient {
			if err = c.ReadReqHeader(); err != nil {
				return
			}
		}
	})
	return c.Conn.Read(b)
}

func (c *Conn) ReadReqHeader() (err error) {
	buf := pool.Get(56)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if !bytes.Equal(c.pass[:], buf[:56]) {
		return FailAuthErr
	}
	if _, err = io.ReadFull(c.Conn, buf[:1]); err != nil {
		return err
	}
	c.metadata.Network = ParseNetwork(buf[0])
	n := c.metadata.Len()
	if n < 2 {
		return fmt.Errorf("invalid trojan header")
	}
	if _, err = c.metadata.Unpack(c.Conn); err != nil {
		return err
	}
	return nil
}
