// protocol spec:
// https://trojan-gfw.github.io/trojan/protocol

package vless

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/vmess"
	"google.golang.org/protobuf/proto"
)

var (
	FailAuthErr = fmt.Errorf("incorrect UUID") // nolint:staticcheck
)

type Metadata struct {
	vmess.Metadata
	Flow string
	Mux  bool
}

type Conn struct {
	netproxy.Conn
	metadata            Metadata
	cmdKey              []byte
	cachedProxyAddrIpIP netip.AddrPort

	writeMutex sync.Mutex
	readMutex  sync.Mutex
	onceWrite  bool
	onceRead   sync.Once

	addonsBytes []byte
}

func NewConn(conn netproxy.Conn, metadata Metadata, cmdKey []byte) (c *Conn, err error) {

	// DO NOT use pool here because Close() cannot interrupt the reading or writing, which will modify the value of the pool buffer.
	key := make([]byte, len(cmdKey))
	copy(key, cmdKey)
	c = &Conn{
		Conn:     conn,
		metadata: metadata,
		cmdKey:   key,
	}
	if metadata.Network == "udp" {
		proxyAddrIp, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port))))
		if err != nil {
			return nil, err
		}
		c.cachedProxyAddrIpIP = proxyAddrIp.AddrPort()
	}
	if metadata.Network == "tcp" && metadata.IsClient {
		time.AfterFunc(100*time.Millisecond, func() {
			// avoid the situation where the server sends messages first
			if _, err = c.Write(nil); err != nil {
				return
			}
		})
	}
	if metadata.Flow != "" {
		c.addonsBytes, err = proto.Marshal(&Addons{
			Flow: metadata.Flow,
		})
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Conn) IntrinsicConn() netproxy.Conn {
	return c.Conn
}

func (c *Conn) reqHeaderFromPool(payload []byte) (buf []byte) {
	addrLen := c.metadata.AddrLen()
	if !c.metadata.Mux {
		buf = pool.Get(1 + 16 + len(c.addonsBytes) + 1 + 1 + 2 + 1 + addrLen + len(payload))
	} else {
		buf = pool.Get(1 + 16 + len(c.addonsBytes) + 1 + 1 + len(payload))
	}
	start := 0
	buf[start] = 0 // version
	start += 1
	copy(buf[start:], c.cmdKey)
	start += 16
	buf[start] = byte(len(c.addonsBytes)) // length of addons
	start += 1
	copy(buf[start:], c.addonsBytes)
	start += len(c.addonsBytes)
	if !c.metadata.Mux {
		buf[start] = vmess.NetworkToByte(c.metadata.Network) // inst
		start += 1
		binary.BigEndian.PutUint16(buf[start:], c.metadata.Port) // port
		start += 2
		buf[start] = vmess.MetadataTypeToByte(c.metadata.Type) // addr type
		start += 1
		c.metadata.PutAddr(buf[start:])
		start += addrLen
	} else {
		buf[start] = vmess.NetworkToByte("mux") // inst
		start += 1
	}
	copy(buf[start:], payload)
	return buf
}

func (c *Conn) Write(b []byte) (n int, err error) {
	// logrus.Println("VLESS CONN WRITE", hex.EncodeToString(b))
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.metadata.Network == "udp" && c.metadata.Flow != XRV {
		// logrus.Println("!!!", "UDP, write")
		bLen := pool.Get(2)
		defer pool.Put(bLen)
		binary.BigEndian.PutUint16(bLen, uint16(len(b)))
		if _, err = c.write(bLen); err != nil {
			return 0, err
		}
	}
	return c.write(b)
}

func (c *Conn) write(b []byte) (n int, err error) {
	if !c.onceWrite {
		if c.metadata.IsClient {
			buf := c.reqHeaderFromPool(b)
			defer pool.Put(buf)
			if _, err = c.Conn.Write(buf); err != nil {
				return 0, fmt.Errorf("write header: %w", err)
			}
			c.onceWrite = true
			return len(b), nil
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.metadata.Network == "udp" && c.metadata.Flow != XRV {
		// logrus.Println("!!!", "UDP, read")
		// defer func() {
		// 	logrus.Println("READ", n, err)
		// }()
		bLen := pool.Get(2)
		defer pool.Put(bLen)
		if _, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, bLen); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(bLen))
		if len(b) < length {
			return 0, fmt.Errorf("buf size is not enough")
		}
	}

	return c.read(b)
}

func (c *Conn) read(b []byte) (n int, err error) {
	c.onceRead.Do(func() {
		if c.metadata.IsClient {
			if err = c.ReadRespHeader(); err != nil {
				return
			}
		} else {
			if err = c.ReadReqHeader(); err != nil {
				return
			}
		}
	})
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) ReadReqHeader() (err error) {
	buf := pool.Get(18)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		return fmt.Errorf("version %v is not supprted", buf[0])
	}
	if subtle.ConstantTimeCompare(c.cmdKey[:16], buf[1:17]) != 1 {
		return FailAuthErr
	}
	if _, err = io.CopyN(io.Discard, c.Conn, int64(buf[17])); err != nil { // ignore addons
		return err
	}
	buf = pool.Get(4)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if err = CompleteMetadataFromReader(&c.metadata, buf, c.Conn); err != nil {
		return err
	}
	return nil
}

func (c *Conn) ReadRespHeader() (err error) {
	buf := pool.Get(2)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		return fmt.Errorf("version %v is not supprted", buf[0])
	}
	if _, err = io.CopyN(io.Discard, c.Conn, int64(buf[1])); err != nil {
		return err
	}
	return nil
}
