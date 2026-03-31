package obfs

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
)

type Conn struct {
	netproxy.Conn
	Obfs                IObfs
	underPostdecryptBuf *bytes.Buffer
	readLater           io.Reader

	init    bool
	addrLen int
	cipher  *ciphers.StreamCipher

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewConn(c netproxy.Conn, obfs IObfs) (*Conn, error) {
	return &Conn{
		Conn:                c,
		Obfs:                obfs,
		underPostdecryptBuf: new(bytes.Buffer),
		addrLen:             30,
	}, nil
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) initEncoder() (err error) {
	if c.cipher == nil {
		return fmt.Errorf("outer conn did not init cipher of Obfs")
	}
	ivLen := c.cipher.InfoIVLen()
	key := c.cipher.Key()
	if key == nil {
		return fmt.Errorf("outer conn did not init cipher")
	}

	info := c.Obfs.GetServerInfo()
	info.IVLen = ivLen
	info.Key = key
	// Dial: obfs->ss->proto
	// Conn Write: obfs<-ss<-proto
	info.AddrLen = c.addrLen
	c.Obfs.SetServerInfo(info)

	return nil
}

func (c *Conn) SetCipher(cipher *ciphers.StreamCipher) {
	c.cipher = cipher
}

func (c *Conn) SetAddrLen(addrLen int) {
	c.addrLen = addrLen
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// Conn Read: obfs->ss->proto
	if c.readLater != nil {
		n, _ = c.readLater.Read(b)
		if n != 0 {
			return n, nil
		}
		c.readLater = nil
	}
readAgain:
	n, err = c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	decodedData, needSendBack, err := c.Obfs.Decode(b[:n])
	if err != nil {
		return 0, err
	}
	if needSendBack {
		_, _ = c.Write(nil)
		goto readAgain
	}
	if len(decodedData) == 0 {
		goto readAgain
		//return 0, nil
	}
	if &b[0] == &decodedData[0] {
		return len(decodedData), nil
	}
	// len(decodedData) may > input len(b[:n])
	n = copy(b, decodedData)
	if n < len(decodedData) {
		c.readLater = bytes.NewReader(decodedData[n:])
	}
	return n, nil
}

func (c *Conn) encode(b []byte) (outData []byte, err error) {
	if !c.init {
		err = c.initEncoder()
		if err != nil {
			return
		}
		c.init = true
	}
	return c.Obfs.Encode(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Conn Write: obfs<-ss<-proto
	data, err := c.encode(b)
	if err != nil {
		return 0, err
	}
	n, err = c.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
