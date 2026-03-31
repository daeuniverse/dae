package ws

import (
	"io"
	"sync"

	"github.com/gorilla/websocket"
	"time"
)

type conn struct {
	*websocket.Conn

	readMu        sync.Mutex
	currentReader io.Reader

	writeMu sync.Mutex
}

func newConn(wsc *websocket.Conn) *conn {
	return &conn{
		Conn: wsc,
	}
}

func (c *conn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.currentReader == nil {
			messageType, reader, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			if messageType != websocket.BinaryMessage {
				_, _ = io.Copy(io.Discard, reader)
				continue
			}
			c.currentReader = reader
		}

		n, err = c.currentReader.Read(b)
		if err == nil {
			return n, nil
		}
		if err == io.EOF {
			c.currentReader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}
func (c *conn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	writer, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err = writer.Write(b)
	closeErr := writer.Close()
	if err != nil {
		return n, err
	}
	if closeErr != nil {
		return n, closeErr
	}
	return n, nil
}

func (c *conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
