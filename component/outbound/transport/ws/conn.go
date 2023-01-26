package ws

import (
	"bytes"
	"github.com/gorilla/websocket"
	"time"
)

type conn struct {
	*websocket.Conn
	readBuffer bytes.Buffer
}

func newConn(wsc *websocket.Conn) *conn {
	return &conn{
		Conn: wsc,
	}
}

func (c *conn) Read(b []byte) (n int, err error) {
	if c.readBuffer.Len() > 0 {
		return c.readBuffer.Read(b)
	}
	_, msg, err := c.Conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	n = copy(b, msg)
	if n < len(msg) {
		c.readBuffer.Write(msg[n:])
	}
	return n, nil

}
func (c *conn) Write(b []byte) (n int, err error) {
	return len(b), c.Conn.WriteMessage(websocket.BinaryMessage, b)
}

func (c *conn) SetDeadline(t time.Time) error {
	_ = c.Conn.SetReadDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}
