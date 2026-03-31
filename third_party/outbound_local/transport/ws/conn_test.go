package ws

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
)

func newWSPair(t *testing.T) (*conn, *websocket.Conn, func()) {
	t.Helper()

	upgrader := websocket.Upgrader{}
	serverConnCh := make(chan *websocket.Conn, 1)
	serverErrCh := make(chan error, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}))

	clientConn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial websocket failed: %v", err)
	}

	var serverConn *websocket.Conn
	select {
	case err := <-serverErrCh:
		_ = clientConn.Close()
		server.Close()
		t.Fatalf("upgrade failed: %v", err)
	case serverConn = <-serverConnCh:
	}

	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		server.Close()
	}
	return newConn(clientConn), serverConn, cleanup
}

func TestConnReadStreamsLargeMessage(t *testing.T) {
	client, server, cleanup := newWSPair(t)
	defer cleanup()

	payload := bytes.Repeat([]byte("abcd"), 4096)
	if err := server.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("server write failed: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestConnWriteStreamsBinaryMessage(t *testing.T) {
	client, server, cleanup := newWSPair(t)
	defer cleanup()

	payload := bytes.Repeat([]byte("hello"), 2048)
	n, err := client.Write(payload)
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected write length: got %d want %d", n, len(payload))
	}

	messageType, reader, err := server.NextReader()
	if err != nil {
		t.Fatalf("server next reader failed: %v", err)
	}
	if messageType != websocket.BinaryMessage {
		t.Fatalf("unexpected message type: got %d want %d", messageType, websocket.BinaryMessage)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}
