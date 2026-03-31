package vision

import (
	gotls "crypto/tls"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	outboundtls "github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

type intrinsicConnWrapper struct {
	netproxy.Conn
	intrinsic netproxy.Conn
}

func (w *intrinsicConnWrapper) IntrinsicConn() netproxy.Conn {
	return w.intrinsic
}

func TestNewConnAcceptsTLSConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	conn, err := NewConn(&intrinsicConnWrapper{Conn: tlsConn, intrinsic: tlsConn}, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if conn.input == nil || conn.rawInput == nil {
		t.Fatal("expected internal TLS buffers to be resolved")
	}
}

func TestNewConnAcceptsUTLSConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	conn, err := NewConn(&intrinsicConnWrapper{Conn: uConn, intrinsic: uConn}, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if conn.input == nil || conn.rawInput == nil {
		t.Fatal("expected internal uTLS buffers to be resolved")
	}
}

func TestNewConnAcceptsRealityConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	realityConn := &outboundtls.RealityUConn{UConn: uConn}
	conn, err := NewConn(&intrinsicConnWrapper{Conn: realityConn, intrinsic: realityConn}, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if conn.input == nil || conn.rawInput == nil {
		t.Fatal("expected internal REALITY buffers to be resolved")
	}
}

func TestNewConnRejectsUnsupportedIntrinsicConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if _, err := NewConn(client, make([]byte, 16)); err == nil {
		t.Fatal("expected error for connection without IntrinsicConn")
	}
}
