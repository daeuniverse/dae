package shadowtls

import (
	"context"
	"crypto/tls"
	stderrors "errors"
	"net"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks_2022"
)

type stubDialer struct {
	wantAddr string
	called   bool
}

func (s *stubDialer) DialContext(_ context.Context, _, addr string) (netproxy.Conn, error) {
	s.called = true
	if s.wantAddr != "" && addr != s.wantAddr {
		return nil, stderrors.New("unexpected addr: " + addr)
	}
	return nil, stderrors.New("stub dialer")
}

func TestParseVersionAndPasswordFromQuery(t *testing.T) {
	link := "shadowtls://v3@47.129.204.82:8443?password=testyuanshen&sni=autopatchcn.yuanshen.com"
	d, _, err := NewShadowTLS(&dialer.ExtraOption{}, &stubDialer{}, link)
	if err != nil {
		t.Fatalf("NewShadowTLS failed: %v", err)
	}
	s, ok := d.(*ShadowTLS)
	if !ok {
		t.Fatalf("unexpected dialer type: %T", d)
	}
	if s.version != 3 {
		t.Fatalf("unexpected version: %d", s.version)
	}
	if s.password != "testyuanshen" {
		t.Fatalf("unexpected password: %q", s.password)
	}
}

func TestShadowTLSExplicitEmptySNI(t *testing.T) {
	link := "shadowtls://v3@47.129.204.82:8443?password=testyuanshen&sni="
	d, _, err := NewShadowTLS(&dialer.ExtraOption{}, &stubDialer{}, link)
	if err != nil {
		t.Fatalf("NewShadowTLS failed: %v", err)
	}
	s, ok := d.(*ShadowTLS)
	if !ok {
		t.Fatalf("unexpected dialer type: %T", d)
	}
	if s.sni != "" {
		t.Fatalf("unexpected sni: got %q want empty", s.sni)
	}
}

func TestShadowTLSUsesUTLSOptions(t *testing.T) {
	link := "shadowtls://v3@47.129.204.82:8443?password=testyuanshen&tlsImplementation=utls&utlsImitate=chrome"
	d, _, err := NewShadowTLS(&dialer.ExtraOption{}, &stubDialer{}, link)
	if err != nil {
		t.Fatalf("NewShadowTLS failed: %v", err)
	}
	s, ok := d.(*ShadowTLS)
	if !ok {
		t.Fatalf("unexpected dialer type: %T", d)
	}
	if s.tlsImpl != "utls" {
		t.Fatalf("unexpected tls implementation: %q", s.tlsImpl)
	}
	if s.utlsImitate != "chrome" {
		t.Fatalf("unexpected uTLS imitate: %q", s.utlsImitate)
	}
}

func TestShadowTLSLinkWithInnerShadowsocks(t *testing.T) {
	next := &stubDialer{wantAddr: "47.129.204.82:8443"}
	link := "shadowtls://v3@47.129.204.82:8443?password=testyuanshen&sni=autopatchcn.yuanshen.com&inner-ss-port=8444&inner-ss-pass=8ImIblO4OS2qwms5mTwnhMaxmLBgISLU0GUNL4dlmWA=&inner-cipher=2022-blake3-aes-256-gcm"
	d, _, err := NewShadowTLS(&dialer.ExtraOption{}, next, link)
	if err != nil {
		t.Fatalf("NewShadowTLS failed: %v", err)
	}
	if _, ok := d.(*ShadowTLS); ok {
		t.Fatalf("expected wrapped shadowsocks dialer, got %T", d)
	}

	_, err = d.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected dial error from stub dialer")
	}
	if !strings.Contains(err.Error(), "stub dialer") {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if !next.called {
		t.Fatal("expected underlying dialer to be called")
	}
}

func TestShadowTLSUTLSHandshakeInvokesSessionIDGenerator(t *testing.T) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         "47.129.204.82",
		NextProtos:         []string{"h2", "http/1.1"},
	}
	handshakeFunc, err := newShadowTLSHandshakeFunc(3, "testyuanshen", tlsConfig, "utls", "chrome")
	if err != nil {
		t.Fatalf("newShadowTLSHandshakeFunc failed: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 4096)
		_, _ = serverConn.Read(buf)
		_ = serverConn.Close()
	}()

	var generatorCalled bool
	err = handshakeFunc(context.Background(), clientConn, func(clientHello []byte, sessionID []byte) error {
		generatorCalled = true
		if len(clientHello) == 0 {
			t.Fatal("expected client hello bytes")
		}
		if len(sessionID) == 0 {
			t.Fatal("expected session id bytes")
		}
		return nil
	})
	if !generatorCalled {
		t.Fatal("expected session id generator to be called")
	}
	if err == nil {
		t.Fatal("expected handshake to fail without a TLS server")
	}
	<-serverDone
}
