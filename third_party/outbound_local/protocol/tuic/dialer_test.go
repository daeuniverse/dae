package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type Params struct {
	Method, Passwd, Address, Port string
}

func TestTcp(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "example.com:10383",
		SNI:          "",
		Feature1:     "bbr",
		TlsConfig:    &tls.Config{NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "example.com"},
		Cipher:       "",
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "password",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: func(network string, addr string) (net.Conn, error) {
			t.Log("target", addr)
			c, err := d.DialContext(context.Background(), "tcp", addr)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{
				Conn:  c,
				LAddr: nil,
				RAddr: nil,
			}, nil
		}},
	}
	resp, err := c.Get("https://ipinfo.io")
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	t.Log(buf.String())
}

func TestUdp(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "example.com:10383",
		SNI:          "",
		Feature1:     "bbr",
		TlsConfig:    &tls.Config{NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "example.com"},
		Cipher:       "",
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "password",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if !strings.HasPrefix(network, "udp") {
				return nil, fmt.Errorf("unsupported network")
			}
			c, err := d.DialContext(context.Background(), "udp", address)
			if err != nil {
				return nil, err
			}
			return netproxy.NewFakeNetPacketConn(
				c.(netproxy.PacketConn),
				nil,
				nil,
			), nil
		},
	}
	ips, err := resolver.LookupNetIP(context.TODO(), "ip", "www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ips)
}
