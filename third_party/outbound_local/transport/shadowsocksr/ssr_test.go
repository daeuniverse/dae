package shadowsocksr

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/obfs"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/proto"
)

func TestTcp(t *testing.T) {
	// https://github.com/winterssy/SSR-Docker
	// Remember to set protocol_param to 3000# (max_client)
	d := direct.SymmetricDirect
	obfsDialer, err := obfs.NewDialer(d, &obfs.ObfsParam{
		ObfsHost:  "",
		ObfsPort:  0,
		Obfs:      "tls1.2_ticket_auth",
		ObfsParam: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	d = obfsDialer
	d, err = shadowsocks_stream.NewDialer(d, protocol.Header{
		ProxyAddress: "127.0.0.1:8989",
		Cipher:       "aes-256-cfb",
		Password:     "p@ssw0rd",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	d = &proto.Dialer{
		NextDialer:    d,
		Protocol:      "auth_chain_b",
		ProtocolParam: "",
		ObfsOverhead:  obfsDialer.ObfsOverhead(),
	}

	c := http.Client{
		Transport: &http.Transport{Dial: func(network string, addr string) (net.Conn, error) {
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
	resp, err := c.Get("https://www.7k7k.com")
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	t.Log(buf.String())
}

func TestUdp(t *testing.T) {
	// https://github.com/winterssy/SSR-Docker
	// Remember to set protocol_param to 3000# (max_client)
	d := direct.SymmetricDirect
	d, err := shadowsocks_stream.NewDialer(d, protocol.Header{
		ProxyAddress: "127.0.0.1:8989",
		Cipher:       "aes-256-cfb",
		Password:     "p@ssw0rd",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	d = &proto.Dialer{
		NextDialer:    d,
		Protocol:      "auth_chain_b",
		ProtocolParam: "",
		ObfsOverhead:  0,
	}

	resolver := net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if !strings.HasPrefix(network, "udp") {
				return nil, fmt.Errorf("unsupported network")
			}
			c, err := d.DialContext(ctx, "udp", address)
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
