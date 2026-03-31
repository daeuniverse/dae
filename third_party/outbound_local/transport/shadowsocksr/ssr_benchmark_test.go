package shadowsocksr

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/obfs"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/proto"
)

func BenchmarkSSR(b *testing.B) {
	for i := 0; i < b.N; i++ {
		d := direct.SymmetricDirect
		obfsDialer, err := obfs.NewDialer(d, &obfs.ObfsParam{
			ObfsHost:  "",
			ObfsPort:  0,
			Obfs:      "tls1.2_ticket_auth",
			ObfsParam: "",
		})
		if err != nil {
			b.Fatal(err)
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
			b.Fatal(err)
		}
		d = &proto.Dialer{
			NextDialer:    d,
			Protocol:      "auth_chain_a",
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
		resp, err := c.Get("http://192.168.1.6:2017")
		if err != nil {
			b.Fatal(err)
		}
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		//b.Log(buf.String())
		_ = resp.Body.Close()
	}
}
