package ws

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mzz2017/softwind/netproxy"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

// Ws is a base Ws struct
type Ws struct {
	dialer          netproxy.Dialer
	wsAddr          string
	header          http.Header
	tlsClientConfig *tls.Config
}

// NewWs returns a Ws infra.
func NewWs(s string, d netproxy.Dialer) (*Ws, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewWs: %w", err)
	}

	t := &Ws{
		dialer: d,
	}

	query := u.Query()
	host := query.Get("host")
	if host == "" {
		host = u.Hostname()
	}
	t.header = http.Header{}
	t.header.Set("Host", host)

	wsUrl := url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
	}
	t.wsAddr = wsUrl.String() + u.Path
	if u.Scheme == "wss" {
		skipVerify, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
		t.tlsClientConfig = &tls.Config{
			ServerName:         u.Query().Get("sni"),
			InsecureSkipVerify: skipVerify,
		}
	}
	return t, nil
}

func (s *Ws) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		wsDialer := &websocket.Dialer{
			NetDial: func(_, addr string) (net.Conn, error) {
				c, err := s.dialer.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  c,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			//Subprotocols: []string{"binary"},
		}
		rc, _, err := wsDialer.Dial(s.wsAddr, s.header)
		if err != nil {
			return nil, fmt.Errorf("[Ws]: dial to %s: %w", s.wsAddr, err)
		}
		return newConn(rc), err
	case "udp":
		return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
