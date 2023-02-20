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
	dialer   netproxy.Dialer
	wsAddr   string
	header   http.Header
	wsDialer *websocket.Dialer
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
	t.wsDialer = &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			c, err := d.DialTcp(addr)
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
	if u.Scheme == "wss" {
		skipVerify, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
		t.wsDialer.TLSClientConfig = &tls.Config{
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
		return s.DialTcp(addr)
	case "udp":
		return s.DialUdp(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Ws) DialUdp(addr string) (netproxy.PacketConn, error) {
	return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
}

// DialTcp connects to the address addr on the network net via the infra.
func (s *Ws) DialTcp(addr string) (netproxy.Conn, error) {
	rc, _, err := s.wsDialer.Dial(s.wsAddr, s.header)
	if err != nil {
		return nil, fmt.Errorf("[Ws]: dial to %s: %w", s.wsAddr, err)
	}
	return newConn(rc), err
}
