package tls

import (
	"crypto/tls"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"net/url"
)

// Tls is a base Tls struct
type Tls struct {
	dialer     netproxy.Dialer
	addr       string
	serverName string
	skipVerify bool
	tlsConfig  *tls.Config
}

// NewTls returns a Tls infra.
func NewTls(s string, d netproxy.Dialer) (*Tls, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewTls: %w", err)
	}

	t := &Tls{
		dialer: d,
		addr:   u.Host,
	}

	query := u.Query()
	t.serverName = query.Get("sni")

	// skipVerify
	if query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1" ||
		query.Get("skipVerify") == "true" || query.Get("skipVerify") == "1" {
		t.skipVerify = true
	}
	if t.serverName == "" {
		t.serverName = u.Hostname()
	}
	t.tlsConfig = &tls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
	}

	return t, nil
}

func (s *Tls) DialUdp(addr string) (conn netproxy.PacketConn, err error) {
	return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
}
func (s *Tls) DialTcp(addr string) (conn netproxy.Conn, err error) {
	rc, err := s.dialer.DialTcp(addr)
	if err != nil {
		return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
	}

	tlsConn := tls.Client(&netproxy.FakeNetConn{
		Conn:  rc,
		LAddr: nil,
		RAddr: nil,
	}, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, err
}
