package tls

import (
	"crypto/tls"
	"fmt"
	"net/url"

	"github.com/mzz2017/softwind/netproxy"
	utls "github.com/refraction-networking/utls"
)

// Tls is a base Tls struct
type Tls struct {
	dialer          netproxy.Dialer
	addr            string
	serverName      string
	skipVerify      bool
	tlsImplentation string
	utlsImitate     string

	tlsConfig *tls.Config
}

// NewTls returns a Tls infra.
func NewTls(s string, d netproxy.Dialer) (*Tls, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewTls: %w", err)
	}

	t := &Tls{
		dialer:          d,
		addr:            u.Host,
		tlsImplentation: u.Scheme,
	}

	query := u.Query()
	t.serverName = query.Get("sni")
	t.utlsImitate = query.Get("utlsImitate")

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

func (s *Tls) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		rc, err := s.dialer.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
		}

		var tlsConn interface {
			netproxy.Conn
			Handshake() error
		}

		switch s.tlsImplentation {
		case "tls":
			tlsConn = tls.Client(&netproxy.FakeNetConn{
				Conn:  rc,
				LAddr: nil,
				RAddr: nil,
			}, s.tlsConfig)

		case "utls":
			clientHelloID, err := nameToUtlsClientHelloID(s.utlsImitate)
			if err != nil {
				return nil, err
			}

			tlsConn = utls.UClient(&netproxy.FakeNetConn{
				Conn:  rc,
				LAddr: nil,
				RAddr: nil,
			}, uTLSConfigFromTLSConfig(s.tlsConfig), *clientHelloID)

		default:
			return nil, fmt.Errorf("unknown tls implementation: %v", s.tlsImplentation)
		}

		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		return tlsConn, err
	case "udp":
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
