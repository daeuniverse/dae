package tls

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/softwind/netproxy"
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
func NewTls(option *dialer.GlobalOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewTls: %w", err)
	}

	query := u.Query()

	tlsImplentation := u.Scheme
	utlsImitate := query.Get("utlsImitate")
	if tlsImplentation == "tls" && option.TlsImplementation != "" {
		tlsImplentation = option.TlsImplementation
		utlsImitate = option.UtlsImitate
	}
	t := &Tls{
		dialer:          nextDialer,
		addr:            u.Host,
		tlsImplentation: tlsImplentation,
		utlsImitate:     utlsImitate,
		serverName:      query.Get("sni"),
	}
	if t.serverName == "" {
		t.serverName = u.Hostname()
	}

	// skipVerify
	allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
	}
	t.skipVerify = allowInsecure || option.AllowInsecure
	t.tlsConfig = &tls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
	}
	if len(query.Get("alpn")) > 0 {
		t.tlsConfig.NextProtos = strings.Split(query.Get("alpn"), ",")
	}

	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.addr,
		Protocol: tlsImplentation,
		Link:     link,
	}, nil
}

func (s *Tls) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		rc, err := s.dialer.Dial(network, s.addr)
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
