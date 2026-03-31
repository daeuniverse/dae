package anytls

import (
	"crypto/tls"
	"net/url"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("anytls", NewAnytls)
}

type Anytls struct {
	link     string
	Name     string
	Auth     string
	Host     string
	Sni      string
	Insecure bool
}

func NewAnytls(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	switch {
	case strings.HasPrefix(link, "anytls://"):
		s, err := parseAnytlsURL(link)
		if err != nil {
			return nil, nil, err
		}
		return s.Dialer(option, nextDialer)
	default:
		return nil, nil, dialer.InvalidParameterErr
	}
}

func parseAnytlsURL(link string) (*Anytls, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	sni := u.Query().Get("peer")
	if sni == "" {
		sni = u.Query().Get("sni")
	}
	if sni == "" {
		sni = u.Hostname()
	}
	antls := &Anytls{
		link:     link,
		Name:     u.Fragment,
		Auth:     u.User.Username(),
		Host:     u.Host,
		Sni:      sni,
		Insecure: u.Query().Get("insecure") == "1",
	}

	return antls, nil
}

func (s *Anytls) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	tlsConfig := &tls.Config{
		ServerName:         s.Sni,
		InsecureSkipVerify: s.Insecure,
	}
	if tlsConfig.ServerName == "" {
		// disable the SNI
		tlsConfig.ServerName = "127.0.0.1"
	}
	d, err := protocol.NewDialer("anytls", nextDialer, protocol.Header{
		ProxyAddress: s.Host,
		Password:     s.Auth,
		IsClient:     true,
		TlsConfig:    tlsConfig,
	})
	if err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Protocol: "anytls",
		Address:  s.Host,
		Link:     s.link,
	}, nil
}
