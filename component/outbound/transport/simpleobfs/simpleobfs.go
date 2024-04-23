package simpleobfs

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type ObfsType int

const (
	HTTP ObfsType = iota
	TLS
)

// SimpleObfs is a base http-obfs struct
type SimpleObfs struct {
	dialer   netproxy.Dialer
	obfstype ObfsType
	addr     string
	path     string
	host     string
}

// NewSimpleobfs returns a simpleobfs proxy.
func NewSimpleObfs(option *dialer.GlobalOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("simpleobfs: %w", err)
	}

	t := &SimpleObfs{
		dialer: nextDialer,
		addr:   u.Host,
	}
	query := u.Query()
	obfstype := query.Get("type")
	if obfstype == "" {
		obfstype = query.Get("obfs")
	}
	switch strings.ToLower(obfstype) {
	case "http":
		t.obfstype = HTTP
	case "tls":
		t.obfstype = TLS
	default:
		return nil, nil, fmt.Errorf("unsupported obfs type %v", obfstype)
	}
	t.host = query.Get("host")
	t.path = query.Get("path")
	if t.path == "" {
		t.path = query.Get("uri")
	}
	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.addr,
		Protocol: "simpleobfs(" + obfstype + ")",
		Link:     link,
	}, nil
}

func (s *SimpleObfs) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		rc, err := s.dialer.Dial(network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[simpleobfs]: dial to %s: %w", s.addr, err)
		}

		host, port, err := net.SplitHostPort(s.addr)
		if err != nil {
			return nil, err
		}
		if s.host != "" {
			host = s.host
		}
		switch s.obfstype {
		case HTTP:
			c = NewHTTPObfs(rc, host, port, s.path)
		case TLS:
			c = NewTLSObfs(rc, host)
		}
		return c, err
	case "udp":
		return nil, fmt.Errorf("%w: simpleobfs+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
