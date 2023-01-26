package simpleobfs

import (
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"strings"
)

type ObfsType int

const (
	HTTP ObfsType = iota
	TLS
)

// SimpleObfs is a base http-obfs struct
type SimpleObfs struct {
	dialer   proxy.Dialer
	obfstype ObfsType
	addr     string
	path     string
	host     string
}

// NewSimpleobfs returns a simpleobfs proxy.
func NewSimpleObfs(s string, d proxy.Dialer) (*SimpleObfs, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("simpleobfs: %w", err)
	}

	t := &SimpleObfs{
		dialer: d,
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
		return nil, fmt.Errorf("unsupported obfs type %v", obfstype)
	}
	t.host = query.Get("host")
	t.path = query.Get("path")
	if t.path == "" {
		t.path = query.Get("uri")
	}
	return t, nil
}

// Dial connects to the address addr on the network net via the proxy.
func (s *SimpleObfs) Dial(network, addr string) (c net.Conn, err error) {
	if network == "udp" {
		return nil, fmt.Errorf("simple-obfs does not support UDP")
	}

	rc, err := s.dialer.Dial("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("[simpleobfs]: dial to %s: %w", s.addr, err)
	}
	switch s.obfstype {
	case HTTP:
		rs := strings.Split(s.addr, ":")
		var port string
		if len(rs) == 1 {
			port = "80"
		} else {
			port = rs[1]
		}
		c = NewHTTPObfs(rc, rs[0], port, s.path)
	case TLS:
		c = NewTLSObfs(rc, s.host)
	}
	return c, err
}
