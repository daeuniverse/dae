package simpleobfs

import (
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
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
	dialer   netproxy.Dialer
	obfstype ObfsType
	addr     string
	path     string
	host     string
}

// NewSimpleobfs returns a simpleobfs proxy.
func NewSimpleObfs(s string, d netproxy.Dialer) (*SimpleObfs, error) {
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

func (s *SimpleObfs) DialUdp(addr string) (conn netproxy.PacketConn, err error) {
	return nil, fmt.Errorf("%w: simpleobfs+udp", netproxy.UnsupportedTunnelTypeError)
}
// DialTcp connects to the address addr on the network net via the proxy.
func (s *SimpleObfs) DialTcp(addr string) (c netproxy.Conn, err error) {

	rc, err := s.dialer.DialTcp(s.addr)
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
}
