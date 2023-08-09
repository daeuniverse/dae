package socks

import (
	"fmt"

	"net"
	"net/url"
	"strconv"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol/socks5"
)

func init() {
	dialer.FromLinkRegister("socks", NewSocks) // socks -> socks5
	//dialer.FromLinkRegister("socks4", NewSocks)
	//dialer.FromLinkRegister("socks4a", NewSocks)
	dialer.FromLinkRegister("socks5", NewSocks)
}

type Socks struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Protocol string `json:"protocol"`
}

func NewSocks(option *dialer.GlobalOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseSocksURL(link)
	if err != nil {
		return nil, nil, dialer.InvalidParameterErr
	}
	return s.Dialer(option, nextDialer)
}

func (s *Socks) Dialer(option *dialer.GlobalOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	link := s.ExportToURL()
	d := nextDialer
	switch s.Protocol {
	case "", "socks", "socks5":
		d, err := socks5.NewSocks5Dialer(link, d) // Socks5 Proxy supports full-cone.
		if err != nil {
			return nil, nil, err
		}
		return d, &dialer.Property{
			Name:     s.Name,
			Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			Protocol: s.Protocol,
			Link:     link,
		}, nil
	//case "socks4", "socks4a":
	//	d, err := socks4.NewSocks4Dialer(link, &proxy.Direct{})
	//	if err != nil {
	//		return nil, err
	//	}
	//	return dialer.NewDialer(d, false, s.Name, s.Protocol, link), nil
	default:
		return nil, nil, fmt.Errorf("unexpected protocol: %v", s.Protocol)
	}
}

func ParseSocksURL(link string) (data *Socks, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	pwd, _ := u.User.Password()
	strPort := u.Port()
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, err
	}
	// socks -> socks5
	if u.Scheme == "socks" {
		u.Scheme = "socks5"
	}
	return &Socks{
		Name:     u.Fragment,
		Server:   u.Hostname(),
		Port:     port,
		Username: u.User.Username(),
		Password: pwd,
		Protocol: u.Scheme,
	}, nil
}

func (s *Socks) ExportToURL() string {
	var user *url.Userinfo
	if s.Password != "" {
		user = url.UserPassword(s.Username, s.Password)
	} else {
		user = url.User(s.Username)
	}
	u := url.URL{
		Scheme:   s.Protocol,
		User:     user,
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	return u.String()
}
