package socks

import (
	"fmt"
	"github.com/v2rayA/dae/component/outbound/dialer"
	//"github.com/mzz2017/softwind/protocol/socks4"
	"github.com/mzz2017/softwind/protocol/socks5"
	"net"
	"net/url"
	"strconv"
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

func NewSocks(option *dialer.GlobalOption, iOption dialer.InstanceOption, link string) (*dialer.Dialer, error) {
	s, err := ParseSocksURL(link)
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	return s.Dialer(option, iOption)
}

func (s *Socks) Dialer(option *dialer.GlobalOption, iOption dialer.InstanceOption) (*dialer.Dialer, error) {
	link := s.ExportToURL()
	switch s.Protocol {
	case "", "socks", "socks5":
		d, err := socks5.NewSocks5Dialer(link, dialer.FullconeDirect) // Socks5 Proxy supports full-cone.
		if err != nil {
			return nil, err
		}
		return dialer.NewDialer(d, option, iOption,  s.Name, s.Protocol, link), nil
	//case "socks4", "socks4a":
	//	d, err := socks4.NewSocks4Dialer(link, &proxy.Direct{})
	//	if err != nil {
	//		return nil, err
	//	}
	//	return dialer.NewDialer(d, false, s.Name, s.Protocol, link), nil
	default:
		return nil, fmt.Errorf("unexpected protocol: %v", s.Protocol)
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
