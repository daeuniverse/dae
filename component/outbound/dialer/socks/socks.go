package socks

import (
	"fmt"
	"foo/component/outbound/dialer"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/proxy/socks4"
	"github.com/nadoo/glider/proxy/socks5"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"strconv"
)

func init() {
	dialer.FromLinkRegister("socks", NewSocks) // socks -> socks5
	dialer.FromLinkRegister("socks4", NewSocks)
	dialer.FromLinkRegister("socks4a", NewSocks)
	dialer.FromLinkRegister("socks5", NewSocks)
	dialer.FromClashRegister("socks5", NewSocks5FromClashObj)
}

type Socks struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Protocol string `json:"protocol"`
}

func NewSocks(link string) (*dialer.Dialer, error) {
	s, err := ParseSocksURL(link)
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	return s.Dialer()
}

func NewSocks5FromClashObj(o *yaml.Node) (*dialer.Dialer, error) {
	s, err := ParseClashSocks5(o)
	if err != nil {
		return nil, err
	}
	return s.Dialer()
}

func (s *Socks) Dialer() (*dialer.Dialer, error) {
	link := s.ExportToURL()
	switch s.Protocol {
	case "", "socks", "socks5":
		d, err := socks5.NewSocks5Dialer(link, &proxy.Direct{})
		if err != nil {
			return nil, err
		}
		return dialer.NewDialer(d, true, s.Name, s.Protocol, link), nil
	case "socks4", "socks4a":
		d, err := socks4.NewSocks4Dialer(link, &proxy.Direct{})
		if err != nil {
			return nil, err
		}
		return dialer.NewDialer(d, false, s.Name, s.Protocol, link), nil
	default:
		return nil, fmt.Errorf("unexpected protocol: %v", s.Protocol)
	}
}

func ParseClashSocks5(o *yaml.Node) (data *Socks, err error) {
	type Socks5Option struct {
		Name           string `yaml:"name"`
		Server         string `yaml:"server"`
		Port           int    `yaml:"port"`
		UserName       string `yaml:"username,omitempty"`
		Password       string `yaml:"password,omitempty"`
		TLS            bool   `yaml:"tls,omitempty"`
		UDP            bool   `yaml:"udp,omitempty"`
		SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"`
	}
	var option Socks5Option
	if err = o.Decode(&option); err != nil {
		return nil, err
	}
	if option.TLS {
		return nil, fmt.Errorf("%w: tls=true", dialer.UnexpectedFieldErr)
	}
	if option.SkipCertVerify {
		return nil, fmt.Errorf("%w: skip-cert-verify=true", dialer.UnexpectedFieldErr)
	}
	return &Socks{
		Name:     option.Name,
		Server:   option.Server,
		Port:     option.Port,
		Username: option.UserName,
		Password: option.Password,
		Protocol: "socks5",
	}, nil
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
