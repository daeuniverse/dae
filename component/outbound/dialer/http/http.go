package http

import (
	"fmt"
	"foo/component/outbound/dialer"
	"github.com/mzz2017/softwind/protocol/http"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"strconv"
)

func init() {
	dialer.FromLinkRegister("http", NewHTTP)
	dialer.FromLinkRegister("https", NewHTTP)
	dialer.FromClashRegister("http", NewSocks5FromClashObj)
}

type HTTP struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	SNI      string `json:"sni"`
	Protocol string `json:"protocol"`
}

func NewHTTP(link string) (*dialer.Dialer, error) {
	s, err := ParseHTTPURL(link)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", dialer.InvalidParameterErr, err)
	}
	return s.Dialer()
}

func NewSocks5FromClashObj(o *yaml.Node) (*dialer.Dialer, error) {
	s, err := ParseClash(o)
	if err != nil {
		return nil, err
	}
	return s.Dialer()
}

func ParseHTTPURL(link string) (data *HTTP, err error) {
	u, err := url.Parse(link)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%w: %v", dialer.InvalidParameterErr, err)
	}
	pwd, _ := u.User.Password()
	strPort := u.Port()
	if strPort == "" {
		if u.Scheme == "http" {
			strPort = "80"
		} else if u.Scheme == "https" {
			strPort = "443"
		}
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, fmt.Errorf("error when parsing port: %w", err)
	}
	return &HTTP{
		Name:     u.Fragment,
		Server:   u.Hostname(),
		Port:     port,
		Username: u.User.Username(),
		Password: pwd,
		SNI:      u.Query().Get("sni"),
		Protocol: u.Scheme,
	}, nil
}

func ParseClash(o *yaml.Node) (data *HTTP, err error) {
	type HttpOption struct {
		Name           string `yaml:"name"`
		Server         string `yaml:"server"`
		Port           int    `yaml:"port"`
		UserName       string `yaml:"username,omitempty"`
		Password       string `yaml:"password,omitempty"`
		TLS            bool   `yaml:"tls,omitempty"`
		SNI            string `yaml:"sni,omitempty"`
		SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"`
	}
	var option HttpOption
	if err = o.Decode(&option); err != nil {
		return nil, err
	}
	scheme := "http"
	if option.TLS {
		scheme = "https"
	}
	if option.SkipCertVerify {
		return nil, fmt.Errorf("%w: skip-cert-verify=true", dialer.UnexpectedFieldErr)
	}
	return &HTTP{
		Name:     option.Name,
		Server:   option.Server,
		Port:     option.Port,
		Username: option.UserName,
		Password: option.Password,
		SNI:      option.SNI,
		Protocol: scheme,
	}, nil
}

func (s *HTTP) Dialer() (*dialer.Dialer, error) {
	u := s.URL()
	d, err := http.NewHTTPProxy(&u, dialer.SymmetricDirect)
	if err != nil {
		return nil, err
	}
	return dialer.NewDialer(d, false, s.Name, s.Protocol, u.String()), nil
}

func (s *HTTP) URL() url.URL {
	u := url.URL{
		Scheme:   s.Protocol,
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	if s.SNI != "" {
		u.RawQuery = url.Values{"sni": []string{s.SNI}}.Encode()
	}
	if s.Username != "" {
		if s.Password != "" {
			u.User = url.UserPassword(s.Username, s.Password)
		} else {
			u.User = url.User(s.Username)
		}
	}
	return u
}

func (s *HTTP) ExportToURL() string {
	u := s.URL()
	return u.String()
}
