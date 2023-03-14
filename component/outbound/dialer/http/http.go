package http

import (
	"fmt"
	"github.com/mzz2017/softwind/protocol/direct"
	"github.com/mzz2017/softwind/protocol/http"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"net"
	"net/url"
	"strconv"
)

func init() {
	dialer.FromLinkRegister("http", NewHTTP)
	dialer.FromLinkRegister("https", NewHTTP)
}

type HTTP struct {
	Name          string `json:"name"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SNI           string `json:"sni"`
	Protocol      string `json:"protocol"`
	AllowInsecure bool   `json:"allowInsecure"`
}

func NewHTTP(option *dialer.GlobalOption, iOption dialer.InstanceOption, link string) (*dialer.Dialer, error) {
	s, err := ParseHTTPURL(link, option)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", dialer.InvalidParameterErr, err)
	}
	return s.Dialer(option, iOption)
}

func ParseHTTPURL(link string, option *dialer.GlobalOption) (data *HTTP, err error) {
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
		Name:          u.Fragment,
		Server:        u.Hostname(),
		Port:          port,
		Username:      u.User.Username(),
		Password:      pwd,
		SNI:           u.Query().Get("sni"),
		Protocol:      u.Scheme,
		AllowInsecure: option.AllowInsecure,
	}, nil
}

func (s *HTTP) Dialer(option *dialer.GlobalOption, iOption dialer.InstanceOption) (*dialer.Dialer, error) {
	u := s.URL()
	d, err := http.NewHTTPProxy(&u, direct.SymmetricDirect) // HTTP Proxy does not support full-cone.
	if err != nil {
		return nil, err
	}
	return dialer.NewDialer(d, option, iOption, dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     u.String(),
	}), nil
}

func (s *HTTP) URL() url.URL {
	u := url.URL{
		Scheme:   s.Protocol,
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	if s.SNI != "" {
		u.RawQuery = url.Values{"sni": []string{s.SNI}, "allowInsecure": []string{common.BoolToString(s.AllowInsecure)}}.Encode()
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
