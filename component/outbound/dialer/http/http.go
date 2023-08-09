package http

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol/http"
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

func NewHTTP(option *dialer.GlobalOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseHTTPURL(link)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", dialer.InvalidParameterErr, err)
	}
	return s.Dialer(option, nextDialer)
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
	return &HTTP{
		Name:          u.Fragment,
		Server:        u.Hostname(),
		Port:          port,
		Username:      u.User.Username(),
		Password:      pwd,
		SNI:           u.Query().Get("sni"),
		Protocol:      u.Scheme,
		AllowInsecure: allowInsecure,
	}, nil
}

func (s *HTTP) Dialer(option *dialer.GlobalOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	u := s.URL()
	d, err := http.NewHTTPProxy(&u, nextDialer)
	if err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     u.String(),
	}, nil
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
