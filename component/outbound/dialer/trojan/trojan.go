package trojan

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/outbound/transport/tls"
	"github.com/daeuniverse/dae/component/outbound/transport/ws"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/direct"
	"github.com/mzz2017/softwind/transport/grpc"
)

func init() {
	dialer.FromLinkRegister("trojan", NewTrojan)
	dialer.FromLinkRegister("trojan-go", NewTrojan)
}

type Trojan struct {
	Name          string `json:"name"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Password      string `json:"password"`
	Sni           string `json:"sni"`
	Type          string `json:"type"`
	Encryption    string `json:"encryption"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	ServiceName   string `json:"serviceName"`
	AllowInsecure bool   `json:"allowInsecure"`
	Protocol      string `json:"protocol"`
}

func NewTrojan(option *dialer.GlobalOption, iOption dialer.InstanceOption, link string) (*dialer.Dialer, error) {
	s, err := ParseTrojanURL(link, option)
	if err != nil {
		return nil, err
	}
	return s.Dialer(option, iOption)
}

func (s *Trojan) Dialer(option *dialer.GlobalOption, iOption dialer.InstanceOption) (*dialer.Dialer, error) {
	d := direct.FullconeDirect // Trojan Proxy supports full-cone.
	u := url.URL{
		Scheme: "tls",
		Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		RawQuery: url.Values{
			"sni":           []string{s.Sni},
			"allowInsecure": []string{common.BoolToString(s.AllowInsecure)},
		}.Encode(),
	}
	var err error
	if s.Type != "grpc" {
		// grpc contains tls
		if d, err = tls.NewTls(u.String(), d); err != nil {
			return nil, err
		}
	}
	// "tls,ws,ss,trojanc"
	switch s.Type {
	case "ws":
		u = url.URL{
			Scheme: "ws",
			Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			RawQuery: url.Values{
				"host": []string{s.Host},
				"path": []string{s.Path},
			}.Encode(),
		}
		if d, err = ws.NewWs(u.String(), d); err != nil {
			return nil, err
		}
	case "grpc":
		serviceName := s.ServiceName
		if serviceName == "" {
			serviceName = "GunService"
		}
		d = &grpc.Dialer{
			NextDialer:    &netproxy.ContextDialer{Dialer: d},
			ServiceName:   serviceName,
			ServerName:    s.Sni,
			AllowInsecure: s.AllowInsecure,
		}
	}
	if strings.HasPrefix(s.Encryption, "ss;") {
		fields := strings.SplitN(s.Encryption, ";", 3)
		if d, err = protocol.NewDialer("shadowsocks", d, protocol.Header{
			ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			Cipher:       fields[1],
			Password:     fields[2],
			IsClient:     false,
		}); err != nil {
			return nil, err
		}
	}
	if d, err = protocol.NewDialer("trojanc", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Password:     s.Password,
		IsClient:     true,
	}); err != nil {
		return nil, err
	}
	return dialer.NewDialer(d, option, iOption, dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}), nil
}

func ParseTrojanURL(u string, option *dialer.GlobalOption) (data *Trojan, err error) {
	//trojan://password@server:port#escape(remarks)
	t, err := url.Parse(u)
	if err != nil {
		err = fmt.Errorf("invalid trojan format")
		return
	}
	allowInsecure, _ := strconv.ParseBool(t.Query().Get("allowInsecure"))
	if !allowInsecure && option.AllowInsecure {
		allowInsecure = true
	}
	sni := t.Query().Get("peer")
	if sni == "" {
		sni = t.Query().Get("sni")
	}
	if sni == "" {
		sni = t.Hostname()
	}
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	data = &Trojan{
		Name:          t.Fragment,
		Server:        t.Hostname(),
		Port:          port,
		Password:      t.User.Username(),
		Sni:           sni,
		AllowInsecure: allowInsecure,
		Protocol:      "trojan",
	}
	if t.Query().Get("type") != "" {
		t.Scheme = "trojan-go"
	}
	if t.Scheme == "trojan-go" {
		data.Protocol = "trojan-go"
		data.Encryption = t.Query().Get("encryption")
		data.Host = t.Query().Get("host")
		data.Path = t.Query().Get("path")
		data.Type = t.Query().Get("type")
		data.ServiceName = t.Query().Get("serviceName")
		if data.Type == "grpc" && data.ServiceName == "" {
			data.ServiceName = data.Path
		}
	}
	return data, nil
}

func (t *Trojan) ExportToURL() string {
	u := &url.URL{
		Scheme:   "trojan",
		User:     url.User(t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)

	if t.Protocol == "trojan-go" {
		u.Scheme = "trojan-go"
		common.SetValue(&q, "host", t.Host)
		common.SetValue(&q, "encryption", t.Encryption)
		common.SetValue(&q, "type", t.Type)
		common.SetValue(&q, "path", t.Path)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
