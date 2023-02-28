package v2ray

import (
	"encoding/base64"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/direct"
	"github.com/mzz2017/softwind/transport/grpc"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/component/outbound/transport/tls"
	"github.com/v2rayA/dae/component/outbound/transport/ws"
	"net"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	dialer.FromLinkRegister("vmess", NewV2Ray)
	dialer.FromLinkRegister("vless", NewV2Ray)
}

type V2Ray struct {
	Ps            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	Aid           string `json:"aid"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	SNI           string `json:"sni"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	Flow          string `json:"flow,omitempty"`
	Alpn          string `json:"alpn,omitempty"`
	AllowInsecure bool   `json:"allowInsecure"`
	V             string `json:"v"`
	Protocol      string `json:"protocol"`
}

func NewV2Ray(option *dialer.GlobalOption, iOption dialer.InstanceOption, link string) (*dialer.Dialer, error) {
	var (
		s   *V2Ray
		err error
	)
	switch {
	case strings.HasPrefix(link, "vmess://"):
		s, err = ParseVmessURL(link, option)
		if err != nil {
			return nil, err
		}
		if s.Aid != "0" && s.Aid != "" {
			return nil, fmt.Errorf("%w: aid: %v, we only support AEAD encryption", dialer.UnexpectedFieldErr, s.Aid)
		}
	case strings.HasPrefix(link, "vless://"):
		s, err = ParseVlessURL(link, option)
		if err != nil {
			return nil, err
		}
	default:
		return nil, dialer.InvalidParameterErr
	}
	return s.Dialer(option, iOption)
}

func (s *V2Ray) Dialer(option *dialer.GlobalOption, iOption dialer.InstanceOption) (data *dialer.Dialer, err error) {
	var d netproxy.Dialer
	switch s.Protocol {
	case "vmess":
		d = direct.FullconeDirect // VMess Proxy supports full-cone.
	case "vless":
		d = direct.SymmetricDirect // VLESS Proxy does not yet support full-cone by softwind.
	default:
		return nil, fmt.Errorf("V2Ray.Dialer: unexpected protocol: %v", s.Protocol)
	}

	switch strings.ToLower(s.Net) {
	case "ws":
		scheme := "ws"
		if s.TLS == "tls" || s.TLS == "xtls" {
			scheme = "wss"
		}
		sni := s.SNI
		if sni == "" {
			sni = s.Host
		}
		u := url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(s.Add, s.Port),
			Path:   s.Path,
			RawQuery: url.Values{
				"host":          []string{s.Host},
				"sni":           []string{sni},
				"allowInsecure": []string{common.BoolToString(s.AllowInsecure)},
			}.Encode(),
		}
		d, err = ws.NewWs(u.String(), d)
		if err != nil {
			return nil, err
		}
	case "tcp":
		if s.TLS == "tls" || s.TLS == "xtls" {
			sni := s.SNI
			if sni == "" {
				sni = s.Host
			}
			u := url.URL{
				Scheme: "tls",
				Host:   net.JoinHostPort(s.Add, s.Port),
				RawQuery: url.Values{
					"sni":           []string{sni},
					"allowInsecure": []string{common.BoolToString(s.AllowInsecure)},
				}.Encode(),
			}
			d, err = tls.NewTls(u.String(), d)
			if err != nil {
				return nil, err
			}
		}
		if s.Type != "none" && s.Type != "" {
			return nil, fmt.Errorf("%w: type: %v", dialer.UnexpectedFieldErr, s.Type)
		}
	case "grpc":
		sni := s.SNI
		if sni == "" {
			sni = s.Host
		}
		serviceName := s.Path
		if serviceName == "" {
			serviceName = "GunService"
		}
		d = &grpc.Dialer{
			NextDialer:    &netproxy.ContextDialer{Dialer: d},
			ServiceName:   serviceName,
			ServerName:    sni,
			AllowInsecure: s.AllowInsecure,
		}
	default:
		return nil, fmt.Errorf("%w: network: %v", dialer.UnexpectedFieldErr, s.Net)
	}

	if d, err = protocol.NewDialer(s.Protocol, d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Add, s.Port),
		Cipher:       "aes-128-gcm",
		Password:     s.ID,
		IsClient:     true,
		//Flags:        protocol.Flags_VMess_UsePacketAddr,
	}); err != nil {
		return nil, err
	}
	return dialer.NewDialer(d, option, iOption, dialer.Property{
		Name:     s.Ps,
		Address:  net.JoinHostPort(s.Add, s.Port),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}), nil
}

func ParseVlessURL(vless string, option *dialer.GlobalOption) (data *V2Ray, err error) {
	u, err := url.Parse(vless)
	if err != nil {
		return nil, err
	}
	data = &V2Ray{
		Ps:       u.Fragment,
		Add:      u.Hostname(),
		Port:     u.Port(),
		ID:       u.User.String(),
		Net:      u.Query().Get("type"),
		Type:     u.Query().Get("headerType"),
		SNI:      u.Query().Get("sni"),
		Host:     u.Query().Get("host"),
		Path:     u.Query().Get("path"),
		TLS:      u.Query().Get("security"),
		Flow:     u.Query().Get("flow"),
		Alpn:     u.Query().Get("alpn"),
		Protocol: "vless",
	}
	if data.Net == "" {
		data.Net = "tcp"
	}
	if data.Net == "grpc" {
		data.Path = u.Query().Get("serviceName")
	}
	if data.Type == "" {
		data.Type = "none"
	}
	if data.TLS == "" {
		data.TLS = "none"
	}
	if data.Flow == "" {
		data.Flow = "xtls-rprx-direct"
	}
	if data.Type == "mkcp" || data.Type == "kcp" {
		data.Path = u.Query().Get("seed")
	}
	if option.AllowInsecure {
		data.AllowInsecure = true
	}
	return data, nil
}

func ParseVmessURL(vmess string, option *dialer.GlobalOption) (data *V2Ray, err error) {
	var info V2Ray
	// perform base64 decoding and unmarshal to VmessInfo
	raw, err := common.Base64StdDecode(vmess[8:])
	if err != nil {
		raw, err = common.Base64UrlDecode(vmess[8:])
	}
	if err != nil {
		// not in json format, try to resolve as vmess://BASE64(Security:ID@Add:Port)?remarks=Ps&obfsParam=Host&Path=Path&obfs=Net&tls=TLS
		var u *url.URL
		u, err = url.Parse(vmess)
		if err != nil {
			return
		}
		re := regexp.MustCompile(`.*:(.+)@(.+):(\d+)`)
		s := strings.Split(vmess[8:], "?")[0]
		s, err = common.Base64StdDecode(s)
		if err != nil {
			s, err = common.Base64UrlDecode(s)
		}
		subMatch := re.FindStringSubmatch(s)
		if subMatch == nil {
			err = fmt.Errorf("unrecognized vmess address")
			return
		}
		q := u.Query()
		ps := q.Get("remarks")
		if ps == "" {
			ps = q.Get("remark")
		}
		obfs := q.Get("obfs")
		obfsParam := q.Get("obfsParam")
		path := q.Get("path")
		if obfs == "kcp" || obfs == "mkcp" {
			m := make(map[string]string)
			//cater to v2rayN definition
			_ = jsoniter.Unmarshal([]byte(obfsParam), &m)
			path = m["seed"]
			obfsParam = ""
		}
		aid := q.Get("alterId")
		if aid == "" {
			aid = q.Get("aid")
		}
		info = V2Ray{
			ID:            subMatch[1],
			Add:           subMatch[2],
			Port:          subMatch[3],
			Ps:            ps,
			Host:          obfsParam,
			Path:          path,
			Net:           obfs,
			Aid:           aid,
			TLS:           map[string]string{"1": "tls"}[q.Get("tls")],
			AllowInsecure: false,
		}
		if info.Net == "websocket" {
			info.Net = "ws"
		}
	} else {
		err = jsoniter.Unmarshal([]byte(raw), &info)
		if err != nil {
			return
		}
	}
	// correct the wrong vmess as much as possible
	if strings.HasPrefix(info.Host, "/") && info.Path == "" {
		info.Path = info.Host
		info.Host = ""
	}
	if info.Aid == "" {
		info.Aid = "0"
	}
	info.Protocol = "vmess"
	if option.AllowInsecure {
		info.AllowInsecure = true
	}
	return &info, nil
}

func (s *V2Ray) ExportToURL() string {
	switch s.Protocol {
	case "vless":
		// https://github.com/XTLS/Xray-core/issues/91
		var query = make(url.Values)
		common.SetValue(&query, "type", s.Net)
		common.SetValue(&query, "security", s.TLS)
		switch s.Net {
		case "websocket", "ws", "http", "h2":
			common.SetValue(&query, "path", s.Path)
			common.SetValue(&query, "host", s.Host)
		case "mkcp", "kcp":
			common.SetValue(&query, "headerType", s.Type)
			common.SetValue(&query, "seed", s.Path)
		case "tcp":
			common.SetValue(&query, "headerType", s.Type)
			common.SetValue(&query, "host", s.Host)
			common.SetValue(&query, "path", s.Path)
		case "grpc":
			common.SetValue(&query, "serviceName", s.Path)
		}
		//TODO: QUIC
		if s.TLS != "none" {
			common.SetValue(&query, "sni", s.Host) // FIXME: it may be different from ws's host
			common.SetValue(&query, "alpn", s.Alpn)
		}
		if s.TLS == "xtls" {
			common.SetValue(&query, "flow", s.Flow)
		}

		U := url.URL{
			Scheme:   "vless",
			User:     url.User(s.ID),
			Host:     net.JoinHostPort(s.Add, s.Port),
			RawQuery: query.Encode(),
			Fragment: s.Ps,
		}
		return U.String()
	case "vmess":
		s.V = "2"
		b, _ := jsoniter.Marshal(s)
		return "vmess://" + strings.TrimSuffix(base64.StdEncoding.EncodeToString(b), "=")
	}
	//log.Warn("unexpected protocol: %v", v.Protocol)
	return ""
}
