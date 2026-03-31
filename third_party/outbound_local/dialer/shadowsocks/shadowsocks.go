package shadowsocks

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/transport/mux"
	"github.com/daeuniverse/outbound/transport/shadowtls"
	"github.com/daeuniverse/outbound/transport/simpleobfs"
	"github.com/daeuniverse/outbound/transport/tls"
	"github.com/daeuniverse/outbound/transport/ws"
)

func init() {
	dialer.FromLinkRegister("shadowsocks", NewShadowsocksFromLink)
	dialer.FromLinkRegister("ss", NewShadowsocksFromLink)
}

type Shadowsocks struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Cipher   string `json:"cipher"`
	Plugin   Sip003 `json:"plugin"`
	UDP      bool   `json:"udp"`
	Protocol string `json:"protocol"`
}

func NewShadowsocksFromLink(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (npd netproxy.Dialer, property *dialer.Property, err error) {
	s, err := ParseSSURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Shadowsocks) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	var err error
	d := nextDialer
	switch s.Plugin.Name {
	case "simple-obfs":
		switch s.Plugin.Opts.Obfs {
		case "http", "tls":
		default:
			return nil, nil, fmt.Errorf("unsupported obfs %v of plugin %v", s.Plugin.Opts.Obfs, s.Plugin.Name)
		}
		host := s.Plugin.Opts.Host
		if host == "" {
			host = "cloudflare.com"
		}
		path := s.Plugin.Opts.Path
		uSimpleObfs := url.URL{
			Scheme: "simple-obfs",
			Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			RawQuery: url.Values{
				"obfs": []string{s.Plugin.Opts.Obfs},
				"host": []string{host},
				"uri":  []string{path},
			}.Encode(),
		}
		d, _, err = simpleobfs.NewSimpleObfs(option, d, uSimpleObfs.String())
		if err != nil {
			return nil, nil, err
		}
	case "v2ray-plugin":
		// https://github.com/teddysun/v2ray-plugin
		switch s.Plugin.Opts.Obfs {
		case "":
			if s.Plugin.Opts.Tls == "tls" {
				u := url.URL{
					Scheme: option.TlsImplementation,
					Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
					RawQuery: url.Values{
						"sni":            []string{s.Plugin.Opts.Host},
						"allowInsecure":  []string{common.BoolToString(option.AllowInsecure)},
						"utlsImitate":    []string{option.UtlsImitate},
						"passthroughUdp": []string{"1"},
					}.Encode(),
				}
				if d, _, err = tls.NewTls(option, d, u.String()); err != nil {
					return nil, nil, err
				}
			}
			u := url.URL{
				Scheme: "ws",
				Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
				RawQuery: url.Values{
					"host":           []string{s.Plugin.Opts.Host},
					"path":           []string{"/"},
					"passthroughUdp": []string{"1"},
				}.Encode(),
			}
			if d, _, err = ws.NewWs(option, d, u.String()); err != nil {
				return nil, nil, err
			}
			d = &mux.Mux{
				NextDialer:     d,
				Addr:           net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
				PassthroughUdp: true,
			}
		default:
			return nil, nil, fmt.Errorf("unsupported mode %v of plugin %v", s.Plugin.Opts.Obfs, s.Plugin.Name)
		}
	case "shadow-tls":
		uShadowTLS := url.URL{
			Scheme: "shadow-tls",
			Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		}
		if s.Plugin.Opts.Password != "" {
			uShadowTLS.User = url.User(s.Plugin.Opts.Password)
		}
		query := uShadowTLS.Query()
		if s.Plugin.Opts.Version != "" {
			query.Set("version", s.Plugin.Opts.Version)
		}
		sni := s.Plugin.Opts.SNI
		if sni == "" {
			sni = s.Plugin.Opts.Host
		}
		if sni != "" {
			query.Set("sni", sni)
		}
		if s.Plugin.Opts.AllowInsecure != "" {
			query.Set("allowInsecure", s.Plugin.Opts.AllowInsecure)
		}
		uShadowTLS.RawQuery = query.Encode()
		if d, _, err = shadowtls.NewShadowTLS(option, d, uShadowTLS.String()); err != nil {
			return nil, nil, err
		}
	default:
	}
	var nextDialerName string
	switch s.Cipher {
	case "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305":
		nextDialerName = "shadowsocks"
	case "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305":
		nextDialerName = "shadowsocks_2022"
	case "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-ofb", "aes-192-ofb", "aes-256-ofb", "des-cfb", "bf-cfb", "cast5-cfb", "rc4-md5", "rc4-md5-6", "chacha20", "chacha20-ietf", "salsa20", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "rc4", "none", "plain":
		nextDialerName = "shadowsocks_stream"
	default:
		return nil, nil, fmt.Errorf("unsupported shadowsocks encryption method: %v", s.Cipher)
	}
	d, err = protocol.NewDialer(nextDialerName, d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Cipher:       s.Cipher,
		Password:     s.Password,
		IsClient:     true,
	})
	if err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func ParseSSURL(u string) (data *Shadowsocks, err error) {
	// parse attempts to parse ss:// links
	parse := func(content string) (v *Shadowsocks, ok bool) {
		// try to parse in the format of ss://BASE64(method:password)@server:port/?plugin=xxxx#name
		u, err := url.Parse(content)
		if err != nil {
			return nil, false
		}
		username := u.User.String()
		username, _ = common.Base64UrlDecode(username)
		arr := strings.SplitN(username, ":", 2)
		if len(arr) != 2 {
			return nil, false
		}
		cipher := arr[0]
		password := arr[1]
		var sip003 Sip003
		plugin := u.Query().Get("plugin")
		if len(plugin) > 0 {
			sip003 = ParseSip003(plugin)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, false
		}
		return &Shadowsocks{
			Cipher:   strings.ToLower(cipher),
			Password: password,
			Server:   u.Hostname(),
			Port:     port,
			Name:     u.Fragment,
			Plugin:   sip003,
			UDP:      sip003.Name == "",
			Protocol: "shadowsocks",
		}, true
	}
	var (
		v  *Shadowsocks
		ok bool
	)
	content := u
	// try to parse the ss:// link, if it fails, base64 decode first
	if v, ok = parse(content); !ok {
		// Decode base64 and unmarshal to VmessInfo
		t := content[5:]
		var l, r string
		if ind := strings.Index(t, "#"); ind > -1 {
			l = t[:ind]
			r = t[ind+1:]
		} else {
			l = t
		}
		l, err = common.Base64StdDecode(l)
		if err != nil {
			l, err = common.Base64UrlDecode(l)
			if err != nil {
				return
			}
		}
		t = "ss://" + l
		if len(r) > 0 {
			t += "#" + r
		}
		v, ok = parse(t)
	}
	if !ok {
		return nil, fmt.Errorf("%w: unrecognized ss address", dialer.InvalidParameterErr)
	}
	return v, nil
}

type Sip003 struct {
	Name string     `json:"name"`
	Opts Sip003Opts `json:"opts"`
}
type Sip003Opts struct {
	Tls           string `json:"tls"`  // for v2ray-plugin
	Obfs          string `json:"obfs"` // mode for v2ray-plugin
	Host          string `json:"host"`
	Path          string `json:"uri"`
	Password      string `json:"password"`
	Version       string `json:"version"`
	SNI           string `json:"sni"`
	AllowInsecure string `json:"allowInsecure"`
}

func ParseSip003Opts(opts string) Sip003Opts {
	var sip003Opts Sip003Opts
	fields := strings.Split(opts, ";")
	for i := range fields {
		if fields[i] == "" {
			continue
		}
		a := strings.SplitN(fields[i], "=", 2)
		if len(a) == 1 {
			a = append(a, "")
		}
		switch strings.ToLower(a[0]) {
		case "tls":
			sip003Opts.Tls = "tls"
		case "obfs", "mode":
			sip003Opts.Obfs = a[1]
		case "obfs-path", "obfs-uri", "path":
			if !strings.HasPrefix(a[1], "/") {
				a[1] += "/"
			}
			sip003Opts.Path = a[1]
		case "obfs-host", "host":
			sip003Opts.Host = a[1]
		case "password", "passwd", "pwd":
			sip003Opts.Password = a[1]
		case "version", "v":
			sip003Opts.Version = a[1]
		case "sni":
			sip003Opts.SNI = a[1]
		case "allowinsecure", "allow_insecure", "insecure", "skip-cert-verify":
			sip003Opts.AllowInsecure = a[1]
		}
	}
	return sip003Opts
}
func ParseSip003(plugin string) Sip003 {
	var sip003 Sip003
	fields := strings.SplitN(plugin, ";", 2)
	opts := ""
	if len(fields) == 2 {
		opts = fields[1]
	}
	switch strings.ToLower(fields[0]) {
	case "obfs-local", "simpleobfs":
		sip003.Name = "simple-obfs"
	case "shadowtls", "shadow-tls", "sstls":
		sip003.Name = "shadow-tls"
	default:
		sip003.Name = fields[0]
	}
	sip003.Opts = ParseSip003Opts(opts)
	return sip003
}

func (s *Sip003) String() string {
	list := []string{s.Name}
	if s.Opts.Tls != "" {
		list = append(list, "tls")
	}
	if s.Opts.Obfs != "" {
		list = append(list, "obfs="+s.Opts.Obfs)
	}
	if s.Opts.Host != "" {
		list = append(list, "obfs-host="+s.Opts.Host)
	}
	if s.Opts.Path != "" {
		list = append(list, "obfs-uri="+s.Opts.Path)
	}
	if s.Opts.Password != "" {
		list = append(list, "password="+s.Opts.Password)
	}
	if s.Opts.Version != "" {
		list = append(list, "version="+s.Opts.Version)
	}
	if s.Opts.SNI != "" {
		list = append(list, "sni="+s.Opts.SNI)
	}
	if s.Opts.AllowInsecure != "" {
		list = append(list, "allowInsecure="+s.Opts.AllowInsecure)
	}
	return strings.Join(list, ";")
}

func (s *Shadowsocks) ExportToURL() string {
	// sip002
	u := &url.URL{
		Scheme:   "ss",
		User:     url.User(strings.TrimSuffix(base64.URLEncoding.EncodeToString([]byte(s.Cipher+":"+s.Password)), "=")),
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	if s.Plugin.Name != "" {
		q := u.Query()
		q.Set("plugin", s.Plugin.String())
		u.RawQuery = q.Encode()
	}
	return u.String()
}
