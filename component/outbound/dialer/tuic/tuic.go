package tuic

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/direct"
)

func init() {
	dialer.FromLinkRegister("tuic", NewTuic)
}

type Tuic struct {
	Name              string
	Server            string
	Port              int
	User              string
	Password          string
	Sni               string
	AllowInsecure     bool
	DisableSni        bool
	CongestionControl string
	Alpn              []string
	Protocol          string
	UdpRelayMode      string
}

func NewTuic(option *dialer.GlobalOption, iOption dialer.InstanceOption, link string) (*dialer.Dialer, error) {
	s, err := ParseTuicURL(link, option)
	if err != nil {
		return nil, err
	}
	return s.Dialer(option, iOption)
}

func (s *Tuic) Dialer(option *dialer.GlobalOption, iOption dialer.InstanceOption) (*dialer.Dialer, error) {
	d := direct.FullconeDirect // Tuic Proxy supports full-cone.
	var err error
	var flags protocol.Flags
	if s.UdpRelayMode == "quic" {
		flags |= protocol.Flags_Tuic_UdpRelayModeQuic
	}
	if d, err = protocol.NewDialer("tuic", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Feature1:     s.CongestionControl,
		TlsConfig:    &tls.Config{NextProtos: s.Alpn, MinVersion: tls.VersionTLS13, ServerName: s.Sni, InsecureSkipVerify: s.AllowInsecure},
		User:         s.User,
		Password:     s.Password,
		IsClient:     true,
		Flags:        flags,
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

func ParseTuicURL(u string, option *dialer.GlobalOption) (data *Tuic, err error) {
	//trojan://password@server:port#escape(remarks)
	t, err := url.Parse(u)
	if err != nil {
		err = fmt.Errorf("invalid trojan format")
		return
	}
	alpn := strings.Split(t.Query().Get("alpn"), ",")
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	for i := range alpn {
		alpn[i] = strings.TrimSpace(alpn[i])
	}
	allowInsecure, _ := strconv.ParseBool(t.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("allow_insecure"))
	}
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
	disableSni, _ := strconv.ParseBool(t.Query().Get("disable_sni"))
	if disableSni {
		sni = ""
		allowInsecure = true
	}
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	password, _ := t.User.Password()
	data = &Tuic{
		Name:              t.Fragment,
		Server:            t.Hostname(),
		Port:              port,
		User:              t.User.Username(),
		Password:          password,
		Sni:               sni,
		AllowInsecure:     allowInsecure,
		DisableSni:        disableSni,
		CongestionControl: t.Query().Get("congestion_control"),
		Alpn:              alpn,
		UdpRelayMode:      strings.ToLower(t.Query().Get("udp_relay_mode")),
		Protocol:          "tuic",
	}
	return data, nil
}

func (t *Tuic) ExportToURL() string {
	u := &url.URL{
		Scheme:   "trojan",
		User:     url.UserPassword(t.User, t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allow_insecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)
	if t.DisableSni {
		common.SetValue(&q, "disable_sni", "1")
	}
	if t.CongestionControl != "" {
		common.SetValue(&q, "congestion_control", t.CongestionControl)
	}
	if len(t.Alpn) > 0 {
		common.SetValue(&q, "alpn", strings.Join(t.Alpn, ","))
	}
	if t.UdpRelayMode != "" {
		common.SetValue(&q, "udp_relay_mode", t.UdpRelayMode)
	}

	u.RawQuery = q.Encode()
	return u.String()
}
