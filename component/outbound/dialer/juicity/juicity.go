package juicity

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
)

func init() {
	dialer.FromLinkRegister("juicity", NewJuice)
}

type Juice struct {
	Name              string
	Server            string
	Port              int
	User              string
	Password          string
	Sni               string
	AllowInsecure     bool
	CongestionControl string
	Protocol          string
}

func NewJuice(option *dialer.GlobalOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseJuiceURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Juice) Dialer(option *dialer.GlobalOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	d := nextDialer
	var err error
	var flags protocol.Flags
	if d, err = protocol.NewDialer("juicity", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Feature1:     s.CongestionControl,
		TlsConfig: &tls.Config{
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			ServerName:         s.Sni,
			InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
		},
		User:     s.User,
		Password: s.Password,
		IsClient: true,
		Flags:    flags,
	}); err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func ParseJuiceURL(u string) (data *Juice, err error) {
	//trojan://password@server:port#escape(remarks)
	t, err := url.Parse(u)
	if err != nil {
		err = fmt.Errorf("invalid trojan format")
		return
	}
	allowInsecure, _ := strconv.ParseBool(t.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("skipVerify"))
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
	data = &Juice{
		Name:              t.Fragment,
		Server:            t.Hostname(),
		Port:              port,
		User:              t.User.Username(),
		Password:          password,
		Sni:               sni,
		AllowInsecure:     allowInsecure,
		CongestionControl: t.Query().Get("congestion_control"),
		Protocol:          "juicity",
	}
	return data, nil
}

func (t *Juice) ExportToURL() string {
	u := &url.URL{
		Scheme:   "juicity",
		User:     url.UserPassword(t.User, t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allow_insecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)
	if t.CongestionControl != "" {
		common.SetValue(&q, "congestion_control", t.CongestionControl)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
