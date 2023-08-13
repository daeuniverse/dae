package juicity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol"
)

func init() {
	dialer.FromLinkRegister("juicity", NewJuicity)
}

type Juicity struct {
	Name                  string
	Server                string
	Port                  int
	User                  string
	Password              string
	Sni                   string
	AllowInsecure         bool
	CongestionControl     string
	PinnedCertchainSha256 string
	Protocol              string
}

func NewJuicity(option *dialer.GlobalOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseJuicityURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Juicity) Dialer(option *dialer.GlobalOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	d := nextDialer
	var err error
	var flags protocol.Flags
	tlsConfig := &tls.Config{
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		ServerName:         s.Sni,
		InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
	}
	if s.PinnedCertchainSha256 != "" {
		pinnedHash, err := base64.URLEncoding.DecodeString(s.PinnedCertchainSha256)
		if err != nil {
			pinnedHash, err = base64.StdEncoding.DecodeString(s.PinnedCertchainSha256)
			if err != nil {
				pinnedHash, err = hex.DecodeString(s.PinnedCertchainSha256)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to decode PinnedCertchainSha256")
				}
			}
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if !bytes.Equal(common.GenerateCertChainHash(rawCerts), pinnedHash) {
				return fmt.Errorf("pinned hash of cert chain does not match")
			}
			return nil
		}
	}
	if d, err = protocol.NewDialer("juicity", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Feature1:     s.CongestionControl,
		TlsConfig:    tlsConfig,
		User:         s.User,
		Password:     s.Password,
		IsClient:     true,
		Flags:        flags,
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

func ParseJuicityURL(u string) (data *Juicity, err error) {
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
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	password, _ := t.User.Password()
	data = &Juicity{
		Name:                  t.Fragment,
		Server:                t.Hostname(),
		Port:                  port,
		User:                  t.User.Username(),
		Password:              password,
		Sni:                   sni,
		AllowInsecure:         allowInsecure,
		CongestionControl:     t.Query().Get("congestion_control"),
		PinnedCertchainSha256: t.Query().Get("pinned_certchain_sha256"),
		Protocol:              "juicity",
	}
	return data, nil
}

func (t *Juicity) ExportToURL() string {
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
	common.SetValue(&q, "congestion_control", t.CongestionControl)
	common.SetValue(&q, "pinned_certchain_sha256", t.PinnedCertchainSha256)
	u.RawQuery = q.Encode()
	return u.String()
}
