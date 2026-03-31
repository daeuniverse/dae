package hysteria2

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common/bandwidth"
	"github.com/daeuniverse/outbound/common/url"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
)

func init() {
	dialer.FromLinkRegister("hysteria2", NewHysteria2)
	dialer.FromLinkRegister("hy2", NewHysteria2)
}

type Hysteria2 struct {
	Name      string
	User      string
	Password  string
	Server    string
	Insecure  bool
	Sni       string
	PinSHA256 string
	CA        string
	MaxTx     uint64
	MaxRx     uint64
}

func NewHysteria2(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := ParseHysteria2URL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.Dialer(option, nextDialer)
}

func (s *Hysteria2) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	d := nextDialer
	// When pinSHA256 is set, certificate pin verification replaces chain
	// verification. Force InsecureSkipVerify so that Go's TLS skips chain
	// verification; the pin callback handles all trust decisions.
	skipVerify := s.Insecure || option.AllowInsecure || s.PinSHA256 != ""
	tlsConfig := &tls.Config{
		ServerName:         s.Sni,
		InsecureSkipVerify: skipVerify,
	}
	if s.CA != "" {
		rootCAs, err := loadCustomRootCAs(s.CA)
		if err != nil {
			return nil, nil, err
		}
		tlsConfig.RootCAs = rootCAs
	}
	header := protocol.Header{
		ProxyAddress: s.Server,
		TlsConfig:    tlsConfig,
		SNI:          s.Sni,
		User:         s.User,
		Password:     s.Password,
		IsClient:     true,
	}

	feature1 := &hysteria2.Feature1{
		UDPHopInterval: option.UDPHopInterval,
	}
	if s.MaxTx > 0 && s.MaxRx > 0 {
		feature1.BandwidthConfig = client.BandwidthConfig{
			MaxRx: s.MaxRx,
			MaxTx: s.MaxTx,
		}
	} else if option.BandwidthMaxRx != "" && option.BandwidthMaxTx != "" {
		maxRx, err := bandwidth.Parse(option.BandwidthMaxRx)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid bandwidth value for MaxRx: %w", err)
		}
		maxTx, err := bandwidth.Parse(option.BandwidthMaxTx)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid bandwidth value for MaxTx: %w", err)
		}
		if maxRx > 0 && maxTx > 0 {
			feature1.BandwidthConfig = client.BandwidthConfig{
				MaxRx: maxRx,
				MaxTx: maxTx,
			}
		}
	}
	header.Feature1 = feature1

	if s.PinSHA256 != "" {
		header.TlsConfig.VerifyPeerCertificate = newPinnedCertVerifier(s.PinSHA256)
	}
	var err error
	if d, err = protocol.NewDialer("hysteria2", d, header); err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Address:  s.Server,
		Protocol: "hysteria2",
		Link:     s.ExportToURL(),
	}, nil
}

func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

func newPinnedCertVerifier(pinSHA256 string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	nHash := normalizeCertHash(pinSHA256)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no peer certificate provided")
		}
		hash := sha256.Sum256(rawCerts[0])
		hashHex := hex.EncodeToString(hash[:])
		if hashHex != nHash {
			return fmt.Errorf("leaf certificate pin mismatch: %s != %s", hashHex, nHash)
		}
		return nil
	}
}

func loadCustomRootCAs(caPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("load custom CA %q: %w", caPath, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("load custom CA %q: failed to parse PEM certificate", caPath)
	}
	return rootCAs, nil
}

// ref: https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func ParseHysteria2URL(link string) (*Hysteria2, error) {
	// TODO: support salamander obfuscation
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	var insecure bool
	if insecureValue := q.Get("insecure"); insecureValue != "" {
		insecure, err = strconv.ParseBool(q.Get("insecure"))
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
	}
	var maxTx, maxRx uint64
	if q.Get("maxTx") != "" && q.Get("maxRx") != "" {
		maxTx, err = strconv.ParseUint(q.Get("maxTx"), 10, 64)
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
		maxRx, err = strconv.ParseUint(q.Get("maxRx"), 10, 64)
		if err != nil {
			return nil, dialer.InvalidParameterErr
		}
	}
	conf := &Hysteria2{
		Name:      u.Fragment,
		User:      u.User.Username(),
		Server:    u.Host,
		Insecure:  insecure,
		Sni:       q.Get("sni"),
		PinSHA256: q.Get("pinSHA256"),
		CA:        q.Get("ca"),
		MaxTx:     maxTx,
		MaxRx:     maxRx,
	}
	conf.Password, _ = u.User.Password()
	return conf, nil
}

func (s *Hysteria2) ExportToURL() string {
	t := url.URL{
		Scheme:   "hysteria2",
		Host:     s.Server,
		User:     url.User(s.User),
		Fragment: s.Name,
	}
	if s.Password != "" {
		t.User = url.UserPassword(s.User, s.Password)
	}
	q := t.Query()
	if s.Insecure {
		q.Set("insecure", "1")
	}
	if s.Sni != "" {
		q.Set("sni", s.Sni)
	}
	if s.PinSHA256 != "" {
		q.Set("pinSHA256", s.PinSHA256)
	}
	if s.CA != "" {
		q.Set("ca", s.CA)
	}
	if s.MaxTx > 0 && s.MaxRx > 0 {
		q.Set("maxTx", strconv.FormatUint(s.MaxTx, 10))
		q.Set("maxRx", strconv.FormatUint(s.MaxRx, 10))
	}
	t.RawQuery = q.Encode()
	return t.String()
}
