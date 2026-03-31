// Modified from https://github.com/Reality/Xray-core/blob/fbc56b88da2808e3181add4935c143e319772c93/transport/internet/reality/reality.go

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var (
	Reality_Version_x byte = 1
	Reality_Version_y byte = 8
	Reality_Version_z byte = 10
)

//go:linkname aesgcmPreferred github.com/refraction-networking/utls.aesgcmPreferred
func aesgcmPreferred(ciphers []uint16) bool

type RealityUConn struct {
	*utls.UConn
	ServerName string
	AuthKey    []byte
	Verified   bool
}

var (
	realityPeerCertificatesFieldOnce sync.Once
	realityPeerCertificatesField     reflect.StructField
	realityPeerCertificatesFieldErr  error
)

func realityPeerCertificatesFieldInfo() (reflect.StructField, error) {
	realityPeerCertificatesFieldOnce.Do(func() {
		field, ok := reflect.TypeOf((*utls.Conn)(nil)).Elem().FieldByName("peerCertificates")
		if !ok {
			realityPeerCertificatesFieldErr = errors.New("REALITY: utls.Conn peerCertificates field unavailable")
			return
		}
		if field.Type != reflect.TypeOf([]*x509.Certificate{}) {
			realityPeerCertificatesFieldErr = fmt.Errorf(
				"REALITY: unexpected utls.Conn peerCertificates type: %v",
				field.Type,
			)
			return
		}
		realityPeerCertificatesField = field
	})
	return realityPeerCertificatesField, realityPeerCertificatesFieldErr
}

func realityPeerCertificates(conn *utls.Conn) ([]*x509.Certificate, error) {
	if conn == nil {
		return nil, errors.New("REALITY: nil uTLS connection")
	}
	field, err := realityPeerCertificatesFieldInfo()
	if err != nil {
		return nil, err
	}
	certs := *(*[]*x509.Certificate)(unsafe.Add(unsafe.Pointer(conn), field.Offset))
	if len(certs) == 0 {
		return nil, errors.New("REALITY: missing peer certificates")
	}
	return certs, nil
}

func (c *RealityUConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c == nil || c.UConn == nil {
		return errors.New("REALITY: nil uTLS connection")
	}
	certs, err := realityPeerCertificates(c.Conn)
	if err != nil {
		return err
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type Reality struct {
	infoWriter io.Writer

	nextDialer  netproxy.Dialer
	serverName  string
	fingerprint *utls.ClientHelloID
	shortId     [8]byte
	publicKey   *ecdh.PublicKey
	spiderX     string
	spiderY     []int64
}

// realityECDHEKey returns the TLS 1.3 ECDHE private key used by REALITY.
// Newer uTLS versions populate KeyShareKeys and may leave the deprecated
// EcdheKey field unset, so keep compatibility with both layouts.
func realityECDHEKey(state *utls.PubClientHandshakeState) *ecdh.PrivateKey {
	if state == nil {
		return nil
	}
	if keyShareKeys := state.State13.KeyShareKeys; keyShareKeys != nil {
		if keyShareKeys.Ecdhe != nil {
			return keyShareKeys.Ecdhe
		}
		if keyShareKeys.MlkemEcdhe != nil {
			return keyShareKeys.MlkemEcdhe
		}
	}
	return state.State13.EcdheKey // nolint:staticcheck
}

func NewReality(s string, d netproxy.Dialer) (*Reality, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewReality: %w", err)
	}

	x := &Reality{
		nextDialer: d,
	}

	query := u.Query()
	x.serverName = query.Get("sni")
	_, err = hex.Decode(x.shortId[:], []byte(query.Get("sid")))
	if err != nil {
		return nil, fmt.Errorf("invalid reality sid")
	}
	_publicKey := query.Get("pbk")
	const x25519ScalarSize = 32
	var publicKey [x25519ScalarSize]byte
	_, err = base64.RawURLEncoding.Decode(publicKey[:], []byte(_publicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid reality pbk")
	}
	x.publicKey, err = ecdh.X25519().NewPublicKey(publicKey[:])
	if err != nil {
		return nil, fmt.Errorf("REALITY: publicKey == nil: %w", err)
	}
	x.spiderX, _ = url.QueryUnescape(query.Get("spx"))
	_fingerprint := query.Get("fp")

	if x.serverName == "" {
		x.serverName = u.Hostname()
	} else if strings.ToLower(x.serverName) == "nosni" { // If ServerName is set to "nosni", we set it empty.
		x.serverName = ""
	}

	x.fingerprint, err = nameToUtlsClientHelloID(_fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint: %w", err)
	}

	if x.spiderX == "" {
		x.spiderX = "/"
	}
	if x.spiderX[0] != '/' {
		return nil, fmt.Errorf(`invalid "spiderX": %v`, x.spiderX)
	}
	x.spiderY = make([]int64, 10)
	tmpU, _ := url.Parse(x.spiderX)
	q := tmpU.Query()
	parse := func(param string, index int) {
		if q.Get(param) != "" {
			s := strings.Split(q.Get(param), "-")
			if len(s) == 1 {
				x.spiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				x.spiderY[index+1], _ = strconv.ParseInt(s[0], 10, 64)
			} else {
				x.spiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				x.spiderY[index+1], _ = strconv.ParseInt(s[1], 10, 64)
			}
		}
		q.Del(param)
	}
	parse("p", 0) // padding
	parse("c", 2) // concurrency
	parse("t", 4) // times
	parse("i", 6) // interval
	parse("r", 8) // return
	u.RawQuery = q.Encode()
	x.spiderX = tmpU.String()
	// x.infoWriter = logger.Logger.WriterLevel(logrus.TraceLevel)
	// logrus.Printf("%#v", x)
	return x, nil
}

func (x *Reality) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		// logrus.Printf("%#v, %T, %v", x.nextDialer, magicNetwork.Network, addr)
		c, err := x.nextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("[REALITY]: dial to %s: %w", addr, err)
		}
		retry := 0
	retryHandshake:
		uConn := &RealityUConn{}
		utlsConfig := &utls.Config{
			VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
			ServerName:             x.serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			KeyLogWriter:           x.infoWriter,
		}
		uConn.ServerName = utlsConfig.ServerName
		uConn.UConn = utls.UClient(&netproxy.FakeNetConn{
			Conn:  c,
			LAddr: nil,
			RAddr: nil,
		}, utlsConfig, *x.fingerprint)
		{
			err = uConn.BuildHandshakeState()
			if err != nil {
				return nil, err
			}
			hello := uConn.HandshakeState.Hello
			hello.SessionId = make([]byte, 32)
			copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
			hello.SessionId[0] = Reality_Version_x
			hello.SessionId[1] = Reality_Version_y
			hello.SessionId[2] = Reality_Version_z
			hello.SessionId[3] = 0 // reserved
			binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
			copy(hello.SessionId[8:], x.shortId[:])
			// if config.Show {
			// logrus.Printf("REALITY hello.SessionId[:16]: %v\n", hello.SessionId[:16])
			// }
			ecdheKey := realityECDHEKey(&uConn.HandshakeState)
			if ecdheKey == nil {
				// logrus.Println("wtf", retry, addr)
				if retry > 2 {
					return nil, errors.New("nil ecdheKey")
				}
				retry++
				goto retryHandshake // retry
			}
			// logrus.Println("OH YEAH", retry)
			uConn.AuthKey, _ = ecdheKey.ECDH(x.publicKey)
			if uConn.AuthKey == nil {
				return nil, errors.New("REALITY: SharedKey == nil")
			}
			if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
				return nil, err
			}
			var aead cipher.AEAD
			if aesgcmPreferred(hello.CipherSuites) {
				block, _ := aes.NewCipher(uConn.AuthKey)
				aead, _ = cipher.NewGCM(block)
			} else {
				aead, _ = chacha20poly1305.New(uConn.AuthKey)
			}
			// if config.Show {
			// logrus.Printf("REALITY uConn.AuthKey[:16]: %v\tAEAD: %T\n", uConn.AuthKey[:16], aead)
			// }
			aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
			copy(hello.Raw[39:], hello.SessionId)
		}
		// logrus.Println("00")
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		// if config.Show {
		// 	newError(fmt.Sprintf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)).WriteToLog(session.ExportIDToError(ctx))
		// }
		// logrus.Println("11", uConn.Verified)
		if !uConn.Verified {
			// Trigger spider.
			go func() {
				client := &http.Client{
					Transport: &http2.Transport{
						DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
							return uConn, nil
						},
					},
				}
				prefix := []byte("https://" + uConn.ServerName)
				maps.Lock()
				if maps.maps == nil {
					maps.maps = make(map[string]map[string]bool)
				}
				paths := maps.maps[uConn.ServerName]
				if paths == nil {
					paths = make(map[string]bool)
					paths[x.spiderX] = true
					maps.maps[uConn.ServerName] = paths
				}
				firstURL := string(prefix) + getPathLocked(paths)
				maps.Unlock()
				get := func(first bool) {
					var (
						req  *http.Request
						resp *http.Response
						err  error
						body []byte
					)
					if first {
						req, _ = http.NewRequest("GET", firstURL, nil)
					} else {
						maps.Lock()
						req, _ = http.NewRequest("GET", string(prefix)+getPathLocked(paths), nil)
						maps.Unlock()
					}
					req.Header.Set("User-Agent", x.fingerprint.Client) // TODO: User-Agent map
					// if first && config.Show {
					// 	newError(fmt.Sprintf("REALITY localAddr: %v\treq.UserAgent(): %v\n", localAddr, req.UserAgent())).WriteToLog(session.ExportIDToError(ctx))
					// }
					// logrus.Printf("session %#v", uConn.HandshakeState.Session)
					times := 1
					if !first {
						times = int(randBetween(x.spiderY[4], x.spiderY[5]))
					}
					for j := 0; j < times; j++ {
						if !first && j == 0 {
							req.Header.Set("Referer", firstURL)
						}
						req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(randBetween(x.spiderY[0], x.spiderY[1])))})
						if resp, err = client.Do(req); err != nil {
							break
						}
						req.Header.Set("Referer", req.URL.String())
						if body, err = io.ReadAll(resp.Body); err != nil {
							break
						}
						maps.Lock()
						for _, m := range href.FindAllSubmatch(body, -1) {
							m[1] = bytes.TrimPrefix(m[1], prefix)
							if !bytes.Contains(m[1], dot) {
								paths[string(m[1])] = true
							}
						}
						req.URL.Path = getPathLocked(paths)
						// if config.Show {
						// 	newError(fmt.Sprintf("REALITY localAddr: %v\treq.Referer(): %v\n", localAddr, req.Referer())).WriteToLog(session.ExportIDToError(ctx))
						// 	newError(fmt.Sprintf("REALITY localAddr: %v\tlen(body): %v\n", localAddr, len(body))).WriteToLog(session.ExportIDToError(ctx))
						// 	newError(fmt.Sprintf("REALITY localAddr: %v\tlen(paths): %v\n", localAddr, len(paths))).WriteToLog(session.ExportIDToError(ctx))
						// }
						maps.Unlock()
						if !first {
							time.Sleep(time.Duration(randBetween(x.spiderY[6], x.spiderY[7])) * time.Millisecond) // interval
						}
					}
				}
				get(true)
				concurrency := int(randBetween(x.spiderY[2], x.spiderY[3]))
				for i := 0; i < concurrency; i++ {
					go get(false)
				}
				// Do not close the connection
			}()
			time.Sleep(time.Duration(randBetween(x.spiderY[8], x.spiderY[9])) * time.Millisecond) // return
			return nil, errors.New("REALITY: processed invalid connection")
		}
		return uConn, nil

	case "udp":
		return nil, fmt.Errorf("%w: Reality+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}

}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

var maps struct {
	sync.Mutex
	maps map[string]map[string]bool
}

func getPathLocked(paths map[string]bool) string {
	stopAt := int(randBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}

func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left))
	return left + bigInt.Int64()
}
