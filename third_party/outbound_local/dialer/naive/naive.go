package naive

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	obtls "github.com/daeuniverse/outbound/transport/tls"
	"golang.org/x/net/http2"
)

func init() {
	dialer.FromLinkRegister("naive+https", NewNaive)
	dialer.FromLinkRegister("naive+quic", NewNaive)
}

// Naive represents a naiveproxy configuration.
type Naive struct {
	Name          string
	Server        string
	Port          int
	Username      string
	Password      string
	Sni           string
	AllowInsecure bool
	Protocol      string // "naive+https" or "naive+quic"
}

// NewNaive creates a naiveproxy dialer from a link.
func NewNaive(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	s, err := parseNaiveURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s.toDialer(option, nextDialer)
}

// parseNaiveURL parses a naiveproxy URL.
// Formats:
//
//	naive+https://user:pass@host:port#tag
//	naive+quic://user:pass@host:port#tag
func parseNaiveURL(link string) (*Naive, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", dialer.InvalidParameterErr, err)
	}

	switch u.Scheme {
	case "naive+https", "naive+quic":
	default:
		return nil, fmt.Errorf("%w: unsupported scheme %q", dialer.InvalidParameterErr, u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: missing host", dialer.InvalidParameterErr)
	}

	portStr := u.Port()
	if portStr == "" {
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return nil, fmt.Errorf("%w: invalid port %q", dialer.InvalidParameterErr, portStr)
	}

	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	sni := u.Query().Get("sni")
	if sni == "" {
		sni = host
	}

	return &Naive{
		Name:          u.Fragment,
		Server:        host,
		Port:          port,
		Username:      username,
		Password:      password,
		Sni:           sni,
		AllowInsecure: parseAllowInsecure(u.Query()),
		Protocol:      u.Scheme,
	}, nil
}

func parseAllowInsecure(query url.Values) bool {
	for _, key := range []string{"allowInsecure", "allow_insecure", "allowinsecure", "skipVerify"} {
		if value := query.Get(key); value != "" {
			allowInsecure, _ := strconv.ParseBool(value)
			if allowInsecure {
				return true
			}
		}
	}
	return false
}

func (s *Naive) toDialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	if s.Protocol == "naive+quic" {
		return nil, nil, fmt.Errorf("naive+quic is not supported yet")
	}

	addr := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	nd := &naiveDialer{
		nextDialer:    nextDialer,
		addr:          addr,
		username:      s.Username,
		password:      s.Password,
		sni:           s.Sni,
		allowInsecure: s.AllowInsecure || option.AllowInsecure,
		option:        option,
		pool:          newNaiveH2ConnPool(),
	}

	return nd, &dialer.Property{
		Name:     s.Name,
		Address:  addr,
		Protocol: s.Protocol,
		Link:     s.exportToURL(),
	}, nil
}

func (s *Naive) exportToURL() string {
	var auth *url.Userinfo
	if s.Password != "" {
		auth = url.UserPassword(s.Username, s.Password)
	} else if s.Username != "" {
		auth = url.User(s.Username)
	}

	u := &url.URL{
		Scheme: s.Protocol,
		Host:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		User:   auth,
	}

	query := u.Query()
	if s.Sni != "" && s.Sni != s.Server {
		query.Set("sni", s.Sni)
	}
	if s.AllowInsecure {
		query.Set("allowInsecure", "1")
	}
	u.RawQuery = query.Encode()

	if s.Name != "" {
		u.Fragment = s.Name
	}

	return u.String()
}

// naiveDialer implements netproxy.Dialer for naiveproxy protocol.
type naiveDialer struct {
	nextDialer    netproxy.Dialer
	addr          string
	username      string
	password      string
	sni           string
	allowInsecure bool
	option        *dialer.ExtraOption
	pool          *naiveH2ConnPool
}

func (d *naiveDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp":
		return d.dialTCP(ctx, magicNetwork.Encode(), addr)
	case "udp":
		return nil, netproxy.UnsupportedTunnelTypeError
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *naiveDialer) dialTCP(ctx context.Context, magicNetwork string, target string) (netproxy.Conn, error) {
	rawConn, h2Conn, err := d.pool.GetConn(ctx, d, magicNetwork)
	if err != nil {
		return nil, err
	}

	return &naiveConn{
		dialer:        d,
		h2Conn:        h2Conn,
		rawConn:       rawConn,
		magicNetwork:  magicNetwork,
		target:        target,
		handshakeDone: make(chan struct{}),
	}, nil
}

func (d *naiveDialer) newClientConn(ctx context.Context, magicNetwork string) (netproxy.Conn, *http2.ClientConn, error) {
	tlsURL := url.URL{
		Scheme: d.option.TlsImplementation,
		Host:   d.addr,
		RawQuery: url.Values{
			"sni":           []string{d.sni},
			"allowInsecure": []string{strconv.FormatBool(d.allowInsecure)},
			"utlsImitate":   []string{d.option.UtlsImitate},
			"alpn":          []string{"h2,http/1.1"},
		}.Encode(),
	}

	tlsDialer, _, err := obtls.NewTls(d.option, d.nextDialer, tlsURL.String())
	if err != nil {
		return nil, nil, fmt.Errorf("naive: create TLS dialer: %w", err)
	}

	dialCtx, dialCancel := netproxy.NewDialTimeoutContextFrom(ctx)
	defer dialCancel()

	rawConn, err := tlsDialer.DialContext(dialCtx, magicNetwork, d.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("naive: TLS dial: %w", err)
	}

	if tc, ok := rawConn.(*tls.Conn); ok {
		if err = tc.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("naive: TLS handshake: %w", err)
		}
		if tc.ConnectionState().NegotiatedProtocol != "h2" {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("naive: server negotiated %q, require h2", tc.ConnectionState().NegotiatedProtocol)
		}
	}

	transport := &http2.Transport{ConnPool: d.pool}
	h2Conn, err := transport.NewClientConn(&netproxy.FakeNetConn{Conn: rawConn})
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("naive: H2 client: %w", err)
	}

	return rawConn, h2Conn, nil
}

func (d *naiveDialer) newPooledClientConn(ctx context.Context, magicNetwork string) (netproxy.Conn, *http2.ClientConn, error) {
	rawConn, h2Conn, err := d.newClientConn(ctx, magicNetwork)
	if err != nil {
		return nil, nil, err
	}
	d.pool.registerConn(magicNetwork, rawConn, h2Conn)
	return rawConn, h2Conn, nil
}

func (d *naiveDialer) newConnectRequest(target string) (*http.Request, *io.PipeWriter, error) {
	reqURL := (&url.URL{
		Scheme: "http",
		Host:   target,
	}).String()

	req, err := http.NewRequest(http.MethodConnect, reqURL, nil)
	if err != nil {
		return nil, nil, err
	}
	if d.username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(d.username + ":" + d.password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	req.Header.Set(paddingHeaderKey, GeneratePaddingHeaderRequest())

	pr, pw := io.Pipe()
	req.Body = pr
	return req, pw, nil
}

// naiveConn implements netproxy.Conn using naiveproxy H2 CONNECT with padding.
// The CONNECT request is sent lazily so plain reads can still initiate the tunnel.
type naiveConn struct {
	dialer *naiveDialer
	h2Conn *http2.ClientConn

	rawConn      netproxy.Conn
	magicNetwork string
	target       string

	stateMu          sync.Mutex
	handshakeStarted bool
	handshakeDone    chan struct{}
	handshakeErr     error
	stream           *naiveH2Stream
	closed           bool
	closeOnce        sync.Once
}

func (c *naiveConn) handshake(firstWrite []byte) (conn *naiveH2Stream, n int, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, pw, reqErr := c.dialer.newConnectRequest(c.target)
		if reqErr != nil {
			return nil, 0, reqErr
		}

		resp, roundTripErr := c.h2Conn.RoundTrip(req)
		if roundTripErr != nil {
			_ = pw.CloseWithError(roundTripErr)
			if attempt == 0 && shouldRetryNaiveRoundTrip(roundTripErr) {
				if refreshErr := c.refreshClientConn(); refreshErr == nil {
					continue
				} else {
					return nil, 0, fmt.Errorf("naive CONNECT retry failed after %v: %w", roundTripErr, refreshErr)
				}
			}
			return nil, 0, fmt.Errorf("naive CONNECT: %w", roundTripErr)
		}

		if resp.StatusCode != http.StatusOK {
			_ = pw.Close()
			_ = resp.Body.Close()
			return nil, 0, fmt.Errorf("naive CONNECT failed: %v", resp.Status)
		}

		paddingSupported := resp.Header.Get(paddingHeaderKey) != ""
		stream := &naiveH2Stream{
			writer:       newPaddedWriter(pw, paddingSupported),
			requestBody:  pw,
			reader:       newPaddedReader(resp.Body, paddingSupported),
			responseBody: resp.Body,
		}

		if len(firstWrite) > 0 {
			n, err = stream.Write(firstWrite)
			if err != nil {
				_ = stream.Close()
				return nil, n, err
			}
		}

		return stream, n, nil
	}

	return nil, 0, fmt.Errorf("naive CONNECT: exhausted retries")
}

func (c *naiveConn) refreshClientConn() error {
	rawConn, h2Conn, err := c.dialer.newPooledClientConn(context.Background(), c.magicNetwork)
	if err != nil {
		return err
	}
	c.rawConn = rawConn
	c.h2Conn = h2Conn
	return nil
}

func shouldRetryNaiveRoundTrip(err error) bool {
	if err == nil {
		return false
	}

	var goAwayErr http2.GoAwayError
	if stderrors.As(err, &goAwayErr) {
		return true
	}

	var streamErr http2.StreamError
	if stderrors.As(err, &streamErr) && streamErr.Code == http2.ErrCodeRefusedStream {
		return true
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "client conn not usable")
}

func (c *naiveConn) ensureHandshake(firstWrite []byte) (stream *naiveH2Stream, firstWriteN int, owner bool, err error) {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil, 0, false, net.ErrClosed
	}
	if !c.handshakeStarted {
		c.handshakeStarted = true
		done := c.handshakeDone
		c.stateMu.Unlock()

		stream, firstWriteN, err = c.handshake(firstWrite)

		c.stateMu.Lock()
		if c.closed && stream != nil {
			_ = stream.Close()
			stream = nil
			if err == nil {
				err = net.ErrClosed
			}
		}
		c.stream = stream
		c.handshakeErr = err
		close(done)
		c.stateMu.Unlock()
		return stream, firstWriteN, true, err
	}
	done := c.handshakeDone
	c.stateMu.Unlock()

	<-done

	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return nil, 0, false, net.ErrClosed
	}
	return c.stream, 0, false, c.handshakeErr
}

func (c *naiveConn) Read(b []byte) (n int, err error) {
	stream, _, _, err := c.ensureHandshake(nil)
	if err != nil {
		return 0, err
	}
	if stream == nil {
		return 0, io.EOF
	}
	return stream.Read(b)
}

func (c *naiveConn) Write(b []byte) (n int, err error) {
	stream, firstWriteN, owner, err := c.ensureHandshake(b)
	if err != nil {
		return 0, err
	}
	if stream == nil {
		return 0, io.EOF
	}
	if owner {
		return firstWriteN, nil
	}
	return stream.Write(b)
}

func (c *naiveConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.stateMu.Lock()
		c.closed = true
		stream := c.stream
		c.stateMu.Unlock()

		if stream != nil {
			err = stream.Close()
		}
	})
	return err
}

func (c *naiveConn) SetDeadline(t time.Time) error {
	_ = t
	// naiveConn represents a single H2 CONNECT stream multiplexed over a shared
	// TCP/TLS session. Propagating stream deadlines to the underlying socket
	// would affect every other stream on the same pooled H2 connection.
	//
	// The TCP dial / TLS handshake / CONNECT setup already honor their own
	// contexts. Once the stream is established, per-stream deadlines cannot be
	// implemented safely via the shared raw connection, so this is intentionally
	// a no-op.
	return nil
}

func (c *naiveConn) SetReadDeadline(t time.Time) error {
	_ = t
	return nil
}

func (c *naiveConn) SetWriteDeadline(t time.Time) error {
	_ = t
	return nil
}

// naiveH2Stream wraps the read/write sides of an H2 CONNECT tunnel with padding.
type naiveH2Stream struct {
	writer       *paddedWriter
	requestBody  *io.PipeWriter
	reader       *paddedReader
	responseBody io.ReadCloser
}

func (s *naiveH2Stream) Read(b []byte) (n int, err error) {
	return s.reader.Read(b)
}

func (s *naiveH2Stream) Write(b []byte) (n int, err error) {
	return s.writer.Write(b)
}

func (s *naiveH2Stream) Close() error {
	err := s.requestBody.Close()
	if closeErr := s.responseBody.Close(); err == nil {
		err = closeErr
	}
	return err
}

type pooledNaiveH2Conn struct {
	rawConn netproxy.Conn
	h2Conn  *http2.ClientConn
}

type naiveH2ConnList struct {
	mu    sync.Mutex
	conns []*pooledNaiveH2Conn
}

type naiveH2ConnPool struct {
	mu         sync.Mutex
	connsByNet map[string]*naiveH2ConnList
	connToNet  map[*http2.ClientConn]string
}

func newNaiveH2ConnPool() *naiveH2ConnPool {
	return &naiveH2ConnPool{
		connsByNet: make(map[string]*naiveH2ConnList),
		connToNet:  make(map[*http2.ClientConn]string),
	}
}

func (p *naiveH2ConnPool) GetConn(ctx context.Context, d *naiveDialer, magicNetwork string) (netproxy.Conn, *http2.ClientConn, error) {
	list := p.getConnList(magicNetwork)

	list.mu.Lock()
	for _, conn := range list.conns {
		if conn.h2Conn.CanTakeNewRequest() {
			list.mu.Unlock()
			return conn.rawConn, conn.h2Conn, nil
		}
	}
	list.mu.Unlock()

	rawConn, h2Conn, err := d.newClientConn(ctx, magicNetwork)
	if err != nil {
		return nil, nil, err
	}
	p.registerConn(magicNetwork, rawConn, h2Conn)

	return rawConn, h2Conn, nil
}

func (p *naiveH2ConnPool) getConnList(magicNetwork string) *naiveH2ConnList {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.connsByNet[magicNetwork] == nil {
		p.connsByNet[magicNetwork] = &naiveH2ConnList{}
	}
	return p.connsByNet[magicNetwork]
}

func (p *naiveH2ConnPool) registerConn(magicNetwork string, rawConn netproxy.Conn, h2Conn *http2.ClientConn) {
	list := p.getConnList(magicNetwork)

	list.mu.Lock()
	list.conns = append(list.conns, &pooledNaiveH2Conn{
		rawConn: rawConn,
		h2Conn:  h2Conn,
	})
	list.mu.Unlock()

	p.mu.Lock()
	p.connToNet[h2Conn] = magicNetwork
	p.mu.Unlock()
}

func (p *naiveH2ConnPool) GetClientConn(_ *http.Request, _ string) (*http2.ClientConn, error) {
	return nil, fmt.Errorf("naiveH2ConnPool: use cached client connections directly")
}

func (p *naiveH2ConnPool) MarkDead(dead *http2.ClientConn) {
	p.mu.Lock()
	magicNetwork, ok := p.connToNet[dead]
	if ok {
		delete(p.connToNet, dead)
	}
	list := p.connsByNet[magicNetwork]
	p.mu.Unlock()

	if !ok || list == nil {
		return
	}

	list.mu.Lock()
	defer list.mu.Unlock()

	for i, conn := range list.conns {
		if conn.h2Conn == dead {
			_ = conn.rawConn.Close()
			list.conns = append(list.conns[:i], list.conns[i+1:]...)
			return
		}
	}
}
