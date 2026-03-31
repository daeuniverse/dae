package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	TCP(addr string, ctx context.Context) (netproxy.Conn, error)
	UDP(addr string, ctx context.Context) (netproxy.Conn, error)
}

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

func NewClient(config *Config) (Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &clientImpl{
		config: config,
	}
	return c, nil
}

// TODO: How to handle quic conn for the same dialer with different marks?

type clientImpl struct {
	config *Config

	pktConn net.PacketConn
	conn    quic.Connection

	udpSM *udpSessionManager

	m sync.Mutex
}

func (c *clientImpl) connect(ctx context.Context) (*HandshakeInfo, error) {
	pktConn, err := c.config.ConnFactory.New(ctx)
	if err != nil {
		return nil, err
	}
	serverAddr := quicRemoteAddr(pktConn, c.config.ServerAddr)
	// Convert config to TLS config & QUIC config
	tlsConfig := &tls.Config{
		ServerName:            c.config.TLSConfig.ServerName,
		InsecureSkipVerify:    c.config.TLSConfig.InsecureSkipVerify,
		VerifyPeerCertificate: c.config.TLSConfig.VerifyPeerCertificate,
		RootCAs:               c.config.TLSConfig.RootCAs,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	// Prepare Transport
	var conn quic.EarlyConnection
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, pktConn, serverAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	u := &url.URL{
		Scheme: "https",
		Host:   protocol.URLHost,
		Path:   protocol.URLPath,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header = make(http.Header)
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return nil, coreErrs.ConnectError{Err: err}
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pktConn.Close()
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(conn, actualTx)
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(conn)
		}
	}
	_ = resp.Body.Close()

	c.pktConn = pktConn
	c.conn = conn
	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

func quicRemoteAddr(pktConn net.PacketConn, fallback net.Addr) net.Addr {
	type remoteAddrConn interface {
		RemoteAddr() net.Addr
	}
	if c, ok := pktConn.(remoteAddrConn); ok {
		if addr := c.RemoteAddr(); addr != nil {
			return addr
		}
	}
	return fallback
}

func (c *clientImpl) active() bool {
	if c.conn == nil {
		return false
	}
	select {
	case <-c.conn.Context().Done():
		return false
	default:
		return true
	}
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *clientImpl) openStream() (*utils.QStream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string, ctx context.Context) (netproxy.Conn, error) {
	c.m.Lock()
	select {
	case <-ctx.Done():
		c.m.Unlock()
		return nil, errors.New("context deadline exceeded")
	default:
	}
	if !c.active() {
		_, err := c.connect(ctx)
		if err != nil {
			c.m.Unlock()
			return nil, err
		}
	}
	c.m.Unlock()

	stream, err := c.openStream()
	if err != nil {
		c.handleIfConnectionClosed(err)
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
		defer func() { _ = stream.SetDeadline(time.Time{}) }()
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		_ = stream.Close()
		c.handleIfConnectionClosed(err)
		return nil, err
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		c.handleIfConnectionClosed(err)
		return nil, err
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: "from remote: " + msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *clientImpl) UDP(addr string, ctx context.Context) (netproxy.Conn, error) {
	c.m.Lock()
	select {
	case <-ctx.Done():
		c.m.Unlock()
		return nil, errors.New("context deadline exceeded")
	default:
	}
	if !c.active() {
		_, err := c.connect(ctx)
		if err != nil {
			c.m.Unlock()
			return nil, err
		}
	}
	c.m.Unlock()

	if c.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	conn, err := c.udpSM.NewUDP(addr)
	c.handleIfConnectionClosed(err)
	return conn, err
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// indicates that the QUIC connection has been permanently closed,
// and if so, wraps the error with coreErrs.ClosedError.
// PITFALL: sometimes quic-go has "internal errors" that are not net.Error,
// but we still need to treat them as ClosedError.
func (c *clientImpl) handleIfConnectionClosed(err error) {
	if err == nil {
		return
	}
	if _, ok := err.(coreErrs.ClosedError); ok {
		_ = c.conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = c.pktConn.Close()
		return
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Temporary() { // nolint:staticcheck
		_ = c.conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = c.pktConn.Close()
	}
}

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, coreErrs.DialError{Message: msg}
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

func (c *tcpConn) CloseWrite() error {
	// quic-go's default close only closes the write side
	// for more info, see comments in utils.QStream struct
	return c.Orig.Stream.Close()
}

func (c *tcpConn) CloseRead() error {
	c.Orig.Stream.CancelRead(0)
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

type udpIOImpl struct {
	Conn quic.Connection
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			if !outbounderrors.IsTemporaryError(err) {
				return nil, err
			}
			continue
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}
