package http

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/http2"
)

type Conn struct {
	nextDialer netproxy.Dialer
	conn       netproxy.Conn

	proxy        *HttpProxy
	magicNetwork string
	tgt          string

	ctxShakeFinished    context.Context
	cancelShakeFinished func()
	muShake             sync.Mutex
	muFinishShakeFuncs  sync.Mutex
	finishShakeFuncs    []func(conn netproxy.Conn)

	isH2      bool
	closeOnce sync.Once
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return io.EOF
		}
		if c.isH2 {
			return nil
		}
		return c.conn.SetDeadline(t)
	default:
		c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn netproxy.Conn) {
			if c.isH2 {
				return
			}
			_ = conn.SetDeadline(t)
		})
		return nil
	}
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return io.EOF
		}
		if c.isH2 {
			return nil
		}
		return c.conn.SetReadDeadline(t)
	default:
		c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn netproxy.Conn) {
			if c.isH2 {
				return
			}
			_ = conn.SetReadDeadline(t)
		})
		return nil
	}
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return io.EOF
		}
		if c.isH2 {
			return nil
		}
		return c.conn.SetWriteDeadline(t)
	default:
		c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn netproxy.Conn) {
			if c.isH2 {
				return
			}
			_ = conn.SetWriteDeadline(t)
		})
		return nil
	}
}

func NewConn(nextDialer netproxy.Dialer, proxy *HttpProxy, addr string, network string) *Conn {
	ctxShakeFinished, cancelShakeFinished := context.WithCancel(context.Background())
	return &Conn{
		nextDialer:          nextDialer,
		proxy:               proxy,
		tgt:                 addr,
		magicNetwork:        network,
		ctxShakeFinished:    ctxShakeFinished,
		cancelShakeFinished: cancelShakeFinished,
	}
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.muShake.Lock()
	defer c.muShake.Unlock()
	defer func() {
		if err == nil {
			c.muFinishShakeFuncs.Lock()
			defer c.muFinishShakeFuncs.Unlock()
			// SetDeadline after c.conn filled.
			for _, f := range c.finishShakeFuncs {
				f(c.conn)
			}
		}
	}()
	select {
	case <-c.ctxShakeFinished.Done():
		if c.conn == nil {
			return 0, io.EOF
		}
		return c.conn.Write(b)
	default:
		// Handshake
		defer c.cancelShakeFinished()
		_, firstLine, _ := bufio.ScanLines(b, true)
		isHttpReq := regexp.MustCompile(`^\S+ \S+ HTTP/[\d.]+$`).Match(firstLine)

		var req *http.Request
		if isHttpReq && !c.proxy.https {
			// HTTP Request

			req, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					// Request more data.
					return len(b), nil
				}
				// Error
				return 0, err
			}

			req.URL.Scheme = "http"
			req.URL.Host = c.tgt
		} else {
			// Arbitrary TCP

			// HACK. http.ReadRequest also does this.
			reqURL, err := url.Parse("http://" + c.tgt)
			if err != nil {
				return 0, err
			}
			method := "CONNECT"
			if !c.proxy.transport {
				reqURL.Scheme = ""
			} else {
				method = "PUT"
			}

			req, err = http.NewRequest(method, reqURL.String(), nil)
			if err != nil {
				return 0, err
			}
		}
		if c.proxy.Host != "" {
			req.Host = c.proxy.Host
		} else if c.proxy.transport {
			req.Host = "www.example.com"
		}
		if c.proxy.transport {
			req.URL.Path = c.proxy.Path
		}
		req.Close = false
		if c.proxy.HaveAuth {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.proxy.Username+":"+c.proxy.Password)))
		}
		// https://www.rfc-editor.org/rfc/rfc7230#appendix-A.1.2
		// As a result, clients are encouraged not to send the Proxy-Connection header field in any requests.
		if len(req.Header.Values("Proxy-Connection")) > 0 {
			req.Header.Del("Proxy-Connection")
		}

		connectHttp1 := func(rawConn netproxy.Conn) (n int, err error) {
			err = req.WriteProxy(rawConn)
			if err != nil {
				return 0, err
			}

			if isHttpReq {
				// Allow read here to void race.
				return len(b), nil
			} else {
				// We should read tcp connection here, and we will be guaranteed higher priority by chShakeFinished.
				resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
				if err != nil {
					if resp != nil {
						_ = resp.Body.Close()
						return 0, err
					}
				}
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					err = fmt.Errorf("connect server using proxy error, StatusCode [%d]", resp.StatusCode)
					return 0, err
				}
				return rawConn.Write(b)
			}
		}

		// Thanks to v2fly/v2ray-core.
		connectHttp2 := func(rawConn netproxy.Conn, h2clientConn *http2.ClientConn, req *http.Request) (conn *http2Conn, n int, err error) {
			pr, pw := io.Pipe()
			req.Body = pr

			var pErr error
			var done = make(chan struct{})

			go func() {
				_, pErr = pw.Write(b)
				done <- struct{}{}
			}()

			resp, err := h2clientConn.RoundTrip(req) // nolint: bodyclose
			if err != nil {
				return nil, 0, err
			}

			<-done
			if pErr != nil {
				return nil, 0, pErr
			}

			if resp.StatusCode != http.StatusOK {
				return nil, 0, fmt.Errorf("proxy responded with non 200 code: %v", resp.Status)
			}
			return newHTTP2Conn(&netproxy.FakeNetConn{
				Conn: rawConn,
			}, pw, resp.Body), len(b), nil
		}

		if !c.proxy.https {
			ctx, cancel := netproxy.NewDialTimeoutContext()
			defer cancel()
			conn, err := c.nextDialer.DialContext(ctx, c.magicNetwork, c.proxy.Addr)
			if err != nil {
				return 0, err
			}
			c.conn = conn
			return connectHttp1(conn)
		}

		rawConn, h2Conn, err := connPool.GetConn(c.nextDialer, c.proxy.Addr, c.magicNetwork)
		if err != nil {
			return 0, err
		}
		if h2Conn != nil {
			proxyConn, n, err := connectHttp2(rawConn, h2Conn, req)
			if err != nil {
				return 0, err
			}
			c.conn = proxyConn
			c.isH2 = true
			return n, nil
		} else {
			ctx, cancel := netproxy.NewDialTimeoutContext()
			defer cancel()
			conn, err := c.nextDialer.DialContext(ctx, c.magicNetwork, c.proxy.Addr)
			if err != nil {
				return 0, err
			}
			c.conn = conn
			return connectHttp1(conn)
		}
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	<-c.ctxShakeFinished.Done()
	if c.conn == nil {
		return 0, io.EOF
	}
	return c.conn.Read(b)
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// HTTP/2 connections are managed by the connection pool, don't close them.
		// HTTP/1.1 connections should be closed to prevent resource leaks.
		if !c.isH2 && c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) *http2Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	_ = h.in.Close()
	return h.out.Close()
}

type h2Conn struct {
	rawConn    netproxy.Conn
	h2Conn     *http2.ClientConn
}

type lockedList struct {
	l  *list.List
	mu sync.Mutex
}

func newLockedList() *lockedList {
	return &lockedList{
		l:  list.New(),
		mu: sync.Mutex{},
	}
}

type poolIdent struct {
	ele  *list.Element
	addr string
}
type h2ConnsPool struct {
	mu           sync.Mutex
	h2ConnsPool  map[string]*lockedList
	h2Conn2Ident map[*http2.ClientConn]*poolIdent
	addr2Dialer  sync.Map
	addr2Somark  sync.Map
}

func newH2ConnsPool() *h2ConnsPool {
	return &h2ConnsPool{
		mu:           sync.Mutex{},
		h2ConnsPool:  make(map[string]*lockedList),
		h2Conn2Ident: make(map[*http2.ClientConn]*poolIdent),
		addr2Dialer:  sync.Map{},
	}
}

func (p *h2ConnsPool) registerAddrToDialerMapping(addr string, dialer netproxy.Dialer) {
	p.addr2Dialer.Store(addr, dialer)
}
func (p *h2ConnsPool) registerAddrToMagicNetworkMapping(addr string, magicNetwork string) {
	p.addr2Somark.Store(addr, magicNetwork)
}

func (p *h2ConnsPool) GetUnderlayConn(c *http2.ClientConn) (netproxy.Conn, error) {
	p.mu.Lock()
	ident, ok := p.h2Conn2Ident[c]
	p.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("GetUnderlayConn: not found")
	}
	return ident.ele.Value.(*h2Conn).rawConn, nil
}

func (p *h2ConnsPool) GetConn(nextDialer netproxy.Dialer, addr string, magicNetwork string) (netproxy.Conn, *http2.ClientConn, error) {
	p.mu.Lock()
	if p.h2ConnsPool[addr] == nil {
		p.h2ConnsPool[addr] = newLockedList()
	}
	conns, cachedConnsFound := p.h2ConnsPool[addr]
	p.mu.Unlock()

	if cachedConnsFound {
		conns.mu.Lock()
		if conns.l.Len() > 0 {
			for p := conns.l.Front(); p != nil; p = p.Next() {
				h2Conn := p.Value.(*h2Conn)
				if h2Conn.h2Conn.CanTakeNewRequest() {
					conns.mu.Unlock()
					return h2Conn.rawConn, h2Conn.h2Conn, nil
				}
			}
		}
		conns.mu.Unlock()
	}

	// New.
	ctx, cancel := netproxy.NewDialTimeoutContext()
	defer cancel()
	rawConn, err := nextDialer.DialContext(ctx, magicNetwork, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("h2ConnsPool.GetClientConn: %w", err)
	}
	nextProto := ""
	if tlsConn, ok := rawConn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			return nil, nil, err
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	switch nextProto {
	case "", "http/1.1":
		return rawConn, nil, nil
	case "h2":
		t := http2.Transport{
			ConnPool: p,
		}
		h2clientConn, err := t.NewClientConn(&netproxy.FakeNetConn{
			Conn: rawConn,
		})
		if err != nil {
			return nil, nil, err
		}
		conns.mu.Lock()
		ele := conns.l.PushFront(&h2Conn{
			rawConn: rawConn,
			h2Conn:  h2clientConn,
		})
		conns.mu.Unlock()
		p.mu.Lock()
		p.h2Conn2Ident[h2clientConn] = &poolIdent{
			ele:  ele,
			addr: addr,
		}
		p.mu.Unlock()
		p.registerAddrToDialerMapping(addr, nextDialer)
		p.registerAddrToMagicNetworkMapping(addr, magicNetwork)
		return rawConn, h2clientConn, nil
	default:
		return nil, nil, fmt.Errorf("negotiated unsupported application layer protocol: %v", nextProto)
	}
}

func (p *h2ConnsPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	d, ok := p.addr2Dialer.Load(addr)
	if !ok {
		return nil, fmt.Errorf("no valid dialer for h2ConnsPool.GetClientConn")
	}
	somark, _ := p.addr2Somark.Load(addr)
	_, h2Conn, err := p.GetConn(d.(netproxy.Dialer), addr, somark.(string))
	return h2Conn, err
}

func (p *h2ConnsPool) MarkDead(h2c *http2.ClientConn) {
	p.mu.Lock()
	ident, ok := p.h2Conn2Ident[h2c]
	if !ok {
		p.mu.Unlock()
		return
	}
	conns := p.h2ConnsPool[ident.addr]
	delete(p.h2Conn2Ident, h2c)
	p.mu.Unlock()
	conns.mu.Lock()
	conns.l.Remove(ident.ele)
	conns.mu.Unlock()
}

var connPool = newH2ConnsPool()
