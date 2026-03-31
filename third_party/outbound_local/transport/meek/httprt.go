package meek

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	globalRoundTripperCacheMap    map[string]http.RoundTripper
	globalRoundTripperCacheAccess sync.Mutex
)

type httpTripperClient struct {
	addr       string
	nextDialer netproxy.Dialer
	tlsConfig  *tls.Config
	url        string
}

func CleanGlobalRoundTripperCache() {
	globalRoundTripperCacheAccess.Lock()
	defer globalRoundTripperCacheAccess.Unlock()
	globalRoundTripperCacheMap = make(map[string]http.RoundTripper)
}

func (c *httpTripperClient) RoundTrip(ctx context.Context, req Request) (resp Response, err error) {
	roundTripper := c.getRoundTripper()

	connectionTagStr := base64.RawURLEncoding.EncodeToString(req.ConnectionTag)

	httpRequest, err := http.NewRequest("POST", c.url, bytes.NewReader(req.Data))
	if err != nil {
		return
	}
	httpRequest.Header.Set("X-Session-ID", connectionTagStr)

	httpResp, err := roundTripper.RoundTrip(httpRequest)
	if err != nil {
		return
	}
	defer func() { _ = httpResp.Body.Close() }()

	result, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return
	}
	return Response{Data: result}, err
}

func (c *httpTripperClient) getRoundTripper() http.RoundTripper {
	globalRoundTripperCacheAccess.Lock()
	defer globalRoundTripperCacheAccess.Unlock()
	if globalRoundTripperCacheMap == nil {
		globalRoundTripperCacheMap = make(map[string]http.RoundTripper)
	}
	if _, ok := globalRoundTripperCacheMap[c.addr]; !ok {
		globalRoundTripperCacheMap[c.addr] = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rc, err := c.nextDialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("[Meek]: dial to %s: %w", c.addr, err)
				}
				return &netproxy.FakeNetConn{
					Conn:  rc,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			TLSClientConfig: c.tlsConfig,
		}
	}
	return globalRoundTripperCacheMap[c.addr]
}
