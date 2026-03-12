/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"

	stickyip "github.com/daeuniverse/outbound/dialer/stickyip"
)

const (
	IdxDnsTcp4 = 0
	IdxDnsTcp6 = 1
	IdxDnsUdp4 = 2
	IdxDnsUdp6 = 3
	IdxTcp4    = 4
	IdxTcp6    = 5
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type Dialer struct {
	*GlobalOption
	InstanceOption
	netproxy.Dialer
	property *Property

	collectionFineMu sync.RWMutex
	collections      [6]*collection

	tickerMu sync.Mutex
	ticker   *time.Timer
	checkCh  chan time.Time
	ctx      context.Context
	cancel   context.CancelFunc

	checkActivated bool

	httpClients  map[string]*http.Client
	httpClientMu sync.Mutex

	failCount [6]int

	// stickyIpDialer holds reference to the sticky IP wrapper for cache management
	// This is used for health check cycle management and failover tracking
	stickyIpDialer *stickyip.StickyIpDialer
}

type GlobalOption struct {
	D.ExtraOption
	Log               *logrus.Logger
	TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
}

type InstanceOption struct {
	DisableCheck bool
}

type Property struct {
	D.Property
	SubscriptionTag string
}

type AliveDialerSetSet map[*AliveDialerSet]int

func NewGlobalOption(global *config.Global, log *logrus.Logger) *GlobalOption {
	return &GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:       global.AllowInsecure,
			TlsImplementation:   global.TlsImplementation,
			UtlsImitate:         global.UtlsImitate,
			BandwidthMaxTx:      global.BandwidthMaxTx,
			BandwidthMaxRx:      global.BandwidthMaxRx,
			TlsFragment:         global.TlsFragment,
			TlsFragmentLength:   global.TlsFragmentLength,
			TlsFragmentInterval: global.TlsFragmentInterval,
			UDPHopInterval:      global.UDPHopInterval,
		},
		Log:               log,
		TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Log: log, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp), Somark: global.SoMarkFromDae},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, iOption InstanceOption, property *Property) *Dialer {
	var collections [6]*collection
	for i := range collections {
		collections[i] = newCollection()
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:     option,
		InstanceOption:   iOption,
		property:         property,
		collectionFineMu: sync.RWMutex{},
		collections:      collections,
		tickerMu:         sync.Mutex{},
		ticker:           nil,
		checkCh:          make(chan time.Time, 1),
		ctx:              ctx,
		cancel:           cancel,
		httpClients:      make(map[string]*http.Client),
	}
	d.Dialer = dialer
	option.Log.WithField("dialer", d.Property().Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.InstanceOption, d.property)
}

func (d *Dialer) Close() error {
	d.cancel()
	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
	}
	d.tickerMu.Unlock()

	d.httpClientMu.Lock()
	for k, cli := range d.httpClients {
		if cli != nil {
			if t, ok := cli.Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
			delete(d.httpClients, k)
		}
	}
	d.httpClientMu.Unlock()
	return nil
}

func (d *Dialer) Property() *Property {
	return d.property
}

// IncrementCheckCycle advances the health check cycle for sticky IP caching.
// This is called by the health checker to advance the cycle and invalidate
// old cache entries, allowing IP failover to different resolved IPs.
func (d *Dialer) IncrementCheckCycle() {
	if d.stickyIpDialer != nil {
		d.stickyIpDialer.IncrementCheckCycle()
	}
}

// NotifyHealthCheckResult notifies about health check results.
// On success: clears failed QUIC DCID cache and resets proxy IP failure counter.
// On failure: tracks consecutive failures and may invalidate cached IP.
func (d *Dialer) NotifyHealthCheckResult(success bool) {
	if success {
		// Reset proxy IP failure counter on success
		if d.property.Address != "" {
			recordProxySuccess(d.property.Address)
		}
		// Clear failed QUIC DCID cache
		notifyQuicDcidCacheClearImpl()
	} else {
		// Track failures - may trigger IP cache invalidation
		if d.property.Address != "" {
			if recordProxyFailure(d.property.Address) {
				// Threshold reached - sticky IP cache will be invalidated
				// and fresh IPs will be tried on next cycle
			}
		}
	}
}

// NotifyProxyFailure is called when a proxy server connection fails (e.g., connection refused).
// It immediately invalidates the cached IP for the specified protocol so that
// the next connection can try a different IP.
func (d *Dialer) NotifyProxyFailure(proxyAddr, protocol string) {
	if d.stickyIpDialer == nil {
		return
	}
	// Invalidate the cache for this specific protocol
	d.stickyIpDialer.InvalidateProtocolCache(proxyAddr, protocol)
}

// notifyQuicDcidCacheClearImpl is the actual implementation.
// It's defined as a var that gets initialized at runtime to avoid circular dependency.
var notifyQuicDcidCacheClearImpl func() = func() {
	// Default implementation does nothing
	// Will be overridden by control package during initialization
}

// SetQuicDcidCacheClearFunc sets the function to clear failed QUIC DCID cache.
// This should be called by control package during initialization.
func SetQuicDcidCacheClearFunc(fn func()) {
	notifyQuicDcidCacheClearImpl = fn
}

func (d *Dialer) GetHttpClient(idx int, ip netip.Addr, soMark uint32, mptcp bool) *http.Client {
	key := fmt.Sprintf("%d-%s", idx, ip.String())

	d.httpClientMu.Lock()
	defer d.httpClientMu.Unlock()

	if cli, ok := d.httpClients[key]; ok {
		return cli
	}

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				// Use the specific IP resolved for this probe to ensure accurate measurement.
				// Connection reuse will happen naturally at the Transport level for the same host/IP.
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(ip.String(), port)

				conn, err := d.Dialer.DialContext(ctx, common.MagicNetwork("tcp", soMark, mptcp), addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			// TLSHandshakeTimeout bounds the TLS setup phase so that a slow
			// or unresponsive proxy server does not indefinitely delay the
			// latency measurement for this probe target.
			TLSHandshakeTimeout: 10 * time.Second,
			// IdleConnTimeout and ResponseHeaderTimeout are per-connection knobs
			// that prevent resource leaks on idle or stalled connections.
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			// Allow a small pool of persistent connections per probe IP so that
			// repeated health checks reuse TCP connections instead of re-doing
			// the full TCP + TLS handshake each interval.
			MaxIdleConnsPerHost: 2,
			// Health checks send minimal HEAD/GET requests; disabling transparent
			// compression avoids the deflate/gzip overhead on the response path
			// and keeps latency measurements free from decompression noise.
			DisableCompression: true,
		},
	}
	d.httpClients[key] = cli
	return cli
}
